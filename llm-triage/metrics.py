"""
Cost, latency, and quality metrics for the LLM triage pipeline.

Tracks per-call and aggregate statistics:
  - Token usage (input/output) and estimated cost
  - Response latency
  - Triage quality signals (confidence distribution, severity breakdown)

Metrics are logged to stdout and optionally written to OpenSearch
for dashboard visualization.
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("llm-triage.metrics")

# ---------------------------------------------------------------------------
# Pricing per 1M tokens (as of March 2026)
# ---------------------------------------------------------------------------

MODEL_PRICING = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
}


@dataclass
class CallMetrics:
    """Metrics captured for a single Claude API call."""

    timestamp: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    estimated_cost_usd: float = 0.0
    severity: str = ""
    confidence: float = 0.0
    false_positive_likelihood: str = ""
    rule_id: str = ""
    rule_level: int = 0
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AggregateMetrics:
    """Running totals across the session lifetime."""

    total_calls: int = 0
    total_errors: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: int = 0
    severity_counts: dict = field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    fp_counts: dict = field(
        default_factory=lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    confidence_sum: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.total_calls, 1)

    @property
    def avg_cost_usd(self) -> float:
        return self.total_cost_usd / max(self.total_calls, 1)

    @property
    def avg_confidence(self) -> float:
        return self.confidence_sum / max(self.total_calls - self.total_errors, 1)

    def summary(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "total_errors": self.total_errors,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "avg_cost_usd": round(self.avg_cost_usd, 4),
            "avg_confidence": round(self.avg_confidence, 3),
            "severity_distribution": dict(self.severity_counts),
            "false_positive_distribution": dict(self.fp_counts),
        }


class MetricsTracker:
    """
    Tracks per-call and aggregate metrics for the triage pipeline.

    Usage:
        tracker = MetricsTracker()
        timer = tracker.start_timer()
        # ... make Claude API call ...
        metrics = tracker.record_call(timer, response, triage_result, alert)
    """

    def __init__(self):
        self.aggregate = AggregateMetrics()
        self.recent_calls: list[CallMetrics] = []
        self._max_recent = 100  # rolling window

    def start_timer(self) -> float:
        """Call before making the API request. Returns a start timestamp."""
        return time.monotonic()

    def record_call(
        self,
        start_time: float,
        api_response,
        triage_result: Optional[dict],
        alert: dict,
        model: str,
        error: Optional[str] = None,
    ) -> CallMetrics:
        """
        Record metrics from a completed Claude API call.

        Args:
            start_time: From start_timer()
            api_response: The anthropic Message object (or None on error)
            triage_result: The parsed structured triage dict (or None)
            alert: The original Wazuh alert
            model: Model name used
            error: Error message if the call failed
        """
        latency_ms = int((time.monotonic() - start_time) * 1000)

        metrics = CallMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            model=model,
            latency_ms=latency_ms,
            rule_id=str(alert.get("rule", {}).get("id", "")),
            rule_level=int(alert.get("rule", {}).get("level", 0)),
        )

        if error:
            metrics.success = False
            metrics.error = error
            self.aggregate.total_errors += 1
        elif api_response:
            # Extract token usage from the API response
            usage = getattr(api_response, "usage", None)
            if usage:
                metrics.input_tokens = usage.input_tokens
                metrics.output_tokens = usage.output_tokens
                metrics.estimated_cost_usd = self._calculate_cost(
                    model, usage.input_tokens, usage.output_tokens
                )

            # Extract quality signals from triage result
            if triage_result:
                metrics.severity = triage_result.get("severity", "")
                metrics.confidence = triage_result.get("confidence", 0.0)
                metrics.false_positive_likelihood = triage_result.get(
                    "false_positive_likelihood", ""
                )

                # Update aggregate quality counters
                if metrics.severity in self.aggregate.severity_counts:
                    self.aggregate.severity_counts[metrics.severity] += 1
                if metrics.false_positive_likelihood in self.aggregate.fp_counts:
                    self.aggregate.fp_counts[metrics.false_positive_likelihood] += 1
                self.aggregate.confidence_sum += metrics.confidence

        # Update aggregate totals
        self.aggregate.total_calls += 1
        self.aggregate.total_input_tokens += metrics.input_tokens
        self.aggregate.total_output_tokens += metrics.output_tokens
        self.aggregate.total_cost_usd += metrics.estimated_cost_usd
        self.aggregate.total_latency_ms += metrics.latency_ms

        # Keep rolling window of recent calls
        self.recent_calls.append(metrics)
        if len(self.recent_calls) > self._max_recent:
            self.recent_calls.pop(0)

        # Log the call metrics
        if metrics.success:
            logger.info(
                "API call: model=%s tokens=%d+%d cost=$%.4f latency=%dms "
                "severity=%s confidence=%.2f",
                model,
                metrics.input_tokens,
                metrics.output_tokens,
                metrics.estimated_cost_usd,
                metrics.latency_ms,
                metrics.severity,
                metrics.confidence,
            )
        else:
            logger.error(
                "API call FAILED: model=%s latency=%dms error=%s",
                model,
                metrics.latency_ms,
                metrics.error,
            )

        return metrics

    def log_summary(self):
        """Log aggregate metrics summary."""
        s = self.aggregate.summary()
        logger.info(
            "Session metrics: calls=%d errors=%d tokens=%d cost=$%.4f "
            "avg_latency=%dms avg_confidence=%.3f",
            s["total_calls"],
            s["total_errors"],
            s["total_tokens"],
            s["total_cost_usd"],
            s["avg_latency_ms"],
            s["avg_confidence"],
        )
        logger.info("Severity distribution: %s", s["severity_distribution"])
        logger.info("FP distribution: %s", s["false_positive_distribution"])

    @staticmethod
    def _calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate estimated cost in USD."""
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["claude-sonnet-4-6"])
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost
