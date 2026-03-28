"""
LangChain Callback Handler for Token & Cost Tracking (v1.1)

LangChain uses a "callback" system to let you hook into what's happening
inside a chain without modifying the chain itself. Think of it like
event listeners — you register a handler that says "whenever an LLM
call finishes, run this code."

This module implements a callback handler that captures:
  - Input tokens (how much text you sent to Claude)
  - Output tokens (how much text Claude sent back)
  - Model name (for cost calculation)
  - Latency (how long the call took)

The handler feeds this data into our existing MetricsTracker, which
calculates costs and logs aggregate statistics.

How callbacks work in LangChain:
  1. You create a handler (this class)
  2. You pass it to chain.invoke() via the `config` parameter
  3. LangChain calls your handler methods at specific points:
     - on_llm_start()  → called when the LLM request begins
     - on_llm_end()    → called when the LLM response arrives
     - on_llm_error()  → called if the LLM request fails

Usage:
    from callbacks import MetricsCallbackHandler

    handler = MetricsCallbackHandler(model="claude-sonnet-4-6")
    result = chain.invoke(inputs, config={"callbacks": [handler]})
    print(handler.total_input_tokens)   # e.g., 1250
    print(handler.total_output_tokens)  # e.g., 430
    print(handler.total_cost_usd)       # e.g., 0.0102
"""

import time
import logging
from typing import Any, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

logger = logging.getLogger("llm-triage.callbacks")

# Pricing per 1M tokens — must match metrics.py
MODEL_PRICING = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
}


class MetricsCallbackHandler(BaseCallbackHandler):
    """
    Captures token usage and cost from every LLM call in a chain.

    This handler is passed into chain.invoke() and LangChain
    automatically calls our methods at the right time. We don't
    need to modify the chain code at all — the callback system
    keeps metrics tracking completely separate from business logic.

    Attributes:
        total_input_tokens:  Total input tokens across all calls
        total_output_tokens: Total output tokens across all calls
        total_cost_usd:      Total estimated cost across all calls
        call_count:          Number of LLM calls made
        last_input_tokens:   Input tokens from the most recent call
        last_output_tokens:  Output tokens from the most recent call
        last_cost_usd:       Cost from the most recent call
        last_latency_ms:     Latency of the most recent call
    """

    def __init__(self, model: str = "claude-sonnet-4-6"):
        super().__init__()
        self.model = model

        # Per-call metrics (reset on each LLM call)
        self.last_input_tokens: int = 0
        self.last_output_tokens: int = 0
        self.last_cost_usd: float = 0.0
        self.last_latency_ms: int = 0
        self._call_start_time: float = 0.0

        # Aggregate metrics (accumulate across all calls)
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self.call_count: int = 0
        self.error_count: int = 0

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when the LLM request is about to be sent."""
        self._call_start_time = time.monotonic()

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when the LLM response arrives successfully.

        LangChain passes an LLMResult object that contains
        llm_output with token usage data from the API response.
        """
        # Calculate latency
        self.last_latency_ms = int(
            (time.monotonic() - self._call_start_time) * 1000
        )

        # Extract token usage from LLMResult
        # ChatAnthropic puts this in response.llm_output
        llm_output = response.llm_output or {}
        usage = llm_output.get("usage", {})

        self.last_input_tokens = usage.get("input_tokens", 0)
        self.last_output_tokens = usage.get("output_tokens", 0)

        # If usage wasn't in llm_output, try token_usage (some LangChain versions)
        if self.last_input_tokens == 0:
            token_usage = llm_output.get("token_usage", {})
            self.last_input_tokens = token_usage.get("prompt_tokens", 0)
            self.last_output_tokens = token_usage.get("completion_tokens", 0)

        # Calculate cost
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["claude-sonnet-4-6"])
        self.last_cost_usd = (
            (self.last_input_tokens / 1_000_000) * pricing["input"]
            + (self.last_output_tokens / 1_000_000) * pricing["output"]
        )

        # Update aggregates
        self.total_input_tokens += self.last_input_tokens
        self.total_output_tokens += self.last_output_tokens
        self.total_cost_usd += self.last_cost_usd
        self.call_count += 1

        logger.debug(
            "LLM call complete: %d+%d tokens, $%.4f, %dms",
            self.last_input_tokens,
            self.last_output_tokens,
            self.last_cost_usd,
            self.last_latency_ms,
        )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when the LLM request fails."""
        self.last_latency_ms = int(
            (time.monotonic() - self._call_start_time) * 1000
        )
        self.error_count += 1
        logger.error("LLM call failed after %dms: %s", self.last_latency_ms, error)

    def get_usage_proxy(self):
        """
        Returns an object that mimics the raw Anthropic API response shape.

        This bridges LangChain callbacks to our existing MetricsTracker,
        which expects an object with .usage.input_tokens and .usage.output_tokens.
        """
        class _Usage:
            def __init__(self, input_tokens, output_tokens):
                self.input_tokens = input_tokens
                self.output_tokens = output_tokens

        class _Proxy:
            def __init__(self, usage):
                self.usage = usage

        return _Proxy(_Usage(self.last_input_tokens, self.last_output_tokens))

    def reset_last(self):
        """Reset per-call metrics (call before each new invocation)."""
        self.last_input_tokens = 0
        self.last_output_tokens = 0
        self.last_cost_usd = 0.0
        self.last_latency_ms = 0
