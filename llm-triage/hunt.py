"""
Proactive Threat Hunt Mode

Instead of triaging individual high-severity alerts, hunt mode pulls
batches of low-to-medium severity events and asks Claude to analyze
them as a group — looking for attack patterns that no single alert
would reveal.

This is the difference between reactive alerting and proactive hunting:
  - Reactive: "Alert level 12 fired → triage it"
  - Proactive: "Here are 200 events from the last hour. Do you see
    any lateral movement, persistence, data staging, or C2 patterns?"

Usage:
    python hunt.py                     # Run one hunt cycle
    python hunt.py --continuous        # Hunt every HUNT_INTERVAL
    python hunt.py --hours 4           # Look back 4 hours
    python hunt.py --focus lateral     # Focus on specific TTP

Hunt findings are written to the 'wazuh-llm-hunts' OpenSearch index.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import requests
from requests.auth import HTTPBasicAuth

from schemas import TRIAGE_TOOL
from metrics import MetricsTracker

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
INDEXER_URL = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200")
INDEXER_USERNAME = os.environ.get("INDEXER_USERNAME", "admin")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD", "")
HUNT_INTERVAL = int(os.environ.get("HUNT_INTERVAL_SECONDS", "3600"))  # 1 hour

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("llm-hunt")

PROMPT_DIR = Path(__file__).parent / "prompts"

# ---------------------------------------------------------------------------
# Hunt-specific system prompt
# ---------------------------------------------------------------------------

HUNT_SYSTEM_PROMPT = (PROMPT_DIR / "hunt_system.txt").read_text()

# ---------------------------------------------------------------------------
# Threat hunt focus areas
# ---------------------------------------------------------------------------

HUNT_FOCUSES = {
    "lateral": {
        "name": "Lateral Movement",
        "description": "Look for signs of an attacker moving between systems",
        "query_boost": ["authentication", "logon", "remote", "smb", "wmi", "psexec"],
        "mitre_tactics": ["TA0008"],
    },
    "persistence": {
        "name": "Persistence Mechanisms",
        "description": "Look for new or modified persistence (services, scheduled tasks, registry Run keys)",
        "query_boost": ["service", "scheduled", "registry", "startup", "run key"],
        "mitre_tactics": ["TA0003"],
    },
    "exfiltration": {
        "name": "Data Exfiltration",
        "description": "Look for unusual data transfers, DNS tunneling, or large outbound connections",
        "query_boost": ["dns", "network", "transfer", "upload", "outbound"],
        "mitre_tactics": ["TA0010"],
    },
    "execution": {
        "name": "Suspicious Execution",
        "description": "Look for encoded commands, LOLBin abuse, macro execution, script engines",
        "query_boost": ["powershell", "cmd", "wscript", "certutil", "mshta", "encoded"],
        "mitre_tactics": ["TA0002"],
    },
    "general": {
        "name": "General Threat Hunt",
        "description": "Broad sweep — look for anything anomalous or suspicious",
        "query_boost": [],
        "mitre_tactics": [],
    },
}

# ---------------------------------------------------------------------------
# Hunt tool schema — structured output for hunt findings
# ---------------------------------------------------------------------------

HUNT_TOOL = {
    "name": "submit_hunt_findings",
    "description": (
        "Submit your threat hunt findings. Report any suspicious patterns, "
        "attack chains, or anomalies you identified in the event batch."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "threat_detected": {
                "type": "boolean",
                "description": "True if you found evidence of suspicious/malicious activity.",
            },
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                "description": "Overall severity of findings.",
            },
            "summary": {
                "type": "string",
                "description": "2-3 sentence summary of what you found (or didn't find).",
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Short title for this finding.",
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed explanation of the suspicious pattern.",
                        },
                        "evidence": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific log entries or event details supporting this finding.",
                        },
                        "mitre_technique": {
                            "type": "string",
                            "description": "MITRE ATT&CK technique ID (e.g., T1059.001).",
                        },
                        "recommended_action": {
                            "type": "string",
                            "description": "What to do about this finding.",
                        },
                    },
                    "required": ["title", "description", "recommended_action"],
                },
                "description": "Individual findings. Empty array if nothing suspicious.",
            },
            "patterns_checked": {
                "type": "array",
                "items": {"type": "string"},
                "description": "What attack patterns you looked for (even if not found).",
            },
            "recommended_rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "What this rule would detect.",
                        },
                        "wazuh_rule_xml": {
                            "type": "string",
                            "description": "Suggested Wazuh XML rule definition.",
                        },
                    },
                    "required": ["description"],
                },
                "description": "Suggested new Wazuh detection rules based on findings.",
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence in the overall assessment.",
            },
        },
        "required": [
            "threat_detected",
            "severity",
            "summary",
            "findings",
            "patterns_checked",
            "confidence",
        ],
    },
}


# ---------------------------------------------------------------------------
# Event collector — pulls batches from OpenSearch
# ---------------------------------------------------------------------------


class EventCollector:
    """Pulls batches of events from OpenSearch for hunt analysis."""

    def __init__(self, indexer_url: str, username: str, password: str):
        self.indexer_url = indexer_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = False

    def get_event_batch(
        self,
        hours_back: int = 1,
        min_level: int = 3,
        max_level: int = 12,
        limit: int = 200,
        focus_terms: list = None,
    ) -> list:
        """
        Pull a batch of events for threat hunting analysis.

        Unlike the triage service which only looks at level 10+,
        hunt mode pulls level 3+ events to find patterns in the noise.
        """
        must_clauses = [
            {"range": {"rule.level": {"gte": min_level, "lte": max_level}}},
            {"range": {"timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
        ]

        # Optionally boost events matching focus area keywords
        if focus_terms:
            should_clauses = [
                {"match": {"full_log": term}} for term in focus_terms
            ]
            query = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "should": should_clauses,
                        "minimum_should_match": 0,
                    }
                },
            }
        else:
            query = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must_clauses}},
            }

        try:
            response = requests.post(
                f"{self.indexer_url}/wazuh-alerts-*/_search",
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            events = [hit.get("_source", {}) for hit in hits]
            logger.info(
                "Collected %d events (level %d-%d, last %dh)",
                len(events),
                min_level,
                max_level,
                hours_back,
            )
            return events
        except requests.exceptions.RequestException as e:
            logger.error("Failed to collect events: %s", e)
            return []

    def get_event_summary(self, events: list) -> dict:
        """Generate a statistical summary of the event batch."""
        if not events:
            return {"total": 0}

        rule_counts = {}
        agent_counts = {}
        level_counts = {}

        for event in events:
            rule = event.get("rule", {})
            rule_desc = rule.get("description", "unknown")
            rule_counts[rule_desc] = rule_counts.get(rule_desc, 0) + 1

            agent = event.get("agent", {}).get("name", "unknown")
            agent_counts[agent] = agent_counts.get(agent, 0) + 1

            level = str(rule.get("level", "?"))
            level_counts[level] = level_counts.get(level, 0) + 1

        return {
            "total": len(events),
            "unique_rules": len(rule_counts),
            "top_rules": dict(sorted(rule_counts.items(), key=lambda x: -x[1])[:10]),
            "agents": agent_counts,
            "level_distribution": dict(sorted(level_counts.items())),
        }


# ---------------------------------------------------------------------------
# Hunt results writer
# ---------------------------------------------------------------------------


class HuntWriter:
    """Writes hunt findings to OpenSearch."""

    INDEX_NAME = "wazuh-llm-hunts"

    def __init__(self, indexer_url: str, username: str, password: str):
        self.indexer_url = indexer_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = False

    def write_findings(
        self,
        findings: dict,
        event_summary: dict,
        focus: str,
        model: str,
        cost: float,
        latency_ms: int,
    ) -> bool:
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hunt_focus": focus,
            "model_used": model,
            "event_summary": event_summary,
            "findings": findings,
            "cost_usd": cost,
            "latency_ms": latency_ms,
        }

        try:
            response = requests.post(
                f"{self.indexer_url}/{self.INDEX_NAME}/_doc",
                auth=self.auth,
                json=doc,
                verify=self.verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            logger.info("Wrote hunt findings to '%s'", self.INDEX_NAME)
            return True
        except requests.exceptions.RequestException as e:
            logger.error("Failed to write hunt findings: %s", e)
            return False


# ---------------------------------------------------------------------------
# Main hunt logic
# ---------------------------------------------------------------------------


def run_hunt(
    focus: str = "general",
    hours_back: int = 1,
    max_events: int = 200,
) -> dict:
    """
    Execute a single threat hunt cycle.

    Returns the structured hunt findings from Claude.
    """
    focus_config = HUNT_FOCUSES.get(focus, HUNT_FOCUSES["general"])

    logger.info("=" * 60)
    logger.info("THREAT HUNT: %s", focus_config["name"])
    logger.info("  Focus: %s", focus_config["description"])
    logger.info("  Lookback: %d hours", hours_back)
    logger.info("  Model: %s", CLAUDE_MODEL)
    logger.info("=" * 60)

    # Collect events
    collector = EventCollector(INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD)
    events = collector.get_event_batch(
        hours_back=hours_back,
        limit=max_events,
        focus_terms=focus_config.get("query_boost"),
    )

    if not events:
        logger.info("No events found — nothing to hunt")
        return {"threat_detected": False, "summary": "No events in time window."}

    summary = collector.get_event_summary(events)
    logger.info("Event summary: %d events, %d unique rules, agents: %s",
                summary["total"], summary["unique_rules"],
                list(summary["agents"].keys()))

    # Format events for Claude — truncate to fit context window
    events_text = json.dumps(events[:100], indent=1, default=str)
    if len(events_text) > 50000:
        events_text = events_text[:50000] + "\n... (truncated)"

    summary_text = json.dumps(summary, indent=2)

    user_prompt = (
        f"HUNT FOCUS: {focus_config['name']}\n"
        f"{focus_config['description']}\n\n"
        f"EVENT BATCH SUMMARY:\n{summary_text}\n\n"
        f"RAW EVENTS ({len(events)} total, showing up to 100):\n"
        f"```json\n{events_text}\n```\n\n"
        "Analyze these events as a batch. Look for attack patterns, "
        "anomalies, and suspicious sequences that individual alerts "
        "would miss. Submit your findings using the submit_hunt_findings tool."
    )

    # Send to Claude
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    tracker = MetricsTracker()
    timer = tracker.start_timer()

    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=3000,
            system=HUNT_SYSTEM_PROMPT,
            tools=[HUNT_TOOL],
            tool_choice={"type": "tool", "name": "submit_hunt_findings"},
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Extract findings
        findings = None
        for block in message.content:
            if block.type == "tool_use" and block.name == "submit_hunt_findings":
                findings = block.input
                break

        usage = getattr(message, "usage", None)
        cost = 0.0
        if usage:
            cost = MetricsTracker._calculate_cost(
                CLAUDE_MODEL, usage.input_tokens, usage.output_tokens
            )

        latency = int((time.monotonic() - timer) * 1000)

        if findings:
            logger.info(
                "Hunt complete: threat_detected=%s severity=%s findings=%d cost=$%.4f",
                findings.get("threat_detected"),
                findings.get("severity"),
                len(findings.get("findings", [])),
                cost,
            )

            # Print findings
            print(f"\n{'='*60}")
            print(f"THREAT HUNT RESULTS: {focus_config['name']}")
            print(f"{'='*60}")
            print(f"Threat detected: {findings.get('threat_detected')}")
            print(f"Severity: {findings.get('severity')}")
            print(f"Confidence: {findings.get('confidence')}")
            print(f"\nSummary: {findings.get('summary')}")

            for i, f in enumerate(findings.get("findings", []), 1):
                print(f"\n--- Finding {i}: {f['title']} ---")
                print(f"  {f['description']}")
                if f.get("mitre_technique"):
                    print(f"  MITRE: {f['mitre_technique']}")
                print(f"  Action: {f['recommended_action']}")
                if f.get("evidence"):
                    for ev in f["evidence"][:3]:
                        print(f"  Evidence: {ev[:120]}")

            if findings.get("recommended_rules"):
                print(f"\n--- Suggested Detection Rules ---")
                for rule in findings["recommended_rules"]:
                    print(f"  - {rule['description']}")
                    if rule.get("wazuh_rule_xml"):
                        print(f"    {rule['wazuh_rule_xml'][:200]}")

            print(f"\nPatterns checked: {', '.join(findings.get('patterns_checked', []))}")
            print(f"Cost: ${cost:.4f} | Latency: {latency}ms")
            print(f"{'='*60}")

            # Write to OpenSearch
            writer = HuntWriter(INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD)
            writer.write_findings(findings, summary, focus, CLAUDE_MODEL, cost, latency)

            return findings

    except anthropic.APIError as e:
        logger.error("Claude API error during hunt: %s", e)
        return {"threat_detected": False, "summary": f"Hunt failed: {e}"}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="LLM Threat Hunt")
    parser.add_argument(
        "--focus",
        default="general",
        choices=list(HUNT_FOCUSES.keys()),
        help="Hunt focus area",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=1,
        help="Hours to look back (default: 1)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=200,
        help="Maximum events to analyze (default: 200)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuously every HUNT_INTERVAL seconds",
    )
    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set")
        sys.exit(1)

    if args.continuous:
        logger.info("Starting continuous hunt loop (interval: %ds)", HUNT_INTERVAL)
        while True:
            try:
                for focus in HUNT_FOCUSES:
                    run_hunt(focus=focus, hours_back=args.hours, max_events=args.max_events)
            except KeyboardInterrupt:
                logger.info("Hunt loop stopped")
                break
            except Exception as e:
                logger.error("Hunt error: %s", e, exc_info=True)
            logger.info("Sleeping %ds before next hunt cycle", HUNT_INTERVAL)
            time.sleep(HUNT_INTERVAL)
    else:
        run_hunt(focus=args.focus, hours_back=args.hours, max_events=args.max_events)


if __name__ == "__main__":
    main()
