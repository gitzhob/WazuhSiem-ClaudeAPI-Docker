"""
Wazuh → Claude LLM Triage Service

Polls the Wazuh API for high-severity alerts and sends them to Claude
for automated triage and enrichment. Results are logged and optionally
written back to OpenSearch for display in the Wazuh Dashboard.

Usage:
    python triage_service.py          # Run the polling loop
    python triage_service.py --test   # Run once with a sample alert (no Wazuh needed)
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anthropic
import requests
from requests.auth import HTTPBasicAuth

# ---------------------------------------------------------------------------
# Configuration — all from environment variables (set in .env / docker-compose)
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh.manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")

ALERT_LEVEL_THRESHOLD = int(os.environ.get("ALERT_LEVEL_THRESHOLD", "10"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

# OpenSearch settings for writing enriched results back
INDEXER_URL = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200")
INDEXER_USERNAME = os.environ.get("INDEXER_USERNAME", "admin")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD", "")

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("llm-triage")

# ---------------------------------------------------------------------------
# Load the system prompt from file
# ---------------------------------------------------------------------------

PROMPT_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT = (PROMPT_DIR / "triage_system.txt").read_text()

# ---------------------------------------------------------------------------
# Wazuh API client
# ---------------------------------------------------------------------------


class WazuhClient:
    """Queries alerts from the Wazuh indexer (OpenSearch).

    Wazuh stores alerts in OpenSearch indices named 'wazuh-alerts-*'.
    The Wazuh Manager REST API does NOT have an /alerts endpoint —
    so we query OpenSearch directly using basic auth.
    """

    def __init__(self, indexer_url: str, username: str, password: str):
        self.indexer_url = indexer_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = False  # Wazuh uses self-signed certs in Docker

    def get_recent_alerts(self, min_level: int = 10, limit: int = 20) -> list:
        """
        Fetch recent alerts from the wazuh-alerts-* OpenSearch index
        with rule.level >= min_level.

        Returns a list of alert dicts (the _source of each hit), newest first.
        """
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-30m",
                                    "lte": "now",
                                }
                            }
                        },
                    ]
                }
            },
        }

        try:
            response = requests.post(
                f"{self.indexer_url}/wazuh-alerts-*/_search",
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            # Return the _source (actual alert data) and inject _id for tracking
            alerts = []
            for hit in hits:
                alert = hit.get("_source", {})
                alert["_id"] = hit.get("_id", "")
                alerts.append(alert)
            logger.info(
                "Fetched %d alerts with level >= %d from OpenSearch",
                len(alerts),
                min_level,
            )
            return alerts
        except requests.exceptions.RequestException as e:
            logger.error("Failed to fetch alerts from OpenSearch: %s", e)
            return []


# ---------------------------------------------------------------------------
# Claude triage client
# ---------------------------------------------------------------------------


class TriageClient:
    """Sends alerts to Claude for analysis and parses the response."""

    def __init__(self, api_key: str, model: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def triage_alert(self, alert: dict) -> str:
        """
        Send a single alert to Claude for triage analysis.

        Args:
            alert: A Wazuh alert dict (raw JSON from the API)

        Returns:
            The triage analysis as a string
        """
        # Format the alert as readable JSON for Claude
        alert_text = json.dumps(alert, indent=2, default=str)

        user_prompt = (
            "Analyze the following Wazuh security alert and provide your "
            "triage assessment:\n\n"
            f"```json\n{alert_text}\n```"
        )

        logger.info(
            "Sending alert to Claude (rule: %s, level: %s)",
            alert.get("rule", {}).get("id", "unknown"),
            alert.get("rule", {}).get("level", "unknown"),
        )

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            analysis = message.content[0].text
            logger.info("Received triage response from Claude (%d chars)", len(analysis))
            return analysis
        except anthropic.APIError as e:
            logger.error("Claude API error: %s", e)
            return f"[TRIAGE ERROR] Claude API call failed: {e}"


# ---------------------------------------------------------------------------
# OpenSearch writer — stores enriched results
# ---------------------------------------------------------------------------


class OpenSearchWriter:
    """Writes enriched triage results back to OpenSearch."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = False
        self.index_name = "wazuh-llm-triage"

    def write_enriched_alert(self, original_alert: dict, analysis: str) -> bool:
        """
        Write the original alert + Claude's analysis to a dedicated index.

        Returns True if successful, False otherwise.
        """
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "original_alert": {
                "rule_id": original_alert.get("rule", {}).get("id"),
                "rule_level": original_alert.get("rule", {}).get("level"),
                "rule_description": original_alert.get("rule", {}).get("description"),
                "agent_name": original_alert.get("agent", {}).get("name"),
                "agent_id": original_alert.get("agent", {}).get("id"),
                "full_log": original_alert.get("full_log", ""),
            },
            "llm_analysis": analysis,
            "model_used": CLAUDE_MODEL,
        }

        try:
            response = requests.post(
                f"{self.base_url}/{self.index_name}/_doc",
                auth=self.auth,
                json=doc,
                verify=self.verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            logger.info(
                "Wrote enriched alert to OpenSearch index '%s'", self.index_name
            )
            return True
        except requests.exceptions.RequestException as e:
            logger.error("Failed to write to OpenSearch: %s", e)
            return False


# ---------------------------------------------------------------------------
# Alert tracker — avoids re-processing the same alert
# ---------------------------------------------------------------------------


class AlertTracker:
    """
    Keeps track of which alert IDs have already been triaged.
    Uses an in-memory set (resets on container restart).
    """

    def __init__(self):
        self._seen: set = set()

    def is_new(self, alert: dict) -> bool:
        """Return True if this alert hasn't been processed yet."""
        alert_id = alert.get("_id", alert.get("id", id(alert)))
        if alert_id in self._seen:
            return False
        self._seen.add(alert_id)
        return True

    @property
    def count(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# Sample alert for --test mode
# ---------------------------------------------------------------------------

SAMPLE_ALERTS = [
    {
        "id": "test-001",
        "timestamp": "2026-03-26T12:00:00.000+0000",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a denied user.",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "agent": {"id": "001", "name": "Collins_Desktop", "ip": "127.0.0.1"},
        "full_log": (
            "Mar 26 12:00:00 server sshd[12345]: Failed password for invalid "
            "user admin from 203.0.113.42 port 54321 ssh2"
        ),
        "data": {"srcip": "203.0.113.42", "dstuser": "admin", "srcport": "54321"},
        "location": "/var/log/auth.log",
    },
    {
        "id": "test-002",
        "timestamp": "2026-03-26T12:05:00.000+0000",
        "rule": {
            "id": "550",
            "level": 10,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {
                "id": ["T1565.001"],
                "tactic": ["Impact"],
                "technique": ["Stored Data Manipulation"],
            },
        },
        "agent": {"id": "001", "name": "Collins_Desktop", "ip": "127.0.0.1"},
        "syscheck": {
            "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "size_before": "824",
            "size_after": "1052",
            "md5_before": "3b2ce8f5e5c7a3e5b5f5e3c5d5a5f5e5",
            "md5_after": "7d4af9b2c1e8d3f6a9c2b5e8f1d4a7b3",
            "changed_attributes": ["size", "md5", "sha1", "sha256", "mtime"],
            "event": "modified",
        },
        "full_log": (
            "File 'C:\\Windows\\System32\\drivers\\etc\\hosts' modified. "
            "Size changed from 824 to 1052 bytes."
        ),
        "location": "syscheck",
    },
    {
        "id": "test-003",
        "timestamp": "2026-03-26T12:10:00.000+0000",
        "rule": {
            "id": "60106",
            "level": 12,
            "description": "Windows: A member was added to a security-enabled global group.",
            "groups": ["windows", "windows_security"],
            "mitre": {
                "id": ["T1098"],
                "tactic": ["Persistence"],
                "technique": ["Account Manipulation"],
            },
        },
        "agent": {"id": "001", "name": "Collins_Desktop", "ip": "127.0.0.1"},
        "data": {
            "win": {
                "system": {"eventID": "4728", "computer": "Collins_Desktop"},
                "eventdata": {
                    "targetUserName": "Domain Admins",
                    "memberSid": "S-1-5-21-3623811015-3361044348-30300820-1013",
                    "subjectUserName": "svc_backup",
                    "subjectDomainName": "CORP",
                },
            }
        },
        "full_log": (
            "A member was added to a security-enabled global group. "
            "Group: Domain Admins. Account: svc_backup. Event ID: 4728."
        ),
        "location": "EventChannel",
    },
]

# Keep backward compatibility
SAMPLE_ALERT = SAMPLE_ALERTS[0]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run_test_mode(alert_index: int = None):
    """
    Run triage on sample alerts — useful for testing without Wazuh.

    Args:
        alert_index: If provided (0, 1, or 2), test only that alert.
                     If None, test all sample alerts.
    """
    logger.info("=" * 60)
    logger.info("RUNNING IN TEST MODE — using sample alerts")
    logger.info("=" * 60)

    if not ANTHROPIC_API_KEY or ANTHROPIC_API_KEY.startswith("sk-ant-REPLACE"):
        logger.error(
            "ANTHROPIC_API_KEY is not set. Please set it in your .env file."
        )
        sys.exit(1)

    triage = TriageClient(ANTHROPIC_API_KEY, CLAUDE_MODEL)

    if alert_index is not None:
        alerts_to_test = [SAMPLE_ALERTS[alert_index]]
    else:
        alerts_to_test = SAMPLE_ALERTS

    for i, alert in enumerate(alerts_to_test):
        rule = alert.get("rule", {})
        data = alert.get("data", {})

        print(f"\n{'='*60}")
        print(f"SAMPLE ALERT {i+1} of {len(alerts_to_test)}:")
        print(f"{'='*60}")
        print(f"Rule: {rule.get('description', 'N/A')}")
        print(f"Level: {rule.get('level', 'N/A')}")
        print(f"Agent: {alert.get('agent', {}).get('name', 'N/A')}")
        if data.get("srcip"):
            print(f"Source IP: {data['srcip']}")
        print(f"Log: {alert.get('full_log', 'N/A')[:120]}")

        analysis = triage.triage_alert(alert)

        print(f"\n{'='*60}")
        print("CLAUDE TRIAGE ANALYSIS:")
        print(f"{'='*60}")
        print(analysis)
        print(f"{'='*60}")


def run_poll_loop():
    """Main polling loop — fetch alerts, triage new ones, write results."""
    logger.info("Starting LLM Triage Service")
    logger.info("  Indexer:       %s", INDEXER_URL)
    logger.info("  Claude model:  %s", CLAUDE_MODEL)
    logger.info("  Min level:     %d", ALERT_LEVEL_THRESHOLD)
    logger.info("  Poll interval: %ds", POLL_INTERVAL_SECONDS)

    if not ANTHROPIC_API_KEY or ANTHROPIC_API_KEY.startswith("sk-ant-REPLACE"):
        logger.error(
            "ANTHROPIC_API_KEY is not set. Please set it in your .env file."
        )
        sys.exit(1)

    if not INDEXER_PASSWORD:
        logger.error(
            "INDEXER_PASSWORD is not set. Please set it in your .env file."
        )
        sys.exit(1)

    wazuh = WazuhClient(INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD)
    triage = TriageClient(ANTHROPIC_API_KEY, CLAUDE_MODEL)
    writer = OpenSearchWriter(INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD)
    tracker = AlertTracker()

    while True:
        try:
            alerts = wazuh.get_recent_alerts(
                min_level=ALERT_LEVEL_THRESHOLD, limit=20
            )

            new_alerts = [a for a in alerts if tracker.is_new(a)]
            if new_alerts:
                logger.info("Found %d new alerts to triage", len(new_alerts))
            else:
                logger.debug("No new alerts above threshold")

            for alert in new_alerts:
                rule = alert.get("rule", {})
                logger.info(
                    "Triaging: rule=%s level=%s desc='%s'",
                    rule.get("id"),
                    rule.get("level"),
                    rule.get("description", "")[:80],
                )

                analysis = triage.triage_alert(alert)

                # Log the analysis to stdout (visible in docker compose logs)
                print(f"\n{'='*60}")
                print(f"ALERT: {rule.get('description', 'Unknown')}")
                print(f"LEVEL: {rule.get('level', '?')}")
                print(f"{'='*60}")
                print(analysis)
                print(f"{'='*60}\n")

                # Write to OpenSearch
                writer.write_enriched_alert(alert, analysis)

        except KeyboardInterrupt:
            logger.info("Shutting down gracefully...")
            break
        except Exception as e:
            logger.error("Error in poll loop: %s", e, exc_info=True)

        logger.info(
            "Sleeping %ds before next poll (tracked %d alerts so far)",
            POLL_INTERVAL_SECONDS,
            tracker.count,
        )
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    # Suppress noisy SSL warnings (Wazuh uses self-signed certs)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if "--test" in sys.argv:
        # Allow testing a specific alert: --test 0, --test 1, --test 2
        # Or test all: --test
        test_idx = sys.argv.index("--test")
        if test_idx + 1 < len(sys.argv) and sys.argv[test_idx + 1].isdigit():
            alert_num = int(sys.argv[test_idx + 1])
            if alert_num >= len(SAMPLE_ALERTS):
                print(f"Alert index {alert_num} out of range. Available: 0-{len(SAMPLE_ALERTS)-1}")
                sys.exit(1)
            run_test_mode(alert_index=alert_num)
        else:
            run_test_mode()
    else:
        run_poll_loop()
