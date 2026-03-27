"""
Threat Intelligence Feed for RAG Context

Manages indicators of compromise (IOCs) that get injected into
Claude's context during triage and hunting. Sources include:

  1. Local IOC file (iocs.json) — manually curated threat data
  2. Analyst feedback — IPs/domains flagged as malicious during review
  3. (Future) External feeds — abuse.ch, AlienVault OTX, etc.

IOCs are stored in ChromaDB alongside alert history, so when a new
alert contains a known-bad IP or domain, Claude automatically gets
context like "this IP was flagged as a C2 server in our threat feed."

Usage:
    python threat_intel.py --load iocs.json    # Load IOCs into ChromaDB
    python threat_intel.py --stats              # Show IOC statistics
    python threat_intel.py --check 203.0.113.42 # Check if IP is known
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("llm-triage.threat_intel")

try:
    import chromadb
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Default IOC dataset — common test/demo indicators
# ---------------------------------------------------------------------------

DEFAULT_IOCS = [
    {
        "type": "ip",
        "value": "203.0.113.42",
        "threat_type": "scanner",
        "severity": "MEDIUM",
        "description": "Known SSH brute-force scanner (TEST/DOCUMENTATION range)",
        "source": "manual",
        "tags": ["brute-force", "ssh", "scanner"],
    },
    {
        "type": "ip",
        "value": "198.51.100.77",
        "threat_type": "c2",
        "severity": "HIGH",
        "description": "Suspected C2 infrastructure (TEST/DOCUMENTATION range)",
        "source": "manual",
        "tags": ["c2", "command-and-control"],
    },
    {
        "type": "ip",
        "value": "10.10.14.1",
        "threat_type": "pentesting",
        "severity": "HIGH",
        "description": "Common pentesting/CTF attack box IP range",
        "source": "manual",
        "tags": ["pentest", "attack-box"],
    },
    {
        "type": "domain",
        "value": "evil-payload.example.com",
        "threat_type": "malware_distribution",
        "severity": "CRITICAL",
        "description": "Malware distribution domain (example)",
        "source": "manual",
        "tags": ["malware", "payload", "download"],
    },
    {
        "type": "hash",
        "value": "e99a18c428cb38d5f260853678922e03",
        "threat_type": "malware",
        "severity": "CRITICAL",
        "description": "Known malware hash (example)",
        "source": "manual",
        "tags": ["malware", "trojan"],
    },
    {
        "type": "filename",
        "value": "svchost.exe",
        "threat_type": "masquerade",
        "severity": "HIGH",
        "description": "Legitimate Windows process — suspicious ONLY when running from outside C:\\Windows\\System32",
        "source": "manual",
        "context": "Flag only if path is NOT C:\\Windows\\System32\\svchost.exe",
        "tags": ["masquerade", "T1036"],
    },
    {
        "type": "command_pattern",
        "value": "-enc[oded]*\\s+[A-Za-z0-9+/=]{20,}",
        "threat_type": "obfuscation",
        "severity": "HIGH",
        "description": "Base64-encoded PowerShell command — commonly used for payload delivery and defense evasion",
        "source": "manual",
        "tags": ["powershell", "encoded", "T1059.001", "T1027"],
    },
    {
        "type": "command_pattern",
        "value": "Invoke-Expression|IEX|DownloadString|DownloadFile",
        "threat_type": "download_cradle",
        "severity": "HIGH",
        "description": "PowerShell download cradle patterns — used to fetch and execute remote payloads",
        "source": "manual",
        "tags": ["powershell", "download", "T1059.001", "T1105"],
    },
    {
        "type": "path",
        "value": "C:\\Users\\Public\\",
        "threat_type": "suspicious_location",
        "severity": "MEDIUM",
        "description": "World-writable directory commonly used by malware for payload drops. Any executable here warrants investigation.",
        "source": "manual",
        "tags": ["suspicious-path", "payload-drop", "T1204"],
    },
    {
        "type": "path",
        "value": "\\AppData\\Local\\Temp\\",
        "threat_type": "suspicious_location",
        "severity": "LOW",
        "description": "Temp directory — legitimate for installers but also used for malware staging",
        "source": "manual",
        "tags": ["temp", "staging"],
    },
]


class ThreatIntelStore:
    """
    Manages threat intelligence IOCs in ChromaDB for RAG context.

    When the triage or hunt service encounters an IP, domain, hash,
    or command pattern that matches a known IOC, the threat context
    is automatically included in Claude's prompt.
    """

    COLLECTION_NAME = "threat_intel"

    def __init__(self, persist_dir: str = "/data/chromadb"):
        if not CHROMA_AVAILABLE:
            self.client = None
            self.collection = None
            return

        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "Threat intelligence IOCs"},
        )

    @property
    def is_available(self) -> bool:
        return self.collection is not None

    def load_iocs(self, iocs: list) -> int:
        """Load a list of IOC dicts into ChromaDB. Returns count loaded."""
        if not self.is_available:
            return 0

        count = 0
        for ioc in iocs:
            doc_text = (
                f"IOC Type: {ioc['type']} | "
                f"Value: {ioc['value']} | "
                f"Threat: {ioc.get('threat_type', 'unknown')} | "
                f"Severity: {ioc.get('severity', 'MEDIUM')} | "
                f"Description: {ioc.get('description', '')} | "
                f"Tags: {', '.join(ioc.get('tags', []))}"
            )

            metadata = {
                "type": ioc["type"],
                "value": ioc["value"],
                "threat_type": ioc.get("threat_type", "unknown"),
                "severity": ioc.get("severity", "MEDIUM"),
                "source": ioc.get("source", "manual"),
                "loaded_at": datetime.now(timezone.utc).isoformat(),
            }

            ioc_id = f"ioc-{ioc['type']}-{hash(ioc['value']) & 0xFFFFFFFF:08x}"

            try:
                self.collection.upsert(
                    ids=[ioc_id],
                    documents=[doc_text],
                    metadatas=[metadata],
                )
                count += 1
            except Exception as e:
                logger.error("Failed to load IOC %s: %s", ioc["value"], e)

        logger.info("Loaded %d IOCs into threat intel store", count)
        return count

    def load_defaults(self) -> int:
        """Load the built-in default IOC set."""
        return self.load_iocs(DEFAULT_IOCS)

    def load_from_file(self, path: str) -> int:
        """Load IOCs from a JSON file."""
        with open(path) as f:
            iocs = json.load(f)
        return self.load_iocs(iocs)

    def check_alert(self, alert: dict) -> list[dict]:
        """
        Check if any values in an alert match known IOCs.

        Searches the alert's IPs, domains, hashes, and file paths
        against the IOC database.

        Returns a list of matching IOC metadata dicts.
        """
        if not self.is_available or self.collection.count() == 0:
            return []

        # Extract searchable values from the alert
        search_values = set()

        # IPs
        for ip_field in ["srcip", "dstip", "ip"]:
            val = alert.get("data", {}).get(ip_field, "")
            if val:
                search_values.add(val)

        # File paths
        syscheck = alert.get("syscheck", {})
        if syscheck.get("path"):
            search_values.add(syscheck["path"])

        # Command lines (from Sysmon)
        win_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
        if win_data.get("commandLine"):
            search_values.add(win_data["commandLine"][:200])
        if win_data.get("image"):
            search_values.add(win_data["image"])

        # Full log snippet
        full_log = alert.get("full_log", "")
        if full_log:
            search_values.add(full_log[:200])

        if not search_values:
            return []

        # Query ChromaDB with each value
        matches = []
        for value in search_values:
            try:
                results = self.collection.query(
                    query_texts=[value],
                    n_results=3,
                )
                for i, meta in enumerate(results.get("metadatas", [[]])[0]):
                    distance = results.get("distances", [[]])[0][i]
                    if distance < 0.5:  # Only close matches
                        meta["match_distance"] = distance
                        meta["matched_against"] = value[:100]
                        matches.append(meta)
            except Exception:
                continue

        return matches

    def format_context_for_prompt(self, matches: list[dict]) -> str:
        """Format IOC matches as context for Claude's prompt."""
        if not matches:
            return ""

        lines = ["THREAT INTELLIGENCE MATCHES:\n"]
        seen = set()

        for match in matches:
            key = f"{match['type']}:{match['value']}"
            if key in seen:
                continue
            seen.add(key)

            lines.append(
                f"  [{match['severity']}] {match['type'].upper()}: {match['value']} "
                f"— {match.get('threat_type', 'unknown')} "
                f"(source: {match.get('source', 'unknown')})"
            )

        lines.append(
            "\nThese IOCs were matched from our threat intelligence database. "
            "Factor them into your assessment.\n"
        )
        return "\n".join(lines)

    def get_stats(self) -> dict:
        """Return summary statistics about loaded IOCs."""
        if not self.is_available:
            return {"available": False}

        count = self.collection.count()
        return {
            "available": True,
            "total_iocs": count,
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Threat Intel IOC Manager")
    parser.add_argument("--load", help="Load IOCs from JSON file")
    parser.add_argument("--load-defaults", action="store_true", help="Load built-in IOCs")
    parser.add_argument("--stats", action="store_true", help="Show IOC stats")
    parser.add_argument("--check", help="Check if a value matches any IOC")
    args = parser.parse_args()

    persist_dir = os.environ.get("CHROMA_PERSIST_DIR", "/data/chromadb")
    store = ThreatIntelStore(persist_dir=persist_dir)

    if not store.is_available:
        print("ChromaDB not available. Install with: pip install chromadb")
        sys.exit(1)

    if args.load:
        count = store.load_from_file(args.load)
        print(f"Loaded {count} IOCs from {args.load}")
    elif args.load_defaults:
        count = store.load_defaults()
        print(f"Loaded {count} default IOCs")
    elif args.stats:
        stats = store.get_stats()
        print(json.dumps(stats, indent=2))
    elif args.check:
        fake_alert = {"data": {"srcip": args.check}, "full_log": args.check}
        matches = store.check_alert(fake_alert)
        if matches:
            print(f"Found {len(matches)} matches:")
            for m in matches:
                print(f"  [{m['severity']}] {m['type']}: {m['value']}")
        else:
            print("No matches found")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
