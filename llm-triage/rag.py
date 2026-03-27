"""
Retrieval-Augmented Generation (RAG) for contextual triage.

Enhances Claude's triage by retrieving similar past alerts and their
analyst-verified outcomes. This gives the model environment-specific
context it wouldn't otherwise have:
  - "This alert from 203.0.113.42 was seen 3 times last week and
    confirmed as a false positive by the SOC team."
  - "A similar hosts file modification on this endpoint was flagged
    as malicious last month — the attacker was redirecting DNS."

Uses ChromaDB as a lightweight vector database that runs locally
(no external service needed). Embeddings are generated from alert
text using a simple TF-IDF approach or optionally via an embedding API.

Architecture:
  Alert → embed → query ChromaDB → retrieve top-K similar → inject
  into Claude prompt as "historical context" → improved triage
"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("llm-triage.rag")

# ChromaDB is optional — gracefully degrade if not installed
try:
    import chromadb
    pass  # PersistentClient needs no extra imports

    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    logger.warning(
        "ChromaDB not installed — RAG features disabled. "
        "Install with: pip install chromadb"
    )


class AlertMemory:
    """
    Vector store for past alerts and triage results.

    Stores alert text + triage outcome in ChromaDB and retrieves
    similar alerts to provide historical context for new triage requests.
    """

    COLLECTION_NAME = "alert_history"

    def __init__(self, persist_dir: str = "/data/chromadb"):
        if not CHROMA_AVAILABLE:
            self.client = None
            self.collection = None
            return

        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "Wazuh alert history with triage outcomes"},
        )
        logger.info(
            "AlertMemory initialized: %d entries in collection",
            self.collection.count(),
        )

    @property
    def is_available(self) -> bool:
        return self.collection is not None

    def store_alert(
        self,
        alert: dict,
        triage_result: dict,
        analyst_verdict: Optional[str] = None,
    ) -> bool:
        """
        Store an alert and its triage outcome in the vector database.

        Args:
            alert: The raw Wazuh alert
            triage_result: Claude's structured triage output
            analyst_verdict: Optional analyst feedback ('agree'/'disagree')
        """
        if not self.is_available:
            return False

        # Create a text representation for embedding
        text = self._alert_to_text(alert, triage_result)
        alert_id = self._generate_id(alert)

        metadata = {
            "rule_id": str(alert.get("rule", {}).get("id", "")),
            "rule_level": int(alert.get("rule", {}).get("level", 0)),
            "rule_description": alert.get("rule", {}).get("description", ""),
            "severity": triage_result.get("severity", ""),
            "false_positive_likelihood": triage_result.get("false_positive_likelihood", ""),
            "confidence": float(triage_result.get("confidence", 0)),
            "agent_name": alert.get("agent", {}).get("name", ""),
            "analyst_verdict": analyst_verdict or "pending",
        }

        try:
            self.collection.upsert(
                ids=[alert_id],
                documents=[text],
                metadatas=[metadata],
            )
            logger.debug("Stored alert %s in vector DB", alert_id)
            return True
        except Exception as e:
            logger.error("Failed to store alert in ChromaDB: %s", e)
            return False

    def retrieve_similar(
        self,
        alert: dict,
        n_results: int = 3,
        min_relevance: float = 0.5,
    ) -> list[dict]:
        """
        Find similar past alerts for context.

        Returns a list of dicts with 'text', 'metadata', and 'distance'.
        Lower distance = more similar.
        """
        if not self.is_available:
            return []

        query_text = self._alert_to_query(alert)

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(n_results, self.collection.count() or 1),
            )

            similar = []
            for i, doc in enumerate(results.get("documents", [[]])[0]):
                distance = results.get("distances", [[]])[0][i]
                metadata = results.get("metadatas", [[]])[0][i]

                # ChromaDB uses L2 distance — lower is more similar
                # Skip results that are too dissimilar
                if distance > (1 - min_relevance) * 2:
                    continue

                similar.append({
                    "text": doc,
                    "metadata": metadata,
                    "distance": round(distance, 4),
                    "relevance": round(1 - distance / 2, 4),
                })

            logger.info(
                "Retrieved %d similar alerts (of %d candidates)",
                len(similar),
                self.collection.count(),
            )
            return similar

        except Exception as e:
            logger.error("Failed to query ChromaDB: %s", e)
            return []

    def format_context_for_prompt(
        self,
        similar_alerts: list[dict],
        max_chars: int = 1500,
    ) -> str:
        """
        Format retrieved similar alerts as context to inject into
        the Claude prompt.
        """
        if not similar_alerts:
            return ""

        lines = [
            "HISTORICAL CONTEXT — Similar alerts from this environment:\n"
        ]
        total_chars = len(lines[0])

        for i, alert in enumerate(similar_alerts, 1):
            meta = alert["metadata"]
            entry = (
                f"[{i}] Rule {meta.get('rule_id', '?')} "
                f"(level {meta.get('rule_level', '?')}): "
                f"{meta.get('rule_description', 'Unknown')}\n"
                f"    Triage: {meta.get('severity', '?')} severity, "
                f"FP likelihood: {meta.get('false_positive_likelihood', '?')}, "
                f"Analyst: {meta.get('analyst_verdict', 'pending')}\n"
                f"    Agent: {meta.get('agent_name', 'Unknown')} "
                f"(relevance: {alert['relevance']:.0%})\n"
            )

            if total_chars + len(entry) > max_chars:
                break
            lines.append(entry)
            total_chars += len(entry)

        lines.append(
            "\nUse this context to inform your assessment — if similar "
            "alerts were confirmed false positives, adjust accordingly.\n"
        )
        return "\n".join(lines)

    @staticmethod
    def _alert_to_text(alert: dict, triage: dict) -> str:
        """Convert alert + triage to a text representation for embedding."""
        rule = alert.get("rule", {})
        parts = [
            f"Rule: {rule.get('description', '')}",
            f"Level: {rule.get('level', '')}",
            f"Log: {alert.get('full_log', '')[:200]}",
            f"Agent: {alert.get('agent', {}).get('name', '')}",
            f"Severity: {triage.get('severity', '')}",
            f"Summary: {triage.get('summary', '')}",
        ]
        return " | ".join(parts)

    @staticmethod
    def _alert_to_query(alert: dict) -> str:
        """Convert alert to a query string for similarity search."""
        rule = alert.get("rule", {})
        parts = [
            rule.get("description", ""),
            alert.get("full_log", "")[:200],
            alert.get("agent", {}).get("name", ""),
        ]
        return " ".join(parts)

    @staticmethod
    def _generate_id(alert: dict) -> str:
        """Generate a stable ID for deduplication."""
        key = json.dumps(
            {
                "rule_id": alert.get("rule", {}).get("id"),
                "full_log": alert.get("full_log", "")[:100],
                "timestamp": alert.get("timestamp", ""),
            },
            sort_keys=True,
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]
