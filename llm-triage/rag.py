"""
Retrieval-Augmented Generation (RAG) for contextual triage.

Enhances Claude's triage by retrieving similar past alerts and their
analyst-verified outcomes. This gives the model environment-specific
context it wouldn't otherwise have:
  - "This alert from 203.0.113.42 was seen 3 times last week and
    confirmed as a false positive by the SOC team."
  - "A similar hosts file modification on this endpoint was flagged
    as malicious last month — the attacker was redirecting DNS."

Uses LangChain's Chroma VectorStore wrapper around ChromaDB, which
gives us a standard interface that could be swapped to Pinecone,
FAISS, or any other LangChain-supported vector store later.

Architecture:
  Alert → embed → query Chroma via LangChain → retrieve top-K similar
  → inject into Claude prompt as "historical context" → improved triage
"""

import json
import hashlib
import logging
from typing import Optional

logger = logging.getLogger("llm-triage.rag")

# LangChain + ChromaDB are optional — gracefully degrade if not installed
try:
    from langchain_community.vectorstores import Chroma
    from langchain_core.documents import Document

    LANGCHAIN_CHROMA_AVAILABLE = True
except ImportError:
    LANGCHAIN_CHROMA_AVAILABLE = False
    logger.warning(
        "LangChain Chroma not installed — RAG features disabled. "
        "Install with: pip install langchain-community chromadb"
    )

# Embeddings — try HuggingFace first, fall back to Chroma's built-in
EMBEDDINGS = None
try:
    from langchain_community.embeddings import HuggingFaceEmbeddings

    EMBEDDINGS = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
    )
    logger.info("Using HuggingFace embeddings (all-MiniLM-L6-v2)")
except ImportError:
    logger.info(
        "sentence-transformers not installed — using ChromaDB default embeddings. "
        "For better results: pip install sentence-transformers"
    )


class AlertMemory:
    """
    Vector store for past alerts and triage results.

    Uses LangChain's Chroma VectorStore wrapper instead of raw ChromaDB.
    This means we get a standard interface — if you want to swap to
    Pinecone or FAISS later, you only change the constructor, not the
    retrieval logic.
    """

    COLLECTION_NAME = "alert_history"

    def __init__(self, persist_dir: str = "/data/chromadb"):
        if not LANGCHAIN_CHROMA_AVAILABLE:
            self.vectorstore = None
            return

        # LangChain's Chroma wrapper handles PersistentClient internally
        # when you pass persist_directory
        self.vectorstore = Chroma(
            collection_name=self.COLLECTION_NAME,
            persist_directory=persist_dir,
            embedding_function=EMBEDDINGS,  # None → ChromaDB default
            collection_metadata={"description": "Wazuh alert history with triage outcomes"},
        )
        logger.info(
            "AlertMemory initialized via LangChain Chroma: %d entries",
            self._count(),
        )

    @property
    def is_available(self) -> bool:
        return self.vectorstore is not None

    def _count(self) -> int:
        """Get the number of documents in the collection."""
        if not self.is_available:
            return 0
        try:
            # Access the underlying ChromaDB collection for count
            return self.vectorstore._collection.count()
        except Exception:
            return 0

    def store_alert(
        self,
        alert: dict,
        triage_result: dict,
        analyst_verdict: Optional[str] = None,
    ) -> bool:
        """
        Store an alert and its triage outcome in the vector database.

        Wraps the data as a LangChain Document with metadata, then
        upserts into the Chroma collection.
        """
        if not self.is_available:
            return False

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
            # LangChain's Chroma.add_texts handles upsert via ids
            self.vectorstore.add_texts(
                texts=[text],
                metadatas=[metadata],
                ids=[alert_id],
            )
            logger.debug("Stored alert %s in vector DB", alert_id)
            return True
        except Exception as e:
            logger.error("Failed to store alert in Chroma: %s", e)
            return False

    def retrieve_similar(
        self,
        alert: dict,
        n_results: int = 3,
        min_relevance: float = 0.5,
    ) -> list[dict]:
        """
        Find similar past alerts for context.

        Uses LangChain's similarity_search_with_score which returns
        (Document, score) tuples. The score is L2 distance —
        lower = more similar.
        """
        if not self.is_available or self._count() == 0:
            return []

        query_text = self._alert_to_query(alert)

        try:
            # LangChain returns list of (Document, distance) tuples
            results = self.vectorstore.similarity_search_with_score(
                query=query_text,
                k=min(n_results, self._count()),
            )

            similar = []
            for doc, distance in results:
                # ChromaDB uses L2 distance — lower is more similar
                # Skip results that are too dissimilar
                if distance > (1 - min_relevance) * 2:
                    continue

                similar.append({
                    "text": doc.page_content,
                    "metadata": doc.metadata,
                    "distance": round(distance, 4),
                    "relevance": round(1 - distance / 2, 4),
                })

            logger.info(
                "Retrieved %d similar alerts (of %d candidates)",
                len(similar),
                self._count(),
            )
            return similar

        except Exception as e:
            logger.error("Failed to query Chroma: %s", e)
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
                "rule_id": a