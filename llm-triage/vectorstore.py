"""
Vector Store Factory — pluggable backend for RAG and Threat Intel.

Supports two backends, selected via the VECTOR_STORE environment variable:
  - "chroma"   (DEFAULT, RECOMMENDED) — local ChromaDB, all data stays on-premise
  - "pinecone" — cloud-hosted Pinecone for production scale

SECURITY NOTE: ChromaDB is the default for a reason. This is a security
monitoring tool — alert data, IOCs, and triage results may contain
sensitive information (internal IPs, hostnames, attack patterns, employee
names). With ChromaDB, all vector data stays on your local machine or
Docker volume. Pinecone sends this data to external cloud servers over
HTTPS. Only use Pinecone if your organization's security policy permits
sending alert metadata to a third-party cloud service.

Both backends use LangChain's VectorStore interface, so the rest of
the codebase doesn't need to know which one is active. Swapping is
just an env var change + API key.

Environment variables:
  VECTOR_STORE          — "chroma" or "pinecone" (default: "chroma")
  CHROMA_PERSIST_DIR    — ChromaDB storage path (default: /data/chromadb)
  PINECONE_API_KEY      — Pinecone API key (required if using pinecone)
  PINECONE_INDEX_NAME   — Pinecone index name (default: "wazuh-alerts")
  PINECONE_ENVIRONMENT  — Pinecone environment/region (default: "us-east-1")

Usage:
    from vectorstore import get_vectorstore

    # Returns the configured LangChain VectorStore — Chroma or Pinecone
    vs = get_vectorstore(collection_name="alert_history")
    vs.add_texts(["some text"], metadatas=[{"key": "value"}])
    results = vs.similarity_search_with_score("query", k=3)
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("llm-triage.vectorstore")

# ---------------------------------------------------------------------------
# Shared embedding function — same model regardless of backend
# ---------------------------------------------------------------------------

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
        "sentence-transformers not installed — using backend default embeddings. "
        "For best results: pip install sentence-transformers"
    )


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def get_vectorstore(
    collection_name: str = "alert_history",
    backend: Optional[str] = None,
):
    """
    Create and return a LangChain VectorStore for the configured backend.

    Args:
        collection_name: Name of the collection/index/namespace
        backend: Override the VECTOR_STORE env var ("chroma" or "pinecone")

    Returns:
        A LangChain VectorStore instance (Chroma or Pinecone)
    """
    backend = backend or os.environ.get("VECTOR_STORE", "chroma").lower()

    if backend == "pinecone":
        return _create_pinecone(collection_name)
    else:
        return _create_chroma(collection_name)


def _create_chroma(collection_name: str):
    """Create a LangChain Chroma VectorStore."""
    try:
        from langchain_community.vectorstores import Chroma
    except ImportError:
        logger.error(
            "langchain-community or chromadb not installed. "
            "Install with: pip install langchain-community chromadb"
        )
        return None

    persist_dir = os.environ.get("CHROMA_PERSIST_DIR", "/data/chromadb")

    store = Chroma(
        collection_name=collection_name,
        persist_directory=persist_dir,
        embedding_function=EMBEDDINGS,
        collection_metadata={"description": f"Wazuh LLM — {collection_name}"},
    )
    logger.info("Created Chroma VectorStore: collection=%s, dir=%s", collection_name, persist_dir)
    return store


def _create_pinecone(collection_name: str):
    """
    Create a LangChain Pinecone VectorStore.

    Requires:
      - pip install langchain-pinecone pinecone-client
      - PINECONE_API_KEY env var set
      - A Pinecone index already created (dimension must match embeddings)

    The collection_name is used as the Pinecone namespace, so multiple
    collections (alert_history, threat_intel) share one index but stay
    logically separated.
    """
    try:
        from langchain_pinecone import PineconeVectorStore
    except ImportError:
        logger.error(
            "langchain-pinecone not installed. "
            "Install with: pip install langchain-pinecone pinecone-client"
        )
        return None

    api_key = os.environ.get("PINECONE_API_KEY", "")
    if not api_key:
        logger.error("PINECONE_API_KEY not set — cannot create Pinecone store")
        return None

    index_name = os.environ.get("PINECONE_INDEX_NAME", "wazuh-alerts")

    if EMBEDDINGS is None:
        logger.error(
            "Pinecone requires an embedding function. "
            "Install sentence-transformers: pip install sentence-transformers"
        )
        return None

    store = PineconeVectorStore(
        index_name=index_name,
        embedding=EMBEDDINGS,
        namespace=collection_name,
        pinecone_api_key=api_key,
    )
   