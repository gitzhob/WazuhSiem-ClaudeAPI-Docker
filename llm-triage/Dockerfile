# =============================================================================
# LLM Triage Service — Dockerfile
# =============================================================================
# Lightweight Python container that polls Wazuh for alerts and sends them
# to Claude for automated triage analysis.
# =============================================================================

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies first (better Docker layer caching —
# dependencies change less often than our code)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code, modules, and prompts
COPY triage_service.py .
COPY schemas.py .
COPY metrics.py .
COPY feedback.py .
COPY rag.py .
COPY hunt.py .
COPY threat_intel.py .
COPY prompts/ prompts/
COPY eval/ eval/

# Don't run as root inside the container (security best practice)
RUN useradd --create-home appuser \
    && mkdir -p /data/chromadb \
    && chown -R appuser:appuser /data
USER appuser

# Default command — run the polling loop
CMD ["python", "-u", "triage_service.py"]
