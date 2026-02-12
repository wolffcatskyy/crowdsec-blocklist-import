# CrowdSec Blocklist Import - Python Edition
# Multi-stage build for minimal image size

# Build stage (for any compilation needs)
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# Production stage
FROM python:3.11-slim

LABEL org.opencontainers.image.title="CrowdSec Blocklist Import"
LABEL org.opencontainers.image.description="Import public threat blocklists into CrowdSec via LAPI"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.source="https://github.com/wolffcatskyy/crowdsec-blocklist-import"
LABEL org.opencontainers.image.licenses="MIT"

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN useradd -r -s /bin/false blocklist

WORKDIR /app

# Copy application
COPY --chown=blocklist:blocklist blocklist_import.py .

# Make script readable/executable
RUN chmod 755 blocklist_import.py

# Switch to non-root user
USER blocklist

# Default environment variables
ENV CROWDSEC_LAPI_URL="http://crowdsec:8080" \
    DECISION_DURATION="24h" \
    LOG_LEVEL="INFO" \
    BATCH_SIZE="1000" \
    PYTHONUNBUFFERED="1"

# Health check (just verifies script is runnable)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=1 \
    CMD python -c "import blocklist_import; print('OK')" || exit 1

# Run the import script
ENTRYPOINT ["python", "blocklist_import.py"]
