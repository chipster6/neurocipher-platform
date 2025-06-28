# AuditHound Dashboard Service - Minimal Production Image
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install requirements
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-prod.txt

# Production stage
FROM python:3.11-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN useradd --create-home --shell /bin/bash --uid 1002 audithound

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=audithound:audithound src/ ./src/
COPY --chown=audithound:audithound streamlit_dashboard.py ./
COPY --chown=audithound:audithound config.yaml ./
COPY --chown=audithound:audithound docker/components/dashboard/entrypoint.sh ./entrypoint.sh

# Create necessary directories
RUN mkdir -p logs static/exports && \
    chown -R audithound:audithound /app && \
    chmod +x entrypoint.sh

# Switch to non-root user
USER audithound

# Environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    LOG_LEVEL=INFO \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    STREAMLIT_SERVER_ENABLE_CORS=false \
    STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Use tini as init system
ENTRYPOINT ["tini", "--", "./entrypoint.sh"]
CMD ["dashboard"]