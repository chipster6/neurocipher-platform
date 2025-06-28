# AuditHound Production Dockerfile with Observability

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY *.py ./
COPY *.ini ./
COPY *.cfg ./

# Create necessary directories
RUN mkdir -p logs data /app/static /app/templates

# Create non-root user
RUN useradd --create-home --shell /bin/bash audithound && \
    chown -R audithound:audithound /app

# Switch to non-root user
USER audithound

# Environment variables
ENV PYTHONPATH=/app
ENV LOG_LEVEL=INFO
ENV METRICS_ENABLED=true
ENV HEALTH_CHECK_ENABLED=true
ENV PROMETHEUS_METRICS_PORT=8080
ENV HEALTH_CHECK_PORT=8081

# Expose ports
EXPOSE 8501 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Copy startup script
COPY docker/entrypoint.sh /app/entrypoint.sh
USER root
RUN chmod +x /app/entrypoint.sh
USER audithound

# Default command
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["streamlit"]