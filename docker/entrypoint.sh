#!/bin/bash

# AuditHound Docker entrypoint script with observability
set -e

echo "Starting AuditHound with observability..."

# Set environment variables with defaults
export PYTHONPATH=${PYTHONPATH:-/app}
export LOG_LEVEL=${LOG_LEVEL:-INFO}
export METRICS_ENABLED=${METRICS_ENABLED:-true}
export HEALTH_CHECK_ENABLED=${HEALTH_CHECK_ENABLED:-true}
export PROMETHEUS_METRICS_PORT=${PROMETHEUS_METRICS_PORT:-8080}
export HEALTH_CHECK_PORT=${HEALTH_CHECK_PORT:-8081}

# Create log directory
mkdir -p /app/logs

# Function to start metrics server
start_metrics_server() {
    if [ "$METRICS_ENABLED" = "true" ]; then
        echo "Starting Prometheus metrics server on port $PROMETHEUS_METRICS_PORT..."
        python -c "
import asyncio
import sys
import os
sys.path.append('/app')
from src.observability.metrics import MetricsCollector
from src.observability.health import HealthChecker

async def run_metrics():
    collector = MetricsCollector()
    health_checker = HealthChecker()
    
    # Start background metrics collection
    collector.start_background_collection()
    
    # Start metrics and health endpoints
    await asyncio.gather(
        collector.start_server(port=$PROMETHEUS_METRICS_PORT),
        health_checker.start_server(port=$HEALTH_CHECK_PORT)
    )

if __name__ == '__main__':
    asyncio.run(run_metrics())
" &
        METRICS_PID=$!
        echo "Metrics server started with PID $METRICS_PID"
    fi
}

# Function to start health check server
start_health_server() {
    if [ "$HEALTH_CHECK_ENABLED" = "true" ]; then
        echo "Starting health check server on port $HEALTH_CHECK_PORT..."
        # Health server is started with metrics server above
        sleep 2
        
        # Test health endpoint
        max_retries=30
        retry_count=0
        while [ $retry_count -lt $max_retries ]; do
            if curl -f http://localhost:$HEALTH_CHECK_PORT/health > /dev/null 2>&1; then
                echo "Health check endpoint is ready"
                break
            fi
            echo "Waiting for health check endpoint... ($((retry_count + 1))/$max_retries)"
            sleep 2
            retry_count=$((retry_count + 1))
        done
        
        if [ $retry_count -eq $max_retries ]; then
            echo "WARNING: Health check endpoint not responding after $max_retries attempts"
        fi
    fi
}

# Function to handle shutdown
shutdown() {
    echo "Shutting down AuditHound..."
    if [ ! -z "$METRICS_PID" ]; then
        kill $METRICS_PID 2>/dev/null || true
    fi
    if [ ! -z "$STREAMLIT_PID" ]; then
        kill $STREAMLIT_PID 2>/dev/null || true
    fi
    exit 0
}

# Set up signal handlers
trap shutdown SIGTERM SIGINT

# Start observability servers
start_metrics_server
start_health_server

# Determine what to run based on arguments
case "${1:-streamlit}" in
    streamlit)
        echo "Starting Streamlit application..."
        exec streamlit run /app/main.py \
            --server.port=8501 \
            --server.address=0.0.0.0 \
            --server.headless=true \
            --server.fileWatcherType=none \
            --server.enableCORS=false \
            --server.enableXsrfProtection=false
        ;;
    
    api)
        echo "Starting Unified API server..."
        exec uvicorn src.api.main:app \
            --host 0.0.0.0 \
            --port 8000 \
            --workers 1 \
            --access-log \
            --log-level info
        ;;
        
    worker)
        echo "Starting background worker..."
        exec python /app/src/worker/main.py
        ;;
        
    shell)
        echo "Starting interactive shell..."
        exec /bin/bash
        ;;
        
    *)
        echo "Starting custom command: $@"
        exec "$@"
        ;;
esac