#!/bin/bash
set -e

echo "Starting AuditHound Worker Service..."

# Wait for dependencies
if [ -n "$REDIS_URL" ]; then
    echo "Waiting for Redis..."
    until redis-cli -u "$REDIS_URL" ping > /dev/null 2>&1; do
        echo "Redis is unavailable - sleeping"
        sleep 2
    done
    echo "Redis is ready"
fi

if [ -n "$WEAVIATE_URL" ]; then
    echo "Waiting for Weaviate..."
    until curl -f "$WEAVIATE_URL/v1/meta" > /dev/null 2>&1; do
        echo "Weaviate is unavailable - sleeping"
        sleep 2
    done
    echo "Weaviate is ready"
fi

# Start background monitoring
python -c "
import asyncio
import sys
sys.path.append('/app')
from src.observability.metrics import MetricsCollector
from src.observability.health import HealthChecker

async def start_monitoring():
    collector = MetricsCollector()
    health_checker = HealthChecker()
    collector.start_background_collection()
    await asyncio.gather(
        collector.start_server(port=${METRICS_PORT:-8080}),
        health_checker.start_server(port=${HEALTH_PORT:-8081})
    )
" &

# Start worker processes
exec python -m src.worker.main \
    --concurrency=${WORKER_CONCURRENCY:-4} \
    --queue=${WORKER_QUEUE:-audithound-tasks}