#!/bin/bash
set -e

echo "Starting AuditHound Scheduler Service..."

# Wait for Redis
if [ -n "$REDIS_URL" ]; then
    echo "Waiting for Redis..."
    until redis-cli -u "$REDIS_URL" ping > /dev/null 2>&1; do
        echo "Redis is unavailable - sleeping"
        sleep 2
    done
    echo "Redis is ready"
fi

# Start health monitoring
python -c "
import asyncio
import sys
sys.path.append('/app')
from src.observability.health import HealthChecker

async def start_health():
    health_checker = HealthChecker()
    await health_checker.start_server(port=${HEALTH_PORT:-8081})
" &

# Start scheduler
exec python -m src.scheduler.main --timezone=${SCHEDULER_TIMEZONE:-UTC}