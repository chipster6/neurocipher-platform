#!/bin/bash
set -e

echo "Starting AuditHound Dashboard Service..."

# Wait for API service
if [ -n "$API_URL" ]; then
    echo "Waiting for API service..."
    until curl -f "$API_URL/health" > /dev/null 2>&1; do
        echo "API service is unavailable - sleeping"
        sleep 2
    done
    echo "API service is ready"
fi

# Start Streamlit dashboard
exec streamlit run streamlit_dashboard.py \
    --server.port=${STREAMLIT_SERVER_PORT:-8501} \
    --server.address=${STREAMLIT_SERVER_ADDRESS:-0.0.0.0} \
    --server.headless=${STREAMLIT_SERVER_HEADLESS:-true} \
    --server.fileWatcherType=${STREAMLIT_SERVER_FILE_WATCHER_TYPE:-none} \
    --server.enableCORS=${STREAMLIT_SERVER_ENABLE_CORS:-false} \
    --server.enableXsrfProtection=${STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION:-false}