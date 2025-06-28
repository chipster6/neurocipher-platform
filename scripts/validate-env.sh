#!/bin/bash

# Environment Variable Validation Script for AuditHound
# This script validates that all required environment variables are set
# before starting the application.

set -e

echo "🔍 Validating AuditHound environment variables..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track validation status
VALIDATION_FAILED=0

# Function to check if variable is set and not empty
check_env_var() {
    local var_name=$1
    local var_value=${!var_name}
    local is_required=${2:-true}
    
    if [ -z "$var_value" ]; then
        if [ "$is_required" = true ]; then
            echo -e "${RED}❌ REQUIRED: $var_name is not set${NC}"
            VALIDATION_FAILED=1
        else
            echo -e "${YELLOW}⚠️  OPTIONAL: $var_name is not set${NC}"
        fi
    else
        # Check for example/placeholder values
        case $var_value in
            *"your-"*|*"change-this"*|*"example"*|*"123"*|*"admin"*)
                echo -e "${RED}❌ SECURITY RISK: $var_name contains example/insecure value${NC}"
                VALIDATION_FAILED=1
                ;;
            *)
                echo -e "${GREEN}✅ $var_name is set${NC}"
                ;;
        esac
    fi
}

# Function to check minimum length
check_min_length() {
    local var_name=$1
    local var_value=${!var_name}
    local min_length=$2
    
    if [ -n "$var_value" ] && [ ${#var_value} -lt $min_length ]; then
        echo -e "${RED}❌ SECURITY: $var_name must be at least $min_length characters${NC}"
        VALIDATION_FAILED=1
    fi
}

echo "📋 Checking required security variables..."

# Critical security variables
check_env_var "POSTGRES_PASSWORD"
check_min_length "POSTGRES_PASSWORD" 12

check_env_var "SECRET_KEY"
check_min_length "SECRET_KEY" 32

check_env_var "JWT_SECRET_KEY"
check_min_length "JWT_SECRET_KEY" 32

check_env_var "GRAFANA_PASSWORD"
check_min_length "GRAFANA_PASSWORD" 8

check_env_var "CORS_ORIGINS"

echo ""
echo "📋 Checking optional configuration variables..."

# Optional but recommended
check_env_var "AZURE_CLIENT_SECRET" false
check_env_var "AZURE_TENANT_ID" false
check_env_var "AZURE_SUBSCRIPTION_ID" false
check_env_var "AZURE_CLIENT_ID" false

check_env_var "AWS_ACCESS_KEY_ID" false
check_env_var "AWS_SECRET_ACCESS_KEY" false

check_env_var "GCP_PROJECT_ID" false

# Application settings
check_env_var "ENVIRONMENT" false
check_env_var "LOG_LEVEL" false

echo ""
echo "📋 Validating configuration security..."

# Check for development settings in production
if [ "$ENVIRONMENT" = "production" ]; then
    if [ "$FLASK_DEBUG" = "true" ] || [ "$LOG_LEVEL" = "DEBUG" ]; then
        echo -e "${RED}❌ SECURITY: Debug mode enabled in production environment${NC}"
        VALIDATION_FAILED=1
    fi
fi

# Check CORS origins for production
if [ "$ENVIRONMENT" = "production" ] && [[ "$CORS_ORIGINS" == *"localhost"* ]]; then
    echo -e "${YELLOW}⚠️  WARNING: CORS origins include localhost in production${NC}"
fi

# Validate .env file exists
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ CRITICAL: .env file not found. Copy .env.example to .env and configure it.${NC}"
    VALIDATION_FAILED=1
fi

# Check if .env is in .gitignore
if [ -f ".gitignore" ] && ! grep -q "\.env$" .gitignore; then
    echo -e "${RED}❌ SECURITY: .env file is not in .gitignore${NC}"
    VALIDATION_FAILED=1
fi

echo ""
if [ $VALIDATION_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All environment variables are properly configured!${NC}"
    echo -e "${GREEN}✅ Safe to start AuditHound${NC}"
    exit 0
else
    echo -e "${RED}💥 Environment validation failed!${NC}"
    echo -e "${RED}Please fix the issues above before starting AuditHound${NC}"
    echo ""
    echo -e "${YELLOW}💡 Quick fixes:${NC}"
    echo "   1. Copy .env.example to .env: cp .env.example .env"
    echo "   2. Edit .env and replace all placeholder values"
    echo "   3. Ensure passwords are strong (12+ characters)"
    echo "   4. Add .env to .gitignore if not already present"
    exit 1
fi