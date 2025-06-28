#!/bin/bash
# AuditHound Unified Security Platform - Self-Onboarding Installation Script
# One-line install: curl -sSL https://get.audithound.com/install.sh | bash

set -e

# Configuration
AUDITHOUND_VERSION="latest"
INSTALL_DIR="$HOME/audithound"
PYTHON_MIN_VERSION="3.8"
LOG_FILE="/tmp/audithound-install.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "    ___            ____ __  __  __                        __ "
    echo "   /   |__  ______/ /_/  /_/ / / /___  __  ______  ____/ / "
    echo "  / /| / / / / __  / / __ / /_/ / __ \/ / / / __ \/ __  /  "
    echo " / ___ / /_/ / /_/ / / / / / __  / /_/ / /_/ / / / / /_/ /   "
    echo "/_/  |_\__,_/\__,_/_/_/ /_/_/ /_/\____/\__,_/_/ /_/\__,_/    "
    echo -e "${NC}"
    echo -e "${WHITE}Unified Security Platform - Enterprise Compliance + Threat Hunting${NC}"
    echo -e "${CYAN}🛡️  Real-time SOC 2 compliance monitoring + ML-powered threat detection${NC}"
    echo ""
}

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo -e "$1"
}

# Error handling
error_exit() {
    log "${RED}❌ ERROR: $1${NC}"
    echo -e "${RED}Installation failed. Check $LOG_FILE for details.${NC}"
    exit 1
}

# Success function
success() {
    log "${GREEN}✅ $1${NC}"
}

# Warning function
warning() {
    log "${YELLOW}⚠️  $1${NC}"
}

# Info function
info() {
    log "${CYAN}ℹ️  $1${NC}"
}

# Progress function
progress() {
    log "${PURPLE}🔄 $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should not be run as root for security reasons"
    fi
}

# Detect OS and architecture
detect_system() {
    progress "Detecting system configuration..."
    
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $OS in
        linux*)  OS="linux" ;;
        darwin*) OS="macos" ;;
        cygwin*) OS="windows" ;;
        mingw*)  OS="windows" ;;
        msys*)   OS="windows" ;;
        *)       error_exit "Unsupported operating system: $OS" ;;
    esac
    
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64)  ARCH="arm64" ;;
        aarch64) ARCH="arm64" ;;
        *)      error_exit "Unsupported architecture: $ARCH" ;;
    esac
    
    success "Detected: $OS ($ARCH)"
}

# Check prerequisites
check_prerequisites() {
    progress "Checking prerequisites..."
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        info "Found Python $PYTHON_VERSION"
        
        # Compare versions
        if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
            error_exit "Python 3.8+ required. Found: $PYTHON_VERSION"
        fi
    else
        error_exit "Python 3.8+ is required but not found"
    fi
    
    # Check Git
    if ! command -v git &> /dev/null; then
        error_exit "Git is required but not found"
    fi
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        error_exit "curl is required but not found"
    fi
    
    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        if docker --version &> /dev/null; then
            info "Docker detected - enabling containerized features"
            DOCKER_AVAILABLE=true
        else
            warning "Docker found but not running - some features will be disabled"
            DOCKER_AVAILABLE=false
        fi
    else
        warning "Docker not found - some features will be disabled"
        DOCKER_AVAILABLE=false
    fi
    
    success "Prerequisites check completed"
}

# Interactive setup
interactive_setup() {
    echo -e "${WHITE}🚀 AuditHound Setup Configuration${NC}"
    echo ""
    
    # Organization information
    echo -e "${CYAN}Organization Information:${NC}"
    read -p "Organization Name: " ORG_NAME
    while [[ -z "$ORG_NAME" ]]; do
        echo -e "${RED}Organization name is required${NC}"
        read -p "Organization Name: " ORG_NAME
    done
    
    read -p "Admin Email: " ADMIN_EMAIL
    while [[ ! "$ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; do
        echo -e "${RED}Please enter a valid email address${NC}"
        read -p "Admin Email: " ADMIN_EMAIL
    done
    
    # Service tier selection
    echo ""
    echo -e "${CYAN}Service Tier Selection:${NC}"
    echo "1) Starter (25 assets, 10 scans/month)"
    echo "2) Professional (100 assets, 50 scans/month)"
    echo "3) Enterprise (500 assets, 200 scans/month)"
    echo "4) MSP (10k assets, 1k scans/month)"
    
    read -p "Select tier [1-4]: " TIER_CHOICE
    case $TIER_CHOICE in
        1) SERVICE_TIER="starter" ;;
        2) SERVICE_TIER="professional" ;;
        3) SERVICE_TIER="enterprise" ;;
        4) SERVICE_TIER="msp" ;;
        *) SERVICE_TIER="starter"; warning "Invalid choice, defaulting to Starter" ;;
    esac
    
    # Cloud providers
    echo ""
    echo -e "${CYAN}Cloud Provider Integration:${NC}"
    read -p "Enable AWS integration? [y/N]: " ENABLE_AWS
    read -p "Enable Google Cloud integration? [y/N]: " ENABLE_GCP
    read -p "Enable Azure integration? [y/N]: " ENABLE_AZURE
    
    # Optional integrations
    echo ""
    echo -e "${CYAN}SOC Integrations (optional):${NC}"
    read -p "MISP Server URL (optional): " MISP_URL
    read -p "TheHive Server URL (optional): " THEHIVE_URL
    read -p "Slack Webhook URL (optional): " SLACK_WEBHOOK
    
    # Installation path
    echo ""
    read -p "Installation directory [$INSTALL_DIR]: " CUSTOM_INSTALL_DIR
    if [[ -n "$CUSTOM_INSTALL_DIR" ]]; then
        INSTALL_DIR="$CUSTOM_INSTALL_DIR"
    fi
}

# Download AuditHound
download_audithound() {
    progress "Downloading AuditHound..."
    
    if [[ -d "$INSTALL_DIR" ]]; then
        warning "Directory $INSTALL_DIR already exists"
        read -p "Remove existing installation? [y/N]: " REMOVE_EXISTING
        if [[ "$REMOVE_EXISTING" =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            success "Removed existing installation"
        else
            error_exit "Installation aborted"
        fi
    fi
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Clone repository (in production, this would be from the actual repo)
    git clone --depth 1 https://github.com/your-org/audithound.git . || {
        # Fallback: copy current directory structure for demo
        info "Using local development copy..."
        cp -r /Users/cody/audithound/* . 2>/dev/null || true
    }
    
    success "AuditHound downloaded to $INSTALL_DIR"
}

# Setup Python environment
setup_python_environment() {
    progress "Setting up Python environment..."
    
    cd "$INSTALL_DIR"
    
    # Create virtual environment
    python3 -m venv venv || error_exit "Failed to create virtual environment"
    
    # Activate virtual environment
    source venv/bin/activate || error_exit "Failed to activate virtual environment"
    
    # Upgrade pip
    python -m pip install --upgrade pip || error_exit "Failed to upgrade pip"
    
    # Install dependencies
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt || error_exit "Failed to install Python dependencies"
    else
        # Install core dependencies
        pip install flask sqlalchemy pytest python-dotenv click pyyaml requests || error_exit "Failed to install core dependencies"
    fi
    
    success "Python environment configured"
}

# Generate configuration
generate_configuration() {
    progress "Generating configuration..."
    
    cd "$INSTALL_DIR"
    
    # Generate config.yaml
    cat > config.yaml << EOF
# AuditHound Unified Configuration
# Generated by installer on $(date)

organization:
  name: "$ORG_NAME"
  admin_email: "$ADMIN_EMAIL"
  service_tier: "$SERVICE_TIER"

cloud_providers:
  aws:
    enabled: $([ "$ENABLE_AWS" = "y" ] && echo "true" || echo "false")
    region: "us-west-2"
    access_key_id: "\${AWS_ACCESS_KEY_ID}"
    secret_access_key: "\${AWS_SECRET_ACCESS_KEY}"
  
  gcp:
    enabled: $([ "$ENABLE_GCP" = "y" ] && echo "true" || echo "false")
    project_id: "\${GCP_PROJECT_ID}"
    credentials_path: "./credentials/gcp-service-account.json"
  
  azure:
    enabled: $([ "$ENABLE_AZURE" = "y" ] && echo "true" || echo "false")
    tenant_id: "\${AZURE_TENANT_ID}"
    subscription_id: "\${AZURE_SUBSCRIPTION_ID}"
    client_id: "\${AZURE_CLIENT_ID}"
    client_secret: "\${AZURE_CLIENT_SECRET}"

compliance_frameworks:
  soc2:
    enabled: true
    controls:
      - "CC6.1"
      - "CC6.2"
      - "CC6.3"
      - "CC7.1"
      - "CC8.1"

scoring:
  thresholds:
    compliant: 90
    partial: 70

dashboard:
  host: "0.0.0.0"
  port: 5001
  debug: false

logging:
  level: "INFO"
  file: "./logs/audithound.log"

integrations:
  misp:
    enabled: $([ -n "$MISP_URL" ] && echo "true" || echo "false")
    url: "$MISP_URL"
    api_key: "\${MISP_API_KEY}"
    verify_ssl: true
  
  thehive:
    enabled: $([ -n "$THEHIVE_URL" ] && echo "true" || echo "false")
    url: "$THEHIVE_URL"
    api_key: "\${THEHIVE_API_KEY}"

notifications:
  slack:
    enabled: $([ -n "$SLACK_WEBHOOK" ] && echo "true" || echo "false")
    webhook_url: "$SLACK_WEBHOOK"
    channel: "#security"
EOF
    
    # Create directories
    mkdir -p logs reports credentials
    
    # Generate environment template
    cat > .env.template << 'EOF'
# AuditHound Environment Variables
# Copy this file to .env and fill in your credentials

# AWS Credentials (if enabled)
# AWS_ACCESS_KEY_ID=your-aws-access-key
# AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# Google Cloud Credentials (if enabled)
# GCP_PROJECT_ID=your-gcp-project-id
# Place your service account JSON file in ./credentials/gcp-service-account.json

# Azure Credentials (if enabled)
# AZURE_TENANT_ID=your-azure-tenant-id
# AZURE_SUBSCRIPTION_ID=your-azure-subscription-id
# AZURE_CLIENT_ID=your-azure-client-id
# AZURE_CLIENT_SECRET=your-azure-client-secret

# Optional Integrations
# MISP_API_KEY=your-misp-api-key
# THEHIVE_API_KEY=your-thehive-api-key

# Optional: Weaviate Vector Database
# WEAVIATE_URL=http://localhost:8080
# WEAVIATE_API_KEY=your-weaviate-key
EOF
    
    success "Configuration generated"
}

# Setup Docker services (optional)
setup_docker_services() {
    if [[ "$DOCKER_AVAILABLE" != "true" ]]; then
        info "Skipping Docker setup (Docker not available)"
        return
    fi
    
    progress "Setting up Docker services..."
    
    cd "$INSTALL_DIR"
    
    # Generate docker-compose.yml for optional services
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  # Weaviate Vector Database (for threat hunting)
  weaviate:
    image: semitechnologies/weaviate:latest
    ports:
      - "8080:8080"
    environment:
      QUERY_DEFAULTS_LIMIT: 25
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'true'
      PERSISTENCE_DATA_PATH: '/var/lib/weaviate'
      DEFAULT_VECTORIZER_MODULE: 'none'
      CLUSTER_HOSTNAME: 'node1'
    volumes:
      - weaviate_data:/var/lib/weaviate

  # Kafka (for streaming analytics)
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"

  kafka:
    image: confluentinc/cp-kafka:latest
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

  # PostgreSQL (for persistent storage)
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: audithound
      POSTGRES_USER: audithound
      POSTGRES_PASSWORD: audithound_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  weaviate_data:
  postgres_data:
EOF
    
    info "Docker services configured. Start with: docker-compose up -d"
    success "Docker setup completed"
}

# Create startup scripts
create_startup_scripts() {
    progress "Creating startup scripts..."
    
    cd "$INSTALL_DIR"
    
    # Create start script
    cat > start.sh << 'EOF'
#!/bin/bash
# AuditHound Startup Script

set -e

# Check if virtual environment exists
if [[ ! -d "venv" ]]; then
    echo "❌ Virtual environment not found. Run install.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check for .env file
if [[ ! -f ".env" ]]; then
    echo "⚠️  No .env file found. Copy .env.template to .env and configure your credentials."
    echo "Using template for now..."
    cp .env.template .env
fi

# Start AuditHound
echo "🚀 Starting AuditHound Unified Security Platform..."
python run_unified_dashboard.py "$@"
EOF
    
    # Create stop script
    cat > stop.sh << 'EOF'
#!/bin/bash
# AuditHound Stop Script

echo "🛑 Stopping AuditHound..."

# Find and kill AuditHound processes
pkill -f "run_unified_dashboard.py" || echo "No AuditHound processes found"

# Stop Docker services if they're running
if [[ -f "docker-compose.yml" ]] && command -v docker-compose &> /dev/null; then
    echo "Stopping Docker services..."
    docker-compose stop || echo "Docker services already stopped"
fi

echo "✅ AuditHound stopped"
EOF
    
    # Create update script
    cat > update.sh << 'EOF'
#!/bin/bash
# AuditHound Update Script

set -e

echo "🔄 Updating AuditHound..."

# Activate virtual environment
source venv/bin/activate

# Pull latest changes
git pull origin main || echo "⚠️  Failed to pull updates (check your git configuration)"

# Update Python dependencies
pip install -r requirements.txt --upgrade

echo "✅ AuditHound updated successfully"
echo "Restart with: ./start.sh"
EOF
    
    # Make scripts executable
    chmod +x start.sh stop.sh update.sh
    
    success "Startup scripts created"
}

# Generate installation summary
generate_summary() {
    echo ""
    echo -e "${WHITE}🎉 AuditHound Installation Complete!${NC}"
    echo ""
    echo -e "${CYAN}Installation Summary:${NC}"
    echo -e "📁 Installation Directory: ${GREEN}$INSTALL_DIR${NC}"
    echo -e "🏢 Organization: ${GREEN}$ORG_NAME${NC}"
    echo -e "📧 Admin Email: ${GREEN}$ADMIN_EMAIL${NC}"
    echo -e "🎯 Service Tier: ${GREEN}$SERVICE_TIER${NC}"
    echo ""
    
    echo -e "${CYAN}Cloud Providers Enabled:${NC}"
    [[ "$ENABLE_AWS" = "y" ]] && echo -e "  ☁️  AWS: ${GREEN}Enabled${NC}" || echo -e "  ☁️  AWS: ${YELLOW}Disabled${NC}"
    [[ "$ENABLE_GCP" = "y" ]] && echo -e "  ☁️  Google Cloud: ${GREEN}Enabled${NC}" || echo -e "  ☁️  Google Cloud: ${YELLOW}Disabled${NC}"
    [[ "$ENABLE_AZURE" = "y" ]] && echo -e "  ☁️  Azure: ${GREEN}Enabled${NC}" || echo -e "  ☁️  Azure: ${YELLOW}Disabled${NC}"
    echo ""
    
    echo -e "${CYAN}SOC Integrations:${NC}"
    [[ -n "$MISP_URL" ]] && echo -e "  🔗 MISP: ${GREEN}$MISP_URL${NC}" || echo -e "  🔗 MISP: ${YELLOW}Not configured${NC}"
    [[ -n "$THEHIVE_URL" ]] && echo -e "  🎯 TheHive: ${GREEN}$THEHIVE_URL${NC}" || echo -e "  🎯 TheHive: ${YELLOW}Not configured${NC}"
    [[ -n "$SLACK_WEBHOOK" ]] && echo -e "  💬 Slack: ${GREEN}Configured${NC}" || echo -e "  💬 Slack: ${YELLOW}Not configured${NC}"
    echo ""
    
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "1. 📝 Configure credentials: ${WHITE}cd $INSTALL_DIR && cp .env.template .env${NC}"
    echo -e "2. ✏️  Edit .env file with your cloud provider credentials"
    echo -e "3. 🚀 Start AuditHound: ${WHITE}cd $INSTALL_DIR && ./start.sh${NC}"
    echo -e "4. 🌐 Access dashboard: ${WHITE}http://localhost:5001${NC}"
    echo ""
    
    if [[ "$DOCKER_AVAILABLE" = "true" ]]; then
        echo -e "${CYAN}Optional Docker Services:${NC}"
        echo -e "🐳 Start enhanced services: ${WHITE}cd $INSTALL_DIR && docker-compose up -d${NC}"
        echo -e "   • Weaviate (threat hunting): http://localhost:8080"
        echo -e "   • Kafka (streaming analytics): localhost:9092"
        echo -e "   • PostgreSQL (persistence): localhost:5432"
        echo ""
    fi
    
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "🚀 Start: ${WHITE}./start.sh${NC}"
    echo -e "🛑 Stop: ${WHITE}./stop.sh${NC}"
    echo -e "🔄 Update: ${WHITE}./update.sh${NC}"
    echo -e "🧪 Test: ${WHITE}./start.sh --test${NC}"
    echo ""
    
    echo -e "${YELLOW}📖 Documentation: https://docs.audithound.com${NC}"
    echo -e "${YELLOW}🆘 Support: https://github.com/your-org/audithound/issues${NC}"
    echo ""
    
    # Save summary to file
    cat > INSTALLATION_SUMMARY.md << EOF
# AuditHound Installation Summary

**Installation Date:** $(date)
**Installation Directory:** $INSTALL_DIR
**Organization:** $ORG_NAME
**Service Tier:** $SERVICE_TIER

## Configuration
- AWS: $([ "$ENABLE_AWS" = "y" ] && echo "Enabled" || echo "Disabled")
- Google Cloud: $([ "$ENABLE_GCP" = "y" ] && echo "Enabled" || echo "Disabled")
- Azure: $([ "$ENABLE_AZURE" = "y" ] && echo "Enabled" || echo "Disabled")
- MISP: $([ -n "$MISP_URL" ] && echo "$MISP_URL" || echo "Not configured")
- TheHive: $([ -n "$THEHIVE_URL" ] && echo "$THEHIVE_URL" || echo "Not configured")
- Slack: $([ -n "$SLACK_WEBHOOK" ] && echo "Configured" || echo "Not configured")

## Quick Start
1. Configure credentials: \`cp .env.template .env\`
2. Edit .env with your cloud credentials
3. Start AuditHound: \`./start.sh\`
4. Access dashboard: http://localhost:5001

## Commands
- Start: \`./start.sh\`
- Stop: \`./stop.sh\`  
- Update: \`./update.sh\`
- Test: \`./start.sh --test\`

## Support
- Documentation: https://docs.audithound.com
- Issues: https://github.com/your-org/audithound/issues
EOF
}

# Main installation function
main() {
    print_banner
    
    log "Starting AuditHound installation at $(date)"
    
    # Pre-installation checks
    check_root
    detect_system
    check_prerequisites
    
    # Interactive setup
    interactive_setup
    
    # Installation steps
    download_audithound
    setup_python_environment
    generate_configuration
    setup_docker_services
    create_startup_scripts
    
    # Post-installation
    generate_summary
    
    log "Installation completed successfully at $(date)"
    
    echo -e "${GREEN}🎉 Installation complete! Run './start.sh' to begin.${NC}"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "AuditHound Unified Security Platform Installer"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --version, -v  Show version information"
        echo "  --quiet, -q    Quiet installation (minimal output)"
        echo "  --docker       Force Docker setup even if not detected"
        echo ""
        echo "Environment Variables:"
        echo "  AUDITHOUND_VERSION    Version to install (default: latest)"
        echo "  INSTALL_DIR           Installation directory (default: \$HOME/audithound)"
        echo ""
        echo "Example:"
        echo "  curl -sSL https://get.audithound.com/install.sh | bash"
        echo "  INSTALL_DIR=/opt/audithound bash install.sh"
        exit 0
        ;;
    --version|-v)
        echo "AuditHound Installer v1.0.0"
        exit 0
        ;;
    --quiet|-q)
        exec > /dev/null 2>&1
        ;;
    --docker)
        DOCKER_AVAILABLE=true
        ;;
esac

# Run main installation
main

exit 0