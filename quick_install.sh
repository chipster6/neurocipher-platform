#!/bin/bash
# AuditHound Quick Install - One-line installer
# Usage: curl -sSL https://get.audithound.com/quick.sh | bash

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🛡️  AuditHound Quick Install${NC}"
echo -e "${BLUE}===============================${NC}"

# Quick prerequisites check
echo -e "${YELLOW}⚡ Quick system check...${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found. Please install Python 3.8+ first.${NC}"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${RED}❌ Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python $PYTHON_VERSION${NC}"

# Set installation directory
INSTALL_DIR="$HOME/audithound"

# Check if directory exists
if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}⚠️  Directory $INSTALL_DIR already exists${NC}"
    read -p "Remove and reinstall? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
    else
        echo "Installation cancelled."
        exit 0
    fi
fi

# Download/copy AuditHound
echo -e "${YELLOW}📥 Installing AuditHound...${NC}"
mkdir -p "$INSTALL_DIR"

# In production, this would clone from GitHub
# For now, copy the current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || {
    echo -e "${RED}❌ Failed to copy files. Please run from AuditHound directory.${NC}"
    exit 1
}

cd "$INSTALL_DIR"

# Create virtual environment
echo -e "${YELLOW}🐍 Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip > /dev/null 2>&1
pip install flask pyyaml requests sqlalchemy python-dotenv click > /dev/null 2>&1

# Create minimal configuration
echo -e "${YELLOW}⚙️  Creating configuration...${NC}"
cat > config.yaml << 'EOF'
organization:
  name: "Demo Organization"
  admin_email: "admin@demo.com"
  service_tier: "starter"

cloud_providers:
  aws:
    enabled: false
  gcp:
    enabled: false
  azure:
    enabled: false

compliance_frameworks:
  soc2:
    enabled: true
    controls:
      - "CC6.1"
      - "CC6.2"
      - "CC6.3"
      - "CC7.1"
      - "CC8.1"

dashboard:
  host: "0.0.0.0"
  port: 5001
  debug: false

notifications:
  slack:
    enabled: false
EOF

# Create environment file
cat > .env << 'EOF'
# AuditHound Environment Variables
# Add your cloud provider credentials here as needed

# Example AWS:
# AWS_ACCESS_KEY_ID=your-key
# AWS_SECRET_ACCESS_KEY=your-secret

# Example GCP:
# GCP_PROJECT_ID=your-project

# Example Azure:
# AZURE_TENANT_ID=your-tenant
# AZURE_SUBSCRIPTION_ID=your-subscription
# AZURE_CLIENT_ID=your-client-id
# AZURE_CLIENT_SECRET=your-secret
EOF

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python run_unified_dashboard.py "$@"
EOF

chmod +x start.sh

# Create directories
mkdir -p logs reports credentials

echo -e "${GREEN}✅ Installation complete!${NC}"
echo
echo -e "${BLUE}🚀 Quick Start:${NC}"
echo -e "   cd $INSTALL_DIR"
echo -e "   ./start.sh"
echo
echo -e "${BLUE}🌐 Dashboard URL:${NC}"
echo -e "   http://localhost:5001"
echo
echo -e "${BLUE}📝 Next Steps:${NC}"
echo -e "   1. Edit .env file to add cloud credentials"
echo -e "   2. Run: ./start.sh"
echo -e "   3. Open dashboard in browser"
echo
echo -e "${YELLOW}💡 Tip: Run './start.sh --test' to validate setup${NC}"

# Offer to start immediately
echo
read -p "Start AuditHound now? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}🚀 Starting AuditHound...${NC}"
    cd "$INSTALL_DIR"
    exec ./start.sh
fi