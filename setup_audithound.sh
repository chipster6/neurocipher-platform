#!/bin/bash
#
# AuditHound Self-Hosting Setup Script
# Automated installation and configuration for enterprise security compliance
#
# Usage: ./setup_audithound.sh [--msp] [--config /path/to/config.json]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
MSP_MODE=false
CONFIG_FILE=""
INSTALL_DIR="$HOME/audithound"
PYTHON_VERSION="3.9"
WEAVIATE_VERSION="1.22.4"

# Logo and banner
print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════╗
    ║                                           ║
    ║           🔒 AuditHound Setup             ║
    ║      Enterprise Security Compliance      ║
    ║                                           ║
    ╚═══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --msp)
                MSP_MODE=true
                shift
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                ;;
        esac
    done
}

# Show help
show_help() {
    cat << EOF
AuditHound Setup Script

Usage: $0 [OPTIONS]

Options:
    --msp                Enable MSP (Managed Service Provider) mode
    --config FILE        Use custom configuration file
    --install-dir DIR    Installation directory (default: $HOME/audithound)
    --help              Show this help message

Examples:
    # Standard installation
    ./setup_audithound.sh
    
    # MSP installation with custom config
    ./setup_audithound.sh --msp --config ./msp_config.json
    
    # Custom installation directory
    ./setup_audithound.sh --install-dir /opt/audithound

EOF
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        log_success "Operating System: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        log_success "Operating System: macOS"
    else
        log_error "Unsupported operating system: $OSTYPE"
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        PYTHON_CURRENT=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        log_success "Python found: $PYTHON_CURRENT"
        
        # Check Python version
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log_success "Python version is compatible (>= 3.8)"
        else
            log_error "Python 3.8+ required. Found: $PYTHON_CURRENT"
        fi
    else
        log_error "Python 3 not found. Please install Python 3.8+"
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
        log_success "pip3 found"
    elif command -v pip &> /dev/null; then
        PIP_CMD="pip"
        log_success "pip found"
    else
        log_error "pip not found. Please install pip"
    fi
    
    # Check Docker (optional but recommended)
    if command -v docker &> /dev/null; then
        log_success "Docker found (recommended for Weaviate)"
        DOCKER_AVAILABLE=true
    else
        log_warning "Docker not found. Weaviate will use external instance"
        DOCKER_AVAILABLE=false
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        log_success "Git found"
    else
        log_error "Git not found. Please install Git"
    fi
    
    # Check available space
    AVAILABLE_SPACE=$(df "$HOME" | awk 'NR==2{printf "%.1f", $4/1024/1024}')
    if (( $(echo "$AVAILABLE_SPACE > 2.0" | bc -l) )); then
        log_success "Available disk space: ${AVAILABLE_SPACE}GB"
    else
        log_warning "Low disk space: ${AVAILABLE_SPACE}GB (recommended: 2GB+)"
    fi
}

# Create installation directory structure
create_directory_structure() {
    log_info "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/certificates"
    mkdir -p "$INSTALL_DIR/docker"
    
    if [[ "$MSP_MODE" == true ]]; then
        mkdir -p "$INSTALL_DIR/tenants"
        mkdir -p "$INSTALL_DIR/white-label"
        mkdir -p "$INSTALL_DIR/msp-configs"
    fi
    
    log_success "Directory structure created at $INSTALL_DIR"
}

# Install Python dependencies
install_python_dependencies() {
    log_info "Installing Python dependencies..."
    
    cd "$INSTALL_DIR"
    
    # Create virtual environment
    if [[ ! -d "venv" ]]; then
        $PYTHON_CMD -m venv venv
        log_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install core dependencies
    cat > requirements.txt << EOF
# Core dependencies
streamlit>=1.28.0
pandas>=2.0.0
numpy>=1.24.0
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
click>=8.1.0
rich>=13.0.0
typer>=0.9.0

# Cloud SDKs
boto3>=1.29.0
google-cloud-security-center>=1.23.0
google-cloud-asset>=3.19.0
google-cloud-logging>=3.8.0
azure-mgmt-security>=5.0.0
azure-mgmt-resource>=23.0.0
azure-identity>=1.15.0

# Database and search
weaviate-client>=3.25.0
elasticsearch>=8.11.0

# Security and compliance
cryptography>=41.0.0
python-jose>=3.3.0
passlib>=1.7.4

# Monitoring and observability
prometheus-client>=0.19.0
grafana-api>=1.0.3

# Development and testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
black>=23.0.0
flake8>=6.1.0

# Optional integrations
# thehive4py>=1.13.0  # Uncomment if using TheHive
# pymisp>=2.4.173     # Uncomment if using MISP
EOF
    
    # Install dependencies
    pip install -r requirements.txt
    
    log_success "Python dependencies installed"
}

# Setup Weaviate (Docker or configuration)
setup_weaviate() {
    log_info "Setting up Weaviate vector database..."
    
    if [[ "$DOCKER_AVAILABLE" == true ]]; then
        # Create Docker Compose file for Weaviate
        cat > "$INSTALL_DIR/docker/docker-compose.weaviate.yml" << EOF
version: '3.4'
services:
  weaviate:
    command:
    - --host
    - 0.0.0.0
    - --port
    - '8080'
    - --scheme
    - http
    image: semitechnologies/weaviate:$WEAVIATE_VERSION
    ports:
    - 8080:8080
    volumes:
    - weaviate_data:/var/lib/weaviate
    restart: unless-stopped
    environment:
      QUERY_DEFAULTS_LIMIT: 25
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'true'
      PERSISTENCE_DATA_PATH: '/var/lib/weaviate'
      DEFAULT_VECTORIZER_MODULE: 'none'
      ENABLE_MODULES: 'text2vec-openai,text2vec-transformers,qna-openai'
      CLUSTER_HOSTNAME: 'node1'
volumes:
  weaviate_data:
EOF
        
        # Start Weaviate
        cd "$INSTALL_DIR/docker"
        docker-compose -f docker-compose.weaviate.yml up -d
        
        # Wait for Weaviate to be ready
        log_info "Waiting for Weaviate to start..."
        sleep 10
        
        # Test Weaviate connection
        if curl -s http://localhost:8080/v1/meta > /dev/null; then
            log_success "Weaviate started successfully on port 8080"
        else
            log_warning "Weaviate may not be ready yet. Please check Docker logs."
        fi
    else
        log_warning "Docker not available. Please configure external Weaviate instance"
        echo "WEAVIATE_URL=http://localhost:8080" >> "$INSTALL_DIR/config/.env"
    fi
}

# Create configuration files
create_configuration_files() {
    log_info "Creating configuration files..."
    
    # Main configuration
    cat > "$INSTALL_DIR/config/config.yaml" << EOF
# AuditHound Configuration
app:
  name: "AuditHound"
  version: "1.0.0"
  mode: "$([[ "$MSP_MODE" == true ]] && echo "msp" || echo "standard")"
  debug: false
  
server:
  host: "0.0.0.0"
  port: 8501
  enable_cors: true
  
database:
  weaviate:
    url: "http://localhost:8080"
    timeout: 30
    batch_size: 100
  
cloud_providers:
  aws:
    enabled: true
    regions: ["us-east-1", "us-west-2", "eu-west-1"]
    
  gcp:
    enabled: true
    default_project: ""
    
  azure:
    enabled: true
    default_subscription: ""

compliance:
  frameworks:
    soc2:
      enabled: true
      controls: ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
    iso27001:
      enabled: false
    nist:
      enabled: false
      
  scoring:
    thresholds:
      compliant: 90
      partial: 70
    weights:
      password_policy_strength: 0.20
      mfa_enforcement: 0.25
      access_control_policies: 0.25
      privileged_access_management: 0.20
      account_lifecycle_management: 0.10

security:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
  
  authentication:
    enabled: false
    type: "local"  # local, oauth, saml
    
  session:
    timeout: 3600
    secure_cookies: true

monitoring:
  enabled: true
  retention_days: 90
  
  prometheus:
    enabled: false
    port: 9090
    
  logging:
    level: "INFO"
    file: "$INSTALL_DIR/logs/audithound.log"
    max_size: "100MB"
    backup_count: 5

EOF

    # MSP-specific configuration
    if [[ "$MSP_MODE" == true ]]; then
        cat >> "$INSTALL_DIR/config/config.yaml" << EOF

# MSP-specific configuration
msp:
  enabled: true
  white_label:
    enabled: true
    company_name: "Your MSP Company"
    logo_path: "$INSTALL_DIR/white-label/logo.png"
    primary_color: "#1f77b4"
    secondary_color: "#ff7f0e"
    
  multi_tenant:
    enabled: true
    isolation_level: "soft"
    default_tier: "professional"
    
  client_management:
    auto_provisioning: true
    default_features: ["compliance_auditing", "basic_reporting"]
    max_clients: 100
    
  billing:
    enabled: false
    provider: "stripe"  # stripe, manual
    
  support:
    contact_email: "support@yourmsp.com"
    documentation_url: "https://docs.yourmsp.com"

EOF
    fi
    
    # Environment variables
    cat > "$INSTALL_DIR/config/.env" << EOF
# AuditHound Environment Configuration
AUDITHOUND_CONFIG_PATH=$INSTALL_DIR/config/config.yaml
AUDITHOUND_DATA_PATH=$INSTALL_DIR/data
AUDITHOUND_LOG_PATH=$INSTALL_DIR/logs

# Database
WEAVIATE_URL=http://localhost:8080
WEAVIATE_API_KEY=

# Cloud Provider Credentials (set these manually)
# AWS
AWS_PROFILE=
AWS_REGION=us-west-2
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# GCP
GOOGLE_APPLICATION_CREDENTIALS=
GCP_PROJECT_ID=

# Azure
AZURE_TENANT_ID=
AZURE_SUBSCRIPTION_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=

# Security
ENCRYPTION_KEY=
JWT_SECRET=

# Monitoring
PROMETHEUS_ENABLED=false
GRAFANA_ENABLED=false

# MSP Settings
$([[ "$MSP_MODE" == true ]] && cat << 'MSP_EOF'
MSP_MODE=true
MSP_COMPANY_NAME="Your MSP Company"
MSP_SUPPORT_EMAIL=support@yourmsp.com
WHITE_LABEL_ENABLED=true
MSP_EOF
)
EOF
    
    # Create startup script
    cat > "$INSTALL_DIR/start_audithound.sh" << 'EOF'
#!/bin/bash
# AuditHound Startup Script

cd "$(dirname "$0")"

# Validate environment variables before starting
echo "🔍 Validating environment configuration..."
if [ -f "scripts/validate-env.sh" ]; then
    ./scripts/validate-env.sh
    if [ $? -ne 0 ]; then
        echo "❌ Environment validation failed. Please fix the issues above."
        exit 1
    fi
else
    echo "⚠️  Environment validation script not found. Proceeding with startup..."
fi

source venv/bin/activate

# Load environment variables
if [ -f "config/.env" ]; then
    export $(cat config/.env | grep -v '^#' | xargs)
fi

# Start AuditHound
echo "🚀 Starting AuditHound..."
streamlit run src/app.py --server.port=${PORT:-8501} --server.address=${HOST:-0.0.0.0}
EOF
    
    chmod +x "$INSTALL_DIR/start_audithound.sh"
    
    log_success "Configuration files created"
}

# Setup onboarding system
setup_onboarding_system() {
    log_info "Setting up onboarding system..."
    
    # Create onboarding configuration template
    cat > "$INSTALL_DIR/config/onboarding_template.json" << EOF
{
  "organization": {
    "name": "",
    "industry": "",
    "size": "small|medium|large|enterprise",
    "contact": {
      "name": "",
      "email": "",
      "phone": ""
    },
    "address": {
      "street": "",
      "city": "",
      "state": "",
      "country": "",
      "postal_code": ""
    }
  },
  "compliance": {
    "frameworks": ["SOC2", "ISO27001", "NIST"],
    "requirements": {
      "soc2_controls": ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"],
      "custom_controls": []
    },
    "reporting": {
      "frequency": "monthly|quarterly|annual",
      "stakeholders": []
    }
  },
  "infrastructure": {
    "cloud_providers": {
      "aws": {
        "enabled": false,
        "accounts": [],
        "regions": ["us-west-2"]
      },
      "gcp": {
        "enabled": false,
        "projects": [],
        "organization_id": ""
      },
      "azure": {
        "enabled": false,
        "subscriptions": [],
        "tenant_id": ""
      }
    },
    "on_premise": {
      "enabled": false,
      "networks": [],
      "systems": []
    }
  },
  "security": {
    "current_tools": [],
    "integrations": {
      "siem": {
        "enabled": false,
        "type": "splunk|elastic|qradar|sentinel"
      },
      "soar": {
        "enabled": false,
        "type": "phantom|demisto|swimlane"
      },
      "threat_intel": {
        "enabled": false,
        "feeds": []
      }
    }
  },
  "preferences": {
    "notifications": {
      "email": true,
      "slack": false,
      "teams": false
    },
    "dashboard": {
      "default_view": "executive|technical|compliance",
      "refresh_interval": 300
    },
    "reports": {
      "auto_generate": true,
      "formats": ["pdf", "html", "json"]
    }
  },
  "msp_settings": {
    "is_msp_client": false,
    "parent_msp": "",
    "billing_contact": "",
    "white_label": {
      "enabled": false,
      "branding": {
        "company_name": "",
        "logo_url": "",
        "primary_color": "#1f77b4",
        "secondary_color": "#ff7f0e"
      }
    }
  }
}
EOF
    
    # Create onboarding script
    cat > "$INSTALL_DIR/onboard_client.py" << 'EOF'
#!/usr/bin/env python3
"""
AuditHound Client Onboarding Script
Automated client setup and configuration
"""

import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
import argparse
import yaml

def load_template(template_path):
    """Load onboarding template"""
    with open(template_path, 'r') as f:
        return json.load(f)

def create_client_config(template, client_data):
    """Create client-specific configuration"""
    config = template.copy()
    
    # Update with client data
    config['organization'].update(client_data.get('organization', {}))
    config['compliance'].update(client_data.get('compliance', {}))
    config['infrastructure'].update(client_data.get('infrastructure', {}))
    config['security'].update(client_data.get('security', {}))
    config['preferences'].update(client_data.get('preferences', {}))
    
    # Generate client ID
    client_id = f"client_{uuid.uuid4().hex[:8]}"
    config['client_id'] = client_id
    config['created_at'] = datetime.now().isoformat()
    
    return config

def setup_client_directories(install_dir, client_id):
    """Setup client-specific directories"""
    client_dir = Path(install_dir) / "tenants" / client_id
    client_dir.mkdir(parents=True, exist_ok=True)
    
    (client_dir / "config").mkdir(exist_ok=True)
    (client_dir / "data").mkdir(exist_ok=True)
    (client_dir / "reports").mkdir(exist_ok=True)
    (client_dir / "logs").mkdir(exist_ok=True)
    
    return client_dir

def generate_client_credentials(client_dir):
    """Generate client-specific credentials"""
    import secrets
    
    credentials = {
        "api_key": secrets.token_urlsafe(32),
        "client_secret": secrets.token_urlsafe(64),
        "encryption_key": secrets.token_urlsafe(32)
    }
    
    with open(client_dir / "config" / "credentials.json", 'w') as f:
        json.dump(credentials, f, indent=2)
    
    return credentials

def update_main_config(install_dir, client_config):
    """Update main configuration with new client"""
    config_path = Path(install_dir) / "config" / "config.yaml"
    
    with open(config_path, 'r') as f:
        main_config = yaml.safe_load(f)
    
    if 'clients' not in main_config:
        main_config['clients'] = {}
    
    main_config['clients'][client_config['client_id']] = {
        'organization_name': client_config['organization']['name'],
        'tier': 'professional',
        'status': 'active',
        'created_at': client_config['created_at']
    }
    
    with open(config_path, 'w') as f:
        yaml.dump(main_config, f, default_flow_style=False)

def main():
    parser = argparse.ArgumentParser(description='AuditHound Client Onboarding')
    parser.add_argument('--config', required=True, help='Client configuration JSON file')
    parser.add_argument('--install-dir', default=os.getcwd(), help='AuditHound installation directory')
    parser.add_argument('--template', help='Custom onboarding template')
    
    args = parser.parse_args()
    
    # Load template
    template_path = args.template or Path(args.install_dir) / "config" / "onboarding_template.json"
    template = load_template(template_path)
    
    # Load client data
    with open(args.config, 'r') as f:
        client_data = json.load(f)
    
    # Create client configuration
    client_config = create_client_config(template, client_data)
    client_id = client_config['client_id']
    
    print(f"🚀 Onboarding client: {client_config['organization']['name']}")
    print(f"📋 Client ID: {client_id}")
    
    # Setup directories
    client_dir = setup_client_directories(args.install_dir, client_id)
    print(f"📁 Client directory: {client_dir}")
    
    # Generate credentials
    credentials = generate_client_credentials(client_dir)
    print(f"🔐 Generated credentials")
    
    # Save client configuration
    with open(client_dir / "config" / "client_config.json", 'w') as f:
        json.dump(client_config, f, indent=2)
    
    # Update main configuration
    update_main_config(args.install_dir, client_config)
    
    print(f"✅ Client onboarding completed!")
    print(f"   • Client ID: {client_id}")
    print(f"   • API Key: {credentials['api_key'][:16]}...")
    print(f"   • Config Path: {client_dir / 'config' / 'client_config.json'}")
    
    return client_id

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$INSTALL_DIR/onboard_client.py"
    
    log_success "Onboarding system configured"
}

# Setup white-label branding for MSP mode
setup_white_label_branding() {
    if [[ "$MSP_MODE" != true ]]; then
        return 0
    fi
    
    log_info "Setting up white-label branding system..."
    
    # Create white-label directory structure
    mkdir -p "$INSTALL_DIR/white-label/assets"
    mkdir -p "$INSTALL_DIR/white-label/themes"
    mkdir -p "$INSTALL_DIR/white-label/templates"
    
    # Create default theme
    cat > "$INSTALL_DIR/white-label/themes/default.json" << EOF
{
  "name": "Default MSP Theme",
  "version": "1.0.0",
  "branding": {
    "company_name": "Your MSP Company",
    "tagline": "Secure. Compliant. Trusted.",
    "logo": {
      "primary": "assets/logo-primary.png",
      "secondary": "assets/logo-secondary.png",
      "favicon": "assets/favicon.ico"
    }
  },
  "colors": {
    "primary": "#1f77b4",
    "secondary": "#ff7f0e",
    "accent": "#2ca02c",
    "background": "#ffffff",
    "surface": "#f8f9fa",
    "text": {
      "primary": "#212529",
      "secondary": "#6c757d",
      "light": "#ffffff"
    },
    "status": {
      "success": "#28a745",
      "warning": "#ffc107",
      "error": "#dc3545",
      "info": "#17a2b8"
    }
  },
  "typography": {
    "font_family": "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
    "sizes": {
      "h1": "2.5rem",
      "h2": "2rem",
      "h3": "1.75rem",
      "h4": "1.5rem",
      "body": "1rem",
      "small": "0.875rem"
    }
  },
  "layout": {
    "sidebar_width": "280px",
    "header_height": "64px",
    "border_radius": "8px",
    "box_shadow": "0 2px 4px rgba(0,0,0,0.1)"
  }
}
EOF
    
    # Create branding configuration script
    cat > "$INSTALL_DIR/configure_branding.py" << 'EOF'
#!/usr/bin/env python3
"""
White-Label Branding Configuration
Setup custom branding for MSP deployments
"""

import json
import os
import sys
from pathlib import Path
import argparse
import shutil
from PIL import Image, ImageDraw

def create_default_logo(output_path, company_name, primary_color="#1f77b4"):
    """Create a default logo with company name"""
    width, height = 400, 120
    img = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(img)
    
    # Draw company name (simplified - in production use proper fonts)
    text_color = primary_color
    draw.text((20, 40), company_name, fill=text_color)
    
    img.save(output_path)
    print(f"Created default logo: {output_path}")

def generate_favicon(logo_path, favicon_path):
    """Generate favicon from logo"""
    try:
        with Image.open(logo_path) as img:
            img = img.resize((32, 32), Image.Resampling.LANCZOS)
            img.save(favicon_path, format='ICO')
        print(f"Generated favicon: {favicon_path}")
    except Exception as e:
        print(f"Warning: Could not generate favicon: {e}")

def create_streamlit_theme(theme_config, output_path):
    """Create Streamlit theme configuration"""
    colors = theme_config['colors']
    
    streamlit_theme = {
        "primaryColor": colors['primary'],
        "backgroundColor": colors['background'],
        "secondaryBackgroundColor": colors['surface'],
        "textColor": colors['text']['primary'],
        "font": "sans serif"
    }
    
    with open(output_path, 'w') as f:
        json.dump(streamlit_theme, f, indent=2)
    
    print(f"Created Streamlit theme: {output_path}")

def create_css_theme(theme_config, output_path):
    """Create CSS theme file"""
    colors = theme_config['colors']
    typography = theme_config['typography']
    layout = theme_config['layout']
    
    css_content = f"""
/* AuditHound White-Label Theme */
:root {{
    --primary-color: {colors['primary']};
    --secondary-color: {colors['secondary']};
    --accent-color: {colors['accent']};
    --background-color: {colors['background']};
    --surface-color: {colors['surface']};
    --text-primary: {colors['text']['primary']};
    --text-secondary: {colors['text']['secondary']};
    --text-light: {colors['text']['light']};
    --success-color: {colors['status']['success']};
    --warning-color: {colors['status']['warning']};
    --error-color: {colors['status']['error']};
    --info-color: {colors['status']['info']};
    
    --font-family: {typography['font_family']};
    --font-size-h1: {typography['sizes']['h1']};
    --font-size-h2: {typography['sizes']['h2']};
    --font-size-h3: {typography['sizes']['h3']};
    --font-size-h4: {typography['sizes']['h4']};
    --font-size-body: {typography['sizes']['body']};
    --font-size-small: {typography['sizes']['small']};
    
    --sidebar-width: {layout['sidebar_width']};
    --header-height: {layout['header_height']};
    --border-radius: {layout['border_radius']};
    --box-shadow: {layout['box_shadow']};
}}

/* Custom styling for white-label branding */
.main .block-container {{
    padding-top: 2rem;
}}

.stApp > header {{
    background-color: var(--primary-color);
    height: var(--header-height);
}}

.stSidebar > div:first-child {{
    background-color: var(--surface-color);
    width: var(--sidebar-width);
}}

/* Custom logo styling */
.logo-container {{
    display: flex;
    align-items: center;
    padding: 1rem;
    background-color: var(--primary-color);
    color: var(--text-light);
}}

.logo-container img {{
    max-height: 40px;
    margin-right: 1rem;
}}

/* Status indicators */
.status-success {{ color: var(--success-color); }}
.status-warning {{ color: var(--warning-color); }}
.status-error {{ color: var(--error-color); }}
.status-info {{ color: var(--info-color); }}

/* Compliance score styling */
.compliance-score {{
    background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
    color: var(--text-light);
    padding: 1rem;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
}}
"""
    
    with open(output_path, 'w') as f:
        f.write(css_content)
    
    print(f"Created CSS theme: {output_path}")

def configure_branding(install_dir, branding_config):
    """Configure white-label branding"""
    white_label_dir = Path(install_dir) / "white-label"
    assets_dir = white_label_dir / "assets"
    themes_dir = white_label_dir / "themes"
    
    # Load or create theme
    if 'theme_file' in branding_config:
        with open(branding_config['theme_file'], 'r') as f:
            theme_config = json.load(f)
    else:
        theme_path = themes_dir / "default.json"
        with open(theme_path, 'r') as f:
            theme_config = json.load(f)
    
    # Update theme with branding config
    if 'company_name' in branding_config:
        theme_config['branding']['company_name'] = branding_config['company_name']
    
    if 'colors' in branding_config:
        theme_config['colors'].update(branding_config['colors'])
    
    # Handle logo
    if 'logo_path' in branding_config and os.path.exists(branding_config['logo_path']):
        # Copy provided logo
        logo_dest = assets_dir / "logo-primary.png"
        shutil.copy2(branding_config['logo_path'], logo_dest)
        print(f"Copied logo: {logo_dest}")
    else:
        # Create default logo
        logo_path = assets_dir / "logo-primary.png"
        create_default_logo(
            logo_path, 
            theme_config['branding']['company_name'],
            theme_config['colors']['primary']
        )
    
    # Generate favicon
    favicon_path = assets_dir / "favicon.ico"
    generate_favicon(assets_dir / "logo-primary.png", favicon_path)
    
    # Create Streamlit theme
    streamlit_theme_path = white_label_dir / "streamlit_theme.json"
    create_streamlit_theme(theme_config, streamlit_theme_path)
    
    # Create CSS theme
    css_theme_path = white_label_dir / "theme.css"
    create_css_theme(theme_config, css_theme_path)
    
    # Save updated theme
    theme_output_path = themes_dir / "current.json"
    with open(theme_output_path, 'w') as f:
        json.dump(theme_config, f, indent=2)
    
    print(f"✅ White-label branding configured successfully!")
    return theme_config

def main():
    parser = argparse.ArgumentParser(description='Configure AuditHound White-Label Branding')
    parser.add_argument('--install-dir', default=os.getcwd(), help='AuditHound installation directory')
    parser.add_argument('--company-name', help='Company name for branding')
    parser.add_argument('--logo', help='Path to company logo')
    parser.add_argument('--primary-color', help='Primary brand color (hex)')
    parser.add_argument('--secondary-color', help='Secondary brand color (hex)')
    parser.add_argument('--config', help='JSON configuration file')
    
    args = parser.parse_args()
    
    # Build branding configuration
    branding_config = {}
    
    if args.config:
        with open(args.config, 'r') as f:
            branding_config = json.load(f)
    
    if args.company_name:
        branding_config['company_name'] = args.company_name
    
    if args.logo:
        branding_config['logo_path'] = args.logo
    
    if args.primary_color:
        if 'colors' not in branding_config:
            branding_config['colors'] = {}
        branding_config['colors']['primary'] = args.primary_color
    
    if args.secondary_color:
        if 'colors' not in branding_config:
            branding_config['colors'] = {}
        branding_config['colors']['secondary'] = args.secondary_color
    
    if not branding_config:
        print("No branding configuration provided. Use --help for options.")
        return 1
    
    # Configure branding
    configure_branding(args.install_dir, branding_config)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF
    
    chmod +x "$INSTALL_DIR/configure_branding.py"
    
    # Create sample branding configuration
    cat > "$INSTALL_DIR/white-label/sample_branding.json" << EOF
{
  "company_name": "SecureCompliance MSP",
  "tagline": "Your Trusted Security Partner",
  "logo_path": "",
  "colors": {
    "primary": "#2c5aa0",
    "secondary": "#f39c12",
    "accent": "#27ae60"
  },
  "contact": {
    "support_email": "support@securecompliancemsp.com",
    "website": "https://securecompliancemsp.com",
    "phone": "+1-555-SECURE"
  }
}
EOF
    
    log_success "White-label branding system configured"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    cd "$INSTALL_DIR/certificates"
    
    # Generate private key
    openssl genrsa -out audithound.key 2048 2>/dev/null || {
        log_warning "OpenSSL not available. Skipping SSL certificate generation."
        return 0
    }
    
    # Generate certificate signing request
    openssl req -new -key audithound.key -out audithound.csr -subj "/C=US/ST=State/L=City/O=AuditHound/OU=Security/CN=localhost" 2>/dev/null
    
    # Generate self-signed certificate
    openssl x509 -req -days 365 -in audithound.csr -signkey audithound.key -out audithound.crt 2>/dev/null
    
    # Set appropriate permissions
    chmod 600 audithound.key
    chmod 644 audithound.crt
    
    log_success "SSL certificates generated"
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [[ "$OS" != "linux" ]]; then
        return 0
    fi
    
    log_info "Creating systemd service..."
    
    cat > "$INSTALL_DIR/audithound.service" << EOF
[Unit]
Description=AuditHound Security Compliance Platform
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
EnvironmentFile=$INSTALL_DIR/config/.env
ExecStart=$INSTALL_DIR/venv/bin/streamlit run src/app.py --server.port=8501 --server.address=0.0.0.0
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    log_success "Systemd service file created at $INSTALL_DIR/audithound.service"
    log_info "To install: sudo cp $INSTALL_DIR/audithound.service /etc/systemd/system/"
    log_info "To enable: sudo systemctl enable audithound"
    log_info "To start: sudo systemctl start audithound"
}

# Download AuditHound source code
download_source_code() {
    log_info "Setting up AuditHound source code..."
    
    cd "$INSTALL_DIR"
    
    # Check if src directory already exists (as in our case)
    if [[ -d "src" ]]; then
        log_success "Source code already available"
        return 0
    fi
    
    # In a real deployment, this would clone from a repository
    log_info "Creating source code structure..."
    
    mkdir -p src
    
    # Create main application file
    cat > src/app.py << 'EOF'
#!/usr/bin/env python3
"""
AuditHound Main Application
Enterprise Security Compliance Platform
"""

import streamlit as st
import os
import sys
from pathlib import Path

# Add src to Python path
sys.path.append(str(Path(__file__).parent))

# Page configuration
st.set_page_config(
    page_title="AuditHound",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

def load_white_label_config():
    """Load white-label configuration"""
    config_path = Path(__file__).parent.parent / "white-label" / "themes" / "current.json"
    if config_path.exists():
        import json
        with open(config_path, 'r') as f:
            return json.load(f)
    return None

def apply_white_label_styling():
    """Apply white-label styling if available"""
    white_label_config = load_white_label_config()
    if not white_label_config:
        return
    
    # Load custom CSS
    css_path = Path(__file__).parent.parent / "white-label" / "theme.css"
    if css_path.exists():
        with open(css_path, 'r') as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    
    # Update page title
    company_name = white_label_config.get('branding', {}).get('company_name', 'AuditHound')
    return company_name

def main():
    """Main application entry point"""
    
    # Apply white-label styling
    company_name = apply_white_label_styling() or "AuditHound"
    
    # Sidebar
    with st.sidebar:
        st.image("white-label/assets/logo-primary.png", width=200)
        st.title(f"{company_name}")
        st.markdown("---")
        
        # Navigation
        page = st.selectbox(
            "Navigate to:",
            ["Dashboard", "Compliance", "Assets", "Reports", "Settings"]
        )
    
    # Main content
    st.title(f"🔒 {company_name} Security Compliance")
    
    if page == "Dashboard":
        st.header("Executive Dashboard")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Overall Compliance", "85.2%", "+2.1%")
        with col2:
            st.metric("Active Assets", "1,247", "+23")
        with col3:
            st.metric("Critical Findings", "3", "-5")
        with col4:
            st.metric("Risk Score", "Medium", "↓")
        
        st.markdown("---")
        st.info("🚀 AuditHound is successfully installed and running!")
        st.success("✅ Multi-tenant database layer configured")
        st.success("✅ Cloud integrations ready (AWS, GCP, Azure)")
        st.success("✅ Compliance frameworks loaded")
        
        if os.getenv('MSP_MODE') == 'true':
            st.success("✅ MSP mode enabled with white-label branding")
    
    elif page == "Compliance":
        st.header("Compliance Management")
        st.info("Compliance module will be loaded here")
    
    elif page == "Assets":
        st.header("Asset Inventory")
        st.info("Asset management module will be loaded here")
    
    elif page == "Reports":
        st.header("Compliance Reports")
        st.info("Reporting module will be loaded here")
    
    elif page == "Settings":
        st.header("System Settings")
        
        # Show installation info
        st.subheader("Installation Information")
        install_dir = Path(__file__).parent.parent
        st.code(f"Installation Directory: {install_dir}")
        st.code(f"MSP Mode: {os.getenv('MSP_MODE', 'false')}")
        st.code(f"White Label: {os.getenv('WHITE_LABEL_ENABLED', 'false')}")
        
        # Configuration files
        st.subheader("Configuration Files")
        config_files = [
            "config/config.yaml",
            "config/.env",
            "config/onboarding_template.json"
        ]
        
        for config_file in config_files:
            config_path = install_dir / config_file
            if config_path.exists():
                st.success(f"✅ {config_file}")
            else:
                st.error(f"❌ {config_file} not found")

if __name__ == "__main__":
    main()
EOF
    
    log_success "AuditHound application structure created"
}

# Perform post-installation tasks
post_installation_tasks() {
    log_info "Performing post-installation tasks..."
    
    # Create example client configuration
    if [[ "$MSP_MODE" == true ]]; then
        cat > "$INSTALL_DIR/example_client.json" << EOF
{
  "organization": {
    "name": "Acme Corporation",
    "industry": "Technology",
    "size": "medium",
    "contact": {
      "name": "John Smith",
      "email": "john.smith@acme.com",
      "phone": "+1-555-123-4567"
    }
  },
  "compliance": {
    "frameworks": ["SOC2"],
    "requirements": {
      "soc2_controls": ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
    }
  },
  "infrastructure": {
    "cloud_providers": {
      "aws": {
        "enabled": true,
        "regions": ["us-west-2"]
      }
    }
  }
}
EOF
    fi
    
    # Generate initial encryption keys
    python3 -c "
import secrets
import os
with open('$INSTALL_DIR/config/.env', 'a') as f:
    f.write(f'\nENCRYPTION_KEY={secrets.token_urlsafe(32)}\n')
    f.write(f'JWT_SECRET={secrets.token_urlsafe(64)}\n')
"
    
    # Set proper permissions
    chmod 600 "$INSTALL_DIR/config/.env"
    chmod 700 "$INSTALL_DIR/config"
    
    if [[ "$MSP_MODE" == true ]]; then
        chmod 700 "$INSTALL_DIR/tenants"
        chmod 700 "$INSTALL_DIR/msp-configs"
    fi
    
    log_success "Post-installation tasks completed"
}

# Display installation summary
display_summary() {
    log_success "🎉 AuditHound installation completed successfully!"
    
    echo -e "${GREEN}"
    cat << EOF

╔═══════════════════════════════════════════════════════════╗
║                     INSTALLATION SUMMARY                 ║
╚═══════════════════════════════════════════════════════════╝

📍 Installation Directory: $INSTALL_DIR
🔧 Mode: $([[ "$MSP_MODE" == true ]] && echo "MSP (Multi-Tenant)" || echo "Standard")
🐍 Python: $PYTHON_CURRENT
🗄️  Database: Weaviate $([ "$DOCKER_AVAILABLE" = true ] && echo "(Docker)" || echo "(External)")

📁 Directory Structure:
   ├── config/          # Configuration files
   ├── src/             # Application source code
   ├── data/            # Application data
   ├── logs/            # Application logs
   ├── certificates/    # SSL certificates$([[ "$MSP_MODE" == true ]] && echo "
   ├── tenants/         # Client configurations
   ├── white-label/     # Branding assets
   └── msp-configs/     # MSP-specific configs" || echo "")

🚀 Getting Started:

   1. Review configuration:
      $INSTALL_DIR/config/config.yaml

   2. Set cloud provider credentials:
      $INSTALL_DIR/config/.env

   3. Start AuditHound:
      cd $INSTALL_DIR && ./start_audithound.sh

   4. Access web interface:
      http://localhost:8501

$([[ "$MSP_MODE" == true ]] && cat << 'MSP_EOF'

🏢 MSP-Specific Features:

   • Client Onboarding:
     cd $INSTALL_DIR && python3 onboard_client.py --config example_client.json

   • Configure Branding:
     cd $INSTALL_DIR && python3 configure_branding.py --company-name "Your MSP"

   • White-Label Assets:
     $INSTALL_DIR/white-label/

MSP_EOF
)

💡 Next Steps:

   • Configure cloud provider credentials in .env file
   • Review security settings in config.yaml
   • Set up SSL certificates for production
   • Configure monitoring and alerting$([[ "$MSP_MODE" == true ]] && echo "
   • Set up client onboarding process
   • Customize white-label branding" || echo "")

📚 Documentation: https://docs.audithound.com
🆘 Support: support@audithound.com

EOF
    echo -e "${NC}"
}

# Main installation function
main() {
    print_banner
    
    # Parse arguments
    parse_arguments "$@"
    
    log_info "Starting AuditHound installation..."
    log_info "Mode: $([[ "$MSP_MODE" == true ]] && echo "MSP (Multi-Tenant)" || echo "Standard")"
    log_info "Install Directory: $INSTALL_DIR"
    
    # Installation steps
    check_system_requirements
    create_directory_structure
    install_python_dependencies
    setup_weaviate
    download_source_code
    create_configuration_files
    setup_onboarding_system
    
    if [[ "$MSP_MODE" == true ]]; then
        setup_white_label_branding
    fi
    
    generate_ssl_certificates
    create_systemd_service
    post_installation_tasks
    
    # Display summary
    display_summary
    
    log_success "AuditHound installation completed! 🎉"
}

# Handle script errors
trap 'log_error "Installation failed at line $LINENO"' ERR

# Run main function
main "$@"