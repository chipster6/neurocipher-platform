# 🏢 AuditHound Multi-Tenant & Self-Onboarding Guide

**Complete multi-tenant separation + 1-line installation for AuditHound Unified Security Platform**

---

## 🆕 New Features Added

### ✅ **Multi-Tenant Client Separation**

#### **Client ID Integration**
- **All Data Models**: Added `client_id` field to `SecurityAsset`, `UnifiedFinding`, and `ScanResult`
- **Organizational Metadata**: Department, cost center, owner tracking
- **Tenant Context**: Organization-specific filtering and isolation

#### **Service Tier Management**
- **Starter**: 25 assets, 10 scans/month
- **Professional**: 100 assets, 50 scans/month  
- **Enterprise**: 500 assets, 200 scans/month
- **MSP**: 10,000 assets, 1,000 scans/month (multi-organization management)

#### **UI Filtering & Isolation**
- **Asset Filtering**: By client, department, cost center
- **Finding Isolation**: Tenant-specific compliance and threat findings
- **Scan Separation**: Client-isolated scan results and history
- **Usage Tracking**: Per-tenant resource consumption monitoring

### ✅ **Self-Onboarding Installation**

#### **1-Line Installation Options**

```bash
# Method 1: Quick Install (fastest)
curl -sSL https://get.audithound.com/quick.sh | bash

# Method 2: Full Interactive Install  
curl -sSL https://get.audithound.com/install.sh | bash

# Method 3: Web-based GUI Installer
python web_installer.py
```

#### **Automated Provisioning**
- **Environment Setup**: Python virtual environment, dependencies
- **Configuration Generation**: YAML config with organization settings
- **Startup Scripts**: Platform-specific start/stop/update scripts
- **Docker Services**: Optional Weaviate, Kafka, PostgreSQL containers

---

## 🏗️ Multi-Tenant Architecture

### Data Model Structure

```python
@dataclass
class SecurityAsset:
    asset_id: str
    client_id: str  # 🆕 Multi-tenant identifier
    name: str
    asset_type: AssetType
    
    # Multi-tenant organization metadata
    organization_name: Optional[str] = None
    department: Optional[str] = None  
    owner: Optional[str] = None
    cost_center: Optional[str] = None

@dataclass  
class UnifiedFinding:
    finding_id: str
    client_id: str  # 🆕 Multi-tenant identifier
    title: str
    
    # Multi-tenant context
    organization_name: Optional[str] = None
    tenant_context: Dict[str, Any] = field(default_factory=dict)
```

### Tenant Management

```python
from multi_tenant_manager import MultiTenantManager, TenantTier

# Create tenant manager
manager = MultiTenantManager()

# Create new tenant
client_id = manager.create_tenant(
    organization_name="Acme Corp",
    email="admin@acme.com", 
    tier=TenantTier.ENTERPRISE
)

# Filter data by tenant
tenant_assets = manager.filter_assets_by_tenant(all_assets, client_id)
tenant_findings = manager.filter_findings_by_tenant(all_findings, client_id)
```

---

## 🚀 Installation Methods

### Method 1: Quick Install (Recommended)

**Single command installation:**

```bash
curl -sSL https://get.audithound.com/quick.sh | bash
```

**What it does:**
- ✅ Checks Python 3.8+ requirement
- ✅ Creates `~/audithound` installation directory
- ✅ Sets up Python virtual environment
- ✅ Installs core dependencies
- ✅ Creates minimal configuration
- ✅ Generates startup scripts
- ✅ Offers immediate startup

### Method 2: Interactive Installation

**Full configuration installation:**

```bash
curl -sSL https://get.audithound.com/install.sh | bash
```

**Interactive setup includes:**
- 🏢 Organization information
- 🎯 Service tier selection
- ☁️ Cloud provider integration
- 🔗 SOC platform connections
- 💬 Chat notification setup
- 🐳 Docker services (optional)

### Method 3: Web-Based Installer

**GUI installation experience:**

```bash
# Download and start web installer
curl -sSL https://get.audithound.com/web_installer.py | python3 -
```

**Features:**
- 🌐 Web-based configuration form
- ✅ Real-time prerequisite checking  
- 📊 Progress tracking
- 🔧 Advanced configuration options
- 📝 Setup validation

---

## 🏢 Multi-Tenant API Endpoints

### Tenant Management

#### Get Tenant Profile
```bash
GET /api/tenant/profile
X-Client-ID: client_abc123

Response:
{
  "client_id": "client_abc123",
  "organization_name": "Acme Corp",
  "tier": "enterprise", 
  "status": "active",
  "enabled_features": ["compliance_auditing", "threat_hunting", "misp_integration"],
  "usage_limits": {
    "max_assets": 500,
    "max_scans_per_month": 200,
    "current_usage": {"assets": 45, "scans": 12}
  }
}
```

#### Get Usage Summary
```bash
GET /api/tenant/usage
X-Client-ID: client_abc123

Response:
{
  "current_month": "2024-12",
  "usage": {
    "assets": {"current": 45, "limit": 500, "percentage": 9.0},
    "scans": {"current": 12, "limit": 200, "percentage": 6.0}
  },
  "trial_info": {
    "is_trial": false,
    "expires": null
  }
}
```

### MSP Multi-Organization Management

#### List Managed Organizations
```bash
GET /api/tenant/organizations
X-Client-ID: msp_client_id

Response:
{
  "total_organizations": 25,
  "organizations": [
    {
      "client_id": "client_customer1",
      "organization_name": "Customer Corp",
      "status": "active",
      "tier": "professional",
      "asset_count": 85,
      "compliance_score": 92.5
    }
  ]
}
```

#### Switch Tenant Context (MSP)
```bash
POST /api/tenant/switch
X-Client-ID: msp_client_id

{
  "target_client_id": "client_customer1"
}

Response:
{
  "success": true,
  "new_context": {
    "client_id": "client_customer1",
    "organization_name": "Customer Corp"
  }
}
```

### Filtered Data Endpoints

All existing endpoints now support multi-tenant filtering:

```bash
# Assets filtered by tenant
GET /api/assets?department=IT&cost_center=CC001
X-Client-ID: client_abc123

# Findings filtered by tenant  
GET /api/findings?type=compliance&severity=critical
X-Client-ID: client_abc123

# Scans filtered by tenant
GET /api/unified-scan/scan_123
X-Client-ID: client_abc123
```

---

## 🔧 Configuration & Setup

### Post-Installation Configuration

**1. Navigate to installation:**
```bash
cd ~/audithound
```

**2. Configure credentials:**
```bash
cp .env.template .env
nano .env  # Add your cloud provider credentials
```

**3. Start AuditHound:**
```bash
./start.sh
```

**4. Access dashboard:**
```
http://localhost:5001
```

### Multi-Tenant Configuration

**Create additional tenants:**
```python
from src.multi_tenant_manager import get_tenant_manager

manager = get_tenant_manager()

# Create enterprise customer
enterprise_client = manager.create_tenant(
    "Enterprise Customer", 
    "admin@enterprise.com", 
    TenantTier.ENTERPRISE
)

# Create MSP tenant
msp_client = manager.create_tenant(
    "MSP Provider",
    "ops@msp.com", 
    TenantTier.MSP
)
```

### Environment Variables

```bash
# Core Platform
AUDITHOUND_CLIENT_ID=default              # Default tenant ID
AUDITHOUND_ORG_NAME="Demo Organization"    # Organization name

# Cloud Providers
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
GCP_PROJECT_ID=your-gcp-project
AZURE_TENANT_ID=your-azure-tenant

# SOC Integrations  
MISP_URL=https://misp.yourdomain.com
MISP_API_KEY=your-misp-key
THEHIVE_URL=https://thehive.yourdomain.com
THEHIVE_API_KEY=your-thehive-key

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/your-webhook

# Multi-Tenant Features
ENABLE_MULTI_TENANT=true
DEFAULT_TENANT_TIER=starter
MSP_MODE=false
```

---

## 📊 Usage & Administration

### Tenant Administration

**View all tenants:**
```bash
curl http://localhost:5001/api/admin/tenants
```

**Create new tenant (MSP):**
```bash
curl -X POST http://localhost:5001/api/tenant/create \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: msp_client_id" \
  -d '{
    "organization_name": "New Customer",
    "email": "admin@newcustomer.com",
    "tier": "professional"
  }'
```

**Update tenant tier:**
```python
manager.update_tenant_tier(client_id, TenantTier.ENTERPRISE)
```

### Usage Monitoring

**Track resource usage:**
```python
tenant = manager.get_tenant(client_id)
tenant.update_usage('assets', 5)      # Add 5 assets
tenant.update_usage('scans', 1)       # Add 1 scan

usage_summary = manager.get_tenant_usage_summary(client_id)
```

**Export tenant data:**
```python
export_data = manager.export_tenant_data(client_id, include_findings=True)
```

---

## 🧪 Testing Multi-Tenant Features

### Test Tenant Separation

```bash
# Test multi-tenant filtering
python test_unified_workflow.py --test-multitenant

# Test MSP functionality  
python test_unified_workflow.py --test-msp

# Test usage limits
python test_unified_workflow.py --test-limits
```

### Manual Testing

```python
# Create test tenants
from src.multi_tenant_manager import get_tenant_manager, TenantTier

manager = get_tenant_manager()
client1 = manager.create_tenant("Test Org 1", "test1@example.com", TenantTier.PROFESSIONAL)
client2 = manager.create_tenant("Test Org 2", "test2@example.com", TenantTier.ENTERPRISE)

# Create assets for different tenants
from src.unified_models import SecurityAsset, AssetType, RiskLevel

asset1 = SecurityAsset(
    asset_id="test-asset-1",
    name="Tenant 1 Server", 
    asset_type=AssetType.SERVER,
    client_id=client1
)

asset2 = SecurityAsset(
    asset_id="test-asset-2",
    name="Tenant 2 Server",
    asset_type=AssetType.SERVER, 
    client_id=client2
)

# Test filtering
tenant1_assets = manager.filter_assets_by_tenant([asset1, asset2], client1)
assert len(tenant1_assets) == 1
assert tenant1_assets[0].client_id == client1
```

---

## 🚀 Production Deployment

### Docker Deployment

**Multi-tenant with Docker:**
```yaml
# docker-compose-multitenant.yml
version: '3.8'

services:
  audithound:
    build: .
    ports:
      - "5001:5001"
    environment:
      - ENABLE_MULTI_TENANT=true
      - MSP_MODE=true
    volumes:
      - ./config:/app/config
      - tenant_data:/app/data

  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: audithound_multitenant
      POSTGRES_USER: audithound
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  tenant_data:
  postgres_data:
```

### Kubernetes Deployment

**Multi-tenant K8s setup:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audithound-multitenant
spec:
  replicas: 3
  selector:
    matchLabels:
      app: audithound
  template:
    metadata:
      labels:
        app: audithound
    spec:
      containers:
      - name: audithound
        image: audithound:latest
        env:
        - name: ENABLE_MULTI_TENANT
          value: "true"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: audithound-secrets
              key: database-url
        ports:
        - containerPort: 5001
```

### Environment-Specific Configs

**Development:**
```yaml
# config-dev.yaml
multi_tenant:
  enabled: true
  default_tier: starter
  allow_self_registration: true
  max_tenants: 100
```

**Production:**
```yaml  
# config-prod.yaml
multi_tenant:
  enabled: true
  default_tier: starter
  allow_self_registration: false  # MSP-managed only
  max_tenants: 1000
  require_approval: true
```

---

## 📚 Examples & Use Cases

### MSP Service Provider

```python
# MSP managing multiple customers
msp_client = manager.create_tenant("SecureMSP", "ops@securemsp.com", TenantTier.MSP)

# Add customers
customer1 = manager.create_tenant("Customer Corp", "admin@customer.com", TenantTier.PROFESSIONAL) 
customer2 = manager.create_tenant("StartupXYZ", "cto@startup.com", TenantTier.STARTER)

# MSP dashboard shows all customers
organizations = manager.get_organizations_for_msp(msp_client)
print(f"Managing {len(organizations)} organizations")

# Switch context to customer
session['client_id'] = customer1  # Switch to customer view
```

### Enterprise Departments

```python
# Enterprise with multiple departments
enterprise_client = manager.create_tenant("Acme Corp", "admin@acme.com", TenantTier.ENTERPRISE)

# Create assets for different departments  
it_server = SecurityAsset(
    asset_id="srv-it-001",
    name="IT Department Server",
    client_id=enterprise_client,
    department="IT",
    cost_center="CC-IT-001"
)

finance_db = SecurityAsset(
    asset_id="db-fin-001", 
    name="Finance Database",
    client_id=enterprise_client,
    department="Finance",
    cost_center="CC-FIN-001"
)

# Filter by department
it_assets = manager.filter_assets_by_tenant([it_server, finance_db], enterprise_client, department="IT")
```

### Trial to Paid Conversion

```python
# Trial customer conversion
trial_client = manager.create_tenant("Trial Customer", "trial@example.com", TenantTier.STARTER)

# Monitor usage
trial_tenant = manager.get_tenant(trial_client)
print(f"Trial expires: {trial_tenant.trial_expires}")
print(f"Asset usage: {trial_tenant.monthly_usage.get('assets', 0)}/{trial_tenant.max_assets}")

# Upgrade to paid tier
manager.update_tenant_tier(trial_client, TenantTier.PROFESSIONAL)
print(f"Upgraded to {trial_tenant.tier.value}")
```

---

## 🔒 Security & Compliance

### Data Isolation

- **Client ID Validation**: All API endpoints validate client_id
- **Database Separation**: Logical separation by client_id in all queries
- **Session Management**: Tenant context stored in secure sessions
- **Access Control**: Feature access controlled by tenant tier

### Audit Logging

```python
# All tenant operations are logged
logger.info(f"Tenant {client_id} performed action: {action}")
logger.info(f"Asset access: {client_id} accessed {asset_id}")
logger.info(f"Finding created: {client_id} - {finding_type}")
```

### Compliance Features

- **Data Residency**: Client data isolation for regulatory compliance
- **Export Capabilities**: GDPR-compliant data export
- **Retention Policies**: Configurable data retention per tenant
- **Access Auditing**: Complete audit trail of tenant data access

---

## 📞 Support & Documentation

### Quick Reference

**Start Commands:**
```bash
./start.sh                    # Start normal mode
./start.sh --debug           # Start debug mode  
./start.sh --test            # Run tests
./start.sh --port 8080       # Custom port
```

**Management Commands:**
```bash
./stop.sh                    # Stop AuditHound
./update.sh                  # Update to latest version
./status.sh                  # Check status
```

### Troubleshooting

**Common Issues:**

1. **Permission Denied:**
   ```bash
   chmod +x start.sh stop.sh update.sh
   ```

2. **Module Not Found:**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Port Already in Use:**
   ```bash
   ./start.sh --port 5002
   ```

4. **Multi-tenant Not Working:**
   ```bash
   export ENABLE_MULTI_TENANT=true
   ./start.sh
   ```

---

**🎉 Multi-tenant AuditHound is ready!** Deploy once, serve many organizations with complete data isolation and tier-based feature access.

---

*Last Updated: December 2024*