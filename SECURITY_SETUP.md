# AuditHound Security & Secrets Management Setup Guide

## 🔒 Overview

This guide covers the complete setup of AuditHound's security and secrets management system, including:

- Environment variables configuration (12-factor app compliance)
- HashiCorp Vault integration
- AWS Secrets Manager integration
- Automated security scanning with CI/CD
- Migration from hardcoded credentials

## 🚀 Quick Start

### 1. Install Security Dependencies

```bash
# Install security scanning tools
pip install bandit safety semgrep

# Install secrets management dependencies (optional)
pip install hvac boto3 cryptography
```

### 2. Generate Environment Configuration

```bash
# Scan for hardcoded credentials
python3 migrate_to_env_vars.py --scan --report

# Generate .env file
python3 migrate_to_env_vars.py --generate-env

# Review and update the generated .env file
cp .env.template .env
# Edit .env with your actual values
```

### 3. Run Security Scan

```bash
# Comprehensive security scan
python3 src/security/security_scanner.py --scan-type all

# Or use Coral TPU acceleration
python3 coral_terminal_assistant.py scan src/
```

## 📋 Environment Variables

### Required Variables

```bash
# Application Security
SECRET_KEY=your_32_character_secret_key_here
AUDITHOUND_ENCRYPTION_KEY=base64_encoded_32_byte_key

# Database
WEAVIATE_URL=http://localhost:8080
```

### Cloud Provider Credentials

```bash
# AWS
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-west-2

# GCP
GCP_PROJECT_ID=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Azure
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

### Secrets Management

```bash
# HashiCorp Vault
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=your_vault_token

# AWS Secrets Manager
AWS_SECRETS_REGION=us-west-2
```

## 🔐 HashiCorp Vault Setup

### 1. Install and Start Vault

```bash
# Install Vault
brew install vault

# Start Vault dev server
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN="your_dev_token"
```

### 2. Configure Vault for AuditHound

```bash
# Enable KV secrets engine
vault secrets enable -path=audithound kv-v2

# Store secrets
vault kv put audithound/weaviate_api_key value="your_api_key"
vault kv put audithound/aws_secret_access_key value="your_secret_key"
vault kv put audithound/encryption_key value="base64_encoded_key"
```

### 3. Use Vault in AuditHound

```python
from src.security.secrets_manager import SecretsManager, SecretType

# Initialize with Vault backend
config = {
    "primary_store": "vault",
    "vault_url": "http://localhost:8200",
    "vault_token": "your_token"
}

secrets_manager = SecretsManager(config)

# Store a secret
secrets_manager.store_secret(
    "api_key", 
    "your_secret_value", 
    SecretType.API_KEY
)

# Retrieve a secret
api_key = secrets_manager.get_secret("api_key")
```

## ☁️ AWS Secrets Manager Setup

### 1. Configure AWS Credentials

```bash
# Using AWS CLI
aws configure

# Or environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-west-2
```

### 2. Use AWS Secrets Manager

```python
from src.security.secrets_manager import SecretsManager

# Initialize with AWS backend
config = {
    "primary_store": "aws_secrets_manager"
}

secrets_manager = SecretsManager(config)

# Secrets are automatically stored with "audithound/" prefix
secrets_manager.store_secret("database_url", "postgresql://...", SecretType.DATABASE_URL)
```

## 🔧 Configuration Management

### Using the Configuration Manager

```python
from src.security.config_manager import get_config, get_config_value

# Get configuration manager
config = get_config()

# Get specific values
database_url = config.get("database.weaviate_url")
aws_credentials = config.get_aws_config()
debug_mode = config.is_debug_enabled()

# Or use convenience functions
from src.security.config_manager import get_database_url, is_debug_mode

db_url = get_database_url()
debug = is_debug_mode()
```

### Configuration Sources (in order of precedence)

1. **Environment Variables** (highest precedence)
2. **Secrets Manager** (Vault/AWS)
3. **Configuration Files**
4. **Default Values** (lowest precedence)

## 🛡️ Security Scanning

### Local Security Scanning

```bash
# Run all security scans
python3 src/security/security_scanner.py --scan-type all

# Individual scans
python3 src/security/security_scanner.py --scan-type bandit
python3 src/security/security_scanner.py --scan-type safety
python3 src/security/security_scanner.py --scan-type secrets
python3 src/security/security_scanner.py --scan-type config
```

### CI/CD Integration

The security pipeline (`.github/workflows/security.yml`) automatically:

- Runs bandit static analysis
- Checks dependencies with safety
- Scans for secrets with semgrep
- Uploads security reports
- Fails builds with critical issues
- Creates GitHub issues for security problems

### Security Scan Results

Security reports are saved to `security_reports/`:

- `bandit_report.json` - Static analysis results
- `safety_report.json` - Dependency vulnerabilities
- `semgrep_report.json` - Code pattern analysis
- `security_summary.json` - Combined summary

## 🔄 Migration from Hardcoded Values

### 1. Scan for Hardcoded Credentials

```bash
# Scan entire project
python3 migrate_to_env_vars.py --scan --report

# Review migration_report.md
cat migration_report.md
```

### 2. Create Migration Plan

```bash
# Generate migration plan
python3 migrate_to_env_vars.py --plan

# Review migration_plan.json
cat migration_plan.json
```

### 3. Execute Migration

```bash
# Dry run first
python3 migrate_to_env_vars.py --execute --dry-run

# Execute migration
python3 migrate_to_env_vars.py --execute
```

### 4. Verify Migration

```bash
# Test configuration
python3 -c "from src.security.config_manager import get_config; print(get_config().get_config_summary())"

# Run security scan
python3 src/security/security_scanner.py --scan-type secrets
```

## 🐙 Production Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Install security tools
RUN pip install bandit safety

# Copy application
COPY . /app
WORKDIR /app

# Install dependencies
RUN pip install -r requirements.txt

# Set secure defaults
ENV DEBUG=False
ENV LOG_LEVEL=INFO

# Run security scan on build
RUN python3 src/security/security_scanner.py --scan-type all

# Start application
CMD ["streamlit", "run", "streamlit_dashboard.py"]
```

### Environment Variables in Production

```bash
# Production .env (do not commit to git)
SECRET_KEY=$(openssl rand -base64 32)
AUDITHOUND_ENCRYPTION_KEY=$(openssl rand -base64 32)
DEBUG=False
LOG_LEVEL=WARNING

# Use external secrets management
VAULT_ADDR=https://vault.production.com
AWS_SECRETS_REGION=us-west-2
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: audithound-secrets
type: Opaque
data:
  secret-key: <base64-encoded-secret>
  encryption-key: <base64-encoded-key>

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audithound
spec:
  template:
    spec:
      containers:
      - name: audithound
        image: audithound:latest
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: audithound-secrets
              key: secret-key
        - name: AUDITHOUND_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: audithound-secrets
              key: encryption-key
```

## 🔍 Security Monitoring

### Health Checks

```python
from src.security.secrets_manager import SecretsManager

secrets_manager = SecretsManager()
health = secrets_manager.get_secrets_health()

print(f"Total secrets: {health['total_secrets']}")
print(f"Vault available: {health['vault_available']}")
print(f"Secrets requiring rotation: {health['secrets_requiring_rotation']}")
```

### Audit Logging

All secret access is automatically logged to `logs/secrets_audit.log`:

```json
{
  "timestamp": 1640995200,
  "action": "retrieve",
  "secret_name": "api_key",
  "details": {}
}
```

### Security Alerts

The CI/CD pipeline automatically:

- Creates GitHub issues for security problems
- Sends Slack notifications (if configured)
- Blocks deployments with critical issues
- Generates security reports

## 🛠️ Troubleshooting

### Common Issues

1. **Vault Connection Failed**
   ```bash
   # Check Vault status
   vault status
   
   # Verify token
   vault auth -method=token
   ```

2. **AWS Secrets Manager Access Denied**
   ```bash
   # Check AWS credentials
   aws sts get-caller-identity
   
   # Test secrets access
   aws secretsmanager list-secrets
   ```

3. **Environment Variables Not Loading**
   ```python
   # Debug configuration
   from src.security.config_manager import get_config
   config = get_config()
   print(config.validate_environment())
   ```

### Security Scan Failures

```bash
# Check bandit configuration
bandit --help

# Verify safety database
safety --version

# Test custom scanner
python3 src/security/security_scanner.py --scan-type secrets --target .
```

## 📚 Best Practices

### 1. Secret Rotation

- Enable automatic rotation for API keys
- Set rotation intervals (default: 90 days)
- Monitor rotation status in health checks

### 2. Access Control

- Use least-privilege principles
- Implement role-based access for secrets
- Audit secret access regularly

### 3. Security Scanning

- Run security scans on every commit
- Block deployments with critical issues
- Review and fix all high-severity findings

### 4. Environment Management

- Never commit `.env` files to version control
- Use different encryption keys per environment
- Validate configuration on startup

### 5. Monitoring

- Monitor secret access patterns
- Alert on unusual access activity
- Track secret rotation compliance

## 🤖 Coral TPU Integration

AuditHound's security scanning can be accelerated using Google Coral TPU:

```bash
# Initialize Coral assistant
python3 coral_terminal_assistant.py

# Run TPU-accelerated security scan
python3 coral_terminal_assistant.py scan src/

# Monitor live coding for security issues
python3 coral_terminal_assistant.py monitor
```

The Coral TPU provides:
- Faster pattern recognition for secrets detection
- Accelerated ML-based security analysis
- Real-time monitoring during development

---

## 📞 Support

For security issues or questions:

- GitHub Issues: [Security label](https://github.com/your-org/audithound/issues?q=label%3Asecurity)
- Security Email: security@yourdomain.com
- Documentation: [Security Wiki](https://github.com/your-org/audithound/wiki/Security)

**Remember: Never share credentials in public channels or commit them to version control!**