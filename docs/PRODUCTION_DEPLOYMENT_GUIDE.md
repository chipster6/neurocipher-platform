# AuditHound Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying AuditHound in a production environment with high availability, security, and performance optimizations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Security Setup](#security-setup)
4. [Environment Configuration](#environment-configuration)
5. [Database Setup](#database-setup)
6. [SSL/TLS Configuration](#ssltls-configuration)
7. [Production Deployment](#production-deployment)
8. [Monitoring and Alerting](#monitoring-and-alerting)
9. [Backup and Recovery](#backup-and-recovery)
10. [Performance Tuning](#performance-tuning)
11. [Troubleshooting](#troubleshooting)

## Prerequisites

### Software Requirements
- Docker Engine 20.10+ with Docker Compose 2.0+
- Linux server (Ubuntu 20.04+ or CentOS 8+ recommended)
- Minimum 16GB RAM, 8 CPU cores, 500GB SSD storage
- Network connectivity for external API integrations

### Access Requirements
- Root or sudo access to the deployment server
- Domain name with DNS management access
- SSL certificate (Let's Encrypt or commercial)
- Cloud provider API credentials (AWS, Azure, GCP)

## Infrastructure Requirements

### Minimum Production Setup
```
┌─────────────────────┐
│   Load Balancer     │ (Nginx)
│   (SSL Termination) │
└─────────┬───────────┘
          │
┌─────────▼───────────┐
│   Application Tier   │
│ ┌─────┐ ┌─────────┐ │
│ │ API │ │Dashboard│ │
│ └─────┘ └─────────┘ │
│ ┌─────┐ ┌─────────┐ │
│ │Work │ │Scheduler│ │
│ └─────┘ └─────────┘ │
└─────────┬───────────┘
          │
┌─────────▼───────────┐
│    Data Tier        │
│ ┌─────┐ ┌───────┐   │
│ │Postg│ │ Redis │   │
│ │ SQL │ │       │   │
│ └─────┘ └───────┘   │
│ ┌─────────────────┐ │
│ │   Weaviate      │ │
│ │ (Vector Store)  │ │
│ └─────────────────┘ │
└─────────────────────┘
```

### High Availability Setup
```
┌─────────────────────┐
│   External LB       │ (AWS ALB/Azure LB)
│                     │
└─────────┬───────────┘
          │
     ┌────▼────┐
     │ Region A │
     └────┬────┘
┌─────────▼───────────┐
│   AZ-1    │   AZ-2  │
│ ┌───────┐ │ ┌─────┐ │
│ │API×3  │ │ │API×3│ │
│ │Dash×2 │ │ │Dash×2│ │
│ └───────┘ │ └─────┘ │
└───────────┴─────────┘
┌─────────────────────┐
│     Data Layer      │
│ ┌─────────────────┐ │
│ │PostgreSQL HA    │ │
│ │(Primary/Replica)│ │
│ └─────────────────┘ │
│ ┌─────────────────┐ │
│ │Redis Cluster    │ │
│ │(3 masters,      │ │
│ │ 3 replicas)     │ │
│ └─────────────────┘ │
└─────────────────────┘
```

## Security Setup

### 1. System Security

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install security tools
sudo apt install -y fail2ban ufw unattended-upgrades

# Configure firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Configure fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 2. Docker Security

```bash
# Create docker group and add user
sudo groupadd docker
sudo usermod -aG docker $USER

# Configure Docker daemon security
sudo mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "experimental": false,
  "icc": false,
  "default-address-pools": [
    {
      "base": "172.80.0.0/12",
      "size": 24
    }
  ]
}
EOF

sudo systemctl restart docker
```

### 3. File System Security

```bash
# Create secure directory structure
sudo mkdir -p /opt/audithound/{data,logs,config,ssl}
sudo chown -R 1000:1000 /opt/audithound
sudo chmod -R 750 /opt/audithound

# Set up log rotation
cat <<EOF | sudo tee /etc/logrotate.d/audithound
/opt/audithound/logs/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        docker-compose -f /opt/audithound/docker-compose.production.yml exec nginx nginx -s reload
    endscript
}
EOF
```

## Environment Configuration

### 1. Environment Variables

Create `/opt/audithound/.env`:

```bash
# Application Configuration
VERSION=latest
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# Security Keys (Generate secure random keys)
SECRET_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 32)
GRAFANA_SECRET_KEY=$(openssl rand -base64 32)

# Database Configuration
DB_NAME=audithound_prod
DB_USER=audithound
DB_PASSWORD=$(openssl rand -base64 24)

# Redis Configuration
REDIS_PASSWORD=$(openssl rand -base64 24)

# External Services
OPENAI_API_KEY=your_openai_api_key
SENTRY_DSN=your_sentry_dsn

# Cloud Provider Credentials
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id
GCP_SERVICE_ACCOUNT_KEY=path_to_gcp_key.json

# Monitoring
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16)
ELASTIC_PASSWORD=$(openssl rand -base64 16)

# Weaviate Configuration
WEAVIATE_API_KEY=$(openssl rand -base64 24)
WEAVIATE_USERS=admin:$(openssl rand -base64 16)
WEAVIATE_ADMIN_USERS=admin

# Network Configuration
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### 2. Secure Environment File

```bash
# Set proper permissions
sudo chown root:docker /opt/audithound/.env
sudo chmod 640 /opt/audithound/.env

# Create backup
sudo cp /opt/audithound/.env /opt/audithound/.env.backup
```

## Database Setup

### 1. PostgreSQL Production Configuration

Create `/opt/audithound/config/postgresql.conf`:

```ini
# Connection Settings
listen_addresses = '*'
port = 5432
max_connections = 200
superuser_reserved_connections = 3

# Memory Settings
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0

# Write-Ahead Logging
wal_level = replica
max_wal_senders = 3
checkpoint_timeout = 5min
max_wal_size = 1GB
min_wal_size = 80MB

# Security
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
```

### 2. Database Initialization

```bash
# Initialize database
docker-compose -f docker-compose.production.yml up -d postgres
sleep 30

# Run migrations
docker-compose -f docker-compose.production.yml exec api python -m alembic upgrade head

# Create database indexes
docker-compose -f docker-compose.production.yml exec api python -c "
from src.optimization.query_optimizer import query_optimizer
from src.persistence.unified_db_manager import UnifiedDatabaseManager
db = UnifiedDatabaseManager()
with db.get_session() as session:
    query_optimizer.create_optimized_indexes(session)
"
```

## SSL/TLS Configuration

### 1. Let's Encrypt Setup

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot certonly --webroot \
  -w /var/www/certbot \
  -d yourdomain.com \
  -d www.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos \
  --non-interactive

# Copy certificates to Docker volume
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/audithound/ssl/audithound.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/audithound/ssl/audithound.key
sudo cp /etc/ssl/certs/ca-certificates.crt /opt/audithound/ssl/ca-bundle.crt

# Set permissions
sudo chown root:docker /opt/audithound/ssl/*
sudo chmod 640 /opt/audithound/ssl/*
```

### 2. Certificate Auto-Renewal

```bash
# Create renewal script
cat <<EOF | sudo tee /opt/audithound/scripts/renew-ssl.sh
#!/bin/bash
certbot renew --quiet
if [ $? -eq 0 ]; then
    cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/audithound/ssl/audithound.crt
    cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/audithound/ssl/audithound.key
    docker-compose -f /opt/audithound/docker-compose.production.yml exec nginx nginx -s reload
fi
EOF

sudo chmod +x /opt/audithound/scripts/renew-ssl.sh

# Add to crontab
echo "0 2 * * 0 /opt/audithound/scripts/renew-ssl.sh" | sudo crontab -
```

## Production Deployment

### 1. Deploy Application Stack

```bash
# Navigate to deployment directory
cd /opt/audithound

# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Start services
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
docker-compose -f docker-compose.production.yml ps
docker-compose -f docker-compose.production.yml logs -f
```

### 2. Health Checks

```bash
#!/bin/bash
# health-check.sh

echo "=== AuditHound Health Check ==="

# Check service status
echo "Checking service status..."
docker-compose -f docker-compose.production.yml ps

# Check API health
echo "Checking API health..."
curl -f https://yourdomain.com/api/health || echo "API health check failed"

# Check database connectivity
echo "Checking database..."
docker-compose -f docker-compose.production.yml exec postgres pg_isready -U audithound

# Check Redis connectivity
echo "Checking Redis..."
docker-compose -f docker-compose.production.yml exec redis redis-cli ping

# Check SSL certificate
echo "Checking SSL certificate..."
echo | openssl s_client -servername yourdomain.com -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates

echo "=== Health Check Complete ==="
```

### 3. Load Testing

```bash
# Install Apache Benchmark
sudo apt install -y apache2-utils

# Basic load test
ab -n 1000 -c 10 https://yourdomain.com/api/health

# Stress test authentication
ab -n 100 -c 5 -p login-data.json -T application/json https://yourdomain.com/api/v1/auth/login
```

## Monitoring and Alerting

### 1. Monitoring Stack Setup

The production deployment includes:
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Elasticsearch + Kibana**: Log aggregation and analysis
- **Alertmanager**: Alert routing and notifications

### 2. Custom Dashboards

Access Grafana at `https://yourdomain.com/grafana/` with admin credentials from environment variables.

Key dashboards include:
- Application Performance Monitoring
- Infrastructure Metrics
- Business Metrics (Compliance Scores)
- Security Monitoring

### 3. Alert Configuration

Configure alert notifications in `/opt/audithound/config/alertmanager.yml`:

```yaml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@yourdomain.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  email_configs:
  - to: 'admin@yourdomain.com'
    subject: 'AuditHound Alert: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#audithound-alerts'
    title: 'AuditHound Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

## Backup and Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/opt/audithound/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="audithound_prod"

mkdir -p $BACKUP_DIR

# Create database backup
docker-compose -f docker-compose.production.yml exec postgres pg_dump -U audithound $DB_NAME | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "db_backup_*.sql.gz" -type f -mtime +30 -delete

# Upload to cloud storage (optional)
# aws s3 cp $BACKUP_DIR/db_backup_$DATE.sql.gz s3://your-backup-bucket/database/
```

### 2. Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/opt/audithound/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration files
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz \
  /opt/audithound/.env \
  /opt/audithound/docker-compose.production.yml \
  /opt/audithound/config/ \
  /opt/audithound/ssl/

# Clean old backups
find $BACKUP_DIR -name "config_backup_*.tar.gz" -type f -mtime +7 -delete
```

### 3. Automated Backup Schedule

```bash
# Add to crontab
0 2 * * * /opt/audithound/scripts/backup-database.sh
0 3 * * 0 /opt/audithound/scripts/backup-config.sh
```

## Performance Tuning

### 1. Application Tuning

```yaml
# docker-compose.production.yml - Resource limits
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 2G
    reservations:
      cpus: '0.5'
      memory: 512M
```

### 2. Database Tuning

```bash
# Analyze database performance
docker-compose -f docker-compose.production.yml exec postgres psql -U audithound -c "
SELECT query, calls, total_time, mean_time, rows 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
"

# Monitor connection usage
docker-compose -f docker-compose.production.yml exec postgres psql -U audithound -c "
SELECT state, count(*) 
FROM pg_stat_activity 
GROUP BY state;
"
```

### 3. Cache Optimization

```python
# Monitor cache performance
from src.optimization.caching_strategy import get_cache_manager

cache_manager = get_cache_manager()
if cache_manager:
    stats = cache_manager.get_performance_stats()
    print(f"Cache hit ratio: {stats['l1_cache']['hit_ratio']:.2%}")
    print(f"Memory usage: {stats['l1_cache']['memory_usage_mb']:.1f}MB")
```

## Troubleshooting

### 1. Common Issues

**Service Won't Start**
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs service_name

# Check resource usage
docker stats

# Check disk space
df -h
```

**Database Connection Issues**
```bash
# Test database connectivity
docker-compose -f docker-compose.production.yml exec postgres pg_isready

# Check connection settings
docker-compose -f docker-compose.production.yml exec api env | grep DATABASE
```

**SSL Certificate Issues**
```bash
# Check certificate validity
openssl x509 -in /opt/audithound/ssl/audithound.crt -text -noout

# Test SSL configuration
curl -I https://yourdomain.com
```

### 2. Performance Issues

**High Memory Usage**
```bash
# Check container memory usage
docker stats --no-stream

# Analyze application memory
docker-compose -f docker-compose.production.yml exec api python -c "
import psutil
print(f'Memory usage: {psutil.virtual_memory().percent}%')
"
```

**Slow Database Queries**
```bash
# Enable query logging
echo "log_min_duration_statement = 100" >> /opt/audithound/config/postgresql.conf

# Restart database
docker-compose -f docker-compose.production.yml restart postgres
```

### 3. Security Issues

**Failed Login Attempts**
```bash
# Check authentication logs
docker-compose -f docker-compose.production.yml logs api | grep "authentication"

# Review fail2ban status
sudo fail2ban-client status
```

**SSL/TLS Issues**
```bash
# Test SSL configuration
nmap --script ssl-enum-ciphers -p 443 yourdomain.com

# Check certificate chain
curl -I https://yourdomain.com 2>&1 | grep -i certificate
```

## Maintenance Procedures

### 1. Regular Maintenance

**Weekly Tasks:**
- Review application logs
- Check disk space usage
- Verify backup integrity
- Update security patches

**Monthly Tasks:**
- Review performance metrics
- Update dependencies
- Rotate secrets and keys
- Conduct security audit

### 2. Update Procedures

```bash
#!/bin/bash
# update-application.sh

# Backup current configuration
./backup-config.sh

# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Update services (rolling update)
for service in api dashboard worker scheduler; do
    echo "Updating $service..."
    docker-compose -f docker-compose.production.yml up -d --no-deps $service
    sleep 30
    
    # Health check
    if ! curl -f https://yourdomain.com/health; then
        echo "Health check failed for $service"
        # Rollback if needed
        exit 1
    fi
done

echo "Update completed successfully"
```

## Conclusion

This production deployment guide provides a comprehensive foundation for running AuditHound in a secure, scalable, and maintainable environment. Regular monitoring, maintenance, and security updates are essential for optimal performance and security.

For additional support or advanced configuration requirements, please refer to the API documentation and contact the support team.