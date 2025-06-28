# 🚀 AuditHound Simple Deployment

**Lightweight, single-server security audit platform** - perfect for getting started quickly and cost-effectively.

## 🎯 **What You Get**

- **Complete security audit platform** in one Docker Compose file
- **Multi-tenant support** for managing multiple clients
- **Built-in monitoring** with Prometheus and Grafana
- **PostgreSQL database** with automatic initialization
- **Redis caching** for performance
- **Weaviate vector database** for AI-powered insights
- **NGINX reverse proxy** with load balancing

## 💰 **Cost-Effective Hosting Options**

### **Option 1: VPS Hosting (~$20-50/month)**
```bash
# Recommended specs:
- 4 vCPU, 8GB RAM, 80GB SSD
- Providers: DigitalOcean, Linode, Vultr
- Cost: $20-40/month
```

### **Option 2: Dedicated Server (~$50-100/month)**
```bash
# For higher performance:
- 8 vCPU, 16GB RAM, 500GB SSD
- Providers: Hetzner, OVH
- Cost: $50-80/month
```

### **Option 3: Self-Hosted (~$0/month)**
```bash
# Your own hardware:
- Any modern server or powerful desktop
- 8GB+ RAM recommended
- Docker and Docker Compose
```

## ⚡ **Quick Start (5 minutes)**

### **1. Clone and Deploy**
```bash
git clone https://github.com/chipster6/audithound.git
cd audithound
./scripts/deploy.sh
```

### **2. Access Your Platform**
```bash
🌐 Dashboard: http://localhost
🔧 API: http://localhost/api  
📊 Monitoring: http://localhost/grafana
```

### **3. Default Login**
```bash
Email: admin@audithound.local
Password: admin123
```

## 🔧 **Management Commands**

```bash
# Check status
./scripts/deploy.sh status

# View logs
./scripts/deploy.sh logs

# Backup data
./scripts/deploy.sh backup

# Update to latest version
./scripts/deploy.sh update

# Stop services
./scripts/deploy.sh stop

# Restart services  
./scripts/deploy.sh restart
```

## 📊 **What's Included**

### **Core Services**
- **AuditHound App**: Main application with Streamlit dashboard
- **PostgreSQL**: Primary database for audit data
- **Redis**: Caching and task queues
- **Weaviate**: Vector database for AI features
- **NGINX**: Reverse proxy and load balancer

### **Monitoring Stack**
- **Prometheus**: Metrics collection
- **Grafana**: Dashboards and visualization
- **Built-in health checks** and alerting

### **Security Features**
- **Multi-tenant isolation** 
- **Role-based access control**
- **Encrypted data storage**
- **Audit logging**
- **Rate limiting**

## 🏗️ **Architecture**

```
┌─────────────────────────────────────────────┐
│                 NGINX                       │
│          (Reverse Proxy)                    │
└─────────────┬───────────────────────────────┘
              │
    ┌─────────▼──────────┐
    │   AuditHound App   │
    │   (Streamlit +     │
    │    FastAPI)        │
    └─────────┬──────────┘
              │
   ┌──────────▼───────────┐
   │    PostgreSQL        │
   │   (Primary DB)       │
   └──────────────────────┘
              │
   ┌──────────▼───────────┐
   │       Redis          │
   │   (Cache/Queue)      │
   └──────────────────────┘
              │
   ┌──────────▼───────────┐
   │     Weaviate         │
   │   (Vector DB)        │
   └──────────────────────┘
```

## 💼 **Business Model Ready**

### **MSP Pricing Example**
```yaml
Your costs: $30/month (VPS hosting)
Charge clients: $99/month per tenant
Profit per client: $69/month
Break-even: 1 client
10 clients = $690/month profit
```

### **Multi-Tenant Management**
- **Isolated data** per client
- **Custom branding** per tenant
- **Usage analytics** and reporting
- **Automated billing** integration ready

## 🔒 **Security & Compliance**

### **Built-in Frameworks**
- ✅ SOC 2 controls and monitoring
- ✅ ISO 27001 compliance mapping
- ✅ NIST Cybersecurity Framework
- ✅ Custom compliance frameworks

### **Security Features**
- 🔐 Encrypted data at rest and in transit
- 🛡️ Role-based access control (RBAC)
- 📝 Comprehensive audit logging
- 🚫 Rate limiting and DDoS protection
- 🔑 Secure credential management

## 📈 **Scaling Options**

### **Vertical Scaling (Same Server)**
```bash
# Upgrade server resources:
- More CPU/RAM for better performance
- Larger SSD for more data storage
- Can handle 50+ tenants easily
```

### **Horizontal Scaling (Future)**
```bash
# When ready for enterprise:
- Add load balancer
- Database read replicas  
- Redis cluster
- Multiple app instances
```

## 🛠️ **Customization**

### **Environment Variables**
```bash
# Edit .env file:
POSTGRES_PASSWORD=your-secure-password
SECRET_KEY=your-secret-key
GRAFANA_PASSWORD=your-grafana-password
DOMAIN_NAME=audithound.yourdomain.com
```

### **Custom Domain & SSL**
```bash
# Update docker/nginx/nginx.conf
# Add SSL certificates to docker/nginx/ssl/
# Uncomment HTTPS server block
```

### **Resource Limits**
```bash
# Modify docker-compose.yml:
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G
```

## 🆘 **Troubleshooting**

### **Common Issues**

**Services won't start:**
```bash
# Check logs
./scripts/deploy.sh logs

# Check Docker
docker ps
docker-compose ps
```

**Database connection issues:**
```bash
# Reset database
docker-compose down
docker volume rm audithound_postgres_data
./scripts/deploy.sh deploy
```

**Performance issues:**
```bash
# Check resource usage
docker stats

# Increase server resources or
# Optimize configuration
```

### **Support Commands**
```bash
# View all containers
docker ps -a

# Check disk usage
df -h

# Check memory usage
free -h

# View Docker logs
docker-compose logs -f [service-name]
```

## 🎉 **Success! You're Ready to Go**

Your AuditHound platform is now running and ready to:

1. **Onboard your first client** in minutes
2. **Start security audits** immediately  
3. **Generate compliance reports** automatically
4. **Scale to multiple tenants** as you grow

**Next Steps:**
- Set up your custom domain
- Configure SSL certificates
- Onboard your first client
- Customize compliance frameworks
- Set up automated backups

---

**Need help?** Check our documentation or open an issue on GitHub.

**Ready to scale?** The enterprise Kubernetes deployment is available when you're ready for it!