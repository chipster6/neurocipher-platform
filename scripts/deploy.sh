#!/bin/bash

# AuditHound Simple Deployment Script
# Lightweight single-server deployment with Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default environment variables
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -base64 32)}"
export SECRET_KEY="${SECRET_KEY:-$(openssl rand -base64 64)}"
export GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin123}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker and try again."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker and try again."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

generate_env_file() {
    log_info "Generating environment configuration..."
    
    cat > "$PROJECT_ROOT/.env" <<EOF
# AuditHound Environment Configuration
# Generated on $(date)

# Database
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# Application
SECRET_KEY=$SECRET_KEY
ENVIRONMENT=production

# Monitoring
GRAFANA_PASSWORD=$GRAFANA_PASSWORD

# Optional: Custom domain (uncomment and modify)
# DOMAIN_NAME=audithound.yourdomain.com

# Optional: SSL certificates (set paths if using HTTPS)
# SSL_CERT_PATH=/path/to/cert.pem
# SSL_KEY_PATH=/path/to/key.pem
EOF
    
    log_success "Environment file created at $PROJECT_ROOT/.env"
    log_warning "Database password: $POSTGRES_PASSWORD"
    log_warning "Grafana password: $GRAFANA_PASSWORD"
    log_warning "Please save these credentials securely!"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "$PROJECT_ROOT/logs"
    mkdir -p "$PROJECT_ROOT/data"
    mkdir -p "$PROJECT_ROOT/docker/nginx/ssl"
    
    # Create basic auth file for monitoring (optional)
    if command -v htpasswd &> /dev/null; then
        echo "admin:\$2y\$10\$rQ8Q8fQ8Q8Q8Q8Q8Q8Q8Q8" > "$PROJECT_ROOT/docker/nginx/.htpasswd"
    fi
    
    log_success "Directories created"
}

build_and_start() {
    log_info "Building and starting AuditHound..."
    
    cd "$PROJECT_ROOT"
    
    # Build the application
    log_info "Building Docker images..."
    docker-compose build
    
    # Start services
    log_info "Starting services..."
    docker-compose up -d
    
    log_success "AuditHound is starting up..."
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for database
    log_info "Waiting for database..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U audithound; do sleep 2; done'
    
    # Wait for application
    log_info "Waiting for application..."
    timeout 120 bash -c 'until curl -f http://localhost:8501/_stcore/health &> /dev/null; do sleep 5; done'
    
    log_success "All services are ready!"
}

show_status() {
    log_info "Service Status:"
    echo "==============="
    docker-compose ps
    
    echo ""
    log_info "Application URLs:"
    echo "=================="
    echo "🌐 Dashboard: http://localhost"
    echo "🔧 API: http://localhost/api"
    echo "📊 Grafana: http://localhost/grafana (admin/$GRAFANA_PASSWORD)"
    echo "📈 Prometheus: http://localhost/prometheus"
    
    echo ""
    log_info "Database Connection:"
    echo "==================="
    echo "Host: localhost"
    echo "Port: 5432"
    echo "Database: audithound"
    echo "Username: audithound"
    echo "Password: $POSTGRES_PASSWORD"
    
    echo ""
    log_success "AuditHound is running successfully!"
    log_info "Default login: admin@audithound.local / admin123"
}

stop_services() {
    log_info "Stopping AuditHound services..."
    cd "$PROJECT_ROOT"
    docker-compose down
    log_success "Services stopped"
}

backup_data() {
    log_info "Creating backup..."
    
    local backup_dir="$PROJECT_ROOT/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup database
    docker-compose exec -T postgres pg_dump -U audithound audithound | gzip > "$backup_dir/database.sql.gz"
    
    # Backup volumes
    docker run --rm -v audithound_postgres_data:/data -v "$backup_dir:/backup" alpine tar czf /backup/postgres_data.tar.gz -C /data .
    docker run --rm -v audithound_weaviate_data:/data -v "$backup_dir:/backup" alpine tar czf /backup/weaviate_data.tar.gz -C /data .
    
    log_success "Backup created at $backup_dir"
}

restore_data() {
    local backup_dir="$1"
    
    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup directory $backup_dir does not exist"
        exit 1
    fi
    
    log_info "Restoring from backup: $backup_dir"
    
    # Stop services
    docker-compose down
    
    # Restore database
    if [[ -f "$backup_dir/database.sql.gz" ]]; then
        docker-compose up -d postgres
        sleep 10
        zcat "$backup_dir/database.sql.gz" | docker-compose exec -T postgres psql -U audithound audithound
    fi
    
    # Restore volumes
    if [[ -f "$backup_dir/postgres_data.tar.gz" ]]; then
        docker run --rm -v audithound_postgres_data:/data -v "$backup_dir:/backup" alpine tar xzf /backup/postgres_data.tar.gz -C /data
    fi
    
    if [[ -f "$backup_dir/weaviate_data.tar.gz" ]]; then
        docker run --rm -v audithound_weaviate_data:/data -v "$backup_dir:/backup" alpine tar xzf /backup/weaviate_data.tar.gz -C /data
    fi
    
    log_success "Restore completed"
}

show_logs() {
    local service="${1:-}"
    
    cd "$PROJECT_ROOT"
    
    if [[ -n "$service" ]]; then
        docker-compose logs -f "$service"
    else
        docker-compose logs -f
    fi
}

show_help() {
    cat << EOF
AuditHound Deployment Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    deploy          Deploy AuditHound (default)
    start           Start existing deployment
    stop            Stop all services
    restart         Restart all services
    status          Show service status
    logs [service]  Show logs (optionally for specific service)
    backup          Create a backup
    restore <dir>   Restore from backup directory
    update          Pull latest images and restart
    clean           Remove all containers and volumes (destructive!)

EXAMPLES:
    # Initial deployment
    $0 deploy

    # Check status
    $0 status

    # View logs
    $0 logs
    $0 logs audithound-app

    # Backup and restore
    $0 backup
    $0 restore ./backups/20231201_120000

    # Update to latest version
    $0 update

ENVIRONMENT VARIABLES:
    POSTGRES_PASSWORD   Database password (auto-generated if not set)
    SECRET_KEY          Application secret key (auto-generated if not set)
    GRAFANA_PASSWORD    Grafana admin password (default: admin123)
    DOMAIN_NAME         Custom domain name (optional)
EOF
}

main() {
    local command="${1:-deploy}"
    
    case "$command" in
        deploy)
            check_prerequisites
            generate_env_file
            create_directories
            build_and_start
            wait_for_services
            show_status
            ;;
        start)
            cd "$PROJECT_ROOT"
            docker-compose up -d
            wait_for_services
            show_status
            ;;
        stop)
            stop_services
            ;;
        restart)
            cd "$PROJECT_ROOT"
            docker-compose restart
            wait_for_services
            show_status
            ;;
        status)
            cd "$PROJECT_ROOT"
            show_status
            ;;
        logs)
            show_logs "$2"
            ;;
        backup)
            backup_data
            ;;
        restore)
            restore_data "$2"
            ;;
        update)
            cd "$PROJECT_ROOT"
            docker-compose pull
            docker-compose up -d
            wait_for_services
            show_status
            ;;
        clean)
            log_warning "This will remove all data! Are you sure? (y/N)"
            read -r confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                cd "$PROJECT_ROOT"
                docker-compose down -v
                docker system prune -f
                log_success "Cleanup completed"
            else
                log_info "Cleanup cancelled"
            fi
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Check if .env file exists and source it
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

main "$@"