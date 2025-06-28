#!/bin/bash

# AuditHound Private Registry Setup Script
set -e

REGISTRY_HOST=${REGISTRY_HOST:-"registry.audithound.local"}
REGISTRY_PORT=${REGISTRY_PORT:-"5000"}
ADMIN_USER=${ADMIN_USER:-"admin"}
ADMIN_PASS=${ADMIN_PASS:-""}

echo "Setting up AuditHound Private Registry..."

# Create directories
mkdir -p certs auth config

# Generate SSL certificates if they don't exist
if [ ! -f "certs/registry.crt" ]; then
    echo "Generating SSL certificates..."
    
    # Create certificate configuration
    cat > certs/registry.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = AuditHound
CN = ${REGISTRY_HOST}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${REGISTRY_HOST}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

    # Generate private key
    openssl genrsa -out certs/registry.key 4096
    
    # Generate certificate signing request
    openssl req -new -key certs/registry.key -out certs/registry.csr -config certs/registry.conf
    
    # Generate self-signed certificate
    openssl x509 -req -in certs/registry.csr -signkey certs/registry.key -out certs/registry.crt -days 365 -extensions v3_req -extfile certs/registry.conf
    
    # Set permissions
    chmod 600 certs/registry.key
    chmod 644 certs/registry.crt
    
    echo "SSL certificates generated"
fi

# Generate admin password if not provided
if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS=$(openssl rand -base64 32)
    echo "Generated admin password: $ADMIN_PASS"
fi

# Create htpasswd file for authentication
if [ ! -f "auth/htpasswd" ]; then
    echo "Creating authentication file..."
    docker run --rm --entrypoint htpasswd httpd:2 -Bbn "$ADMIN_USER" "$ADMIN_PASS" > auth/htpasswd
    echo "Authentication configured for user: $ADMIN_USER"
fi

# Create registry configuration
cat > config/registry-config.yml <<EOF
version: 0.1
log:
  fields:
    service: registry
  level: info
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
auth:
  htpasswd:
    realm: "AuditHound Registry"
    path: /auth/htpasswd
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
  tls:
    certificate: /certs/registry.crt
    key: /certs/registry.key
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
EOF

# Create docker-compose override for environment-specific settings
cat > docker-compose.override.yml <<EOF
version: '3.8'

services:
  registry:
    environment:
      REGISTRY_LOG_LEVEL: info
      REGISTRY_STORAGE_CACHE_BLOBDESCRIPTOR: inmemory
    labels:
      - "com.audithound.service=registry"
      - "com.audithound.version=1.0.0"

  registry-ui:
    environment:
      REGISTRY_URL: "https://${REGISTRY_HOST}:${REGISTRY_PORT}"
    labels:
      - "com.audithound.service=registry-ui"
      - "com.audithound.version=1.0.0"
EOF

# Create build and push script
cat > build-and-push.sh <<'EOF'
#!/bin/bash

# AuditHound Container Build and Push Script
set -e

REGISTRY_HOST=${REGISTRY_HOST:-"registry.audithound.local:5000"}
VERSION=${VERSION:-"latest"}
COMPONENTS=("api" "dashboard" "worker" "scheduler")

echo "Building and pushing AuditHound components to $REGISTRY_HOST..."

# Build and push each component
for component in "${COMPONENTS[@]}"; do
    echo "Building $component..."
    
    # Build the image
    docker build -t "audithound-$component:$VERSION" \
        -f "docker/components/$component/Dockerfile" .
    
    # Tag for registry
    docker tag "audithound-$component:$VERSION" \
        "$REGISTRY_HOST/audithound/$component:$VERSION"
    
    # Push to registry
    echo "Pushing $component to registry..."
    docker push "$REGISTRY_HOST/audithound/$component:$VERSION"
    
    echo "$component pushed successfully"
done

echo "All components built and pushed successfully!"

# List pushed images
echo "Images in registry:"
curl -s -k -u admin:$ADMIN_PASS "https://$REGISTRY_HOST/v2/_catalog" | jq .
EOF

chmod +x build-and-push.sh

# Create login script
cat > login-registry.sh <<EOF
#!/bin/bash

# Login to AuditHound Registry
REGISTRY_HOST=${REGISTRY_HOST:-"registry.audithound.local:5000"}
ADMIN_USER=${ADMIN_USER:-"admin"}

echo "Logging into AuditHound Registry at \$REGISTRY_HOST..."
echo "Username: \$ADMIN_USER"
echo "Password: $ADMIN_PASS"

docker login \$REGISTRY_HOST -u \$ADMIN_USER -p "$ADMIN_PASS"

echo "Logged in successfully!"
EOF

chmod +x login-registry.sh

# Create trust setup script for clients
cat > setup-client-trust.sh <<EOF
#!/bin/bash

# Setup client to trust registry certificate
REGISTRY_HOST=${REGISTRY_HOST}
CERT_DIR="/etc/docker/certs.d/\${REGISTRY_HOST}"

echo "Setting up client trust for registry: \$REGISTRY_HOST"

# Create certificate directory
sudo mkdir -p "\$CERT_DIR"

# Copy certificate
sudo cp certs/registry.crt "\$CERT_DIR/ca.crt"

echo "Certificate installed. Docker will now trust the registry."
echo "You can now pull/push images to: \$REGISTRY_HOST"
EOF

chmod +x setup-client-trust.sh

# Create cleanup script
cat > cleanup-registry.sh <<'EOF'
#!/bin/bash

# Cleanup old images from registry
set -e

REGISTRY_HOST=${REGISTRY_HOST:-"registry.audithound.local:5000"}
KEEP_TAGS=${KEEP_TAGS:-"5"}

echo "Cleaning up old images in registry..."

# Get list of repositories
REPOS=$(curl -s -k -u admin:$ADMIN_PASS "https://$REGISTRY_HOST/v2/_catalog" | jq -r '.repositories[]')

for repo in $REPOS; do
    echo "Processing repository: $repo"
    
    # Get tags for repository
    TAGS=$(curl -s -k -u admin:$ADMIN_PASS "https://$REGISTRY_HOST/v2/$repo/tags/list" | jq -r '.tags[]' | sort -V)
    
    # Count tags
    TAG_COUNT=$(echo "$TAGS" | wc -l)
    
    if [ "$TAG_COUNT" -gt "$KEEP_TAGS" ]; then
        # Delete old tags
        OLD_TAGS=$(echo "$TAGS" | head -n -$KEEP_TAGS)
        
        for tag in $OLD_TAGS; do
            echo "Deleting $repo:$tag"
            
            # Get manifest digest
            DIGEST=$(curl -s -k -u admin:$ADMIN_PASS \
                -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
                "https://$REGISTRY_HOST/v2/$repo/manifests/$tag" \
                -I | grep Docker-Content-Digest | cut -d' ' -f2 | tr -d '\r')
            
            # Delete manifest
            curl -s -k -u admin:$ADMIN_PASS \
                -X DELETE \
                "https://$REGISTRY_HOST/v2/$repo/manifests/$DIGEST"
        done
    fi
done

echo "Cleanup completed. Remember to run garbage collection on the registry."
EOF

chmod +x cleanup-registry.sh

echo "Registry setup completed!"
echo ""
echo "Next steps:"
echo "1. Start the registry: docker-compose -f docker-compose.registry.yml up -d"
echo "2. Setup client trust: ./setup-client-trust.sh"
echo "3. Login to registry: ./login-registry.sh"
echo "4. Build and push images: ./build-and-push.sh"
echo ""
echo "Registry will be available at: https://$REGISTRY_HOST:$REGISTRY_PORT"
echo "Registry UI will be available at: http://localhost:8080"
echo "Admin credentials: $ADMIN_USER / $ADMIN_PASS"