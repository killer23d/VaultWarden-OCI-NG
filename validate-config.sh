#!/bin/bash
# validate-config.sh - Validate configuration files and settings

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

errors=0
warnings=0

# Function to print error
print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
    ((errors++))
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
    ((warnings++))
}

# Function to print success
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to get container ID dynamically (for validation only)
get_container_id() {
    local service_name=$1
    docker compose ps -q "$service_name" 2>/dev/null || echo ""
}

echo -e "${BLUE}=== Configuration Validation ===${NC}"
echo ""

# 1. Check required files
echo -e "${BLUE}📁 File Structure Validation:${NC}"

required_files=(
    "./settings.env:Settings file"
    "./docker-compose.yml:Docker Compose configuration"
    "./caddy/Caddyfile:Caddy configuration"
    "./fail2ban/jail.d/jail.local.template:Fail2ban template"
    "./caddy/cloudflare_ips.caddy:Cloudflare IP ranges"
    "./caddy/cloudflare_ips.txt:Cloudflare IP text file"
)

for file_info in "${required_files[@]}"; do
    file="${file_info%:*}"
    desc="${file_info#*:}"
    
    if [ -f "$file" ]; then
        print_success "$desc exists"
    else
        print_error "$desc not found at $file"
    fi
done

# Check directories
required_dirs=("./data" "./caddy" "./fail2ban" "./backup")
for dir in "${required_dirs[@]}"; do
    if [ -d "$dir" ]; then
        if [ -w "$dir" ]; then
            print_success "Directory $dir exists and is writable"
        else
            print_warning "Directory $dir exists but may not be writable"
        fi
    else
        print_error "Directory $dir not found"
    fi
done

echo ""

# 2. Validate settings.env
echo -e "${BLUE}⚙️  Settings Validation:${NC}"

if [ -f ./settings.env ]; then
    source ./settings.env
    
    # Required settings
    required_vars=(
        "DOMAIN_NAME:Domain name"
        "ADMIN_TOKEN:Admin token"
        "DATABASE_URL:Database URL"
        "MARIADB_ROOT_PASSWORD:MariaDB root password"
        "MARIADB_PASSWORD:MariaDB password"
        "REDIS_PASSWORD:Redis password"
    )
    
    for var_info in "${required_vars[@]}"; do
        var="${var_info%:*}"
        desc="${var_info#*:}"
        
        if [ -n "${!var:-}" ]; then
            print_success "$desc configured"
            
            # Validate password strength for password fields
            if [[ "$var" == *"PASSWORD"* ]] || [[ "$var" == *"TOKEN"* ]]; then
                if [ ${#!var} -lt 16 ]; then
                    print_warning "$desc is shorter than 16 characters"
                fi
            fi
        else
            print_error "$desc not configured ($var)"
        fi
    done
    
    # Optional but recommended settings
    optional_vars=(
        "SMTP_HOST:SMTP configuration"
        "BACKUP_PASSPHRASE:Backup encryption"
        "PUSH_INSTALLATION_ID:Push notifications"
    )
    
    for var_info in "${optional_vars[@]}"; do
        var="${var_info%:*}"
        desc="${var_info#*:}"
        
        if [ -n "${!var:-}" ]; then
            print_success "$desc configured"
        else
            print_warning "$desc not configured (optional)"
        fi
    done
    
    # Validate domain format
    if [ -n "${DOMAIN_NAME:-}" ]; then
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
            print_success "Domain name format is valid"
        else
            print_warning "Domain name format may be invalid: $DOMAIN_NAME"
        fi
    fi
    
else
    print_error "settings.env file not found"
fi

echo ""

# 3. Validate Docker Compose
echo -e "${BLUE}🐳 Docker Compose Validation:${NC}"

if command -v docker &> /dev/null; then
    print_success "Docker is installed"
    
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_error "Docker daemon is not running"
    fi
    
    if command -v docker compose &> /dev/null; then
        print_success "Docker Compose is installed"
        
        # Validate compose file syntax
        if docker compose config &> /dev/null; then
            print_success "docker-compose.yml syntax is valid"
        else
            print_error "docker-compose.yml has syntax errors"
        fi
    else
        print_error "Docker Compose is not installed"
    fi
else
    print_error "Docker is not installed"
fi

echo ""

# 4. Validate network connectivity (if containers are running)
echo -e "${BLUE}🌐 Network Validation:${NC}"

# Check if any containers are running
running_services=()
services=("vaultwarden" "mariadb" "redis" "caddy" "fail2ban" "backup")
for service in "${services[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        running_services+=("$service")
    fi
done

if [ ${#running_services[@]} -gt 0 ]; then
    print_success "Found ${#running_services[@]} running services"
    
    # Test connectivity between services
    vaultwarden_id=$(get_container_id "vaultwarden")
    mariadb_id=$(get_container_id "mariadb")
    
    if [ -n "$vaultwarden_id" ] && [ -n "$mariadb_id" ]; then
        if docker exec "$vaultwarden_id" nc -z bw_mariadb 3306 2>/dev/null; then
            print_success "Vaultwarden can connect to MariaDB"
        else
            print_warning "Vaultwarden cannot connect to MariaDB"
        fi
    fi
else
    print_warning "No containers running - skipping network tests"
fi

echo ""

# 5. Validate backup configuration
echo -e "${BLUE}💾 Backup Validation:${NC}"

if [ -f ./backup/rclone.conf ]; then
    print_success "rclone configuration found"
    
    # Check if rclone config is valid (basic check)
    if grep -q "\[.*\]" ./backup/rclone.conf; then
        print_success "rclone configuration appears valid"
    else
        print_warning "rclone configuration may be empty or invalid"
    fi
else
    print_warning "rclone configuration not found (backups disabled)"
fi

if [ -f ./backup/backup.sh ] && [ -x ./backup/backup.sh ]; then
    print_success "Backup script is executable"
else
    print_warning "Backup script not found or not executable"
fi

echo ""

# Summary
echo -e "${BLUE}📋 Validation Summary:${NC}"
echo -e "Errors: ${RED}$errors${NC}"
echo -e "Warnings: ${YELLOW}$warnings${NC}"

if [ $errors -eq 0 ]; then
    if [ $warnings -eq 0 ]; then
        echo -e "${GREEN}✅ Configuration validation passed with no issues!${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  Configuration validation passed with $warnings warnings${NC}"
        echo "Consider addressing warnings for optimal operation"
        exit 0
    fi
else
    echo -e "${RED}❌ Configuration validation failed with $errors errors${NC}"
    echo "Please fix the errors before proceeding"
    exit 1
fi
