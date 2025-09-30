#!/usr/bin/env bash
# init-setup.sh - Initial system setup automation for VaultWarden-OCI

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuration
DOCKER_COMPOSE_VERSION="2.23.3"
OCI_CLI_VERSION="3.39.0"
PROJECT_DIR="${PWD}"
SKIP_DOCKER_INSTALL=false
SKIP_OCI_SETUP=false
SETUP_MODE="interactive"

# ================================
# UTILITY FUNCTIONS
# ================================

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
    exit "${2:-1}"
}

log_step() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_root() {
    [[ $EUID -eq 0 ]]
}

get_os_info() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID $VERSION_ID"
    else
        echo "unknown"
    fi
}

# ================================
# SYSTEM REQUIREMENTS CHECK
# ================================

check_system_requirements() {
    log_step "Checking System Requirements"
    
    local os_info
    os_info=$(get_os_info)
    log_info "Detected OS: $os_info"
    
    # Check architecture
    local arch
    arch=$(uname -m)
    log_info "Architecture: $arch"
    
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
        log_error "Unsupported architecture: $arch"
    fi
    
    # Check memory
    local memory_gb
    memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    log_info "Available memory: ${memory_gb}GB"
    
    if [[ $memory_gb -lt 2 ]]; then
        log_warning "Low memory detected (${memory_gb}GB). Minimum 2GB recommended"
    fi
    
    # Check disk space
    local disk_gb
    disk_gb=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
    log_info "Available disk space: ${disk_gb}GB"
    
    if [[ $disk_gb -lt 10 ]]; then
        log_error "Insufficient disk space (${disk_gb}GB). Minimum 10GB required"
    fi
    
    # Check for required system packages
    local missing_packages=()
    local required_packages=("curl" "wget" "git" "unzip" "sudo")
    
    for package in "${required_packages[@]}"; do
        if ! command_exists "$package"; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_warning "Missing system packages: ${missing_packages[*]}"
        install_system_packages "${missing_packages[@]}"
    fi
    
    log_success "System requirements check completed"
}

# ================================
# SYSTEM PACKAGE INSTALLATION
# ================================

install_system_packages() {
    local packages=("$@")
    log_info "Installing system packages: ${packages[*]}"
    
    local os_info
    os_info=$(get_os_info)
    
    case "$os_info" in
        "ubuntu"*|"debian"*)
            sudo apt-get update
            sudo apt-get install -y "${packages[@]}"
            ;;
        "centos"*|"rhel"*|"fedora"*)
            if command_exists dnf; then
                sudo dnf install -y "${packages[@]}"
            else
                sudo yum install -y "${packages[@]}"
            fi
            ;;
        "alpine"*)
            sudo apk add "${packages[@]}"
            ;;
        *)
            log_warning "Unknown OS, please install manually: ${packages[*]}"
            ;;
    esac
}

# ================================
# DOCKER INSTALLATION
# ================================

install_docker() {
    if [[ "$SKIP_DOCKER_INSTALL" == "true" ]]; then
        log_info "Skipping Docker installation"
        return 0
    fi
    
    log_step "Installing Docker"
    
    if command_exists docker; then
        log_info "Docker is already installed: $(docker --version)"
        
        # Check if user is in docker group
        if groups "$USER" | grep -q docker; then
            log_success "User is in docker group"
        else
            log_warning "Adding user to docker group"
            sudo usermod -aG docker "$USER"
            log_warning "Please log out and log back in for group changes to take effect"
        fi
        
        # Check if Docker daemon is running
        if docker info >/dev/null 2>&1; then
            log_success "Docker daemon is running"
        else
            log_info "Starting Docker daemon"
            sudo systemctl enable docker
            sudo systemctl start docker
        fi
        
        return 0
    fi
    
    log_info "Installing Docker..."
    
    # Install Docker using the official installation script
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
    
    # Add user to docker group
    sudo usermod -aG docker "$USER"
    
    # Enable and start Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    log_success "Docker installed successfully"
    log_warning "Please log out and log back in for group changes to take effect"
}

install_docker_compose() {
    log_info "Checking Docker Compose..."
    
    # Check if Docker Compose is available as a plugin
    if docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose plugin is available: $(docker compose version --short)"
        return 0
    fi
    
    # Install Docker Compose as a plugin
    log_info "Installing Docker Compose plugin..."
    
    local arch
    arch=$(uname -m)
    case "$arch" in
        "x86_64") arch="x86_64" ;;
        "aarch64"|"arm64") arch="aarch64" ;;
        *) log_error "Unsupported architecture for Docker Compose: $arch" ;;
    esac
    
    local compose_url="https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-linux-${arch}"
    
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo curl -L "$compose_url" -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    
    # Verify installation
    if docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose installed successfully: $(docker compose version --short)"
    else
        log_error "Docker Compose installation failed"
    fi
}

# ================================
# PROJECT SETUP
# ================================

setup_project_structure() {
    log_step "Setting Up Project Structure"
    
    log_info "Creating required directories..."
    
    local required_dirs=(
        "data"
        "data/bwdata"
        "data/mariadb"
        "data/redis"
        "data/caddy_data"
        "data/caddy_config"
        "data/caddy_logs"
        "data/fail2ban"
        "data/backups"
        "data/backup_logs"
        "config"
        "config/mariadb"
        "config/redis"
        "config/logrotate"
        "benchmarks"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 data/
    chmod 700 data/mariadb data/redis data/fail2ban
    chmod 755 data/caddy_data data/caddy_config data/caddy_logs
    chmod 755 data/backups data/backup_logs
    
    log_success "Project structure created"
}

create_initial_config() {
    log_step "Creating Initial Configuration"
    
    if [[ ! -f "settings.env" ]]; then
        if [[ -f "settings.env.example" ]]; then
            log_info "Creating settings.env from example..."
            cp settings.env.example settings.env
            chmod 600 settings.env
            
            log_warning "Please edit settings.env to configure your installation:"
            log_info "  - Set DOMAIN_NAME to your domain"
            log_info "  - Replace all 'generate-with-openssl-rand-base64-32' with secure passwords"
            log_info "  - Configure SMTP settings for email notifications"
            log_info "  - Set backup configuration if using remote storage"
            
        else
            log_error "settings.env.example not found"
        fi
    else
        log_info "settings.env already exists"
    fi
    
    # Create additional config files
    create_mariadb_config
    create_redis_config
    create_logrotate_config
    
    log_success "Initial configuration created"
}

create_mariadb_config() {
    local config_file="config/mariadb/my.cnf"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "Creating MariaDB configuration..."
        
        cat > "$config_file" <<'EOF'
[mysqld]
# === Performance Configuration for OCI A1 Flex (1 CPU, 6GB RAM) ===

# Basic Settings
user                    = mysql
default-storage-engine  = InnoDB
socket                  = /var/run/mysqld/mysqld.sock
pid-file                = /var/run/mysqld/mysqld.pid

# Connection Settings
max_connections         = 15
thread_cache_size       = 8
max_allowed_packet      = 64M
max_connect_errors      = 100000
skip_name_resolve       = 1

# InnoDB Settings (Optimized for limited RAM)
innodb_buffer_pool_size         = 512M
innodb_log_file_size           = 128M
innodb_log_buffer_size         = 32M
innodb_flush_log_at_trx_commit = 2
innodb_lock_wait_timeout       = 120
innodb_flush_method            = O_DIRECT
innodb_file_per_table          = 1
innodb_open_files              = 400

# MyISAM Settings (Minimal usage expected)
key_buffer_size         = 32M
myisam_recover_options  = BACKUP,FORCE

# Query Cache (Disabled for better performance with InnoDB)
query_cache_size        = 0
query_cache_type        = 0

# Table Settings
table_open_cache        = 64
table_definition_cache  = 400

# Logging (Minimal for performance)
slow_query_log          = 1
slow_query_log_file     = /var/lib/mysql/slow.log
long_query_time         = 2
log_queries_not_using_indexes = 0

# Binary Logging (Disabled to save resources)
skip_log_bin

# Temporary Tables
tmp_table_size          = 64M
max_heap_table_size     = 64M

# Sort Buffer
sort_buffer_size        = 2M
read_buffer_size        = 128K
read_rnd_buffer_size    = 256K
join_buffer_size        = 128K

# Character Set
character_set_server    = utf8mb4
collation_server        = utf8mb4_unicode_ci

# Time Zone
default_time_zone       = '+00:00'

# Security
sql_mode                = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

[client]
default-character-set   = utf8mb4

[mysql]
default-character-set   = utf8mb4
EOF
        
        log_success "MariaDB configuration created"
    fi
}

create_redis_config() {
    local config_file="config/redis/redis.conf"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "Creating Redis configuration..."
        
        cat > "$config_file" <<'EOF'
# === Redis Configuration for VaultWarden-OCI ===
# Optimized for OCI A1 Flex (1 CPU, 6GB RAM)

# Network
bind 0.0.0.0
port 6379
timeout 300
keepalive 60

# Memory Management
maxmemory 200mb
maxmemory-policy allkeys-lru
maxmemory-samples 3

# Persistence (Optimized for performance)
save 300 10
save 60 1000
rdbcompression yes
rdbchecksum yes

# AOF (Append Only File) - Better durability
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite yes
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Performance Tuning
tcp-keepalive 60
tcp-backlog 511
databases 1
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000

# Logging
loglevel notice
syslog-enabled no

# Security - Password will be set via environment variable
# requirepass ${REDIS_PASSWORD}

# Client Management
maxclients 25

# Slow Log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Latency Monitoring
latency-monitor-threshold 100
EOF
        
        log_success "Redis configuration created"
    fi
}

create_logrotate_config() {
    local config_file="config/logrotate/vaultwarden-logs"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "Creating log rotation configuration..."
        
        cat > "$config_file" <<'EOF'
# VaultWarden Log Rotation Configuration

# Caddy logs
/var/log/caddy/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        # Reload Caddy gracefully to reopen log files
        docker kill --signal=USR1 bw_caddy 2>/dev/null || true
    endscript
}

# Backup logs
/var/log/backup/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}

# Docker container logs (JSON files)
/var/lib/docker/containers/*/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}
EOF
        
        log_success "Log rotation configuration created"
    fi
}

# ================================
# OCI CLI SETUP (OPTIONAL)
# ================================

setup_oci_cli() {
    if [[ "$SKIP_OCI_SETUP" == "true" ]]; then
        log_info "Skipping OCI CLI setup"
        return 0
    fi
    
    log_step "OCI CLI Setup (Optional)"
    
    if [[ "$SETUP_MODE" == "interactive" ]]; then
        echo ""
        echo "OCI CLI allows you to:"
        echo "  - Store configuration securely in OCI Vault"
        echo "  - Use OCI Object Storage for backups"
        echo "  - Leverage OCI cloud services"
        echo ""
        read -p "Do you want to install and configure OCI CLI? (y/N): " setup_oci
        
        if [[ ! "$setup_oci" =~ ^[Yy]$ ]]; then
            log_info "Skipping OCI CLI setup"
            return 0
        fi
    fi
    
    if command_exists oci; then
        log_success "OCI CLI is already installed: $(oci --version)"
        return 0
    fi
    
    log_info "Installing OCI CLI..."
    
    # Download and install OCI CLI
    local temp_dir
    temp_dir=$(mktemp -d)
    
    pushd "$temp_dir" >/dev/null
    
    local arch
    arch=$(uname -m)
    case "$arch" in
        "x86_64") arch="x86_64" ;;
        "aarch64"|"arm64") arch="aarch64" ;;
        *) log_error "Unsupported architecture for OCI CLI: $arch" ;;
    esac
    
    local oci_url="https://github.com/oracle/oci-cli/releases/download/v${OCI_CLI_VERSION}/oci-cli-${OCI_CLI_VERSION}-linux-${arch}.tar.gz"
    
    wget "$oci_url" -O oci-cli.tar.gz
    tar -xzf oci-cli.tar.gz
    
    # Install OCI CLI
    sudo ./oci-cli-*/install.sh --accept-all-defaults
    
    popd >/dev/null
    rm -rf "$temp_dir"
    
    log_success "OCI CLI installed successfully"
    
    if [[ "$SETUP_MODE" == "interactive" ]]; then
        log_info "Run './oci_setup.sh setup' to configure OCI Vault integration"
    fi
}

# ================================
# FINAL SETUP AND VERIFICATION
# ================================

verify_installation() {
    log_step "Verifying Installation"
    
    local issues=()
    
    # Check Docker
    if command_exists docker && docker info >/dev/null 2>&1; then
        log_success "Docker is working"
    else
        issues+=("Docker is not working properly")
    fi
    
    # Check Docker Compose
    if docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose is working"
    else
        issues+=("Docker Compose is not working")
    fi
    
    # Check project structure
    if [[ -f "docker-compose.yml" ]]; then
        if docker compose config >/dev/null 2>&1; then
            log_success "docker-compose.yml is valid"
        else
            issues+=("docker-compose.yml has syntax errors")
        fi
    else
        issues+=("docker-compose.yml not found")
    fi
    
    # Check settings
    if [[ -f "settings.env" ]]; then
        log_success "settings.env exists"
    else
        issues+=("settings.env not found")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        log_success "Installation verification passed"
        return 0
    else
        log_warning "Installation issues found:"
        for issue in "${issues[@]}"; do
            log_warning "  - $issue"
        done
        return 1
    fi
}

show_next_steps() {
    log_step "Next Steps"
    
    cat <<EOF

${BOLD}${GREEN}Setup completed successfully!${NC}

${BOLD}Next steps:${NC}

1. ${BOLD}Configure your installation:${NC}
   ${BLUE}nano settings.env${NC}
   
   Required changes:
   - Set DOMAIN_NAME to your actual domain
   - Replace all password placeholders with secure passwords
   - Configure SMTP settings for email notifications

2. ${BOLD}Generate secure passwords:${NC}
   ${BLUE}openssl rand -base64 32${NC}  # Run this for each password field

3. ${BOLD}Optional - Set up OCI Vault (for secure config storage):${NC}
   ${BLUE}./oci_setup.sh setup${NC}

4. ${BOLD}Start VaultWarden:${NC}
   ${BLUE}./startup.sh${NC}

5. ${BOLD}Monitor your installation:${NC}
   ${BLUE}./dashboard.sh${NC}           # Interactive dashboard
   ${BLUE}./perf-monitor.sh status${NC}  # Performance monitoring
   ${BLUE}./diagnose.sh${NC}            # System diagnostics

${BOLD}Useful commands:${NC}
   ${BLUE}docker compose ps${NC}                    # Check service status
   ${BLUE}docker compose logs -f vaultwarden${NC}   # View logs
   ${BLUE}./alerts.sh check${NC}                   # Check for alerts

${BOLD}Backup configuration:${NC}
   - Edit BACKUP_* variables in settings.env
   - Enable backup profile: ${BLUE}docker compose --profile backup up -d${NC}

${YELLOW}Important:${NC}
- Your settings.env file contains sensitive information - keep it secure!
- Make sure to configure your domain's DNS to point to this server
- Consider setting up SSL certificates (Caddy will handle this automatically)

Happy self-hosting! 🚀

EOF
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-docker)
                SKIP_DOCKER_INSTALL=true
                shift
                ;;
            --skip-oci)
                SKIP_OCI_SETUP=true
                shift
                ;;
            --non-interactive)
                SETUP_MODE="non-interactive"
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Initial Setup Script

Usage: $0 [OPTIONS]

Options:
    --skip-docker        Skip Docker installation
    --skip-oci          Skip OCI CLI setup
    --non-interactive   Run without interactive prompts
    --help, -h          Show this help message

This script will:
1. Check system requirements
2. Install Docker and Docker Compose
3. Set up project directory structure
4. Create initial configuration files
5. Optionally install and configure OCI CLI

Examples:
    $0                          # Full interactive setup
    $0 --skip-docker            # Skip Docker (already installed)
    $0 --non-interactive        # Automated setup
    $0 --skip-docker --skip-oci # Minimal setup

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Main setup flow
    cat <<EOF
${BOLD}${BLUE}
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VaultWarden-OCI Initial Setup                           ║
║                                                                              ║
║  This script will prepare your system for VaultWarden deployment            ║
╚══════════════════════════════════════════════════════════════════════════════╝
${NC}

EOF
    
    # Check if running as root
    if is_root; then
        log_error "Please do not run this script as root"
    fi
    
    # Check sudo access
    if ! sudo -n true 2>/dev/null; then
        log_info "This script requires sudo access for system package installation"
        sudo -v || log_error "Sudo access required"
    fi
    
    # Execute setup steps
    check_system_requirements
    install_docker
    install_docker_compose
    setup_project_structure
    create_initial_config
    setup_oci_cli
    
    # Verification and completion
    if verify_installation; then
        show_next_steps
    else
        log_error "Setup completed with issues - please review the output above"
    fi
}

# Execute main function
main "$@"
