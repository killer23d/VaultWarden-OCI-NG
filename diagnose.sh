#!/usr/bin/env bash
# diagnose.sh -- Comprehensive diagnostic script for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_diagnose_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/config.sh"

# ================================
# DIAGNOSTIC MODULES
# ================================

# System diagnostics
run_system_diagnostics() {
    echo -e "${BOLD}=== SYSTEM DIAGNOSTICS ===${NC}"
    
    log_info "Checking system requirements..."
    validate_system_requirements
    
    log_info "System Information:"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo 'Unknown')"
    echo "Uptime: $(uptime)"
    
    # Resource usage
    echo -e "\n${BLUE}Resource Usage:${NC}"
    echo "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | head -1 || echo "CPU info not available"
    
    echo -e "\nMemory Usage:"
    free -h
    
    echo -e "\nDisk Usage:"
    df -h . 2>/dev/null
    
    # Check for system limits
    echo -e "\n${BLUE}System Limits:${NC}"
    echo "Max open files: $(ulimit -n)"
    echo "Max processes: $(ulimit -u)"
    echo "Max file size: $(ulimit -f)"
    
    # Check Docker system info
    echo -e "\n${BLUE}Docker System:${NC}"
    docker system df 2>/dev/null || echo "Docker system info not available"
    
    echo ""
}

# Project structure diagnostics
run_project_diagnostics() {
    echo -e "${BOLD}=== PROJECT DIAGNOSTICS ===${NC}"
    
    validate_project_structure
    
    # Check configuration files
    log_info "Checking configuration files..."
    
    if [[ -f "$SETTINGS_FILE" ]]; then
        log_success "Settings file found"
        
        # Check file permissions
        local perms
        perms=$(stat -c "%a" "$SETTINGS_FILE")
        if [[ "$perms" == "600" ]]; then
            log_success "Settings file has correct permissions (600)"
        else
            log_warning "Settings file permissions: $perms (recommended: 600)"
        fi
        
        # Basic validation
        set -a
        source "$SETTINGS_FILE" 2>/dev/null || {
            log_error "Failed to source settings file - syntax error?"
            return 1
        }
        set +a
        
        # Check critical variables
        local missing_vars=()
        for var in "${REQUIRED_VARS[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                missing_vars+=("$var")
            fi
        done
        
        if [[ ${#missing_vars[@]} -eq 0 ]]; then
            log_success "All required variables are configured"
        else
            log_warning "Missing required variables: ${missing_vars[*]}"
        fi
        
        # Check for placeholder values
        local placeholder_vars=()
        for var in "${REQUIRED_VARS[@]}"; do
            if [[ "${!var:-}" == *"generate-with-openssl"* ]] || [[ "${!var:-}" == *"example.com"* ]]; then
                placeholder_vars+=("$var")
            fi
        done
        
        if [[ ${#placeholder_vars[@]} -gt 0 ]]; then
            log_warning "Variables with placeholder values: ${placeholder_vars[*]}"
        fi
        
    else
        log_warning "Settings file not found: $SETTINGS_FILE"
        
        if [[ -f "$SETTINGS_EXAMPLE" ]]; then
            log_info "Settings example file is available: $SETTINGS_EXAMPLE"
        else
            log_error "Settings example file is also missing: $SETTINGS_EXAMPLE"
        fi
    fi
    
    # Check Docker Compose file
    echo -e "\n${BLUE}Docker Compose Validation:${NC}"
    if docker compose config >/dev/null 2>&1; then
        log_success "docker-compose.yml syntax is valid"
        
        # Show configured services
        local services
        services=$(docker compose config --services)
        log_info "Configured services: $(echo "$services" | tr '\n' ' ')"
        
        # Check for profiles
        local profiles
        profiles=$(docker compose config | grep -A5 "profiles:" | grep -E "^\s*-" | awk '{print $2}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
        if [[ -n "$profiles" ]]; then
            log_info "Available profiles: $profiles"
        fi
        
    else
        log_error "docker-compose.yml syntax validation failed"
        docker compose config 2>&1 | tail -5
    fi
    
    # Check data directories
    echo -e "\n${BLUE}Data Directories:${NC}"
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            local size
            size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "unknown")
            log_info "Directory $dir: $size"
        else
            log_warning "Directory missing: $dir"
        fi
    done
    
    echo ""
}

# Docker diagnostics
run_docker_diagnostics() {
    echo -e "${BOLD}=== DOCKER DIAGNOSTICS ===${NC}"
    
    # Docker system info
    log_info "Docker version information:"
    docker --version
    docker compose version
    
    echo -e "\n${BLUE}Docker System Information:${NC}"
    docker info --format "{{.ServerVersion}}" 2>/dev/null && echo "Docker Engine: $(docker info --format "{{.ServerVersion}}" 2>/dev/null)"
    docker info --format "{{.Driver}}" 2>/dev/null && echo "Storage Driver: $(docker info --format "{{.Driver}}" 2>/dev/null)"
    docker info --format "{{.LoggingDriver}}" 2>/dev/null && echo "Logging Driver: $(docker info --format "{{.LoggingDriver}}" 2>/dev/null)"
    
    # Check Docker daemon status
    if docker info >/dev/null 2>&1; then
        log_success "Docker daemon is running"
    else
        log_error "Docker daemon is not accessible"
        return 1
    fi
    
    # Stack status
    echo -e "\n${BLUE}Stack Status:${NC}"
    log_info "Checking stack status..."
    if is_stack_running; then
        log_success "Stack is running"
        
        # Detailed service check
        perform_health_check
        
        # Network connectivity
        echo -e "\n${BLUE}Network Connectivity:${NC}"
        test_internal_connectivity
        
        # Show resource usage
        echo -e "\n${BLUE}Container Resource Usage:${NC}"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null || echo "Unable to get container stats"
        
    else
        log_warning "Stack is not running"
        
        # Check for stopped containers
        local stopped_containers
        stopped_containers=$(docker compose ps -a --format "table {{.Name}}\t{{.Status}}" | grep -v "Up" | tail -n +2)
        if [[ -n "$stopped_containers" ]]; then
            echo -e "\n${BLUE}Stopped Containers:${NC}"
            echo "$stopped_containers"
        fi
    fi
    
    # Show service details
    echo -e "\n${BLUE}Service Status:${NC}"
    docker compose ps
    
    # Check networks
    echo -e "\n${BLUE}Docker Networks:${NC}"
    docker network ls --filter name=vaultwarden --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}\t{{.Created}}"
    
    # Check volumes
    echo -e "\n${BLUE}Docker Volumes:${NC}"
    docker volume ls --filter name=vaultwarden --format "table {{.Name}}\t{{.Driver}}\t{{.CreatedAt}}" 2>/dev/null || echo "No VaultWarden volumes found"
    
    echo ""
}

# Configuration diagnostics
run_config_diagnostics() {
    echo -e "${BOLD}=== CONFIGURATION DIAGNOSTICS ===${NC}"
    
    if [[ -f "$SETTINGS_FILE" ]]; then
        # Load configuration
        set -a
        source "$SETTINGS_FILE"
        set +a
        
        # Test SMTP if configured
        echo -e "${BLUE}SMTP Configuration:${NC}"
        if [[ -n "${SMTP_HOST:-}" ]] && [[ -n "${SMTP_PORT:-}" ]]; then
            if test_smtp_config "$SETTINGS_FILE"; then
                log_success "SMTP configuration appears valid"
            else
                log_warning "SMTP configuration may have issues"
            fi
            
            # Test SMTP connectivity
            if command -v nc >/dev/null 2>&1; then
                if nc -z "${SMTP_HOST}" "${SMTP_PORT}" 2>/dev/null; then
                    log_success "SMTP server is reachable"
                else
                    log_warning "SMTP server is not reachable"
                fi
            fi
        else
            log_info "SMTP not configured"
        fi
        
        # Test database if running
        echo -e "\n${BLUE}Database Configuration:${NC}"
        if is_service_running "bw_mariadb"; then
            if test_database_config "$SETTINGS_FILE"; then
                log_success "Database configuration is working"
                
                # Additional database info
                local db_id
                db_id=$(get_container_id "bw_mariadb")
                if [[ -n "$db_id" ]]; then
                    echo "Database version: $(docker exec "$db_id" mysql --version 2>/dev/null | cut -d' ' -f6 || echo 'Unknown')"
                    echo "Active connections: $(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW STATUS LIKE 'Threads_connected';" -s -N 2>/dev/null | cut -f2 || echo 'Unknown')"
                fi
            else
                log_warning "Database configuration has issues"
            fi
        else
            log_warning "Database is not running - cannot test"
        fi
        
        # Check Redis if running
        echo -e "\n${BLUE}Redis Configuration:${NC}"
        if is_service_running "bw_redis"; then
            local redis_id
            redis_id=$(get_container_id "bw_redis")
            if [[ -n "$redis_id" ]]; then
                if docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" ping >/dev/null 2>&1; then
                    log_success "Redis connection is working"
                    echo "Redis version: $(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" INFO server 2>/dev/null | grep "redis_version" | cut -d: -f2 | tr -d '\r' || echo 'Unknown')"
                    echo "Connected clients: $(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" INFO clients 2>/dev/null | grep "connected_clients" | cut -d: -f2 | tr -d '\r' || echo 'Unknown')"
                else
                    log_warning "Redis connection failed"
                fi
            fi
        else
            log_info "Redis is not running"
        fi
        
        # Check Cloudflare IP status
        echo -e "\n${BLUE}Cloudflare Configuration:${NC}"
        if need_cloudflare_ip_update; then
            log_warning "Cloudflare IP files need updating"
            echo "Run: ./caddy/update_cloudflare_ips.sh"
        else
            log_success "Cloudflare IP files are current"
        fi
        
        # Check domain resolution
        echo -e "\n${BLUE}Domain Configuration:${NC}"
        if [[ -n "${APP_DOMAIN:-}" ]]; then
            if nslookup "${APP_DOMAIN}" >/dev/null 2>&1; then
                log_success "Domain ${APP_DOMAIN} resolves"
                
                # Check if domain points to this server
                local domain_ip server_ip
                domain_ip=$(nslookup "${APP_DOMAIN}" | grep "Address:" | tail -1 | awk '{print $2}' 2>/dev/null || echo "")
                server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
                
                if [[ -n "$domain_ip" && "$domain_ip" == "$server_ip" ]]; then
                    log_success "Domain points to this server"
                else
                    log_info "Domain IP: $domain_ip, Server IP: $server_ip"
                fi
            else
                log_warning "Domain ${APP_DOMAIN} does not resolve"
            fi
        else
            log_warning "APP_DOMAIN not configured"
        fi
        
        # Check backup configuration
        echo -e "\n${BLUE}Backup Configuration:${NC}"
        if [[ -n "${BACKUP_PASSPHRASE:-}" ]]; then
            log_success "Backup encryption is configured"
        else
            log_warning "Backup encryption not configured (recommended)"
        fi
        
        if [[ -n "${BACKUP_REMOTE:-}" ]]; then
            log_info "Remote backup configured: ${BACKUP_REMOTE}"
            
            if command -v rclone >/dev/null 2>&1 && [[ -f "./backup/rclone.conf" ]]; then
                # Test rclone configuration
                if rclone --config ./backup/rclone.conf listremotes | grep -q "${BACKUP_REMOTE}"; then
                    log_success "rclone remote is configured"
                else
                    log_warning "rclone remote not found in configuration"
                fi
            fi
        else
            log_info "Remote backup not configured"
        fi
        
    else
        log_warning "No configuration file to test"
        echo "Create $SETTINGS_FILE from $SETTINGS_EXAMPLE"
    fi
    
    echo ""
}

# Security diagnostics
run_security_diagnostics() {
    echo -e "${BOLD}=== SECURITY DIAGNOSTICS ===${NC}"
    
    # Check file permissions
    echo -e "${BLUE}File Permissions:${NC}"
    
    if [[ -f "$SETTINGS_FILE" ]]; then
        local perms
        perms=$(stat -c "%a" "$SETTINGS_FILE")
        if [[ "$perms" == "600" ]]; then
            log_success "Settings file has correct permissions (600)"
        else
            log_warning "Settings file permissions: $perms (should be 600)"
            echo "Fix with: chmod 600 $SETTINGS_FILE"
        fi
    fi
    
    # Check for exposed secrets
    echo -e "\n${BLUE}Git Security:${NC}"
    if git status >/dev/null 2>&1; then
        if git ls-files | grep -q "$SETTINGS_FILE"; then
            log_error "Settings file is tracked in git!"
            echo "Remove with: git rm --cached $SETTINGS_FILE"
        else
            log_success "Settings file is not tracked in git"
        fi
        
        # Check gitignore
        if [[ -f ".gitignore" ]] && grep -q "$SETTINGS_FILE" ".gitignore"; then
            log_success "Settings file is in .gitignore"
        else
            log_warning "Settings file should be added to .gitignore"
        fi
    else
        log_info "Not a git repository"
    fi
    
    # Check container security
    echo -e "\n${BLUE}Container Security:${NC}"
    if is_stack_running; then
        # Check for containers running as root
        local root_containers=()
        for service in "${SERVICES[@]}"; do
            local container_id
            container_id=$(get_container_id "$service")
            if [[ -n "$container_id" ]]; then
                local user_info
                user_info=$(docker exec "$container_id" id 2>/dev/null || echo "unknown")
                if echo "$user_info" | grep -q "uid=0(root)"; then
                    root_containers+=("$service")
                fi
            fi
        done
        
        if [[ ${#root_containers[@]} -gt 0 ]]; then
            log_warning "Services running as root: ${root_containers[*]}"
        else
            log_success "No services running as root"
        fi
    fi
    
    # Check Fail2ban status
    echo -e "\n${BLUE}Fail2ban Security:${NC}"
    if is_service_running "bw_fail2ban"; then
        local f2b_id
        f2b_id=$(get_container_id "bw_fail2ban")
        
        if [[ -n "$f2b_id" ]]; then
            local jail_status banned_count
            jail_status=$(docker exec "$f2b_id" fail2ban-client status 2>/dev/null || echo "Unable to get status")
            banned_count=$(echo "$jail_status" | grep -c "Status" || echo "0")
            
            log_info "Fail2ban status: $jail_status"
            
            # Check banned IPs
            local banned_ips
            banned_ips=$(docker exec "$f2b_id" fail2ban-client status | grep "Banned" | wc -l 2>/dev/null || echo "0")
            log_info "Currently banned IPs: $banned_ips"
        fi
    else
        log_warning "Fail2ban is not running"
    fi
    
    # Check SSL/TLS
    echo -e "\n${BLUE}SSL/TLS Security:${NC}"
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        source "$SETTINGS_FILE"
        set +a
        
        if [[ -n "${APP_DOMAIN:-}" ]]; then
            # Check SSL certificate
            if command -v openssl >/dev/null 2>&1; then
                local cert_info
                cert_info=$(echo | openssl s_client -servername "${APP_DOMAIN}" -connect "${APP_DOMAIN}":443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
                
                if [[ -n "$cert_info" ]]; then
                    log_success "SSL certificate is present"
                    echo "$cert_info"
                    
                    # Check expiration
                    local expiry_date
                    expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
                    if [[ -n "$expiry_date" ]]; then
                        local days_until_expiry
                        days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
                        
                        if [[ $days_until_expiry -lt 30 ]]; then
                            log_warning "SSL certificate expires in $days_until_expiry days"
                        else
                            log_success "SSL certificate expires in $days_until_expiry days"
                        fi
                    fi
                else
                    log_warning "Unable to retrieve SSL certificate information"
                fi
            fi
        fi
    fi
    
    echo ""
}

# Network diagnostics
run_network_diagnostics() {
    echo -e "${BOLD}=== NETWORK DIAGNOSTICS ===${NC}"
    
    # Test external connectivity
    echo -e "${BLUE}External Connectivity:${NC}"
    
    if curl -f https://httpbin.org/status/200 --max-time 10 >/dev/null 2>&1; then
        log_success "External HTTPS connectivity working"
    else
        log_warning "External HTTPS connectivity failed"
    fi
    
    if nslookup google.com >/dev/null 2>&1; then
        log_success "DNS resolution working"
    else
        log_warning "DNS resolution failed"
    fi
    
    # Test specific services
    echo -e "\n${BLUE}Service Connectivity:${NC}"
    
    # Test Docker Hub connectivity
    if curl -f https://index.docker.io/v1/ --max-time 10 >/dev/null 2>&1; then
        log_success "Docker Hub connectivity working"
    else
        log_warning "Docker Hub connectivity failed"
    fi
    
    # Test domain resolution if configured
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        source "$SETTINGS_FILE"
        set +a
        
        if [[ -n "${APP_DOMAIN:-}" ]]; then
            if nslookup "${APP_DOMAIN}" >/dev/null 2>&1; then
                log_success "Domain ${APP_DOMAIN} resolves"
            else
                log_warning "Domain ${APP_DOMAIN} does not resolve"
            fi
        fi
        
        # Test SMTP connectivity
        if [[ -n "${SMTP_HOST:-}" ]] && [[ -n "${SMTP_PORT:-}" ]]; then
            if command -v nc >/dev/null 2>&1; then
                if nc -z "${SMTP_HOST}" "${SMTP_PORT}" 2>/dev/null; then
                    log_success "SMTP server ${SMTP_HOST}:${SMTP_PORT} is reachable"
                else
                    log_warning "SMTP server ${SMTP_HOST}:${SMTP_PORT} is not reachable"
                fi
            fi
        fi
    fi
    
    # Internal connectivity
    echo -e "\n${BLUE}Internal Network:${NC}"
    test_internal_connectivity
    
    # Port checks
    echo -e "\n${BLUE}Port Status:${NC}"
    if command -v ss >/dev/null 2>&1; then
        echo "Listening ports:"
        ss -tulpn | grep ":80\|:443\|:3306\|:6379" | head -10
    elif command -v netstat >/dev/null 2>&1; then
        echo "Listening ports:"
        netstat -tulpn | grep ":80\|:443\|:3306\|:6379" | head -10
    else
        echo "Port checking tools not available"
    fi
    
    echo ""
}

# Performance diagnostics
run_performance_diagnostics() {
    echo -e "${BOLD}=== PERFORMANCE DIAGNOSTICS ===${NC}"
    
    if is_stack_running; then
        # Container resource usage
        echo -e "${BLUE}Container Resource Usage:${NC}"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}" 2>/dev/null || echo "Unable to get container stats"
        
        # Database performance check
        echo -e "\n${BLUE}Database Performance:${NC}"
        if is_service_running "bw_mariadb"; then
            local db_id
            db_id=$(get_container_id "bw_mariadb")
            
            if [[ -n "$db_id" ]]; then
                echo "Database status:"
                docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD:-}" -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" 2>/dev/null || echo "Unable to check database status"
                docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD:-}" -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';" 2>/dev/null || echo "Unable to check slow queries"
            fi
        else
            log_warning "Database is not running"
        fi
        
        # Redis performance check
        echo -e "\n${BLUE}Redis Performance:${NC}"
        if is_service_running "bw_redis"; then
            local redis_id
            redis_id=$(get_container_id "bw_redis")
            
            if [[ -n "$redis_id" ]]; then
                echo "Redis info:"
                docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD:-}" INFO memory 2>/dev/null | head -5 || echo "Unable to get Redis info"
            fi
        else
            log_warning "Redis is not running"
        fi
        
        # Disk I/O
        echo -e "\n${BLUE}Disk Performance:${NC}"
        if command -v iostat >/dev/null 2>&1; then
            iostat -d 1 1 | tail -n +4
        else
            echo "iostat not available - install sysstat package"
        fi
        
    else
        log_warning "Stack not running - skipping performance checks"
    fi
    
    echo ""
}

# Backup diagnostics
run_backup_diagnostics() {
    echo -e "${BOLD}=== BACKUP DIAGNOSTICS ===${NC}"
    
    # Check backup service
    if is_service_running "bw_backup"; then
        log_success "Backup service is running"
        
        # Check recent backups
        if [[ -d "./data/backups" ]]; then
            local backup_count recent_backup
            backup_count=$(find ./data/backups -name "db_backup_*.sql*" 2>/dev/null | wc -l)
            recent_backup=$(find ./data/backups -name "db_backup_*.sql*" -mtime -1 2>/dev/null | head -1)
            
            echo "Total backups: $backup_count"
            if [[ -n "$recent_backup" ]]; then
                local backup_size backup_age
                backup_size=$(du -h "$recent_backup" 2>/dev/null | cut -f1)
                backup_age=$(stat -c %Y "$recent_backup" 2>/dev/null)
                backup_age=$(( ($(date +%s) - backup_age) / 3600 ))
                
                log_success "Recent backup found: $(basename "$recent_backup") (${backup_size}, ${backup_age}h ago)"
            else
                log_warning "No recent backup found (last 24 hours)"
            fi
            
            # Check backup logs
            if [[ -d "./data/backup_logs" ]]; then
                local recent_log
                recent_log=$(find ./data/backup_logs -name "db_backup_*.log" -mtime -1 2>/dev/null | head -1)
                
                if [[ -n "$recent_log" ]]; then
                    echo -e "\n${BLUE}Recent Backup Log Excerpt:${NC}"
                    tail -10 "$recent_log"
                fi
            fi
        else
            log_warning "Backup directory not found"
        fi
        
        # Check rclone configuration
        if [[ -f "./backup/rclone.conf" ]]; then
            log_success "rclone configuration file exists"
        else
            log_info "rclone configuration not found (local backups only)"
        fi
        
    else
        log_warning "Backup service is not running"
        echo "Enable with: docker compose --profile backup up -d"
    fi
    
    echo ""
}

# Generate summary report
generate_summary() {
    echo -e "${BOLD}=== DIAGNOSTIC SUMMARY ===${NC}"
    
    local total_issues=0
    
    # Count warnings and errors from log
    if [[ -f "$LOG_FILE" ]]; then
        local warnings errors
        warnings=$(grep -c "WARNING" "$LOG_FILE" 2>/dev/null || echo "0")
        errors=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo "0")
        
        echo "Warnings: $warnings"
        echo "Errors: $errors"
        
        total_issues=$((warnings + errors))
    fi
    
    if [[ $total_issues -eq 0 ]]; then
        log_success "No issues detected!"
    elif [[ $total_issues -lt 5 ]]; then
        log_warning "$total_issues issues detected (minor)"
    else
        log_error "$total_issues issues detected (requires attention)" 1
    fi
    
    echo -e "\n${BLUE}Quick Actions:${NC}"
    echo "View monitoring:        ./dashboard.sh"
    echo "Performance analysis:   ./perf-monitor.sh status"
    echo "Check alerts:           ./alerts.sh status"
    echo "Restart services:       docker compose restart"
    echo "Update configuration:   ./startup.sh"
    echo "Manual database backup: docker compose exec bw_backup /backup/db-backup.sh -n"
    echo "Collect full diagnostics: $0 --collect"
    
    echo -e "\n${BLUE}Configuration Files:${NC}"
    echo "Main config:     $SETTINGS_FILE"
    echo "Example config:  $SETTINGS_EXAMPLE"
    echo "Docker Compose:  $COMPOSE_FILE"
    
    echo -e "\nFull diagnostic log: $LOG_FILE"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local collect_diagnostics_flag=false
    local run_all=true
    local selected_modules=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --collect)
                collect_diagnostics_flag=true
                shift
                ;;
            --system)
                selected_modules+=("system")
                run_all=false
                shift
                ;;
            --project)
                selected_modules+=("project")
                run_all=false
                shift
                ;;
            --docker)
                selected_modules+=("docker")
                run_all=false
                shift
                ;;
            --config)
                selected_modules+=("config")
                run_all=false
                shift
                ;;
            --network)
                selected_modules+=("network")
                run_all=false
                shift
                ;;
            --security)
                selected_modules+=("security")
                run_all=false
                shift
                ;;
            --performance)
                selected_modules+=("performance")
                run_all=false
                shift
                ;;
            --backup)
                selected_modules+=("backup")
                run_all=false
                shift
                ;;
            --debug)
                export DEBUG="true"
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Comprehensive Diagnostic Script

Usage: $0 [OPTIONS]

Options:
    --collect       Collect diagnostic files to directory
    --system        Run only system diagnostics
    --project       Run only project structure diagnostics
    --docker        Run only Docker diagnostics
    --config        Run only configuration diagnostics
    --network       Run only network diagnostics
    --security      Run only security diagnostics
    --performance   Run only performance diagnostics
    --backup        Run only backup diagnostics
    --debug         Enable debug logging
    --help, -h      Show this help message

Examples:
    $0                          # Run all diagnostics
    $0 --docker --network       # Run only Docker and network checks
    $0 --config --security      # Run only configuration and security checks
    $0 --collect                # Collect diagnostic files

Specialized Tools:
    Performance monitoring:     ./perf-monitor.sh
    Real-time dashboard:        ./dashboard.sh
    Alert management:           ./alerts.sh

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    echo -e "${BOLD}${BLUE}VaultWarden-OCI Comprehensive Diagnostics${NC}"
    echo "Generated at: $(date)"
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Collect diagnostics if requested
    if [[ "$collect_diagnostics_flag" == "true" ]]; then
        local diag_dir
        diag_dir=$(collect_diagnostics)
        log_success "Diagnostic files collected in: $diag_dir"
        exit 0
    fi
    
    # Run selected modules or all
    if [[ "$run_all" == "true" ]]; then
        selected_modules=("system" "project" "docker" "config" "security" "network" "performance" "backup")
    fi
    
    for module in "${selected_modules[@]}"; do
        case "$module" in
            "system") run_system_diagnostics ;;
            "project") run_project_diagnostics ;;
            "docker") run_docker_diagnostics ;;
            "config") run_config_diagnostics ;;
            "security") run_security_diagnostics ;;
            "network") run_network_diagnostics ;;
            "performance") run_performance_diagnostics ;;
            "backup") run_backup_diagnostics ;;
            *) log_warning "Unknown diagnostic module: $module" ;;
        esac
    done
    
    generate_summary
    
    log_success "Diagnostics complete!"
}

# Execute main function
main "$@"
