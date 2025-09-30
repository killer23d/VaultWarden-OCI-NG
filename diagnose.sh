#!/usr/bin/env bash
# diagnose.sh -- Modular diagnostic script for VaultWarden-OCI

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
    echo "Uptime: $(uptime)"
    
    # Resource usage
    echo -e "\n${BLUE}Resource Usage:${NC}"
    echo "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | head -1 || echo "CPU info not available"
    
    echo -e "\nMemory Usage:"
    free -h
    
    echo -e "\nDisk Usage:"
    df -h . 2>/dev/null
    
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
        
        # Basic validation
        set -a
        source "$SETTINGS_FILE"
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
            log_warning "Missing variables: ${missing_vars[*]}"
        fi
    else
        log_warning "Settings file not found"
    fi
    
    echo ""
}

# Docker diagnostics
run_docker_diagnostics() {
    echo -e "${BOLD}=== DOCKER DIAGNOSTICS ===${NC}"
    
    # Docker system info
    log_info "Docker version:"
    docker --version
    docker compose version
    
    # Stack status
    log_info "Checking stack status..."
    if is_stack_running; then
        log_success "Stack is running"
        
        # Detailed service check
        perform_health_check
        
        # Network connectivity
        test_internal_connectivity
        
    else
        log_warning "Stack is not running"
    fi
    
    # Show service details
    echo -e "\n${BLUE}Service Status:${NC}"
    docker compose ps
    
    echo ""
}

# Configuration diagnostics
run_config_diagnostics() {
    echo -e "${BOLD}=== CONFIGURATION DIAGNOSTICS ===${NC}"
    
    if [[ -f "$SETTINGS_FILE" ]]; then
        # Test SMTP if configured
        if test_smtp_config "$SETTINGS_FILE"; then
            log_success "SMTP configuration appears valid"
        fi
        
        # Test database if running
        if test_database_config "$SETTINGS_FILE"; then
            log_success "Database configuration is working"
        fi
        
        # Check Cloudflare IP status
        if need_cloudflare_ip_update; then
            log_warning "Cloudflare IP files need updating"
        else
            log_success "Cloudflare IP files are current"
        fi
        
    else
        log_warning "No configuration file to test"
    fi
    
    echo ""
}

# Security diagnostics
run_security_diagnostics() {
    echo -e "${BOLD}=== SECURITY DIAGNOSTICS ===${NC}"
    
    # Check file permissions
    log_info "Checking file permissions..."
    
    if [[ -f "$SETTINGS_FILE" ]]; then
        local perms
        perms=$(stat -c "%a" "$SETTINGS_FILE")
        if [[ "$perms" == "600" ]]; then
            log_success "Settings file has correct permissions (600)"
        else
            log_warning "Settings file permissions: $perms (should be 600)"
        fi
    fi
    
    # Check for exposed secrets
    log_info "Checking for exposed secrets..."
    if git status >/dev/null 2>&1; then
        if git ls-files | grep -q "$SETTINGS_FILE"; then
            log_error "Settings file is tracked in git!"
        else
            log_success "Settings file is not tracked in git"
        fi
    fi
    
    # Check Fail2ban status
    if is_service_running "bw_fail2ban"; then
        local f2b_id
        f2b_id=$(get_container_id "bw_fail2ban")
        local banned_count
        banned_count=$(docker exec "$f2b_id" fail2ban-client status 2>/dev/null | grep -c "Banned" || echo "0")
        log_info "Fail2ban has banned $banned_count IPs"
    fi
    
    echo ""
}

# Network diagnostics
run_network_diagnostics() {
    echo -e "${BOLD}=== NETWORK DIAGNOSTICS ===${NC}"
    
    # Test external connectivity
    log_info "Testing external connectivity..."
    
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
    fi
    
    # Internal connectivity
    test_internal_connectivity
    
    echo ""
}

# Performance diagnostics
run_performance_diagnostics() {
    echo -e "${BOLD}=== PERFORMANCE DIAGNOSTICS ===${NC}"
    
    if is_stack_running; then
        # Container resource usage
        echo -e "${BLUE}Container Resource Usage:${NC}"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null || echo "Unable to get container stats"
        
        # Database performance check
        if is_service_running "bw_mariadb"; then
            local db_id
            db_id=$(get_container_id "bw_mariadb")
            
            echo -e "\n${BLUE}Database Status:${NC}"
            docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD:-}" -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" 2>/dev/null || echo "Unable to check database status"
        fi
    else
        log_warning "Stack not running - skipping performance checks"
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
        log_error "$total_issues issues detected (requires attention)"
    fi
    
    echo -e "\n${BLUE}Useful Commands:${NC}"
    echo "View logs:          ./monitor.sh"
    echo "Performance stats:  ./perf-monitor.sh status"
    echo "Restart services:   docker compose restart"
    echo "Update config:      ./startup.sh"
    echo "Manual backup:      docker compose exec bw_backup /backup/backup.sh -n"
    echo "Collect diagnostics: $0 --collect"
    
    echo -e "\nFull log: $LOG_FILE"
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
            --debug)
                export DEBUG="true"
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Diagnostic Script

Usage: $0 [OPTIONS]

Options:
    --collect       Collect diagnostic files to directory
    --system        Run only system diagnostics
    --docker        Run only Docker diagnostics
    --config        Run only configuration diagnostics
    --network       Run only network diagnostics
    --security      Run only security diagnostics
    --performance   Run only performance diagnostics
    --debug         Enable debug logging
    --help, -h      Show this help message

Examples:
    $0                    # Run all diagnostics
    $0 --docker --network # Run only Docker and network checks
    $0 --collect          # Collect diagnostic files

For detailed performance analysis, use: ./perf-monitor.sh

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    echo -e "${BOLD}${BLUE}VaultWarden-OCI Diagnostics${NC}"
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
        selected_modules=("system" "project" "docker" "config" "security" "network" "performance")
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
            *) log_warning "Unknown diagnostic module: $module" ;;
        esac
    done
    
    generate_summary
    
    log_success "Diagnostics complete!"
}

# Execute main function
main "$@"
