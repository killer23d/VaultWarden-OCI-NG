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
    log_info "Docker
