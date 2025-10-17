#!/usr/bin/env bash
# lib/monitoring.sh — Consolidated health checks and monitoring library with SOPS+Age integration, self-heal, and alert helpers

set -euo pipefail

# Source dependencies first
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"

# Load SOPS integration if available
SOPS_INTEGRATION_AVAILABLE=false
if [[ -f "$ROOT_DIR/lib/sops.sh" ]]; then
    source "$ROOT_DIR/lib/sops.sh"
    SOPS_INTEGRATION_AVAILABLE=true
fi

# Set logging prefix
_set_log_prefix "monitor-lib"

# Source config to get dynamic container names
if [[ -f "$ROOT_DIR/lib/config.sh" ]]; then
    source "$ROOT_DIR/lib/config.sh"
    load_config >/dev/null 2>&1 || _log_warning "Failed to load configuration for container names"
fi

# Source system library for compose helpers
if [[ -f "$ROOT_DIR/lib/system.sh" ]]; then
    source "$ROOT_DIR/lib/system.sh"
fi

# Dynamic Container Names - Enhanced with project awareness
BW_VW="${CONTAINER_NAME_VAULTWARDEN:-${COMPOSE_PROJECT_NAME:-vaultwarden}_vaultwarden}"
BW_CADDY="${CONTAINER_NAME_CADDY:-${COMPOSE_PROJECT_NAME:-vaultwarden}_caddy}"
BW_FAIL2BAN="${CONTAINER_NAME_FAIL2BAN:-${COMPOSE_PROJECT_NAME:-vaultwarden}_fail2ban}"
BW_WATCHTOWER="${CONTAINER_NAME_WATCHTOWER:-${COMPOSE_PROJECT_NAME:-vaultwarden}_watchtower}"

# Health check results tracking
declare -A HEALTH_RESULTS
WARNINGS_COUNT=0
CRITICAL_COUNT=0

record_health_result() {
    local category="$1"
    local test_name="$2" 
    local status="$3"
    local message="$4"

    HEALTH_RESULTS["${category}_${test_name}"]="$status:$message"

    case "$status" in
        "PASS")
            _log_success "✅ $category - $test_name: $message"
            ;;
        "WARN")
            _log_warning "⚠️  $category - $test_name: $message"
            ((WARNINGS_COUNT++))
            ;;
        "FAIL")
            _log_error "❌ $category - $test_name: $message"
            ((CRITICAL_COUNT++))
            ;;
        "SKIP")
            _log_info "⏭️  $category - $test_name: $message"
            ;;
    esac
}

#
# SOPS+Age Health Checks
#
check_sops_system_health() {
    _log_section "SOPS+Age System Health"

    if [[ "$SOPS_INTEGRATION_AVAILABLE" != "true" ]]; then
        record_health_result "SOPS" "Integration" "SKIP" "SOPS integration not available"
        return 0
    fi

    # Check SOPS installation
    if command -v sops >/dev/null 2>&1; then
        local sops_version
        sops_version=$(sops --version 2>&1 | head -1 || echo "unknown")
        record_health_result "SOPS" "Installation" "PASS" "SOPS available ($sops_version)"
    else
        record_health_result "SOPS" "Installation" "FAIL" "SOPS not installed"
        return 1
    fi

    # Check Age installation  
    if command -v age >/dev/null 2>&1; then
        local age_version
        age_version=$(age --version 2>&1 || echo "unknown")
        record_health_result "SOPS" "Age_Installation" "PASS" "Age available ($age_version)"
    else
        record_health_result "SOPS" "Age_Installation" "FAIL" "Age not installed"
        return 1
    fi

    # Check Age key accessibility
    local age_key_file="$ROOT_DIR/secrets/keys/age-key.txt"
    if [[ -f "$age_key_file" ]]; then
        local key_perms
        key_perms=$(stat -c "%a" "$age_key_file")
        if [[ "$key_perms" == "600" ]]; then
            record_health_result "SOPS" "Age_Key_Permissions" "PASS" "Age key has correct permissions (600)"
        else
            record_health_result "SOPS" "Age_Key_Permissions" "WARN" "Age key permissions incorrect ($key_perms, should be 600)"
        fi

        # Test Age key validity
        if age-keygen -y "$age_key_file" >/dev/null 2>&1; then
            record_health_result "SOPS" "Age_Key_Validity" "PASS" "Age key is valid"
        else
            record_health_result "SOPS" "Age_Key_Validity" "FAIL" "Age key appears corrupted"
            return 1
        fi
    else
        record_health_result "SOPS" "Age_Key_File" "FAIL" "Age private key not found"
        return 1
    fi

    # Check SOPS configuration
    local sops_config="$ROOT_DIR/.sops.yaml"
    if [[ -f "$sops_config" ]]; then
        if yq eval '.' "$sops_config" >/dev/null 2>&1; then
            record_health_result "SOPS" "Config_Syntax" "PASS" "SOPS config syntax valid"
        else
            record_health_result "SOPS" "Config_Syntax" "FAIL" "SOPS config has invalid YAML syntax"
            return 1
        fi
    else
        record_health_result "SOPS" "Config_File" "FAIL" "SOPS config file not found"
        return 1
    fi

    # Check encrypted secrets file
    local secrets_file="$ROOT_DIR/secrets/secrets.yaml"
    if [[ -f "$secrets_file" ]]; then
        # Test SOPS decryption
        if timeout 10 sops -d "$secrets_file" >/dev/null 2>&1; then
            record_health_result "SOPS" "Decryption" "PASS" "SOPS decryption working"

            # Initialize SOPS environment and load secrets
            if init_sops_environment 2>/dev/null && load_secrets 2>/dev/null; then
                record_health_result "SOPS" "Secret_Loading" "PASS" "Secrets loaded successfully"

                # Check for placeholder values
                local placeholders=()
                for secret_name in "${!DECRYPTED_SECRETS[@]}"; do
                    local secret_value="${DECRYPTED_SECRETS[$secret_name]}"
                    if [[ "$secret_value" =~ CHANGE_ME ]]; then
                        placeholders+=("$secret_name")
                    fi
                done

                if [[ ${#placeholders[@]} -eq 0 ]]; then
                    record_health_result "SOPS" "Placeholder_Check" "PASS" "No placeholder values detected"
                else
                    record_health_result "SOPS" "Placeholder_Check" "WARN" "Placeholder values found: ${placeholders[*]}"
                fi

                # Check secret age (rotation recommendation)
                local secrets_age_days
                secrets_age_days=$(( ($(date +%s) - $(stat -c %Y "$secrets_file")) / 86400 ))
                if [[ $secrets_age_days -lt 90 ]]; then
                    record_health_result "SOPS" "Secret_Age" "PASS" "Secrets age: $secrets_age_days days"
                else
                    record_health_result "SOPS" "Secret_Age" "WARN" "Secrets are $secrets_age_days days old (rotation recommended)"
                fi
            else
                record_health_result "SOPS" "Secret_Loading" "FAIL" "Failed to load decrypted secrets"
            fi
        else
            record_health_result "SOPS" "Decryption" "FAIL" "SOPS decryption failed"
            return 1
        fi
    else
        record_health_result "SOPS" "Secrets_File" "FAIL" "Encrypted secrets file not found"
        return 1
    fi

    # Check Docker secrets preparation
    local docker_secrets_dir="$ROOT_DIR/secrets/.docker_secrets"
    if [[ -d "$docker_secrets_dir" ]]; then
        local secret_count
        secret_count=$(find "$docker_secrets_dir" -type f 2>/dev/null | wc -l)
        if [[ $secret_count -gt 0 ]]; then
            record_health_result "SOPS" "Docker_Secrets" "PASS" "Docker secrets prepared ($secret_count files)"

            # Check Docker secrets permissions
            local bad_perms
            bad_perms=$(find "$docker_secrets_dir" -type f ! -perm 644 2>/dev/null | wc -l)
            if [[ $bad_perms -eq 0 ]]; then
                record_health_result "SOPS" "Docker_Secret_Perms" "PASS" "Docker secrets have correct permissions"
            else
                record_health_result "SOPS" "Docker_Secret_Perms" "WARN" "$bad_perms Docker secret files have incorrect permissions"
            fi
        else
            record_health_result "SOPS" "Docker_Secrets" "WARN" "No Docker secret files found"
        fi
    else
        record_health_result "SOPS" "Docker_Secrets_Dir" "WARN" "Docker secrets directory not found (normal if services not running)"
    fi

    return 0
}

#
# Container Health Checks
#
check_container_health() {
    _log_section "Container Health"

    if ! command -v docker >/dev/null 2>&1; then
        record_health_result "Container" "Docker_Installation" "FAIL" "Docker not installed"
        return 1
    fi

    # Check Docker daemon
    if docker info >/dev/null 2>&1; then
        record_health_result "Container" "Docker_Daemon" "PASS" "Docker daemon running"
    else
        record_health_result "Container" "Docker_Daemon" "FAIL" "Docker daemon not accessible"
        return 1
    fi

    # Check if Docker Compose project exists
    cd "$ROOT_DIR"
    if [[ -f "docker-compose.yml" ]]; then
        record_health_result "Container" "Compose_File" "PASS" "Docker Compose file present"

        # Validate Docker Compose configuration
        if docker compose config >/dev/null 2>&1; then
            record_health_result "Container" "Compose_Config" "PASS" "Docker Compose configuration valid"
        else
            record_health_result "Container" "Compose_Config" "FAIL" "Docker Compose configuration invalid"
            return 1
        fi
    else
        record_health_result "Container" "Compose_File" "FAIL" "Docker Compose file not found"
        return 1
    fi

    # Check individual container health
    local containers=("vaultwarden" "caddy" "fail2ban" "watchtower")
    local running_containers=0

    for container in "${containers[@]}"; do
        local container_name="${COMPOSE_PROJECT_NAME:-vaultwarden}_$container"

        if docker ps --format '{{.Names}}' | grep -qx "$container_name" 2>/dev/null; then
            running_containers=$((running_containers + 1))

            # Check container health
            local health_status
            health_status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_name" 2>/dev/null || echo "none")

            case "$health_status" in
                "healthy")
                    record_health_result "Container" "${container}_Health" "PASS" "$container is healthy"
                    ;;
                "unhealthy")
                    record_health_result "Container" "${container}_Health" "FAIL" "$container is unhealthy"
                    ;;
                "starting")
                    record_health_result "Container" "${container}_Health" "WARN" "$container is still starting"
                    ;;
                "none")
                    # No health check defined, check if running
                    if docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null | grep -q "running"; then
                        record_health_result "Container" "${container}_Health" "PASS" "$container is running (no health check)"
                    else
                        record_health_result "Container" "${container}_Health" "FAIL" "$container is not running"
                    fi
                    ;;
                *)
                    record_health_result "Container" "${container}_Health" "WARN" "$container has unknown health status: $health_status"
                    ;;
            esac
        else
            # Container not running - check if it should be
            if [[ "$container" == "vaultwarden" ]] || [[ "$container" == "caddy" ]]; then
                record_health_result "Container" "${container}_Running" "FAIL" "$container is not running (critical service)"
            else
                record_health_result "Container" "${container}_Running" "WARN" "$container is not running (optional service)"
            fi
        fi
    done

    # Overall container status
    if [[ $running_containers -ge 2 ]]; then
        record_health_result "Container" "Overall_Status" "PASS" "$running_containers containers running"
    else
        record_health_result "Container" "Overall_Status" "FAIL" "Only $running_containers containers running"
    fi

    return 0
}

#
# System Resource Checks
#
check_system_health() {
    _log_section "System Resources"

    # Check CPU load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')
    local cpu_cores
    cpu_cores=$(nproc)
    local load_per_core
    load_per_core=$(echo "scale=2; $load_avg / $cpu_cores" | bc -l 2>/dev/null || echo "0")

    if (( $(echo "$load_per_core < 1.0" | bc -l) )); then
        record_health_result "System" "CPU_Load" "PASS" "CPU load normal ($load_avg on $cpu_cores cores)"
    elif (( $(echo "$load_per_core < 2.0" | bc -l) )); then
        record_health_result "System" "CPU_Load" "WARN" "CPU load elevated ($load_avg on $cpu_cores cores)"
    else
        record_health_result "System" "CPU_Load" "FAIL" "CPU load critical ($load_avg on $cpu_cores cores)"
    fi

    # Check memory usage
    local mem_info
    mem_info=$(free -m)
    local total_mem used_mem mem_percent
    total_mem=$(echo "$mem_info" | awk '/^Mem:/ { print $2 }')
    used_mem=$(echo "$mem_info" | awk '/^Mem:/ { print $3 }')
    mem_percent=$(echo "scale=1; ($used_mem * 100) / $total_mem" | bc -l)

    if (( $(echo "$mem_percent < 80" | bc -l) )); then
        record_health_result "System" "Memory_Usage" "PASS" "Memory usage normal (${mem_percent}% of ${total_mem}MB)"
    elif (( $(echo "$mem_percent < 90" | bc -l) )); then
        record_health_result "System" "Memory_Usage" "WARN" "Memory usage elevated (${mem_percent}% of ${total_mem}MB)"
    else
        record_health_result "System" "Memory_Usage" "FAIL" "Memory usage critical (${mem_percent}% of ${total_mem}MB)"
    fi

    # Check disk usage
    local project_state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    if [[ -d "$project_state_dir" ]]; then
        local disk_usage
        disk_usage=$(df "$project_state_dir" | awk 'NR==2 { print $5 }' | sed 's/%//')

        if [[ $disk_usage -lt 80 ]]; then
            record_health_result "System" "Disk_Usage" "PASS" "Disk usage normal (${disk_usage}%)"
        elif [[ $disk_usage -lt 90 ]]; then
            record_health_result "System" "Disk_Usage" "WARN" "Disk usage elevated (${disk_usage}%)"
        else
            record_health_result "System" "Disk_Usage" "FAIL" "Disk usage critical (${disk_usage}%)"
        fi
    else
        record_health_result "System" "Disk_Usage" "SKIP" "Project state directory not found"
    fi

    # Check system uptime
    local uptime_seconds
    uptime_seconds=$(awk '{print int($1)}' /proc/uptime)
    local uptime_days=$((uptime_seconds / 86400))

    if [[ $uptime_days -gt 0 ]]; then
        record_health_result "System" "Uptime" "PASS" "System uptime: $uptime_days days"
    else
        record_health_result "System" "Uptime" "WARN" "System recently restarted (uptime: $((uptime_seconds / 3600)) hours)"
    fi

    return 0
}

#
# Network Health Checks
#
check_network_health() {
    _log_section "Network Health"

    # Check internet connectivity
    if timeout 10 curl -s --head https://www.google.com >/dev/null 2>&1; then
        record_health_result "Network" "Internet_Connectivity" "PASS" "Internet connectivity working"
    else
        record_health_result "Network" "Internet_Connectivity" "FAIL" "No internet connectivity"
    fi

    # Check DNS resolution
    if timeout 5 nslookup google.com >/dev/null 2>&1; then
        record_health_result "Network" "DNS_Resolution" "PASS" "DNS resolution working"
    else
        record_health_result "Network" "DNS_Resolution" "FAIL" "DNS resolution failed"
    fi

    # Check domain configuration if available
    local domain
    domain=$(get_config_value "DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$domain" ]]; then
        local clean_domain
        clean_domain=$(echo "$domain" | sed 's|https\?://||')

        # DNS resolution for configured domain
        if timeout 10 nslookup "$clean_domain" >/dev/null 2>&1; then
            record_health_result "Network" "Domain_DNS" "PASS" "Domain DNS resolution working"
        else
            record_health_result "Network" "Domain_DNS" "WARN" "Domain DNS resolution failed for $clean_domain"
        fi

        # SSL certificate check
        if timeout 15 echo | openssl s_client -connect "$clean_domain:443" -servername "$clean_domain" 2>/dev/null | openssl x509 -noout -dates >/dev/null 2>&1; then
            record_health_result "Network" "SSL_Certificate" "PASS" "SSL certificate accessible"

            # Check certificate expiration
            local cert_end_date
            cert_end_date=$(echo | openssl s_client -connect "$clean_domain:443" -servername "$clean_domain" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
            if [[ -n "$cert_end_date" ]]; then
                local cert_end_epoch
                cert_end_epoch=$(date -d "$cert_end_date" +%s 2>/dev/null || echo "0")
                local current_epoch
                current_epoch=$(date +%s)
                local days_until_expiry=$(( (cert_end_epoch - current_epoch) / 86400 ))

                if [[ $days_until_expiry -gt 30 ]]; then
                    record_health_result "Network" "SSL_Expiry" "PASS" "SSL certificate valid for $days_until_expiry days"
                elif [[ $days_until_expiry -gt 7 ]]; then
                    record_health_result "Network" "SSL_Expiry" "WARN" "SSL certificate expires in $days_until_expiry days"
                else
                    record_health_result "Network" "SSL_Expiry" "FAIL" "SSL certificate expires in $days_until_expiry days"
                fi
            fi
        else
            record_health_result "Network" "SSL_Certificate" "WARN" "SSL certificate check failed for $clean_domain"
        fi

        # HTTP/HTTPS connectivity test
        if timeout 15 curl -s --head "$domain" >/dev/null 2>&1; then
            record_health_result "Network" "HTTP_Connectivity" "PASS" "HTTP/HTTPS connectivity working"
        else
            record_health_result "Network" "HTTP_Connectivity" "WARN" "HTTP/HTTPS connectivity failed for $domain"
        fi
    else
        record_health_result "Network" "Domain_Config" "SKIP" "No domain configured"
    fi

    return 0
}

#
# Backup Health Checks
#
check_backup_health() {
    _log_section "Backup Health"

    local backup_base_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"

    # Check database backups
    local db_backup_dir="$backup_base_dir/db"
    if [[ -d "$db_backup_dir" ]]; then
        local recent_db_backups
        recent_db_backups=$(find "$db_backup_dir" -name "*.gpg" -mtime -2 2>/dev/null | wc -l)

        if [[ $recent_db_backups -gt 0 ]]; then
            record_health_result "Backup" "Database_Backups" "PASS" "$recent_db_backups recent database backup(s)"
        else
            record_health_result "Backup" "Database_Backups" "WARN" "No recent database backups found"
        fi

        # Check backup retention
        local total_db_backups
        total_db_backups=$(find "$db_backup_dir" -name "*.gpg" 2>/dev/null | wc -l)
        record_health_result "Backup" "DB_Backup_Count" "PASS" "$total_db_backups total database backups"
    else
        record_health_result "Backup" "Database_Backup_Dir" "WARN" "Database backup directory not found"
    fi

    # Check full system backups
    local full_backup_dir="$backup_base_dir/full"
    if [[ -d "$full_backup_dir" ]]; then
        local recent_full_backups
        recent_full_backups=$(find "$full_backup_dir" -name "*.tar.gz" -mtime -8 2>/dev/null | wc -l)

        if [[ $recent_full_backups -gt 0 ]]; then
            record_health_result "Backup" "Full_Backups" "PASS" "$recent_full_backups recent full backup(s)"
        else
            record_health_result "Backup" "Full_Backups" "WARN" "No recent full backups found"
        fi
    else
        record_health_result "Backup" "Full_Backup_Dir" "WARN" "Full backup directory not found"
    fi

    # Age key backup validation (if SOPS available)
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
        local age_key_file="$ROOT_DIR/secrets/keys/age-key.txt"
        if [[ -f "$age_key_file" ]]; then
            record_health_result "Backup" "Age_Key_Present" "PASS" "Age private key file present"

            # Check if backup instructions exist
            local secrets_readme="$ROOT_DIR/secrets/README.md"
            if [[ -f "$secrets_readme" ]]; then
                record_health_result "Backup" "Backup_Documentation" "PASS" "Backup documentation available"
            else
                record_health_result "Backup" "Backup_Documentation" "WARN" "Age key backup documentation missing"
            fi
        else
            record_health_result "Backup" "Age_Key_Present" "FAIL" "Age private key file missing"
        fi
    fi

    return 0
}

#
# Service Integration Checks
#
check_service_integration() {
    _log_section "Service Integration"

    # Check VaultWarden admin interface
    local domain
    domain=$(get_config_value "DOMAIN" 2>/dev/null || echo "")
    if [[ -n "$domain" ]]; then
        local admin_url="$domain/admin"
        if timeout 15 curl -s --head "$admin_url" | grep -q "HTTP.*[23]"; then
            record_health_result "Service" "VW_Admin_Interface" "PASS" "VaultWarden admin interface accessible"
        else
            record_health_result "Service" "VW_Admin_Interface" "WARN" "VaultWarden admin interface not accessible"
        fi

        # Check main VaultWarden interface
        if timeout 15 curl -s --head "$domain" | grep -q "HTTP.*[23]"; then
            record_health_result "Service" "VW_Web_Interface" "PASS" "VaultWarden web interface accessible"
        else
            record_health_result "Service" "VW_Web_Interface" "WARN" "VaultWarden web interface not accessible"
        fi
    else
        record_health_result "Service" "Domain_Config" "SKIP" "No domain configured for interface testing"
    fi

    # Check if secrets are properly mounted in containers
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]] && docker ps --format '{{.Names}}' | grep -q "vaultwarden"; then
        local vw_container
        vw_container=$(docker ps --format '{{.Names}}' | grep "vaultwarden" | head -1)

        if docker exec "$vw_container" test -f "/run/secrets/admin_token" 2>/dev/null; then
            record_health_result "Service" "Secret_Mounting" "PASS" "Docker secrets mounted in VaultWarden container"
        else
            record_health_result "Service" "Secret_Mounting" "WARN" "Docker secrets may not be mounted properly"
        fi
    fi

    # Check log accessibility
    local log_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs"
    if [[ -d "$log_dir" ]]; then
        local log_files
        log_files=$(find "$log_dir" -name "*.log" -mtime -1 2>/dev/null | wc -l)
        if [[ $log_files -gt 0 ]]; then
            record_health_result "Service" "Log_Files" "PASS" "$log_files recent log file(s) found"
        else
            record_health_result "Service" "Log_Files" "WARN" "No recent log files found"
        fi
    else
        record_health_result "Service" "Log_Directory" "WARN" "Log directory not found"
    fi

    return 0
}

#
# Self-Healing and Alerting
#
alert_on_sops_failures() {
    local failure_type="$1"
    local failure_details="$2"

    _log_error "SOPS FAILURE ALERT: $failure_type"
    _log_error "Details: $failure_details"

    # Send email alert if configured
    local admin_email
    admin_email=$(get_config_value "ADMIN_EMAIL" 2>/dev/null || echo "")

    if [[ -n "$admin_email" ]]; then
        local subject="VaultWarden SOPS FAILURE: $failure_type"
        local body="CRITICAL ALERT: VaultWarden SOPS+Age system failure detected

Failure Type: $failure_type
Details: $failure_details
Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Host: $(hostname)

IMMEDIATE ACTION REQUIRED:
1. Check Age key integrity: ls -la secrets/keys/age-key.txt
2. Test SOPS decryption: sops -d secrets/secrets.yaml
3. Run health check: ./tools/check-health.sh --sops-only
4. Review logs: docker compose logs

If Age key is lost/corrupted:
1. STOP all services immediately: docker compose down
2. Restore Age key from backup: ./tools/backup-recovery.sh restore-age-key
3. Verify recovery: ./tools/check-health.sh
4. Restart services: ./startup.sh

Recovery Documentation: docs/DISASTER-RECOVERY.md"

        # Use send_mail function if available, otherwise use mail command
        if declare -f send_mail >/dev/null 2>&1; then
            send_mail "$subject" "$body"
        elif command -v mail >/dev/null 2>&1; then
            echo "$body" | mail -s "$subject" "$admin_email"
        else
            _log_warning "Cannot send email alert - no mail system available"
        fi
    fi
}

self_heal_once() {
    local wait="${1:-15}"

    _log_info "Starting self-heal procedure..."

    # Step 1: Ensure SOPS+Age is healthy first
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
        if ! monitor_age_key_accessibility || ! monitor_sops_decryption_health; then
            _log_error "SOPS+Age system unhealthy - cannot proceed with container healing"
            alert_on_sops_failures "Self-Heal Blocked" "SOPS+Age system must be healthy before container healing"
            return 1
        fi
    fi

    _log_info "Self-heal step 1: compose up -d"
    (cd "$ROOT_DIR" && docker compose up -d --remove-orphans) || _log_error "compose up failed"
    sleep "$wait"

    # Check if stack is healthy after compose up
    if stack_is_healthy; then
        _log_success "Self-heal successful after compose up"
        return 0
    fi

    _log_info "Self-heal step 2: compose restart"
    (cd "$ROOT_DIR" && docker compose restart) || _log_error "compose restart failed"
    sleep "$wait"

    # Check if stack is healthy after restart
    if stack_is_healthy; then
        _log_success "Self-heal successful after compose restart"
        return 0
    fi

    _log_info "Self-heal step 3: compose reset (down + up)"
    (cd "$ROOT_DIR" && docker compose down) || true
    sleep 5
    (cd "$ROOT_DIR" && docker compose up -d --remove-orphans) || _log_error "compose reset failed"
    sleep "$wait"

    # Final health check
    if stack_is_healthy; then
        _log_success "Self-heal successful after compose reset"
        return 0
    else
        _log_error "Self-heal failed - manual intervention required"
        return 1
    fi
}

# Library initialization
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "Consolidated lib/monitoring.sh loaded successfully"
    _log_debug "SOPS integration: $([[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]] && echo "Available" || echo "Not available")"
else
    _log_warning "lib/monitoring.sh should be sourced, not executed directly"
    echo "Running monitoring library test..."
    check_sops_system_health
    check_container_health
    check_system_health
fi