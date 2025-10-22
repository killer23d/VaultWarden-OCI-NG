#!/usr/bin/env bash
# lib/monitoring.sh — Consolidated health checks and monitoring library with SOPS+Age integration, self-heal, and alert helpers

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[monitoring.sh][INFO] $*"; }
    log_warn() { echo "[monitoring.sh][WARN] $*"; }
    log_error() { echo "[monitoring.sh][ERROR] $*" >&2; }
    log_success() { echo "[monitoring.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    _set_log_prefix() { :; } # Define dummy _set_log_prefix
fi

# Set logging prefix early
_set_log_prefix "monitor-lib"

# Load SOPS integration (optional, checked via flag)
SOPS_INTEGRATION_AVAILABLE=false
if [[ -f "$LIB_DIR/sops.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/sops.sh"
    SOPS_INTEGRATION_AVAILABLE=true
else
    log_warn "SOPS library (lib/sops.sh) not found. SOPS health checks disabled."
fi

# Source config (critical)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
         log_warn "Failed to load project configuration via lib/config.sh. Using defaults."
         # Define defaults if needed, or rely on script defaults
         COMPOSE_PROJECT_NAME="vaultwarden"
    fi
else
    log_error "CRITICAL: Configuration library (lib/config.sh) not found."
    # Handle error or exit if config is essential
    exit 1
fi

# Source system library (optional for compose helpers, checked via flag)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
     log_warn "System library (lib/system.sh) not found. Service helpers unavailable, using fallback checks."
fi

# --- Library functions follow ---


# Dynamic Container Names - Use defaults if config loading failed or vars not set
# Use get_config_value for safer access to potentially unset vars
BW_VW=$(get_config_value "CONTAINER_NAME_VAULTWARDEN" "${COMPOSE_PROJECT_NAME:-vaultwarden}_vaultwarden")
BW_CADDY=$(get_config_value "CONTAINER_NAME_CADDY" "${COMPOSE_PROJECT_NAME:-vaultwarden}_caddy")
BW_FAIL2BAN=$(get_config_value "CONTAINER_NAME_FAIL2BAN" "${COMPOSE_PROJECT_NAME:-vaultwarden}_fail2ban")
BW_WATCHTOWER=$(get_config_value "CONTAINER_NAME_WATCHTOWER" "${COMPOSE_PROJECT_NAME:-vaultwarden}_watchtower")
BW_DDCLIENT=$(get_config_value "CONTAINER_NAME_DDCLIENT" "${COMPOSE_PROJECT_NAME:-vaultwarden}_ddclient") # Added ddclient

_log_debug "Using container name mappings: VW=$BW_VW, CADDY=$BW_CADDY, F2B=$BW_FAIL2BAN, WT=$BW_WATCHTOWER, DD=$BW_DDCLIENT"

# Health check results tracking
declare -A HEALTH_RESULTS
WARNINGS_COUNT=0
CRITICAL_COUNT=0

# Helper to reset counts for reuse (e.g., in monitor loops)
reset_health_counts() {
    HEALTH_RESULTS=()
    WARNINGS_COUNT=0
    CRITICAL_COUNT=0
    _log_debug "Health counts reset."
}

# Records health check results and logs them appropriately.
# Accepts: category, test_name, status (PASS|WARN|FAIL|SKIP), message
record_health_result() {
    # Validate input count
    if [[ $# -ne 4 ]]; then
        log_error "[Internal Error] record_health_result requires 4 arguments, got $#."
        return 1
    fi

    local category="$1"
    local test_name="$2"
    local status="$3" # Should be PASS, WARN, FAIL, SKIP
    local message="$4"
    local status_icon="❓" log_func="_log_debug" # Default log level is debug

    # Sanitize inputs (basic)
    category=${category//[^a-zA-Z0-9_]/}
    test_name=${test_name//[^a-zA-Z0-9_]/}
    message=${message//$'\n'/ } # Replace newlines with spaces

    case "$status" in
        "PASS")
            status_icon="✅"
            log_func="log_success" # Log success at info level
            _log_debug "$status_icon $category - $test_name: $message" # Keep debug log too
            ;;
        "WARN")
            status_icon="⚠️"
            log_func="log_warn"
            ((WARNINGS_COUNT++))
            ;;
        "FAIL")
            status_icon="❌"
            log_func="log_error"
            ((CRITICAL_COUNT++))
            ;;
        "SKIP")
            status_icon="⏭️"
            log_func="log_info"
            ;;
        *) # Handle unexpected status
            log_error "[Internal Error] Unknown status '$status' for $category - $test_name"
            status="UNKN" # Mark as Unknown
            status_icon="❓"
            log_func="log_error"
            ((CRITICAL_COUNT++))
           ;;
    esac

    # Log using the determined function and level
    "$log_func" "$status_icon $category - $test_name: $message"

    # Store result regardless of logging level
    HEALTH_RESULTS["${category}_${test_name}"]="$status:$message"
}


#
# SOPS+Age Health Checks
#
check_sops_system_health() {
    _log_section "SOPS+Age System Health"

    if [[ "$SOPS_INTEGRATION_AVAILABLE" != "true" ]]; then
        record_health_result "SOPS" "Integration" "SKIP" "SOPS library (lib/sops.sh) not available"
        return 0 # Not a failure of SOPS itself, just not used
    fi

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check SOPS installation
    if "$check_cmd_func" sops >/dev/null 2>&1; then
        local sops_version
        sops_version=$(sops --version 2>&1 | head -1 || echo "unknown version")
        record_health_result "SOPS" "Installation" "PASS" "SOPS command available ($sops_version)"
    else
        record_health_result "SOPS" "Installation" "FAIL" "SOPS command not found. Secrets cannot be managed."
        return 1 # Critical failure
    fi

    # Check Age installation
    if "$check_cmd_func" age >/dev/null 2>&1 && "$check_cmd_func" age-keygen >/dev/null 2>&1; then
        local age_version
        age_version=$(age --version 2>&1 || echo "unknown version")
        record_health_result "SOPS" "Age_Installation" "PASS" "Age commands available ($age_version)"
    else
        record_health_result "SOPS" "Age_Installation" "FAIL" "Age command (age/age-keygen) not found. Secrets cannot be decrypted."
        return 1 # Critical failure
    fi

    # Check Age key accessibility and permissions (use constant AGE_KEY_FILE from sops.sh)
    if [[ -f "$AGE_KEY_FILE" ]]; then
        if [[ -r "$AGE_KEY_FILE" ]]; then
             record_health_result "SOPS" "Age_Key_Readable" "PASS" "Age key file exists and is readable: $AGE_KEY_FILE"
             local key_perms
             key_perms=$(stat -c "%a" "$AGE_KEY_FILE" 2>/dev/null) || key_perms="unknown"
             if [[ "$key_perms" =~ ^[46]00$ ]]; then # Allow 600 or 400
                 record_health_result "SOPS" "Age_Key_Permissions" "PASS" "Age key has secure permissions ($key_perms)"
             else
                 record_health_result "SOPS" "Age_Key_Permissions" "FAIL" "Age key permissions incorrect ($key_perms, MUST be 600 or 400)"
                 # This is critical, decryption will likely fail system-wide
             fi
        else
             record_health_result "SOPS" "Age_Key_Readable" "FAIL" "Age key file exists but is not readable: $AGE_KEY_FILE"
             return 1 # Critical failure if not readable
        fi

        # Test Age key validity (basic check by generating public key)
        if age-keygen -y "$AGE_KEY_FILE" >/dev/null 2>&1; then
            record_health_result "SOPS" "Age_Key_Validity" "PASS" "Age private key is syntactically valid"
        else
            record_health_result "SOPS" "Age_Key_Validity" "FAIL" "Age private key appears corrupted or invalid"
            return 1 # Critical failure
        fi
    else
        record_health_result "SOPS" "Age_Key_File" "FAIL" "Age private key file not found at '$AGE_KEY_FILE'"
        return 1 # Critical failure
    fi

    # Check SOPS configuration file presence (use constant SOPS_CONFIG from sops.sh)
    if [[ -f "$SOPS_CONFIG" ]]; then
        record_health_result "SOPS" "Config_File" "PASS" "SOPS config file found: $SOPS_CONFIG"
        # Basic syntax check if yq available
        if "$check_cmd_func" yq >/dev/null 2>&1; then
            if yq eval '.' "$SOPS_CONFIG" >/dev/null 2>&1; then
                record_health_result "SOPS" "Config_Syntax" "PASS" "SOPS config syntax appears valid"
            else
                record_health_result "SOPS" "Config_Syntax" "FAIL" "SOPS config file '$SOPS_CONFIG' has invalid YAML syntax"
                # Continue checks, but decryption might fail if syntax is bad
            fi
        else
             record_health_result "SOPS" "Config_Syntax" "SKIP" "SOPS config found, but yq not available for syntax check"
        fi
    else
        # If .sops.yaml is missing, SOPS might still work if env vars are set, but it's non-standard for this project
        record_health_result "SOPS" "Config_File" "WARN" "SOPS config file not found at '$SOPS_CONFIG'. Relying on environment variables or defaults."
        # Don't fail hard, but warn
    fi

    # Check encrypted secrets file presence (use constant SECRETS_FILE from sops.sh)
    if [[ -f "$SECRETS_FILE" ]]; then
        record_health_result "SOPS" "Secrets_File_Presence" "PASS" "Encrypted secrets file found: $SECRETS_FILE"
        # Test SOPS decryption (most important check)
        # Use timeout for safety
        if timeout 10 sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
            record_health_result "SOPS" "Decryption" "PASS" "SOPS decryption test successful for '$SECRETS_FILE'"

            # Load secrets into memory to check for placeholders only if decryption worked
            # Use load_secrets function from sops.sh (it's idempotent)
            if load_secrets; then
                record_health_result "SOPS" "Secret_Loading" "PASS" "Secrets loaded into memory successfully"

                # Check for common placeholder values using get_secret
                local placeholders=()
                # Check critical secrets for placeholders or emptiness
                local secrets_to_check=("admin_token" "admin_basic_auth_hash" "smtp_password" "backup_passphrase") # Add others as needed
                for secret_name in "${secrets_to_check[@]}"; do
                     # Skip check if secret isn't expected (e.g., SMTP not configured)
                     if [[ "$secret_name" == "smtp_password" && -z $(get_config_value "SMTP_HOST") ]]; then continue; fi
                     # ... add similar checks for PUSH keys, CF token if needed

                    local secret_value
                    secret_value=$(get_secret "$secret_name" || echo "__MISSING__") # Get value or marker

                    if [[ "$secret_value" == "__MISSING__" ]]; then
                        placeholders+=("$secret_name=MISSING")
                    # Check for CHANGE_ME variations and specific empty required fields
                    elif [[ "$secret_value" =~ CHANGE_ME|PASTE_[A-Z_]+_HERE|\[auto-generated|\[auto-bcrypt ]] || \
                         ( [[ "$secret_name" == "admin_token" || "$secret_name" == "admin_basic_auth_hash" ]] && [[ -z "$secret_value" ]] ); then
                        placeholders+=("$secret_name=PLACEHOLDER")
                    fi
                done

                if [[ ${#placeholders[@]} -eq 0 ]]; then
                    record_health_result "SOPS" "Placeholder_Check" "PASS" "No placeholder or empty required values detected in critical secrets"
                else
                    record_health_result "SOPS" "Placeholder_Check" "WARN" "Placeholder, missing, or empty values found in critical secrets: ${placeholders[*]}"
                fi

                # Check secret modification time (recommend rotation) - optional check
                 local secrets_mtime secrets_age_days
                 secrets_mtime=$(stat -c %Y "$SECRETS_FILE" 2>/dev/null || date +%s) # Get mod time or current time
                 secrets_age_days=$(( ($(date +%s) - secrets_mtime) / 86400 ))
                 if [[ $secrets_age_days -lt 90 ]]; then
                     record_health_result "SOPS" "Secret_Age" "PASS" "Secrets file last modified $secrets_age_days days ago"
                 elif [[ $secrets_age_days -lt 180 ]]; then
                     record_health_result "SOPS" "Secret_Age" "WARN" "Secrets file last modified $secrets_age_days days ago (consider rotating secrets soon)"
                 else
                     record_health_result "SOPS" "Secret_Age" "FAIL" "Secrets file last modified $secrets_age_days days ago (rotation overdue!)"
                 fi
            else
                record_health_result "SOPS" "Secret_Loading" "FAIL" "Failed to load decrypted secrets into memory after successful decryption test. Check yq availability and YAML format."
                # Don't fail hard here, decryption itself worked
            fi
            # Note: load_secrets keeps secrets loaded. Reset if desired: SECRETS_LOADED=false; DECRYPTED_SECRETS=()

        else
            record_health_result "SOPS" "Decryption" "FAIL" "SOPS decryption test failed for '$SECRETS_FILE'. Check Age key, file integrity, and sops config."
            return 1 # Critical failure
        fi
    else
        # Secrets file missing is only critical if SOPS is expected to be used
        record_health_result "SOPS" "Secrets_File_Presence" "WARN" "Encrypted secrets file not found at '$SECRETS_FILE'. Normal if not yet configured."
        # Don't return 1 here, maybe first run
    fi

    # Check Docker secrets directory and permissions (should exist after startup.sh runs prepare_docker_secrets)
    local docker_secrets_dir="$PROJECT_ROOT/secrets/.docker_secrets" # Use constant if defined elsewhere
    if [[ -d "$docker_secrets_dir" ]]; then
        local secret_file_count
        secret_file_count=$(find "$docker_secrets_dir" -type f 2>/dev/null | wc -l)
        if [[ $secret_file_count -gt 0 ]]; then
            record_health_result "SOPS" "Docker_Secrets_Prepared" "PASS" "Docker secrets directory exists and contains files ($secret_file_count)"

            # Check permissions are strictly 600 or 400
            local bad_perms_files
            bad_perms_files=$(find "$docker_secrets_dir" -type f ! -perm 600 ! -perm 400 -print -quit 2>/dev/null) # Find first bad one quickly
            if [[ -z "$bad_perms_files" ]]; then
                record_health_result "SOPS" "Docker_Secret_Perms" "PASS" "Docker secrets have secure permissions (600 or 400)"
            else
                record_health_result "SOPS" "Docker_Secret_Perms" "WARN" "At least one Docker secret file has incorrect permissions (e.g., '$bad_perms_files'). Expected 600 or 400."
                # Attempt to fix permissions? Needs sudo. Skip auto-fix in monitoring lib.
                 # if [[ "$DRY_RUN:-false}" != "true" ]]; then
                 #     log_info "Attempting to fix Docker secret permissions..."
                 #     sudo find "$docker_secrets_dir" -type f -exec chmod 600 {} \; || log_error "Failed to fix permissions."
                 # fi
            fi
        else
            record_health_result "SOPS" "Docker_Secrets_Prepared" "WARN" "Docker secrets directory exists but is empty. Run startup.sh?"
        fi
    else
        record_health_result "SOPS" "Docker_Secrets_Dir" "WARN" "Docker secrets directory not found ($docker_secrets_dir). Run startup.sh?"
    fi

    # Check overall SOPS health based on critical failures accumulated
    local final_sops_status=0
     for key in "${!HEALTH_RESULTS[@]}"; do
         # Iterate over results for this category
         if [[ $key == SOPS_* ]] && [[ ${HEALTH_RESULTS[$key]} == FAIL* ]]; then
             final_sops_status=1 # Mark as failed if any SOPS check failed critically
             break
         fi
     done
     return $final_sops_status # Return 0 if OK, 1 if any critical SOPS failure
}


#
# Container Health Checks
#
check_container_health() {
    _log_section "Container Health"

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    if ! "$check_cmd_func" docker >/dev/null 2>&1; then
        record_health_result "Container" "Docker_Installation" "FAIL" "Docker command not found."
        return 1
    fi

    # Check Docker daemon accessibility
    if timeout 10 docker info >/dev/null 2>&1; then
        record_health_result "Container" "Docker_Daemon" "PASS" "Docker daemon accessible"
    else
        record_health_result "Container" "Docker_Daemon" "FAIL" "Docker daemon not accessible or timed out"
        return 1 # Cannot check containers if daemon is down
    fi

    # Check Docker Compose plugin
    if docker compose version >/dev/null 2>&1; then
         record_health_result "Container" "Docker_Compose" "PASS" "Docker Compose plugin available"
    else
         # Check for legacy docker-compose
         if "$check_cmd_func" docker-compose >/dev/null 2>&1; then
              record_health_result "Container" "Docker_Compose" "WARN" "Using legacy docker-compose (v1). Recommend upgrading to plugin (v2)."
         else
              record_health_result "Container" "Docker_Compose" "FAIL" "Docker Compose command (plugin or legacy) not found."
              return 1
         fi
    fi


    # Check if Docker Compose project file exists
    cd "$PROJECT_ROOT" # Ensure we are in the project root
    local compose_file="docker-compose.yml" # Use constant if defined
    if [[ -f "$compose_file" ]]; then
        record_health_result "Container" "Compose_File" "PASS" "Docker Compose file present: $compose_file"

        # Validate Docker Compose configuration syntax using timeout
        if timeout 15 docker compose config >/dev/null 2>&1; then
            record_health_result "Container" "Compose_Config" "PASS" "Docker Compose configuration syntax valid"
        else
            record_health_result "Container" "Compose_Config" "FAIL" "Docker Compose configuration invalid syntax or command timed out"
            return 1 # Cannot proceed if config is broken
        fi
    else
        record_health_result "Container" "Compose_File" "FAIL" "Docker Compose file not found: $compose_file"
        return 1 # Cannot check containers without the file
    fi

    # Check individual container health using docker compose ps --format json
    _log_debug "Checking status of services defined in compose file..."
    local compose_ps_json compose_ps_rc=0
    # Use timeout for ps command
    compose_ps_json=$(timeout 20 docker compose ps --format json 2>&1) || compose_ps_rc=$?

    if [[ $compose_ps_rc -ne 0 ]]; then
         record_health_result "Container" "Compose_PS" "FAIL" "Failed to get container status via 'docker compose ps' (rc=$compose_ps_rc)."
         _log_debug "Compose PS Output/Error: $compose_ps_json"
         return 1
    fi

    # Check if jq is available for parsing
    if ! "$check_cmd_func" jq >/dev/null 2>&1; then
         record_health_result "Container" "JQ_Check" "FAIL" "jq command not found. Cannot parse container status."
         return 1
    fi

    # Dynamically get services actually defined in compose file to check against
    local defined_services
    defined_services=$(docker compose config --services 2>/dev/null || echo "")
    if [[ -z "$defined_services" ]]; then
        record_health_result "Container" "Service_Discovery" "FAIL" "Could not determine services defined in compose file."
        return 1
    fi

    local running_containers=0 unhealthy_containers=0 expected_running=0
    local service service_info container_status health_status is_enabled enabled_var_name

    for service in $defined_services; do
         expected_running=$((expected_running + 1)) # Count this as an expected service

         # Extract info for this service from the JSON output
         service_info=$(echo "$compose_ps_json" | jq --arg svc "$service" '.[] | select(.Service == $svc)' 2>/dev/null || echo "{}")

         if [[ -z "$service_info" || "$service_info" == "{}" ]]; then
              # No container found for this service definition
              # Check if the service should be enabled based on config (e.g., DDCLIENT_ENABLED)
              enabled_var_name=$(echo "${service}_ENABLED" | tr '[:lower:]' '[:upper:]' | sed 's/-/_/g') # e.g., DDCLIENT_ENABLED
              is_enabled=$(get_config_value "$enabled_var_name" "true") # Assume enabled unless explicitly false

              if [[ "$is_enabled" == "true" ]]; then
                  # Only fail critical services (vaultwarden, caddy)
                  if [[ "$service" == "vaultwarden" || "$service" == "caddy" ]]; then
                       record_health_result "Container" "${service}_Running" "FAIL" "$service container is not running (critical service)"
                  elif [[ "$service" == "watchtower" && "$(docker compose config 2>/dev/null)" =~ "monitor-only|run-once" ]]; then
                       # Special case: run-once watchtower might not be running, that's okay
                       record_health_result "Container" "${service}_Running" "SKIP" "$service container (run-once mode) is not running (expected)"
                       expected_running=$((expected_running - 1)) # Don't count it towards expected running
                  else
                       record_health_result "Container" "${service}_Running" "WARN" "$service container is not running (optional/utility service)"
                  fi
              else
                   record_health_result "Container" "${service}_Running" "SKIP" "$service container is not running (disabled in config via $enabled_var_name=false)"
                   expected_running=$((expected_running - 1)) # Don't count disabled services
              fi
              continue # Move to next service
         fi

         # Container found, check its state and health
         container_status=$(echo "$service_info" | jq -r '.State // "unknown"')
         health_status=$(echo "$service_info" | jq -r '.Health // "none"') # Health can be empty string if starting/no check

         if [[ "$container_status" == "running" ]]; then
            running_containers=$((running_containers + 1))

            case "$health_status" in
                "healthy")
                    record_health_result "Container" "${service}_Health" "PASS" "$service is running and healthy"
                    ;;
                "unhealthy")
                    record_health_result "Container" "${service}_Health" "FAIL" "$service is running but unhealthy"
                    unhealthy_containers=$((unhealthy_containers + 1))
                    ;;
                "starting"|"" ) # Starting or no health check defined/running yet
                    record_health_result "Container" "${service}_Health" "WARN" "$service is running but starting or health status pending"
                    ;;
                "none") # Explicitly no health check defined
                    record_health_result "Container" "${service}_Health" "PASS" "$service is running (no health check defined)"
                    ;;
                *) # Unknown health status string
                    record_health_result "Container" "${service}_Health" "WARN" "$service is running with unknown health status: '$health_status'"
                    ;;
            esac
         else
             # Container exists but is not running
             record_health_result "Container" "${service}_Running" "FAIL" "$service container exists but is not running (State: $container_status)"
         fi
    done

    # Overall container status summary
    # Handle case where expected_running might be 0 if all services are disabled/skipped
    if [[ $expected_running -eq 0 ]]; then
         record_health_result "Container" "Overall_Status" "PASS" "No services expected to be running or all are disabled."
    elif [[ $running_containers -eq $expected_running ]]; then
         if [[ $unhealthy_containers -eq 0 ]]; then
             record_health_result "Container" "Overall_Status" "PASS" "All $expected_running expected services are running and appear healthy"
         else
              record_health_result "Container" "Overall_Status" "FAIL" "$running_containers/$expected_running services running, but $unhealthy_containers are unhealthy"
         fi
    elif [[ $running_containers -gt 0 ]]; then
         record_health_result "Container" "Overall_Status" "WARN" "Only $running_containers/$expected_running expected services are running"
    else
         record_health_result "Container" "Overall_Status" "FAIL" "No expected services are running ($expected_running expected)"
    fi

    # Check for orphaned containers (optional, complex to do reliably with labels only)

    # Determine overall container health status code (0 = OK, 1 = Failure)
    local final_container_status=0
    for key in "${!HEALTH_RESULTS[@]}"; do
        if [[ $key == Container_* ]] && [[ ${HEALTH_RESULTS[$key]} == FAIL* ]]; then
            final_container_status=1
            break
        fi
    done
    return $final_container_status
}


#
# System Resource Checks
#
check_system_health() {
    _log_section "System Resources"

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check CPU load
    local load_avg cpu_cores load_per_core load_threshold high_load_threshold
    # Default cores
    cpu_cores=1
    if "$check_cmd_func" nproc >/dev/null; then cpu_cores=$(nproc 2>/dev/null || echo 1); fi

    if uptime_output=$(uptime 2>/dev/null); then
        # Extract 1-minute load average robustly
        load_avg=$(echo "$uptime_output" | sed -n 's/.*load average: \([^,]*\).*/\1/p' | tr -d ' ' || echo "0.0")

        if "$check_cmd_func" bc >/dev/null; then
            load_per_core=$(echo "scale=2; $load_avg / $cpu_cores" | bc -l)
            load_threshold=$(echo "scale=1; $cpu_cores * 1.5" | bc) # Warning threshold
            high_load_threshold=$(echo "scale=1; $cpu_cores * 2.5" | bc) # Critical threshold

            _log_debug "CPU Load: $load_avg | Cores: $cpu_cores | Load/Core: $load_per_core | Warn > $load_threshold | Crit > $high_load_threshold"

            # Use bc for comparison
            if (( $(echo "$load_per_core > $high_load_threshold" | bc -l) )); then
                record_health_result "System" "CPU_Load" "FAIL" "CPU load critical (${load_avg} on ${cpu_cores} cores)"
            elif (( $(echo "$load_per_core > $load_threshold" | bc -l) )); then
                record_health_result "System" "CPU_Load" "WARN" "CPU load elevated (${load_avg} on ${cpu_cores} cores)"
            else
                record_health_result "System" "CPU_Load" "PASS" "CPU load normal (${load_avg} on ${cpu_cores} cores)"
            fi
        else
             record_health_result "System" "CPU_Load" "SKIP" "Cannot calculate load per core (bc command missing)"
        fi
    else
        record_health_result "System" "CPU_Load" "WARN" "Cannot determine system load via uptime command"
    fi

    # Check memory usage (prioritize MemAvailable if available)
    local mem_info total_mem used_mem available_mem mem_percent
    total_mem=0; used_mem=0; available_mem=-1; # Initialize

    if [[ -r /proc/meminfo ]]; then
         _log_debug "Reading memory info from /proc/meminfo"
         total_mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo || echo 0) # KB
         available_mem=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo || echo -1) # KB, -1 if not found
         # Calculate used = Total - Available (more accurate than 'used' from free)
         [[ "$available_mem" -ne -1 ]] && used_mem=$((total_mem - available_mem))
         total_mem=$((total_mem / 1024)) # Convert to MB
         used_mem=$((used_mem / 1024)) # Convert to MB
         available_mem=$((available_mem / 1024)) # Convert to MB
    elif "$check_cmd_func" free >/dev/null; then
         _log_debug "Reading memory info using 'free -m'"
         mem_info=$(free -m 2>/dev/null || echo "")
         total_mem=$(echo "$mem_info" | awk '/^Mem:/ { print $2 }' || echo 0)
         used_mem=$(echo "$mem_info" | awk '/^Mem:/ { print $3 }' || echo 0) # 'used' column
         # Estimate available using 'free' + 'buffers/cache' if MemAvailable wasn't found
         available_mem=$(echo "$mem_info" | awk '/^Mem:/ { print $4 + $6 }' || echo -1) # free + cache/buffers
    fi

    if [[ "$total_mem" -gt 0 ]] && [[ "$used_mem" -ge 0 ]] && "$check_cmd_func" bc >/dev/null; then
        mem_percent=$(echo "scale=1; ($used_mem * 100) / $total_mem" | bc -l)
        local available_str=""
        [[ "$available_mem" -ge 0 ]] && available_str=" (~${available_mem}MB available)" || available_str=""

        # Define thresholds (e.g., Warn > 85%, Fail > 95%)
        local warn_mem_threshold=85
        local fail_mem_threshold=95

        if (( $(echo "$mem_percent < $warn_mem_threshold" | bc -l) )); then
            record_health_result "System" "Memory_Usage" "PASS" "Memory usage normal (${mem_percent}% of ${total_mem}MB used${available_str})"
        elif (( $(echo "$mem_percent < $fail_mem_threshold" | bc -l) )); then
            record_health_result "System" "Memory_Usage" "WARN" "Memory usage elevated (${mem_percent}% of ${total_mem}MB used${available_str})"
        else
            record_health_result "System" "Memory_Usage" "FAIL" "Memory usage critical (${mem_percent}% of ${total_mem}MB used${available_str})"
        fi
    else
         record_health_result "System" "Memory_Usage" "SKIP" "Cannot calculate memory usage (check free/bc commands or /proc/meminfo access)"
    fi


    # Check disk usage for project state directory and root filesystem
    local project_state_dir=$(get_config_value "PROJECT_STATE_DIR" "/var/lib/vaultwarden") # Get from config
    local paths_to_check=("/" "$project_state_dir")
    local unique_paths=() # Array to hold unique mount points

    # Find unique mount points for paths to check
    local path mp df_output
    for path in "${paths_to_check[@]}"; do
        # Ensure path exists before checking mount point
        [[ ! -e "$path" ]] && continue
        # Get mount point for the path
        mp=$(df -P "$path" 2>/dev/null | awk 'NR==2{print $NF}') || continue
        # Add mount point to unique list if not already present
        [[ -n "$mp" ]] && ! [[ " ${unique_paths[*]} " =~ " $mp " ]] && unique_paths+=("$mp")
    done
    _log_debug "Unique mount points to check disk usage for: ${unique_paths[*]}"


    for mp in "${unique_paths[@]}"; do
         local path_label disk_usage available_space available_human disk_info
         path_label=$( [[ "$mp" == "/" ]] && echo "RootFS" || echo "FS_$(basename "$mp")" ) # Label for clarity

         # df POSIX standard flags for better compatibility, use block size 1K
         if disk_info=$(df -Pk "$mp" 2>/dev/null | awk 'NR==2'); then
             disk_usage=$(echo "$disk_info" | awk '{ print $5 }' | sed 's/%//')
             available_space=$(echo "$disk_info" | awk '{ print $4 }') # Available KB
             available_human=""
             # Use numfmt for human readable size if available
              if "$check_cmd_func" numfmt >/dev/null 2>&1; then
                 available_human=$(numfmt --to=iec --suffix=B $((available_space * 1024)) 2>/dev/null || echo "${available_space}K")
              else
                 available_human="${available_space}K"
              fi

             # Define thresholds (e.g., Warn > 85%, Fail > 95%)
             local warn_disk_threshold=85
             local fail_disk_threshold=95

             if [[ "$disk_usage" -lt $warn_disk_threshold ]]; then
                 record_health_result "System" "${path_label}_Disk_Usage" "PASS" "Disk usage normal (${disk_usage}% used, ${available_human} free on $mp)"
             elif [[ "$disk_usage" -lt $fail_disk_threshold ]]; then
                 record_health_result "System" "${path_label}_Disk_Usage" "WARN" "Disk usage elevated (${disk_usage}% used, ${available_human} free on $mp)"
             else
                 record_health_result "System" "${path_label}_Disk_Usage" "FAIL" "Disk usage critical (${disk_usage}% used, ${available_human} free on $mp)"
             fi
         else
              record_health_result "System" "${path_label}_Disk_Usage" "WARN" "Cannot determine disk usage for mount point $mp"
         fi
    done


    # Check system uptime
    local uptime_seconds uptime_days uptime_hours
    if [[ -r "/proc/uptime" ]]; then
        uptime_seconds=$(awk '{print int($1)}' /proc/uptime)
        uptime_days=$((uptime_seconds / 86400))
        uptime_hours=$(( (uptime_seconds % 86400) / 3600 ))


        if [[ $uptime_days -ge 1 ]]; then # Consider >= 1 day stable
            record_health_result "System" "Uptime" "PASS" "System uptime: $uptime_days days, $uptime_hours hours"
        else
            record_health_result "System" "Uptime" "WARN" "System recently restarted (uptime: $uptime_hours hours)"
        fi
    else
         # Fallback using 'uptime' command if /proc/uptime fails
         if uptime_output=$(uptime -p 2>/dev/null); then
             record_health_result "System" "Uptime" "PASS" "System uptime: ${uptime_output#up }" # Remove 'up ' prefix
         else
              record_health_result "System" "Uptime" "WARN" "Cannot determine system uptime"
         fi
    fi

    # Check for zombie processes (optional but good indicator of system issues)
    local zombie_count
    zombie_count=$(ps aux | awk '$8=="Z"' | wc -l)
    if [[ "$zombie_count" -eq 0 ]]; then
         record_health_result "System" "Zombie_Processes" "PASS" "No zombie processes detected"
    else
         record_health_result "System" "Zombie_Processes" "WARN" "$zombie_count zombie process(es) detected. System might need investigation."
    fi

    return 0 # System checks usually don't cause hard failure return code
}

#
# Network Health Checks (Improved SSL Check)
#
check_network_health() {
    _log_section "Network Health"

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check internet connectivity (use Cloudflare DNS as a reliable target)
    if timeout 5 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
        record_health_result "Network" "Internet_Connectivity" "PASS" "Basic internet connectivity (ping 1.1.1.1) working"
    else
        record_health_result "Network" "Internet_Connectivity" "FAIL" "No basic internet connectivity (ping 1.1.1.1 failed). Check firewall/network."
        # No point checking DNS or domain if basic connectivity fails
        return 1
    fi

    # Check DNS resolution
    # Use getent hosts for standard check, timeout for safety
    if timeout 5 getent hosts google.com >/dev/null 2>&1; then
        record_health_result "Network" "DNS_Resolution" "PASS" "DNS resolution working (resolved google.com)"
    else
        record_health_result "Network" "DNS_Resolution" "FAIL" "DNS resolution failed (check /etc/resolv.conf)"
        # Continue checks, but domain connectivity will likely fail
    fi

    # Check domain configuration if available
    local domain clean_domain
    domain=$(get_config_value "DOMAIN" "") # Get from lib/config.sh, default empty
    if [[ -n "$domain" ]]; then
        # Clean domain (remove protocol and path) - use CLEAN_DOMAIN if set by validation lib
        clean_domain=$(get_config_value "CLEAN_DOMAIN" "")
        if [[ -z "$clean_domain" ]]; then # Derive if validation lib didn't set it
            clean_domain=$(echo "$domain" | sed 's|https\?://||; s|/.*$||')
        fi
        _log_debug("Checking network health for domain: $domain (Clean: $clean_domain)")

        # DNS resolution for configured domain
        if timeout 10 getent hosts "$clean_domain" >/dev/null 2>&1; then
            record_health_result "Network" "Domain_DNS" "PASS" "Domain DNS resolution working for '$clean_domain'"
        else
            record_health_result "Network" "Domain_DNS" "WARN" "Domain DNS resolution failed for '$clean_domain'. Check DNS records."
        fi

        # SSL certificate check (using openssl s_client and x509)
        if "$check_cmd_func" openssl >/dev/null 2>&1; then
             local cert_status="FAIL"
             local cert_message="Could not connect or verify SSL certificate for $clean_domain:443"
             local days_until_expiry=-1 # Default -1 for error
             # Use constants for expiry checks if defined, else defaults
             local fail_days="${SSL_EXPIRY_FAIL_DAYS:-7}"
             local warn_days="${SSL_EXPIRY_WARN_DAYS:-30}"
             local check_end_seconds=$(( warn_days * 86400 )) # Check if expires within warn period

             # Use openssl s_client piped to x509 check, with timeout
             # Try connecting first
             if openssl s_client -connect "$clean_domain:443" -servername "$clean_domain" -showcerts -brief </dev/null >/dev/null 2>&1; then
                 _log_debug "SSL connection successful to $clean_domain:443. Checking expiry..."
                  # Get expiry date string
                  local expiry_date_str
                  expiry_date_str=$(echo | openssl s_client -connect "$clean_domain:443" -servername "$clean_domain" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')

                  if [[ -n "$expiry_date_str" ]]; then
                       # Calculate days until expiry
                       local expiry_epoch current_epoch
                       # Use 'date' command for parsing, handle potential errors
                       expiry_epoch=$(date -d "$expiry_date_str" +%s 2>/dev/null)
                       current_epoch=$(date +%s)

                       if [[ -n "$expiry_epoch" ]]; then
                            days_until_expiry=$(( (expiry_epoch - current_epoch + 86399) / 86400 )) # Round up days

                            if [[ "$days_until_expiry" -lt 0 ]]; then
                                 cert_status="FAIL"
                                 cert_message="SSL certificate has EXPIRED!"
                            elif [[ "$days_until_expiry" -lt "$fail_days" ]]; then
                                 cert_status="FAIL"
                                 cert_message="SSL certificate expires in $days_until_expiry days (CRITICAL!)"
                            elif [[ "$days_until_expiry" -lt "$warn_days" ]]; then
                                 cert_status="WARN"
                                 cert_message="SSL certificate expires in $days_until_expiry days (soon)"
                            else
                                 cert_status="PASS"
                                 cert_message="SSL certificate valid for $days_until_expiry days"
                            fi
                       else
                            cert_status="WARN"
                            cert_message="SSL certificate expiry date found ('$expiry_date_str'), but could not calculate days remaining."
                       fi
                  else
                       cert_status="WARN"
                       cert_message="SSL connection successful, but could not extract certificate expiry date."
                  fi
             else
                  # Connection failed
                  cert_status="FAIL"
                  cert_message="SSL connection failed to $clean_domain:443. Check firewall or Caddy status."
             fi
             record_health_result "Network" "SSL_Certificate" "$cert_status" "$cert_message"
        else
            record_health_result "Network" "SSL_Certificate" "SKIP" "openssl command not found. Cannot check certificate."
        fi # End openssl check

        # HTTP/HTTPS connectivity test (check if service responds via Caddy)
        # Use full DOMAIN (with protocol if provided, default https)
        local check_url="https://${clean_domain}/alive" # Check against /alive endpoint
        if "$check_cmd_func" curl >/dev/null 2>&1; then
            local http_code curl_error=""
            # Follow redirects (-L), silent (-s), output only http_code (-w), max time 15s
            http_code=$(curl -L -s -o /dev/null -w "%{http_code}" --max-time 15 "$check_url" 2>&1) || curl_error=$?

            if [[ $curl_error -eq 0 ]]; then
                if [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then
                    record_health_result "Network" "HTTP_Connectivity" "PASS" "Vaultwarden reachable at '$check_url' (HTTP $http_code)"
                else
                    record_health_result "Network" "HTTP_Connectivity" "FAIL" "Vaultwarden responded with error at '$check_url' (HTTP $http_code)"
                fi
            else
                # Curl command failed (timeout, DNS error, SSL error etc.)
                 record_health_result "Network" "HTTP_Connectivity" "FAIL" "Failed to connect to Vaultwarden at '$check_url' (curl rc=$curl_error)"
            fi
        else
             record_health_result "Network" "HTTP_Connectivity" "SKIP" "curl command not found. Cannot check HTTP connectivity."
        fi # End curl check
    else
        record_health_result "Network" "Domain_Checks" "SKIP" "No DOMAIN configured in .env. Skipping domain-specific network checks."
    fi

    return 0 # Network checks usually don't return failure code unless internet down
}


#
# Backup Health Checks
#
check_backup_health() {
    _log_section "Backup Health"

    # Use PROJECT_STATE_DIR from loaded config
    local backup_base_dir="$PROJECT_ROOT/backups" # Backups relative to project root
    local db_backup_dir="$backup_base_dir/db"
    local full_backup_dir="$backup_base_dir/full"

    # Use constants for retention if available, else defaults
    local keep_db="${DEFAULT_BACKUP_KEEP_DB:-14}"
    local keep_full="${DEFAULT_BACKUP_KEEP_FULL:-4}"

    # Check database backups
    if [[ -d "$db_backup_dir" ]]; then
        local recent_db_backups db_backup_count cutoff_db_minutes=$((2*24*60)) # 48 hours

        # Use find -mmin to check for recent files reliably
        recent_db_backups=$(find "$db_backup_dir" -maxdepth 1 -type f -name "*.age" -mmin "-${cutoff_db_minutes}" 2>/dev/null | wc -l)
        db_backup_count=$(find "$db_backup_dir" -maxdepth 1 -type f -name "*.age" 2>/dev/null | wc -l)


        if [[ $recent_db_backups -gt 0 ]]; then
            record_health_result "Backup" "Database_Recent" "PASS" "$recent_db_backups recent DB backup(s) found (last 48h)"
        else
            # Only warn if total count is also low or zero? Be strict for now.
            record_health_result "Backup" "Database_Recent" "WARN" "No recent DB backups found (last 48h)"
        fi
         record_health_result "Backup" "Database_Count" "PASS" "$db_backup_count total DB backups found (retention target: >= $keep_db)"

         # Check if count meets retention target (optional)
         # [[ $db_backup_count -lt $keep_db ]] && record_health_result "Backup" "Database_Retention" "WARN" "Low DB backup count ($db_backup_count < target $keep_db)"

    else
        record_health_result "Backup" "Database_Dir" "WARN" "Database backup directory '$db_backup_dir' not found"
    fi

    # Check full system backups
    if [[ -d "$full_backup_dir" ]]; then
        local recent_full_backups full_backup_count cutoff_full_minutes=$((8*24*60)) # 8 days (for weekly + buffer)

        recent_full_backups=$(find "$full_backup_dir" -maxdepth 1 -type f -name "*.age" -mmin "-${cutoff_full_minutes}" 2>/dev/null | wc -l)
        full_backup_count=$(find "$full_backup_dir" -maxdepth 1 -type f -name "*.age" 2>/dev/null | wc -l)

        if [[ $recent_full_backups -gt 0 ]]; then
            record_health_result "Backup" "Full_Recent" "PASS" "$recent_full_backups recent full backup(s) found (last 8 days)"
        else
            record_health_result "Backup" "Full_Recent" "WARN" "No recent full backups found (last 8 days)"
        fi
         record_health_result "Backup" "Full_Count" "PASS" "$full_backup_count total full backups found (retention target: >= $keep_full)"
    else
        record_health_result "Backup" "Full_Dir" "WARN" "Full backup directory '$full_backup_dir' not found"
    fi

    # Check backup directory disk usage against threshold (use constant)
    if [[ -d "$backup_base_dir" ]]; then
        local backup_usage_percent max_allowed_percent=${MAX_BACKUP_DISK_PERCENTAGE:-40} # Default 40%
        local disk_info

         if disk_info=$(df -P "$backup_base_dir" 2>/dev/null | awk 'NR==2'); then
             backup_usage_percent=$(echo "$disk_info" | awk '{print $5}' | sed 's/%//')
             if [[ "$backup_usage_percent" -lt $max_allowed_percent ]]; then
                  record_health_result "Backup" "Directory_Size" "PASS" "Backup directory filesystem usage is acceptable (${backup_usage_percent}% used, limit ${max_allowed_percent}%)"
             elif [[ "$backup_usage_percent" -lt $((max_allowed_percent + 10)) ]]; then # Add buffer before failure
                  record_health_result "Backup" "Directory_Size" "WARN" "Backup directory filesystem usage is high (${backup_usage_percent}% used, limit ${max_allowed_percent}%). Cleanup might be needed soon."
             else
                   record_health_result "Backup" "Directory_Size" "FAIL" "Backup directory filesystem usage is CRITICAL (${backup_usage_percent}% used, limit ${max_allowed_percent}%). Cleanup required!"
             fi
         else
              record_health_result "Backup" "Directory_Size" "WARN" "Cannot determine disk usage for backup directory '$backup_base_dir'"
         fi
    fi


    # Age key backup validation (presence and documentation)
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
        # Use constant AGE_KEY_FILE
        if [[ -f "$AGE_KEY_FILE" ]]; then
            # Check if backup instructions/README exist in the keys directory or secrets root
            if [[ -f "$PROJECT_ROOT/secrets/keys/readme.md" ]] || [[ -f "$PROJECT_ROOT/secrets/README.md" ]]; then
                 record_health_result "Backup" "AgeKey_BackupDoc" "PASS" "Age key backup documentation/reminder found"
            else
                 record_health_result "Backup" "AgeKey_BackupDoc" "WARN" "Age key backup documentation/reminder missing in secrets/ or secrets/keys/"
            fi
        else
            # This should have been caught by SOPS check, but double-check
             record_health_result "Backup" "AgeKey_Presence" "FAIL" "Age private key file missing! CRITICAL for backup recovery!"
        fi
    fi

    return 0 # Backup checks usually don't return failure code unless key is missing
}


#
# Service Integration Checks
#
check_service_integration() {
    _log_section "Service Integration & Logs"

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check VaultWarden admin interface reachability (if domain configured)
    local domain clean_domain admin_url http_code
    domain=$(get_config_value "DOMAIN" "") # Get from config
    if [[ -n "$domain" ]]; then
        # Get clean domain if needed (use export from validation lib if available)
        clean_domain=$(get_config_value "CLEAN_DOMAIN" "")
        if [[ -z "$clean_domain" ]]; then
            clean_domain=$(echo "$domain" | sed 's|https\?://||; s|/.*$||')
        fi
        admin_url="https://${clean_domain}/admin" # Construct admin URL

        if "$check_cmd_func" curl >/dev/null 2>&1; then
            # Use curl: -L follow redirects, -I head only, -s silent, -o /dev/null, -w http_code, --max-time
            # Head request might get 401/403 which is ok for reachability
            http_code=$(curl -L -I -s -o /dev/null -w "%{http_code}" --max-time 15 "$admin_url" 2>&1) || http_code="ERR"

            if [[ "$http_code" == "ERR" ]]; then
                 record_health_result "Service" "VW_Admin_Interface" "FAIL" "Failed to connect to VaultWarden admin interface ($admin_url)"
            elif [[ "$http_code" -ge 200 && "$http_code" -lt 500 ]]; then # Allow 2xx, 3xx, 4xx (auth errors are ok)
                 record_health_result "Service" "VW_Admin_Interface" "PASS" "VaultWarden admin interface reachable ($admin_url -> HTTP $http_code)"
            else # 5xx errors or unexpected codes
                 record_health_result "Service" "VW_Admin_Interface" "FAIL" "VaultWarden admin interface returned server error ($admin_url -> HTTP $http_code)"
            fi
        else
            record_health_result "Service" "VW_Admin_Interface" "SKIP" "curl not found. Skipping admin interface check."
        fi

        # Check main VaultWarden web interface reachability (root)
        local root_url="https://${clean_domain}"
         if "$check_cmd_func" curl >/dev/null 2>&1; then
             http_code=$(curl -L -I -s -o /dev/null -w "%{http_code}" --max-time 15 "$root_url" 2>&1) || http_code="ERR"
             if [[ "$http_code" == "ERR" ]]; then
                 record_health_result "Service" "VW_Web_Interface" "FAIL" "Failed to connect to VaultWarden web interface ($root_url)"
             elif [[ "$http_code" -ge 200 && "$http_code" -lt 400 ]]; then # Expect 2xx or 3xx
                 record_health_result "Service" "VW_Web_Interface" "PASS" "VaultWarden web interface accessible ($root_url -> HTTP $http_code)"
             else
                  record_health_result "Service" "VW_Web_Interface" "WARN" "VaultWarden web interface returned unexpected status ($root_url -> HTTP $http_code)"
             fi
         else
             record_health_result "Service" "VW_Web_Interface" "SKIP" "curl not found. Skipping web interface check."
         fi
    else
        record_health_result "Service" "Interface_Checks" "SKIP" "No DOMAIN configured. Skipping interface reachability tests."
    fi

    # Check if secrets are properly mounted inside the running VaultWarden container
    # Use container name mapping
    local vw_container_name="$BW_VW" # From global vars set at top
    # Check if container exists and is running
    local vw_container_id vw_is_running=false
    if vw_container_id=$(docker compose ps -q vaultwarden 2>/dev/null) && [[ -n "$vw_container_id" ]]; then
         if docker inspect -f '{{.State.Running}}' "$vw_container_id" 2>/dev/null | grep -q true; then
             vw_is_running=true
         fi
    fi

    if [[ "$vw_is_running" == "true" ]]; then
        # Check for existence of a key secret file inside container using docker exec
        if docker exec "$vw_container_id" test -f "/run/secrets/admin_token" 2>/dev/null; then
            record_health_result "Service" "Secret_Mounting" "PASS" "Docker secrets appear mounted in VaultWarden container (checked for admin_token)"
        else
            record_health_result "Service" "Secret_Mounting" "WARN" "Docker secrets may not be mounted correctly in VaultWarden container (checked for admin_token)"
        fi
    else
        record_health_result "Service" "Secret_Mounting" "SKIP" "VaultWarden container not running. Skipping secret mount check."
    fi

    # Check log file accessibility and recent activity
    local state_dir=$(get_config_value "PROJECT_STATE_DIR" "/var/lib/vaultwarden")
    local caddy_log_file="$state_dir/logs/caddy/access.log"
    local vw_log_file_in_vol="$state_dir/data/bwdata/vaultwarden.log" # VW logs inside volume

    local log_files_checked=0 log_files_recent=0 log_check_minutes=60 # Check if modified in last hour

    _log_debug "Checking log file activity (last $log_check_minutes minutes)..."
    if [[ -f "$caddy_log_file" ]]; then
        ((log_files_checked++))
        _log_debug "Checking Caddy log: $caddy_log_file"
        if find "$caddy_log_file" -mmin "-${log_check_minutes}" 2>/dev/null | grep -q .; then
            _log_debug "Caddy log is recent."
            ((log_files_recent++))
        else
             _log_debug "Caddy log is NOT recent (older than $log_check_minutes min)."
        fi
    else
         _log_debug "Caddy log file not found: $caddy_log_file"
    fi

     if [[ -f "$vw_log_file_in_vol" ]]; then
         ((log_files_checked++))
         _log_debug "Checking Vaultwarden internal log: $vw_log_file_in_vol"
         if find "$vw_log_file_in_vol" -mmin "-${log_check_minutes}" 2>/dev/null | grep -q .; then
             _log_debug "Vaultwarden internal log is recent."
             ((log_files_recent++))
         else
             _log_debug "Vaultwarden internal log is NOT recent (older than $log_check_minutes min)."
         fi
     else
          _log_debug "Vaultwarden internal log file not found: $vw_log_file_in_vol"
     fi


    if [[ $log_files_checked -gt 0 ]]; then
        if [[ $log_files_recent -eq $log_files_checked ]]; then
             record_health_result "Service" "Log_Activity" "PASS" "Checked log files show recent activity ($log_files_recent/$log_files_checked within last $log_check_minutes min)"
        elif [[ $log_files_recent -gt 0 ]]; then
             record_health_result "Service" "Log_Activity" "WARN" "Some log files do not show recent activity ($log_files_recent/$log_files_checked within last $log_check_minutes min)"
        else
              # If no files are recent, it might indicate a bigger issue
              record_health_result "Service" "Log_Activity" "FAIL" "NO checked log files show recent activity ($log_files_recent/$log_files_checked within last $log_check_minutes min). Services might be stalled."
        fi
    else
         record_health_result "Service" "Log_Presence" "WARN" "Could not find expected log files to check activity (checked Caddy & VW internal)."
    fi

    return 0 # Service integration checks usually don't return failure code unless critical endpoint down
}


#
# Self-Healing and Alerting (Added SOPS Check)
#

# Checks overall stack health based on container status. Returns 0 if healthy, 1 otherwise.
stack_is_healthy() {
    _log_debug "Performing quick stack health check for self-heal..."
    # Define critical services based on container name mapping
    local critical_services=("$BW_VW" "$BW_CADDY") # Services essential for basic operation
    local service healthy_found=true service_name_only

    # Use _have_cmd if available, fallback otherwise
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check Docker availability first
    if ! "$check_cmd_func" docker >/dev/null || ! docker info >/dev/null 2>&1; then
        log_error "Stack health check: Docker not available."
        return 1
    fi


    for service_container_name in "${critical_services[@]}"; do
        # Extract service name (e.g., 'vaultwarden' from 'project_vaultwarden') if needed, though ps uses name
        service_name_only="${service_container_name##*_}" # Get part after last underscore

        local container_id container_status health_status
        # Use docker ps with filter for name, get ID
        container_id=$(docker ps -q --filter "name=^/${service_container_name}$" 2>/dev/null)

        if [[ -z "$container_id" ]]; then
            log_warn "Stack health check: Critical service container '$service_container_name' not found."
            healthy_found=false
            break # Exit loop on first critical failure
        fi

        # Inspect using ID
        container_status=$(docker inspect -f '{{.State.Status}}' "$container_id" 2>/dev/null || echo "error")
        if [[ "$container_status" != "running" ]]; then
            log_warn "Stack health check: Critical service '$service_container_name' is not running (Status: $container_status)."
            healthy_found=false
            break
        fi

         # Check health status if defined
         health_status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || echo "error")
         if [[ "$health_status" == "unhealthy" ]]; then
              log_warn "Stack health check: Critical service '$service_container_name' is unhealthy."
              healthy_found=false
              break
         fi
         # Consider 'starting' or empty health status as potentially unhealthy for quick check? Be lenient for now.
         _log_debug "Stack health check: '$service_container_name' is running (Health: $health_status)."
    done

    if [[ "$healthy_found" == "true" ]]; then
        _log_debug "Stack health check: PASSED (critical services running and not unhealthy)"
        return 0 # Success
    else
        _log_debug "Stack health check: FAILED"
        return 1 # Failure
    fi
}

# Attempts to restart services to fix issues. Includes SOPS pre-check.
# Relies on stack_is_healthy for verification.
self_heal_once() {
    local wait="${1:-15}" # Default wait time between steps

    _log_section "Attempting Self-Heal Procedure"

    # *** Prerequisite Check: Ensure SOPS/Age is healthy if used ***
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
        _log_debug "Running SOPS health check before attempting container healing..."
        reset_health_counts # Reset counts before this specific check
        if ! check_sops_system_health; then
            log_error "SOPS+Age system unhealthy - cannot safely proceed with container healing as secrets might be inaccessible."
            # Maybe send an alert here? Depends on notification library integration
             if [[ "$NOTIFICATIONS_AVAILABLE" == "true" ]] && declare -f send_notification >/dev/null; then
                 # Only call alert_on_sops_failures if it exists, otherwise basic notification
                 local subject="❌ Self-Heal Blocked: SOPS Unhealthy"
                 local body="Attempted self-heal blocked because the SOPS/Age encryption system is unhealthy on $(hostname -f 2>/dev/null || hostname). Secrets may be inaccessible. Manual intervention required to fix SOPS/Age before services can be healed."
                 send_notification "critical" "$subject" "$body" || log_warn "Failed to send SOPS failure alert."
             fi
            return 1 # Fail heal procedure
        else
            log_info "SOPS+Age check passed. Proceeding with container healing."
        fi
    else
         _log_debug "SOPS not available/enabled. Skipping SOPS check."
    fi

    # Try different restart strategies
    local heal_attempt=0 heal_successful=false

    # Check initial state before attempting heals
    if stack_is_healthy; then
         log_info "Stack already healthy. No healing action needed."
         return 0
    fi

    # Attempt 1: Simple Restart (less disruptive)
    ((heal_attempt++))
    log_info "Self-heal attempt $heal_attempt: Docker compose restart of unhealthy/stopped critical services"
    # Identify specific unhealthy services if possible from HEALTH_RESULTS? More complex.
    # Just try restarting critical ones for simplicity.
    local restart_cmd="docker compose restart $BW_VW $BW_CADDY" # Restart only critical ones initially?
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would run: $restart_cmd"
        heal_successful=true # Assume success in dry run to stop loop
    else
        if (cd "$PROJECT_ROOT" && $restart_cmd); then
            log_info "Waiting ${wait}s after restart attempt..."
            sleep "$wait"
            if stack_is_healthy; then heal_successful=true; fi
        else
            log_warn "compose restart command failed for one or more services."
            # Proceed to next attempt even if restart command failed
        fi
    fi


    # Attempt 2: Up --force-recreate (more comprehensive, handles missing containers/config changes)
    if [[ "$heal_successful" == "false" ]]; then
        ((heal_attempt++))
        log_info "Self-heal attempt $heal_attempt: Docker compose up -d --force-recreate"
        local up_cmd="docker compose up -d --force-recreate --remove-orphans"
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            log_info "[DRY RUN] Would run: $up_cmd"
            heal_successful=true
        else
            # Ensure Docker secrets are prepared before 'up'
             if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
                 if ! prepare_docker_secrets; then # Assumes prepare_docker_secrets exists (from startup-helpers?)
                      log_error "Failed to prepare Docker secrets before 'compose up'. Aborting heal."
                      return 1
                 fi
             fi
             # Run compose up
            if (cd "$PROJECT_ROOT" && $up_cmd); then
                log_info "Waiting $((wait * 2))s after 'up --force-recreate'..." # Longer wait after recreate
                sleep $((wait * 2))
                if stack_is_healthy; then heal_successful=true; fi
            else
                 log_error "'compose up --force-recreate' command failed."
                 # Don't proceed to full reset if 'up' fails, likely deeper issue
                 heal_successful=false # Mark as failed
            fi
        fi
    fi

    # Attempt 3: Full Reset (down + up) - Maybe remove this? 'up --force-recreate' is usually sufficient.
    # Keep it as last resort for now.
     if [[ "$heal_successful" == "false" ]]; then
         ((heal_attempt++))
         log_info "Self-heal attempt $heal_attempt: Full stack reset (down + up)"
         local down_cmd="docker compose down --remove-orphans"
         local up_cmd="docker compose up -d --remove-orphans" # No force-recreate needed after down
         if [[ "${DRY_RUN:-false}" == "true" ]]; then
              log_info "[DRY RUN] Would run: $down_cmd"
              log_info "[DRY RUN] Would run: $up_cmd"
             heal_successful=true
         else
             log_info "Bringing stack down..."
             (cd "$PROJECT_ROOT" && $down_cmd) || log_warn "'compose down' command failed, attempting 'up' anyway..."
             sleep 5 # Brief pause

             # Ensure Docker secrets are prepared again after down
             if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
                 if ! prepare_docker_secrets; then # Assumes prepare_docker_secrets exists
                      log_error "Failed to prepare Docker secrets before 'compose up' after reset. Aborting heal."
                      return 1
                 fi
             fi

             log_info "Bringing stack up..."
             if (cd "$PROJECT_ROOT" && $up_cmd); then
                 log_info "Waiting $((wait * 2))s after full reset..." # Longer wait after full restart
                 sleep $((wait * 2))
                 if stack_is_healthy; then heal_successful=true; fi
             else
                  log_error "'compose up' command failed after reset."
                  heal_successful=false
             fi
         fi
     fi


    # Final result
    if [[ "$heal_successful" == "true" ]]; then
        log_success "Self-heal successful after attempt #$heal_attempt."
        # Optionally send a notification about successful auto-heal
         if [[ "$NOTIFICATIONS_AVAILABLE" == "true" ]] && declare -f send_notification >/dev/null; then
             local subject="✅ VaultWarden Auto-Heal Successful"
             local body="Monitoring system successfully recovered services on $(hostname -f 2>/dev/null || hostname) after $heal_attempt attempt(s)."
             send_notification "maintenance" "$subject" "$body" || log_warn "Failed to send auto-heal success notification."
         fi
        return 0 # Success
    else
        log_error "Self-heal FAILED after $heal_attempt attempts. Stack remains unhealthy."
        # Critical alert should be sent by the main monitoring loop based on failure count
        return 1 # Failure
    fi
}

# --- Library Initialization / Self-Test ---
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "lib/monitoring.sh loaded successfully"
else
    # Allow running directly for testing purposes
    _log_warning "lib/monitoring.sh should be sourced, but running self-test..."
    export DEBUG=true # Enable debug for test run
    reset_health_counts
    check_sops_system_health
    check_container_health
    check_system_health
    check_network_health
    check_backup_health
    check_service_integration
    echo ""
    log_header "Health Summary (Self-Test)"
    echo "Critical Errors: $CRITICAL_COUNT"
    echo "Warnings: $WARNINGS_COUNT"
    echo "Results:"
    # Print results sorted by key
    printf '%s\n' "${!HEALTH_RESULTS[@]}" | sort | while IFS= read -r key; do
        printf "  %-30s: %s\n" "$key" "${HEALTH_RESULTS[$key]}"
    done
    echo ""
    # Test self-heal in dry run mode
    _log_section "Testing Self-Heal (Dry Run)"
    export DRY_RUN=true
    self_heal_once
    echo ""
    log_info "Self-test complete."

    if [[ $CRITICAL_COUNT -gt 0 ]]; then exit 1; fi
fi
