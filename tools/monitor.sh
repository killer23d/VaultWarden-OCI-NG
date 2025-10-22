#!/usr/bin/env bash
# tools/monitor.sh - Simple health monitoring with basic auto-healing for VaultWarden-OCI-NG

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
# Source config first as it's needed by notifications and defines constants
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh. Using defaults."
        # Define necessary defaults if config fails
        COMPOSE_PROJECT_NAME="vaultwarden"
        MONITOR_INTERVAL=300
        MAX_FAILURES=3
    fi
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    exit 1
fi

# Source notifications library (optional, check availability)
NOTIFICATIONS_AVAILABLE=false
if [[ -f "lib/notifications.sh" ]]; then
    source "lib/notifications.sh"
    NOTIFICATIONS_AVAILABLE=true
else
    log_warn "Optional library not found: lib/notifications.sh. Notifications disabled."
    # Define dummy send_notification if notifications lib is missing
    send_notification() { log_warn "Notification library missing, cannot send: [$1] $2"; }
fi
# Source system library (optional, for compose helpers)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "lib/system.sh" ]]; then
    source "lib/system.sh"
    SYSTEM_LIB_AVAILABLE=true
fi
# Source constants if available
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi


# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---


# --- Configuration ---
COMPOSE_FILE="docker-compose.yml" # Use constant COMPOSE_FILE if defined
# Use constants or loaded config values, provide defaults
MONITOR_INTERVAL_SECONDS=${MONITOR_INTERVAL:-${DEFAULT_MONITOR_INTERVAL_SECONDS:-300}}
MAX_CONSECUTIVE_FAILURES=${MAX_FAILURES:-${DEFAULT_MAX_CONSECUTIVE_FAILURES:-3}}
# Use a state directory path if defined, otherwise /tmp
STATE_DIR="${PROJECT_STATE_DIR:-/tmp}"
FAILURE_COUNT_FILE="${STATE_DIR}/.vaultwarden-monitor-failures.count"

# --- Script Flags (Argument Parsing) ---
FLAG_AUTO_HEAL=false
FLAG_RUN_ONCE=false
FLAG_DRY_RUN=false

# --- Global State ---
declare -gA G_FAILED_SERVICES_LIST=() # Use associative array


# --- Help text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Simple Monitoring System
USAGE:
    $0 [OPTIONS]
DESCRIPTION:
    Monitors service health (defined in docker-compose.yml), attempts restarts
    on failure if --auto-heal is enabled, and sends alerts via notifications library.
    Tracks consecutive failures using '$FAILURE_COUNT_FILE'.

OPTIONS:
    --help        Show this help message
    --auto-heal   Enable automatic service restarts on failure (Default: false)
    --once        Run one check cycle and exit (useful for immediate checks)
    --dry-run     Preview check results and heal actions without executing restarts
    --debug       Enable debug logging (set DEBUG=true)

CRON USAGE EXAMPLE (run every 5 minutes with auto-heal):
    */5 * * * * cd $PROJECT_ROOT && ./tools/monitor.sh --auto-heal >> ${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/monitor-cron.log 2>&1
EOF
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --auto-heal) FLAG_AUTO_HEAL=true; shift ;;
        --once) FLAG_RUN_ONCE=true; shift ;;
        --dry-run) FLAG_DRY_RUN=true; shift ;;
        --debug) export DEBUG=true; shift ;; # Enable debug logging
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- State Management Functions ---

get_failure_count() {
    local count=0
    # Ensure state directory exists
    mkdir -p "$STATE_DIR" || log_warn "Cannot create state directory '$STATE_DIR' for failure count file."

    if [[ -f "$FAILURE_COUNT_FILE" ]]; then
        # Read count, validate it's a number
        local file_content
        file_content=$(< "$FAILURE_COUNT_FILE")
        if [[ "$file_content" =~ ^[0-9]+$ ]]; then
             count="$file_content"
        else
             log_warn "Failure count file '$FAILURE_COUNT_FILE' contains invalid data ('$file_content'). Resetting to 0."
             # Attempt to overwrite with 0
             echo "0" > "$FAILURE_COUNT_FILE" || log_error "Failed to reset failure count file '$FAILURE_COUNT_FILE'."
             count=0
        fi
    fi
    _log_debug "Current failure count: $count"
    echo "$count"
}

set_failure_count() {
    local count="$1"
    # Ensure state directory exists
    mkdir -p "$STATE_DIR" || log_warn "Cannot create state directory '$STATE_DIR' for failure count file."

    # Validate count is a number before writing
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        log_error "Invalid value provided to set_failure_count: '$count'. Must be a number."
        return 1
    fi

    _log_debug "Setting failure count to $count in $FAILURE_COUNT_FILE"
    if ! echo "$count" > "$FAILURE_COUNT_FILE"; then
         log_error "Failed to write failure count '$count' to file '$FAILURE_COUNT_FILE'. Check permissions."
         return 1
    fi
    return 0
}

reset_failure_count() {
    log_info "Resetting consecutive failure count."
    set_failure_count 0
}

increment_failure_count() {
    local current_count new_count
    current_count=$(get_failure_count)
    new_count=$(( current_count + 1 ))
    log_info "Incrementing failure count to $new_count."
    set_failure_count "$new_count"
    echo "$new_count" # Return the new count
}

# --- Core Monitoring Functions ---

check_services_health() {
    log_info "Checking VaultWarden service health..."
    G_FAILED_SERVICES_LIST=() # Reset global list
    local overall_status=0 # 0=PASS, 1=FAIL/WARN

    # Use _have_cmd if available
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Check Docker and Compose availability
    if ! "$check_cmd_func" docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
         log_error "Docker or Docker Compose plugin not available. Cannot check services."
         G_FAILED_SERVICES_LIST["docker_setup"]="Docker/Compose missing or broken"
         return 1
    fi
    # Check Compose file existence
     if [[ ! -f "$COMPOSE_FILE" ]]; then
         log_error "Docker Compose file not found: $COMPOSE_FILE"
         G_FAILED_SERVICES_LIST["compose_file"]="Compose file missing"
         return 1
     fi

    # Get defined services from compose config
    local defined_services
    defined_services=$(docker compose -f "$COMPOSE_FILE" config --services 2>/dev/null || echo "")
    if [[ -z "$defined_services" ]]; then
        log_error "Could not list services from '$COMPOSE_FILE'. Check file syntax."
        G_FAILED_SERVICES_LIST["compose_config"]="Cannot parse services"
        return 1
    fi
    _log_debug "Checking services defined in compose file: $defined_services"

    # Get current status using docker compose ps JSON output
    local compose_ps_json compose_ps_rc=0
    compose_ps_json=$(timeout 20 docker compose -f "$COMPOSE_FILE" ps --format json 2>&1) || compose_ps_rc=$?
    if [[ $compose_ps_rc -ne 0 ]]; then
        log_error "Failed to get container status via 'docker compose ps' (rc=$compose_ps_rc)."
        G_FAILED_SERVICES_LIST["compose_ps"]="Command failed"
        _log_debug "Compose PS Output/Error: $compose_ps_json"
        return 1
    fi

    # Check for jq
    if ! "$check_cmd_func" jq >/dev/null; then
        log_error "jq command not found. Cannot parse container status."
        G_FAILED_SERVICES_LIST["jq_missing"]="jq command missing"
        return 1
    fi


    local service service_info state health_status is_enabled enabled_var_name
    for service in $defined_services; do
        _log_debug "Checking service: $service"
        # Extract info for this service from the JSON
        service_info=$(echo "$compose_ps_json" | jq --arg svc "$service" '.[] | select(.Service == $svc)' 2>/dev/null || echo "{}")

        # Check if service should be enabled based on config (e.g., DDCLIENT_ENABLED)
        enabled_var_name=$(echo "${service}_ENABLED" | tr '[:lower:]' '[:upper:]' | sed 's/-/_/g')
        is_enabled=$(get_config_value "$enabled_var_name" "true") # Assume enabled unless explicitly 'false'

        # Special case: run-once watchtower
        local is_run_once_watchtower=false
        if [[ "$service" == "watchtower" && "$(docker compose config 2>/dev/null)" =~ "monitor-only|run-once" ]]; then
            is_run_once_watchtower=true
        fi


        if [[ -z "$service_info" || "$service_info" == "{}" ]]; then
            # Container for this service not found by 'ps'
            if [[ "$is_enabled" == "true" && "$is_run_once_watchtower" == false ]]; then
                 log_warn "Service '$service' container not found (but expected to be running)."
                 G_FAILED_SERVICES_LIST["$service"]="Not Found"
                 overall_status=1
            elif [[ "$is_enabled" == "false" ]]; then
                 _log_debug("Service '$service' container not found (disabled in config).")
            elif [[ "$is_run_once_watchtower" == true ]]; then
                 _log_debug("Service '$service' container (run-once mode) not found (expected).")
            fi
            continue # Move to next service
        fi

        # Container found, check state and health
        state=$(echo "$service_info" | jq -r '.State // "unknown"')
        health_status=$(echo "$service_info" | jq -r '.Health // "none"') # Health can be "", starting, healthy, unhealthy

        if [[ "$state" == "running" ]]; then
             case "$health_status" in
                 "healthy")
                     _log_debug("Service '$service' is running and healthy.")
                     ;;
                 "unhealthy")
                     log_warn("Service '$service' is running but UNHEALTHY.")
                     G_FAILED_SERVICES_LIST["$service"]="Unhealthy"
                     overall_status=1
                     ;;
                 "starting"|"") # Starting or health status pending
                     log_info("Service '$service' is running but starting or health pending.")
                     # Consider 'starting' as a warning state? Or just informational? Info for now.
                     ;;
                 "none") # No health check defined
                     _log_debug("Service '$service' is running (no health check defined).")
                     ;;
                 *) # Unknown health status
                     log_warn("Service '$service' is running with unknown health status: '$health_status'")
                     ;;
             esac
        else
            # Container exists but is not running
            # Check if this is expected (e.g., run-once watchtower that finished)
             if [[ "$is_run_once_watchtower" == true && "$state" == "exited" ]]; then
                  _log_debug("Service '$service' container (run-once mode) has exited (expected).")
             elif [[ "$is_enabled" == "true" ]]; then
                 log_warn("Service '$service' container exists but is not running (State: $state).")
                 G_FAILED_SERVICES_LIST["$service"]="Not Running ($state)"
                 overall_status=1
             else
                  _log_debug("Service '$service' container exists but is not running (State: $state, disabled in config).")
             fi
        fi
    done

    # Final summary based on overall status
    if [[ $overall_status -eq 0 ]]; then
        log_success "All checked services appear to be running and healthy."
    else
        log_error "Health check detected issues with one or more services: ${!G_FAILED_SERVICES_LIST[*]}"
    fi
    return $overall_status
}


attempt_healing() {
    # Check if there are any failed services recorded
    if [[ ${#G_FAILED_SERVICES_LIST[@]} -eq 0 ]]; then
        log_info "No failed services detected. No healing action needed."
        return 0
    fi

    log_info "Attempting auto-healing for affected services: ${!G_FAILED_SERVICES_LIST[*]}"
    local healed_services=() restart_failed=false service heal_cmd heal_rc

    for service in "${!G_FAILED_SERVICES_LIST[@]}"; do
        # Skip pseudo-services or general errors
        if [[ "$service" == "docker_setup" || "$service" == "compose_file" || "$service" == "compose_config" || "$service" == "compose_ps" || "$service" == "jq_missing" ]]; then
             _log_debug "Skipping heal attempt for non-service issue: $service"
             continue
        fi

        log_info "Attempting to heal service '$service'..."
        # Default action: restart the service container
        heal_cmd=(docker compose -f "$COMPOSE_FILE" restart "$service")

        if [[ "$FLAG_DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would execute: ${heal_cmd[*]}"
            healed_services+=("$service (dry run)") # Mark as dry run
            continue # Assume success in dry run
        fi

        # Execute the heal command
        if "${heal_cmd[@]}"; then
            log_info "Restart command issued for '$service'. Waiting briefly to check status..."
            sleep 15 # Wait for service to potentially restart and stabilize

            # Re-check status specifically for this service
            local container_info state health_status
            container_info=$(docker compose -f "$COMPOSE_FILE" ps --format json "$service" 2>/dev/null | jq '.[0] // empty')
            state=$(echo "$container_info" | jq -r '.State // "unknown"')
            health_status=$(echo "$container_info" | jq -r '.Health // "none"')

            # Check if now running and not unhealthy
            if [[ "$state" == "running" && "$health_status" != "unhealthy" ]]; then
                 log_success("Successfully restarted '$service'. New status: $state ($health_status)")
                 healed_services+=("$service")
            else
                 log_error("Restarted '$service', but it remains unhealthy or stopped (State: $state, Health: $health_status).")
                 restart_failed=true
            fi
        else
            heal_rc=$?
            log_error("Command to restart '$service' failed (rc=$heal_rc).")
            restart_failed=true
        fi
    done

    # Send notification if any services were successfully healed (in non-dry-run mode)
    if [[ ${#healed_services[@]} -gt 0 && "$FLAG_DRY_RUN" == "false" ]]; then
        send_healing_notification "${healed_services[*]}"
    fi

    # Return overall success/failure of the healing attempt
    [[ "$restart_failed" == "true" ]] && return 1 || return 0
}

# --- Notification Functions ---

send_healing_notification() {
    if [[ "$NOTIFICATIONS_AVAILABLE" != "true" ]]; then return; fi
    local healed_list="$1"
    local subject="✅ VaultWarden Auto-Healing: Services Restarted"
    local body="Monitoring system automatically restarted the following service(s) on $(hostname -f 2>/dev/null || hostname):

${healed_list}

System health will be re-evaluated in the next cycle."
    send_notification "maintenance" "$subject" "$body" || log_warn "Failed to send healing notification email."
}

send_failure_alert() {
    if [[ "$NOTIFICATIONS_AVAILABLE" != "true" ]]; then return; fi
    local failure_count="$1"
    # Get details of failed services from the global array
    local failed_details=""
    for service in "${!G_FAILED_SERVICES_LIST[@]}"; do
         failed_details+="- ${service}: ${G_FAILED_SERVICES_LIST[$service]}\n"
    done
    [[ -z "$failed_details" ]] && failed_details="- (Could not determine specific service failures)"


    local subject="❌ CRITICAL: VaultWarden Failure Alert (#${failure_count}) on $(hostname -f 2>/dev/null || hostname)"
    local body="VaultWarden monitoring system on $(hostname -f 2>/dev/null || hostname) has detected failures for ${failure_count} consecutive checks.

Failed/Unhealthy Services Detected:
${failed_details}
Auto-healing attempts may have failed or the issue persists.

MANUAL INTERVENTION REQUIRED. Please check the server logs immediately:
- Monitor log: ${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/monitor-cron.log (if using cron example)
- System log: ${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/system.log
- Docker logs: docker compose logs"

    send_notification "critical" "$subject" "$body" || log_warn "Failed to send critical failure alert email."
}

send_recovery_notification() {
    if [[ "$NOTIFICATIONS_AVAILABLE" != "true" ]]; then return; fi
    local previous_failures="$1"
    local subject="✅ VaultWarden System Recovered on $(hostname -f 2>/dev/null || hostname)"
    local body="VaultWarden monitoring system on $(hostname -f 2>/dev/null || hostname) has detected that the system recovered after ${previous_failures} consecutive failure(s).

All services are now reporting as healthy. No immediate action required, but monitoring is advised."
    send_notification "success" "$subject" "$body" || log_warn "Failed to send system recovery notification email."
}

# --- Main Monitoring Loop ---

run_monitoring_cycle() {
    log_info "Starting health check cycle..."
    local current_failures failure_check_rc new_failure_count
    current_failures=$(get_failure_count)

    # Run the health check and capture its return code
    check_services_health
    failure_check_rc=$?

    if [[ $failure_check_rc -eq 0 ]]; then
        # Health check passed
        if [[ "$current_failures" -gt 0 ]]; then
            log_success "System has RECOVERED after $current_failures previous failure(s)."
            send_recovery_notification "$current_failures"
        fi
        reset_failure_count
        log_info "Health check cycle PASSED."
        return 0
    else
        # Health check failed
        new_failure_count=$(increment_failure_count)
        log_error "Health check cycle FAILED (Failure #${new_failure_count} consecutive)."

        # Attempt healing if enabled
        if [[ "$FLAG_AUTO_HEAL" == "true" ]]; then
            attempt_healing # Logs success/failure internally
            # Optional: Re-check health immediately after healing? Or wait for next cycle? Wait for next.
        else
             log_info "Auto-healing is disabled (--auto-heal not specified)."
        fi

        # Send critical alert if failure threshold is reached/exceeded
        # Only send *once* when threshold is first reached
        if [[ "$new_failure_count" -ge "$MAX_CONSECUTIVE_FAILURES" ]]; then
             if [[ "$current_failures" -lt "$MAX_CONSECUTIVE_FAILURES" ]]; then
                 # Threshold just reached on this cycle
                 log_error "Failure threshold ($MAX_CONSECUTIVE_FAILURES) reached! Sending critical alert."
                 send_failure_alert "$new_failure_count"
             else
                  # Threshold already exceeded, alert likely sent previously
                  log_warn "Failure threshold ($MAX_CONSECUTIVE_FAILURES) still exceeded (Failure #${new_failure_count}). Alert previously sent."
             fi
        fi
        return 1 # Indicate failure for this cycle
    fi
}

main() {
    log_header "VaultWarden Monitoring Started (PID $$)"
    if [[ "$FLAG_DRY_RUN" == "true" ]]; then log_warn "*** DRY RUN MODE ENABLED - No service restarts will occur ***"; fi
    # Config already loaded during library sourcing

    if [[ "$FLAG_RUN_ONCE" == "true" ]]; then
        log_info "Running a single monitoring cycle (--once specified)."
        run_monitoring_cycle
        local exit_code=$?
        log_header "Monitoring Finished (Single Run)"
        exit $exit_code
    fi

    # --- Continuous Monitoring Mode (Not recommended for direct execution, use cron/systemd) ---
    log_warn "Running in continuous monitoring mode (PID $$). Use --once for single checks or schedule via cron/systemd timer."
    # In continuous mode, reset failure count on start. For cron, state is preserved between runs.
    reset_failure_count

    while true; do
        run_monitoring_cycle || true # Don't exit loop on single failure
        log_info "Sleeping for $MONITOR_INTERVAL_SECONDS seconds before next check..."
        sleep "$MONITOR_INTERVAL_SECONDS"
    done
}

# --- Script Entry Point ---
# Run main execution logic
main
