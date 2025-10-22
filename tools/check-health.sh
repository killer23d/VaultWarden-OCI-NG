#!/usr/bin/env bash
# tools/check-health.sh - Comprehensive health checks with optional auto-fix

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
source "lib/config.sh" # Needed for DOMAIN, container names etc.
source "lib/monitoring.sh" # Contains the check functions

# Set script-specific log prefix
# Note: lib/monitoring.sh might set its own prefix internally during checks
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Configuration ---
AUTO_FIX=false
COMPREHENSIVE=false
CHECK_COMPONENT=""

# --- Help Text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Health Check Utility
USAGE:
    $0 [OPTIONS]
DESCRIPTION:
    Performs various health checks on the VaultWarden stack and host system.
    Can optionally attempt to automatically fix certain issues.
OPTIONS:
    --help           Show this help message
    --fix            Attempt to automatically fix detected issues (e.g., restart unhealthy containers)
    --comprehensive  Run all available checks (can be slower)
    --component NAME Run only checks for a specific component (e.g., containers, network, sops, system, backup, services)
EOF
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help) show_help; exit 0 ;;
        --fix) AUTO_FIX=true; shift ;;
        --comprehensive) COMPREHENSIVE=true; shift ;;
        --component) CHECK_COMPONENT="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Validate component name if provided
if [[ -n "$CHECK_COMPONENT" ]]; then
    case "$CHECK_COMPONENT" in
        containers|network|sops|system|backup|services|security) # Added security
            log_info "Running checks only for component: $CHECK_COMPONENT"
            COMPREHENSIVE=true # Force comprehensive if a specific component is requested
            ;;
        *)
            log_error "Invalid component specified: $CHECK_COMPONENT"
            log_info "Valid components are: containers, network, sops, system, backup, services, security"
            exit 1
            ;;
    esac
fi


# --- Main Execution ---
main() {
    log_header "VaultWarden Health Check Started"
    if [[ "$AUTO_FIX" == "true" ]]; then log_warn "Auto-fix mode enabled. Will attempt to restart services."; fi

    # Load configuration - essential for most checks
    if ! load_config; then
        log_error "Failed to load configuration. Cannot perform most health checks."
        exit 1
    fi

    # Reset health counts before running checks
    reset_health_counts

    local overall_status=0 # 0 = OK, 1 = Error

    # Run checks based on flags
    # Use || { overall_status=1; } to track if any check function returns non-zero (failure)

    if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "sops" ]]; then
        check_sops_system_health || { overall_status=1; }
        [[ $overall_status -ne 0 && "$CHECK_COMPONENT" == "sops" ]] && exit $overall_status # Exit if only checking SOPS and it failed
    fi
    # Only proceed with other checks if SOPS is healthy (critical dependency)
    if [[ $overall_status -ne 0 ]]; then
        log_error "SOPS/Age check failed. Cannot reliably perform further checks. Aborting."
        exit $overall_status
    fi

    if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "containers" ]]; then
        check_container_health || { overall_status=1; }
        [[ $overall_status -ne 0 && "$CHECK_COMPONENT" == "containers" ]] && exit $overall_status # Exit if only checking containers and it failed
    fi

    if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "system" ]]; then
        check_system_health || { overall_status=1; } # System checks usually don't fail hard
    fi

    if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "network" ]]; then
        check_network_health || { overall_status=1; }
    fi

    # Comprehensive checks (run if --comprehensive or specific component requested)
    if [[ "$COMPREHENSIVE" == "true" ]]; then
        if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "backup" ]]; then
            check_backup_health || { overall_status=1; } # Backup checks are often warnings
        fi
        if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "services" ]]; then
            check_service_integration || { overall_status=1; } # Service integration checks often warnings
        fi
        # Add security check if comprehensive or explicitly requested
        if [[ -z "$CHECK_COMPONENT" || "$CHECK_COMPONENT" == "security" ]]; then
             # Placeholder for potential dedicated security checks in monitoring.sh
             # verify_container_security || { overall_status=1; } # Example call
             log_info "Security component check placeholder (actual checks might be integrated elsewhere)."
        fi
    fi


    # --- Summarize Results ---
    log_header "Health Check Summary"
    local status_color="${C_GREEN}"

    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        status_color="${C_RED}"
        log_error "${C_BOLD}Overall Status: FAILED${C_RESET}${status_color} ($CRITICAL_COUNT critical error(s), $WARNINGS_COUNT warning(s))"
    elif [[ $WARNINGS_COUNT -gt 0 ]]; then
        status_color="${C_YELLOW}"
        log_warn "${C_BOLD}Overall Status: WARNING${C_RESET}${status_color} ($WARNINGS_COUNT warning(s))"
    else
        log_success "${C_BOLD}Overall Status: PASSED${C_RESET}${status_color} (All checks passed)"
    fi

    # Optionally print detailed results if errors or warnings occurred or in debug mode
    if [[ $CRITICAL_COUNT -gt 0 || $WARNINGS_COUNT -gt 0 || "${DEBUG:-false}" == "true" ]]; then
        _log_section "Detailed Results"
        local category test_name status message prev_category="" sorted_keys
        # Sort keys for consistent output
        mapfile -t sorted_keys < <(printf '%s\n' "${!HEALTH_RESULTS[@]}" | sort)

        for key in "${sorted_keys[@]}"; do
             category="${key%%_*}"
             test_name="${key#*_}"
             IFS=':' read -r status message <<< "${HEALTH_RESULTS[$key]}"

             # Print category header only when it changes
             if [[ "$category" != "$prev_category" ]]; then
                 echo -e "\n${C_BOLD}${category}${C_RESET}:"
                 prev_category="$category"
             fi

             # Print result with appropriate color/icon
             local status_icon="?" color="$C_RESET" padded_status
             padded_status=$(printf '%-4s' "$status") # Pad status to 4 chars
             case "$status" in
                 PASS) status_icon="✅"; color="$C_GREEN" ;;
                 WARN) status_icon="⚠️"; color="$C_YELLOW" ;;
                 FAIL) status_icon="❌"; color="$C_RED" ;;
                 SKIP) status_icon="⏭️"; color="" ;; # No color for skip
                 UNKN) status_icon="❓"; color="$C_RED" ;;
             esac
             # Indent test results under category
             printf "  %-25s [%s%s%s] %s\n" "$test_name" "$color" "$padded_status" "$C_RESET" "$message"
        done
    fi

    # --- Auto-Fix ---
    if [[ "$AUTO_FIX" == "true" && $CRITICAL_COUNT -gt 0 ]]; then
        log_warn "Attempting auto-fix due to critical errors..."
        # Call the self_heal_once function from monitoring.sh
        if self_heal_once; then
             log_success "Auto-fix attempt completed. Re-run check-health.sh to verify."
             # Optionally re-run checks here? Could lead to loops. Better to suggest manual re-run.
        else
             log_error "Auto-fix attempt failed. Manual intervention required."
             overall_status=1 # Ensure exit code reflects final failure
        fi
    fi

    log_header "Health Check Finished"
    exit $overall_status
}

# --- Execute Main ---
main "$@"
