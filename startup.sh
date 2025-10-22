#!/usr/bin/env bash
# startup.sh - Orchestrates VaultWarden-OCI-NG stack startup and health checks

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
# For scripts in the root directory, SCRIPT_DIR is PROJECT_ROOT
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
# cd "$PROJECT_ROOT" # Already in project root

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
# Source essential libraries with error checking first
for lib in config startup-helpers; do # Load config first, then helpers
    lib_file="lib/${lib}.sh"
    if [[ -f "$lib_file" ]]; then
        # shellcheck source=/dev/null
        source "$lib_file"
    else
        # Use log_error now that logging.sh is sourced
        log_error "CRITICAL: Required library not found: $lib_file"
        log_error "Cannot continue without essential libraries."
        exit 1
    fi
done

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Configuration & Flags ---
# Default values for flags (moved here, previously defined before sourcing helpers)
FORCE_RESTART=false
DRY_RUN=false
SKIP_HEALTH=false
STOP_MODE=false # Added STOP_MODE flag

# --- Help Text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Startup Script
USAGE:
    $0 [OPTIONS]
DESCRIPTION:
    Starts, restarts, or manages the VaultWarden Docker Compose stack.
    Includes configuration loading, secret decryption, health checks,
    and optional cleanup.
OPTIONS:
    --help           Show this help message
    --force-restart  Stop existing containers and recreate them before starting
    --dry-run        Show what commands would be run without executing them
    --skip-health    Skip the post-startup health check (faster startup)
    --down           Stop and remove all containers defined in the compose file
EOF
}

# --- Argument Parsing ---
# STOP_MODE=false # Defined earlier
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help) show_help; exit 0 ;;
        --force-restart) FORCE_RESTART=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --skip-health) SKIP_HEALTH=true; shift ;;
        --down) STOP_MODE=true; shift ;; # Handle stop command
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- Main Functions ---

# Function to stop and remove containers
stop_stack() {
    log_header "Stopping VaultWarden Stack"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run 'docker compose down --remove-orphans'."
        return 0
    fi

    # Check dependencies needed for stop operation
    if ! command -v docker >/dev/null || ! docker compose version >/dev/null; then
        log_error "Docker or Docker Compose not available. Cannot stop stack."
        return 1
    fi

    # Check if compose file exists before trying to use it
    local compose_file_path="$PROJECT_ROOT/$COMPOSE_FILE" # Use constant from constants.sh via startup-helpers
    if [[ ! -f "$compose_file_path" ]]; then
        log_warn "Compose file '$compose_file_path' not found. Nothing to stop."
        return 0
    fi

    log_info "Running 'docker compose down --remove-orphans'..."
    # Ensure command runs from project root context
    if (cd "$PROJECT_ROOT" && docker compose -f "$compose_file_path" down --remove-orphans); then
        log_success "VaultWarden stack stopped successfully."
        # Clean up temporary Docker secrets directory after stopping
        local docker_secrets_path="$PROJECT_ROOT/$DOCKER_SECRETS_DIR" # Use constant
        if [[ -d "$docker_secrets_path" ]]; then
             log_info "Cleaning up temporary Docker secrets directory..."
             # Use rm -rf, shred is overkill here as files contain already-known secrets
             rm -rf "$docker_secrets_path" || log_warn "Failed to remove $docker_secrets_path"
        fi
    else
        log_error "Failed to stop VaultWarden stack using 'docker compose down'."
        return 1
    fi
    return 0
}


# --- Main Execution ---
main() {

    # Handle --down command first if present
    if [[ "$STOP_MODE" == "true" ]]; then
        stop_stack
        exit $?
    fi

    log_header "Starting VaultWarden-OCI-NG Stack"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "*** DRY RUN MODE ENABLED - NO CHANGES WILL BE MADE ***"
    fi

    # Load configuration (.env + secrets) using the config library
    # load_config now also performs consistency checks and logs warnings
    if ! load_config; then
        log_error "Failed to load system configuration. Aborting startup."
        exit 1
    fi
    # Consistency checks are now part of load_config()

    # --- Run startup steps using helper functions ---
    # These functions are now defined in lib/startup-helpers.sh

    # 1. Basic Validation (Docker, Files, SOPS Env)
    basic_validation || { log_error "Basic validation failed."; exit 1; }

    # 2. Ensure Log Dirs
    ensure_log_directories || { log_error "Failed to ensure log directories."; exit 1; }

    # 3. Prepare Docker Secrets (Decrypt SOPS -> Files)
    prepare_docker_secrets || { log_error "Failed to prepare Docker secrets."; exit 1; }

    # 4. Render ddclient config if enabled
    local render_script="tools/render-ddclient-conf.sh"
    if [[ "$(get_config_value "DDCLIENT_ENABLED" "false")" == "true" ]]; then
         if [[ -x "$render_script" ]]; then
             log_info "DDClient enabled. Rendering configuration..."
             # Run script in subshell to avoid polluting environment? Or source and call function?
             # Running as separate script is safer.
             if "$render_script"; then
                 log_success "DDClient configuration rendered."
             else
                  log_error "Failed to render DDClient configuration. DDClient service may fail."
                  # Continue startup? Or exit? Continue but warn.
             fi
         else
              log_warn "DDClient enabled but render script '$render_script' not found/executable."
         fi
    fi


    # 5. Handle Force Restart (Stop existing containers)
    if [[ "$FORCE_RESTART" == "true" ]]; then
        log_info "Force restart requested. Stopping existing containers..."
        stop_stack || { log_error "Failed to stop stack during force restart."; exit 1; }
        sleep 2 # Brief pause after down
    fi

    # 6. Start Services (docker compose up)
    start_services || { log_error "Failed to start services."; exit 1; }

    # 7. Post-Startup Health Check (Optional)
    # Pass DRY_RUN and SKIP_HEALTH status to the helper function if needed, or rely on global vars
    post_startup_health_check || true # Log warnings on failure but don't exit script

    log_success "VaultWarden-OCI-NG startup process completed."
}

# Execute main function
main
