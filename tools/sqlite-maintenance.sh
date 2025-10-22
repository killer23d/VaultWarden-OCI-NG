#!/usr/bin/env bash
# tools/sqlite-maintenance.sh - SQLite database maintenance and optimization

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
# Source config first for PROJECT_STATE_DIR
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh."
        # Use default state dir if config fails
        PROJECT_STATE_DIR="/var/lib/vaultwarden"
    fi
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    # Use default state dir if config lib missing
    PROJECT_STATE_DIR="/var/lib/vaultwarden"
fi

# Source system library for service management
SYSTEM_LIB_AVAILABLE=false
if [[ -f "lib/system.sh" ]]; then
    source "lib/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
    log_warn "lib/system.sh not found. Automatic service stop/start disabled."
fi

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Configuration ---
MAINTENANCE_TYPE="quick" # Default maintenance type
DRY_RUN=false
DB_PATH="" # Will be detected

# --- Help text ---
show_help() {
    cat << EOF
SQLite Database Maintenance Tool for VaultWarden-OCI-NG
USAGE:
  sudo $0 [OPTIONS] # Sudo needed if service stop/start required for offline tasks
OPTIONS:
  -t, --type TYPE      Maintenance type to perform:
                       - quick (default): Fast integrity check (online safe).
                       - integrity: Thorough integrity check (online safe).
                       - analyze: Updates query statistics (requires offline).
                       - optimize: Applies PRAGMA optimize, enables WAL mode (requires offline).
                       - vacuum: Reclaims unused space (requires offline, can take time).
                       - full: Runs integrity, vacuum, analyze, optimize (requires offline).
  -n, --dry-run        Show commands that would be executed without making changes.
  -h, --help           Show this help message.
  --debug              Enable debug logging (set DEBUG=true).

NOTES:
  - 'offline' tasks require stopping the Vaultwarden service. The script attempts this automatically if possible.
  - Ensure sufficient disk space before running 'vacuum' or 'full' on large databases.
  - Recommended schedule: 'quick' or 'integrity' daily/weekly, 'full' monthly.
EOF
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            # Validate maintenance type
            if [[ "$2" =~ ^(quick|integrity|analyze|optimize|vacuum|full)$ ]]; then
                MAINTENANCE_TYPE="$2"
            else
                log_error "Invalid maintenance type: '$2'. See --help for valid types."
                exit 1
            fi
            shift 2
            ;;
        -n|--dry-run) DRY_RUN=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        --debug) export DEBUG=true; shift ;; # Enable debug logging
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- Functions ---
detect_database_path() {
    # Relies on PROJECT_STATE_DIR being set by config.sh loading
    DB_PATH="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/db.sqlite3"
    _log_debug "Using database path: $DB_PATH"
    if [[ ! -f "$DB_PATH" ]]; then
        log_error "Database file not found at detected path: $DB_PATH"
        log_info "Ensure Vaultwarden has run at least once to create the database."
        return 1
    fi
    log_info "Detected database at: $DB_PATH"
    return 0
}

# Helper to run SQLite commands, handling dry run and errors
run_sqlite_command() {
    local db="$1"
    local command="$2"
    local description="$3"
    local timeout_seconds="${4:-600}" # Default timeout 10 minutes

    log_info "Running: $description..."
    _log_debug "Executing on '$db' (timeout ${timeout_seconds}s): $command"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would execute on '$db': $command"
        return 0 # Assume success in dry run
    fi

    # Check if DB file exists before running command
    if [[ ! -f "$db" ]]; then
         log_error "Database file '$db' not found. Cannot execute command."
         return 1
    fi

    local output error_occurred=false exit_code
    # Use timeout command for safety, capture stderr to stdout
    output=$(timeout "$timeout_seconds" sqlite3 "$db" "$command" 2>&1)
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        error_occurred=true
        if [[ $exit_code -eq 124 ]]; then # Timeout exit code
            log_error "$description timed out after ${timeout_seconds} seconds."
        else
            log_error "$description failed (SQLite Exit Code: $exit_code)."
        fi
        # Log output only if it's not empty
        [[ -n "$output" ]] && log_error "Output: $output"
    fi

    # Specific check for integrity_check result (only if command ran successfully)
    if [[ "$command" == "PRAGMA integrity_check;" && "$error_occurred" == false ]]; then
        # Trim whitespace from output
        local trimmed_output="${output//[$'\t\r\n ']}"
        if [[ "$trimmed_output" == "ok" ]]; then
            log_success "$description passed."
        else
            log_error "$description FAILED."
            [[ -n "$output" ]] && log_error "Details: $output" # Show non-"ok" output
            error_occurred=true # Mark failure
        fi
    elif [[ "$error_occurred" == false ]]; then
        # For other commands, log success if exit code was 0
        log_success "$description complete."
        # Log output in debug mode for other commands if needed
        _log_debug "Output: $output"
    fi

    # Return final status
    [[ "$error_occurred" == "true" ]] && return 1 || return 0
}


run_integrity_check() {
    # Use a shorter timeout for integrity check
    run_sqlite_command "$DB_PATH" "PRAGMA integrity_check;" "Database Integrity Check" 300 # 5 min timeout
}

run_vacuum() {
    local size_before size_after
    size_before=$(du -sh "$DB_PATH" 2>/dev/null | awk '{print $1}' || echo "N/A")
    # Vacuum can take a long time, use a longer timeout (e.g., 30 mins)
    if run_sqlite_command "$DB_PATH" "VACUUM;" "Database VACUUM" 1800; then
        size_after=$(du -sh "$DB_PATH" 2>/dev/null | awk '{print $1}' || echo "N/A")
        log_info "VACUUM complete. Size changed from $size_before to $size_after."
        return 0
    else
        return 1
    fi
}

run_analyze() {
    # Analyze is usually fast, shorter timeout (e.g., 5 mins)
    run_sqlite_command "$DB_PATH" "ANALYZE;" "Database ANALYZE" 300
}

run_optimize_wal() {
    log_info "Applying database optimizations (WAL mode, Optimize)..."
    # Commands to run sequentially
    local commands=(
        "PRAGMA journal_mode = WAL;"        # Enable Write-Ahead Logging
        "PRAGMA synchronous = NORMAL;"    # Improve performance with good safety balance in WAL mode
        "PRAGMA optimize;"                # Run built-in SQLite optimizations
        "PRAGMA wal_checkpoint(TRUNCATE);" # Checkpoint and truncate WAL file aggressively (requires exclusive lock briefly)
    )
    local all_cmds_success=true overall_status=0
    # Use a reasonable timeout for each command (e.g., 2 mins)
    local cmd_timeout=120

    for cmd in "${commands[@]}"; do
        local desc="Applying: ${cmd%%;*}" # Get description from command
        if ! run_sqlite_command "$DB_PATH" "$cmd" "$desc" "$cmd_timeout"; then
             all_cmds_success=false
             overall_status=1
             log_warn "Failed command: $cmd. Continuing with others..."
             # Decide whether to stop on first error or continue? Continue for optimize.
             # break # Uncomment to stop on first error
        fi
    done

     # Check final journal mode after attempting to set it
     log_info "Verifying final journal mode..."
     local current_journal_mode
     current_journal_mode=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;" 2>/dev/null || echo "error")
     if [[ "$current_journal_mode" == "wal" ]]; then
         log_success "Database confirmed to be in WAL mode."
     elif [[ "$current_journal_mode" != "error" ]]; then
         log_error "Failed to set WAL mode! Current mode: $current_journal_mode"
         all_cmds_success=false # Mark failure if WAL mode wasn't set
         overall_status=1
     else
          log_error "Could not verify journal mode after optimization attempts."
          all_cmds_success=false
          overall_status=1
     fi

    if [[ "$all_cmds_success" == "true" ]]; then
        log_success "All optimization commands completed successfully."
    else
        log_warn "One or more optimization commands failed. Check logs above."
    fi
    return $overall_status
}


# --- Service Management ---
stop_vaultwarden() {
    log_info "Attempting to stop Vaultwarden service..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would stop Vaultwarden service via Docker Compose."
        return 0
    fi

    # Use library function if available
    if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _stop_service >/dev/null; then
         # Assuming _stop_service handles docker compose internally or via systemd unit
         # Need to clarify how _stop_service works for compose services
         # For now, use direct docker compose command for clarity
         log_info "Using 'docker compose stop vaultwarden'..."
         if (cd "$PROJECT_ROOT" && docker compose stop vaultwarden); then
              log_success "Vaultwarden service stopped."
              sleep 5 # Allow time for service to fully stop
              return 0
         else
              log_error "Failed to stop Vaultwarden service using Docker Compose."
              return 1
         fi
    elif command -v docker >/dev/null && docker compose version >/dev/null; then
        # Fallback if system library missing/incomplete
         log_info "Using 'docker compose stop vaultwarden' (fallback)..."
         if (cd "$PROJECT_ROOT" && docker compose stop vaultwarden); then
              log_success "Vaultwarden service stopped."
              sleep 5
              return 0
         else
              log_error "Failed to stop Vaultwarden service using Docker Compose."
              return 1
         fi
    else
         log_error "Cannot stop service: Docker Compose or system library missing."
         return 1
    fi
}

start_vaultwarden() {
    log_info "Attempting to start Vaultwarden service..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would start Vaultwarden service via Docker Compose."
        return 0
    fi

    # Use library function if available
    if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _start_service >/dev/null; then
         # See comment in stop_vaultwarden regarding library vs direct command
         log_info "Using 'docker compose up -d vaultwarden'..."
         if (cd "$PROJECT_ROOT" && docker compose up -d vaultwarden); then
              log_success "Vaultwarden service started."
              log_info "Allowing time for service to initialize..."
              sleep 15 # Wait a bit before script exits
              return 0
         else
              log_error "Failed to start Vaultwarden service using Docker Compose."
              return 1
         fi
    elif command -v docker >/dev/null && docker compose version >/dev/null; then
        # Fallback
         log_info "Using 'docker compose up -d vaultwarden' (fallback)..."
         if (cd "$PROJECT_ROOT" && docker compose up -d vaultwarden); then
              log_success "Vaultwarden service started."
              sleep 15
              return 0
         else
              log_error "Failed to start Vaultwarden service using Docker Compose."
              return 1
         fi
    else
         log_error "Cannot start service: Docker Compose or system library missing."
         return 1
    fi
}

# Check if service is running
is_vaultwarden_running() {
    _log_debug "Checking if Vaultwarden service is running..."
    local is_running=false
    # Use library function if available
    if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _compose_service_running >/dev/null; then
        _compose_service_running "vaultwarden" && is_running=true
    elif command -v docker >/dev/null && docker compose version >/dev/null; then
        # Fallback check
        if (cd "$PROJECT_ROOT" && docker compose ps --status running | grep -q vaultwarden); then
            is_running=true
        fi
    else
        log_warn "Cannot check service status: Docker Compose or system library missing."
        # Assume not running if we can't check? Or assume running? Assume not running.
        is_running=false
    fi

    if [[ "$is_running" == "true" ]]; then
        _log_debug "Vaultwarden service is currently running."
        return 0 # Bash success (true)
    else
        _log_debug "Vaultwarden service is not running."
        return 1 # Bash failure (false)
    fi
}


# --- Main Execution ---
main() {
    log_header "SQLite Database Maintenance for Vaultwarden"

    # Check for sqlite3 command early
     if ! command -v sqlite3 >/dev/null 2>&1; then
        log_error "sqlite3 command not found. Please install it (e.g., sudo apt install sqlite3)."
        exit 1
     fi

    # Detect DB path (requires config loaded)
    if ! detect_database_path; then
        exit 1
    fi

    # Determine if offline maintenance is needed
    local requires_offline=false service_was_running=false overall_status=0
    case "$MAINTENANCE_TYPE" in
        full|vacuum|analyze|optimize) requires_offline=true ;;
        quick|integrity) requires_offline=false ;;
        *) log_error "Internal error: Invalid maintenance type '$MAINTENANCE_TYPE'."; exit 1 ;;
    esac
    log_info "Selected maintenance type: $MAINTENANCE_TYPE (Requires offline: $requires_offline)"

    # Check current service status
    if is_vaultwarden_running; then
        service_was_running=true
    fi

    # Stop service if required and currently running
    if [[ "$requires_offline" == "true" ]]; then
        if [[ "$service_was_running" == "true" ]]; then
            if ! stop_vaultwarden; then
                log_error "Failed to stop Vaultwarden service. Aborting maintenance that requires offline access."
                exit 1
            fi
        else
            log_info "Vaultwarden service is not running. Proceeding with offline maintenance."
        fi
    fi

    # --- Perform Maintenance Tasks ---
    log_info "Starting maintenance task(s)..."
    case "$MAINTENANCE_TYPE" in
        "quick"|"integrity")
            run_integrity_check || overall_status=1
            ;;
        "full")
            if run_integrity_check; then
                # Only proceed if integrity is okay
                run_vacuum || overall_status=1
                run_analyze || overall_status=1
                run_optimize_wal || overall_status=1
            else
                 log_error "Integrity check failed. Aborting full maintenance."
                 overall_status=1
            fi
            ;;
        "vacuum")
            run_vacuum || overall_status=1
            ;;
        "analyze")
            run_analyze || overall_status=1
            ;;
        "optimize")
             run_optimize_wal || overall_status=1
            ;;
    esac

    # --- Restart Service if Stopped ---
    if [[ "$requires_offline" == "true" && "$service_was_running" == "true" ]]; then
        # Always attempt to restart if we stopped it, even if maintenance failed
        log_info "Maintenance attempt complete. Restarting Vaultwarden service..."
        if ! start_vaultwarden; then
             log_error "Failed to restart Vaultwarden service after maintenance attempt!"
             # If start fails, the overall status should reflect failure
             overall_status=1
        fi
    fi

    # --- Final Report ---
    log_header "Maintenance Summary"
    if [[ $overall_status -eq 0 ]]; then
        log_success "Maintenance task '$MAINTENANCE_TYPE' completed successfully."
        exit 0
    else
        log_error "Maintenance task '$MAINTENANCE_TYPE' encountered errors."
        exit 1
    fi
}

# --- Script Entry Point ---
# Wrap main execution
main
