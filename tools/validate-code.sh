#!/usr/bin/env bash
# tools/validate-code.sh - Runs shellcheck on all shell scripts in the project.

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# This script is simple and might not need full logging, but include for consistency.
if [[ -f "lib/logging.sh" ]]; then
    source "lib/logging.sh"
    _set_log_prefix "$(basename "$0" .sh)" # Set prefix if logging loaded
else
    # Minimal logging if library missing
    echo "[validate-code.sh][INFO] lib/logging.sh not found, using basic echo." >&2
    log_info() { echo "[INFO] $*"; }
    log_warn() { echo "[WARN] $*"; }
    log_error() { echo "[ERROR] $*" >&2; }
    log_success() { echo "[SUCCESS] $*"; }
    _log_debug() { :; }
    log_header() { echo "--- $* ---"; }
fi

# --- Rest of script follows ---

log_header "Shell Script Code Validation"

# Check if shellcheck command exists
if ! command -v shellcheck >/dev/null 2>&1; then
    log_error "shellcheck command not found."
    log_info "Please install shellcheck to perform code validation."
    log_info "On Debian/Ubuntu: sudo apt install shellcheck"
    exit 1 # Fail if shellcheck is missing
fi

log_info "Running ShellCheck on all .sh files in tools/ and lib/ directories..."
log_info "(Excluding backup directories, node_modules, etc. if they exist)"

# Find all .sh files in tools/ and lib/ directories.
# Exclude potential vendor/backup directories for safety.
# Use find with -print0 and xargs -0 for safer handling of filenames with spaces/special chars.
local find_output find_rc=0 files_found=0 files_failed=0

# Use process substitution to count files found
mapfile -t files_to_check < <(find tools lib -type f -name "*.sh" -print)
files_found=${#files_to_check[@]}

if [[ $files_found -eq 0 ]]; then
    log_warn "No .sh files found in tools/ or lib/ directories to validate."
    exit 0 # Not an error, just nothing to do
fi

log_info "Found $files_found shell script(s) to check..."

# Run shellcheck on the found files.
# The `+` at the end of exec passes multiple files at once for efficiency.
# Capture output and check exit code.
# Run directly without find -exec to get better output formatting from shellcheck itself.
shellcheck_output=$(shellcheck "${files_to_check[@]}" 2>&1) || find_rc=$?

# Check shellcheck's exit code
if [[ $find_rc -eq 0 ]]; then
    log_success "----------------------------------------"
    log_success "✅ SUCCESS: All $files_found shell scripts passed validation."
    exit 0
else
    # shellcheck returns:
    # 0: All files passed
    # 1: Files had issues
    # 2: Files had issues, some couldn't be parsed
    # >2: Other errors
    log_error "----------------------------------------"
    log_error "❌ ERROR: Shell script validation failed (ShellCheck exit code: $find_rc)."
    log_error "Please fix the issues reported by shellcheck below:"
    # Print the captured output
    echo "$shellcheck_output" >&2 # Output errors to stderr
    # Try to count failed files (heuristic based on output lines starting with './' or 'tools/' or 'lib/')
    files_failed=$(echo "$shellcheck_output" | grep -Ec '^(In |(\./)?(tools|lib)/.*\.sh):')
    [[ $files_failed -gt 0 ]] && log_error "Estimated $files_failed file(s) with issues." || log_error "Issues found, count unclear."
    exit 1 # Exit with error code
fi
