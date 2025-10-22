#!/usr/bin/env bash
# tools/edit-secrets.sh - Securely edit encrypted secrets using SOPS

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
# Source SOPS library (essential for this script)
SOPS_AVAILABLE=false
if [[ -f "lib/sops.sh" ]]; then
    source "lib/sops.sh"
    # Check if SOPS lib loaded successfully (it sets SOPS_LIB_LOADED=true)
    if [[ "${SOPS_LIB_LOADED:-false}" == "true" ]]; then
        SOPS_AVAILABLE=true
    else
        log_error "Failed to properly load SOPS library (lib/sops.sh)."
        # Continue for now, but validation will likely fail
    fi
else
    log_error "CRITICAL: SOPS library not found: lib/sops.sh. Cannot manage secrets."
    exit 1 # Cannot function without SOPS library
fi
# Source notifications library (optional, for --test-smtp)
NOTIFICATIONS_AVAILABLE=false
if [[ -f "lib/notifications.sh" ]]; then
    # Source it here, just before potential use in _run_smtp_test
    # source "lib/notifications.sh" # Deferred sourcing below
    NOTIFICATIONS_AVAILABLE=true
else
    log_warn "Optional library not found: lib/notifications.sh. SMTP testing disabled."
fi
# Source constants if available (for paths)
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi


# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---


# --- Configuration ---
# Use constants from sops.sh/constants.sh if defined, else defaults
readonly SECRETS_FILE="${SECRETS_FILE:-secrets/secrets.yaml}"
readonly SECRETS_EXAMPLE_FILE="${SECRETS_EXAMPLE_FILE:-secrets/secrets.yaml.example}"
readonly AGE_KEY_FILE="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
# Preferred editor order: VISUAL, EDITOR environment variables, then nano as fallback
EDITOR="${VISUAL:-${EDITOR:-nano}}"
_log_debug "Using editor: $EDITOR"

# --- Help text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Secure Secret Editor
USAGE:
    $0 [OPTIONS]
DESCRIPTION:
    Securely opens the encrypted secrets file ('$SECRETS_FILE') for editing using SOPS
    and your preferred editor (\$VISUAL, \$EDITOR, fallback: nano).

    SOPS uses the Age key at '$AGE_KEY_FILE' for decryption/encryption.

    After a successful save where changes are detected, it can optionally trigger
    the generation of a new Emergency Access Kit via email (if configured).

OPTIONS:
    --help          Show this help message
    --view          View decrypted secrets in read-only mode (outputs to terminal)
    --test-smtp     Test the SMTP configuration stored in the secrets file
                    (requires lib/notifications.sh)
    --no-kit        Disable automatic emergency kit generation after editing
    --editor EDITOR Override the editor used (e.g., --editor vim)
    --debug         Enable debug logging (set DEBUG=true)

SECURITY:
    Ensures secrets remain encrypted at rest. Uses Age for strong encryption.
    Temporary decrypted files are handled by SOPS internally.
EOF
}

# --- Argument Parsing ---
VIEW_ONLY=false
TEST_SMTP=false
NO_KIT=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --view) VIEW_ONLY=true; shift ;;
        --test-smtp) TEST_SMTP=true; shift ;;
        --no-kit) NO_KIT=true; shift ;;
        --editor)
             EDITOR="$2"
             # Check if specified editor exists
              if ! command -v "$EDITOR" >/dev/null; then
                   log_error "Specified editor '$EDITOR' not found in PATH."
                   exit 1
              fi
              _log_debug "Overriding editor to: $EDITOR"
              shift 2
              ;;
        --debug) export DEBUG=true; shift ;; # Enable debug logging
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- Functions ---

# Function to test SMTP using the notification library
_run_smtp_test() {
    log_info "Attempting to test SMTP configuration from secrets..."
    if [[ "$NOTIFICATIONS_AVAILABLE" != "true" ]]; then
         log_error "Notification library (lib/notifications.sh) is required for SMTP testing but was not found."
         return 1
    fi

    # Source notifications lib here, just before use, handle failure
    if ! source "lib/notifications.sh"; then
         log_error "Failed to source the notification library. Cannot perform SMTP test."
         return 1
    fi

    # Check if the required function exists after sourcing
    if ! declare -f test_smtp_connection > /dev/null; then
         log_error "'test_smtp_connection' function not found in sourced notification library."
         log_info "Ensure lib/notifications.sh is up-to-date."
         return 1
    fi

    # The test_smtp_connection function should handle secrets loading and sending
    log_info "Calling test_smtp_connection function..."
    if test_smtp_connection; then
        # Success message logged by the function itself
        log_info "SMTP test command finished."
        return 0
    else
        # Error logged by the function itself
        log_error "SMTP test command failed. Check secrets and notification logs."
        return 1
    fi
}

# Function to trigger emergency kit generation
_generate_emergency_kit() {
    if [[ "$NO_KIT" == "true" ]]; then
        log_info "Skipping emergency kit generation as requested (--no-kit)."
        return 0
    fi

    log_info "Secrets appear to have been modified. Generating a new Emergency Access Kit..."
    local kit_script="$PROJECT_ROOT/tools/create-emergency-kit.sh"
    if [[ -x "$kit_script" ]]; then
        # Run non-interactively, auto-generate password, use sudo if needed?
        # Kit script handles sudo check internally if required.
        log_info "Running: $kit_script --auto-password"
        local kit_output kit_rc=0
        kit_output=$("$kit_script" --auto-password 2>&1) || kit_rc=$?

        if [[ $kit_rc -eq 0 ]]; then
            log_success "A new Emergency Access Kit has been generated and should be sent via email (if configured)."
            log_warn "Ensure you received the kit email and store the kit file securely offline."
            _log_debug "Kit generation output:\n$kit_output"
            return 0
        else
            log_error "Failed to generate the Emergency Access Kit automatically (rc=$kit_rc)."
            log_error "Output:\n$kit_output"
            log_error "Please run '$kit_script' manually to generate and secure the kit."
            return 1 # Indicate failure
        fi
    else
        log_error "'$kit_script' not found or not executable. Emergency kit NOT generated."
        log_warn "It is STRONGLY recommended to generate a kit manually after changing secrets using: ./tools/create-emergency-kit.sh"
        return 1 # Indicate failure
    fi
}


# --- Main Execution ---
main() {
    log_header "Secure Secret Management via SOPS"

    # Validate the SOPS environment before proceeding (uses function from sops.sh)
    if [[ "$SOPS_AVAILABLE" != "true" ]]; then
        log_error "SOPS library did not load correctly. Cannot proceed."
        exit 1
    fi
    log_info "Validating SOPS/Age environment..."
    if ! validate_sops_environment; then
        log_error "SOPS environment validation failed. Cannot proceed securely."
        log_info "Ensure 'sops'/'age' commands are installed, Age key exists at '$AGE_KEY_FILE' with correct permissions, and SOPS config '$SOPS_CONFIG' is correct."
        exit 1
    fi
    log_success "SOPS/Age environment appears healthy."

    # Handle SMTP test mode
    if [[ "$TEST_SMTP" == "true" ]]; then
        _run_smtp_test
        exit $?
    fi

    # --- Ensure Secrets File Exists ---
    if [[ ! -f "$SECRETS_FILE" ]]; then
        log_warn "'$SECRETS_FILE' not found."
        if [[ ! -f "$SECRETS_EXAMPLE_FILE" ]]; then
            log_error "FATAL: Example secrets file '$SECRETS_EXAMPLE_FILE' is also missing. Cannot create new secrets file."
            exit 1
        fi
         log_info "Creating a new encrypted secrets file from template '$SECRETS_EXAMPLE_FILE'..."
         # Copy template
         if ! cp "$SECRETS_EXAMPLE_FILE" "$SECRETS_FILE"; then
              log_error "Failed to copy template to '$SECRETS_FILE'. Check permissions."
              exit 1
         fi
         # Encrypt it in place using SOPS default rules (.sops.yaml) and environment (key file)
         log_info "Encrypting the new secrets file..."
         # Run sops command directly, ensuring environment (key file) is exported by sops.sh
         if sops --encrypt --in-place "$SECRETS_FILE"; then
            log_success "New encrypted secrets file created at '$SECRETS_FILE'."
            log_info "Opening the new file for initial editing..."
            # Continue to editor below
         else
             log_error "Failed to encrypt new secrets file '$SECRETS_FILE' using SOPS."
             rm -f "$SECRETS_FILE" # Clean up potentially corrupt file
             exit 1
         fi
    fi

    # Handle view-only mode
    if [[ "$VIEW_ONLY" == "true" ]]; then
        log_info "Viewing decrypted secrets (read-only) from '$SECRETS_FILE':"
        # Use sops -d, ensuring environment (key file) is exported
        # Capture output, check exit code
        local decrypted_content rc=0
        decrypted_content=$(sops -d "$SECRETS_FILE" 2>&1) || rc=$?

        if [[ $rc -ne 0 ]]; then
             log_error "Failed to decrypt secrets for viewing (rc=$rc)."
             log_error "SOPS Output/Error: $decrypted_content"
             exit 1
        else
             # Print decrypted content to standard output
             echo "$decrypted_content"
             exit 0
        fi
    fi

    # --- Edit Mode ---
    log_info "Opening '$SECRETS_FILE' for editing using '${EDITOR}'..."
    log_warn "Save and close the editor when finished. SOPS will automatically re-encrypt."
    log_info "(Ensure your editor is configured correctly and does not save backup files in place)."

    # Get checksum or modification time *before* editing to reliably detect changes
    local original_mtime original_checksum
    original_mtime=$(stat -c %Y "$SECRETS_FILE" 2>/dev/null || echo "0")
    original_checksum=$(sha256sum "$SECRETS_FILE" 2>/dev/null | awk '{print $1}' || echo "new_file_or_error")


    # Use the specified editor with sops
    # sops command opens the decrypted content in $EDITOR and re-encrypts on save.
    # Ensure SOPS_AGE_KEY_FILE is exported (done by sourcing sops.sh).
    # Capture stderr to check for specific SOPS messages if needed.
    local sops_output sops_rc=0
    # Run sops with the chosen editor, capture stderr
    sops_output=$(EDITOR="$EDITOR" sops "$SECRETS_FILE" 2>&1) || sops_rc=$?


    # Check SOPS exit code
    if [[ $sops_rc -ne 0 ]]; then
        log_error "SOPS editor session failed or was cancelled (rc=$sops_rc)."
        # Check if file still exists and wasn't corrupted
         if [[ -f "$SECRETS_FILE" ]]; then
              # Check if SOPS reported "clean exit" despite non-zero rc (e.g., editor cancelled)
              if [[ "$sops_output" == *"clean exit"* ]]; then
                   log_info "Editor session cancelled or exited without saving. No changes applied."
              else
                   log_error "SOPS reported an error during editing/re-encryption."
                   log_error "SOPS Output/Error:\n$sops_output"
                   log_warn "Your changes were likely NOT saved. The original encrypted file may remain, but verify its integrity."
              fi
         else
              log_error "CRITICAL: The secrets file '$SECRETS_FILE' seems to be missing after the SOPS session!"
              log_error "Manual recovery from backups might be needed."
         fi
        exit 1
    fi
    # SOPS command succeeded (rc=0)

    # Re-validate the SOPS file after editing (optional but good practice)
     _log_debug "Re-validating secrets file integrity after edit..."
     if ! timeout 10 sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
          log_error "Verification failed: Could not decrypt secrets file after saving!"
          log_error "The file might be corrupted. Check SOPS logs or editor behavior."
          exit 1
     fi
     _log_debug("Post-edit verification successful.")

    # Check if the file content actually changed
    local new_mtime new_checksum changes_detected=false
    new_mtime=$(stat -c %Y "$SECRETS_FILE" 2>/dev/null || echo "1") # Get new timestamp
    new_checksum=$(sha256sum "$SECRETS_FILE" 2>/dev/null | awk '{print $1}' || echo "error_reading")

    # Compare checksums and modification time for robust change detection
    if [[ "$original_checksum" != "$new_checksum" || "$original_mtime" == "0" ]]; then
        # Checksum differs OR it was a new file (original_mtime=0)
        changes_detected=true
    elif [[ "$original_mtime" != "$new_mtime" ]]; then
         # Checksum is same, but timestamp changed (might happen with some editors/saves)
         log_info "Timestamp changed but checksum is identical. Treating as no significant change."
         changes_detected=false
    else
         # Checksum and timestamp are identical
         changes_detected=false
    fi


    if [[ "$changes_detected" == false ]]; then
        log_success "Secrets file saved and re-encrypted. No content changes detected."
        log_info "Skipping emergency kit generation."
    else
        log_success "Secrets updated and re-encrypted successfully in '$SECRETS_FILE'."
        # Trigger emergency kit generation
        _generate_emergency_kit
    fi

    log_header "Secret Management Session Complete"
}

# --- Script Entry Point ---
# Run main execution logic
main
