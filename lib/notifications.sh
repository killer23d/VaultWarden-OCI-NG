#!/usr/bin/env bash
# lib/notifications.sh - Simple email notification system using msmtp and Age secrets

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
    log_info() { echo "[notifications.sh][INFO] $*"; }
    log_warn() { echo "[notifications.sh][WARN] $*"; }
    log_error() { echo "[notifications.sh][ERROR] $*" >&2; }
    log_success() { echo "[notifications.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
fi

# Source SOPS library (needed for get_secret)
SOPS_AVAILABLE=false
if [[ -f "$LIB_DIR/sops.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/sops.sh"
    SOPS_AVAILABLE=true
else
    log_error "CRITICAL: SOPS library (lib/sops.sh) not found. Cannot load secrets for SMTP."
    # Cannot function without sops
fi

# Source config library (needed for SMTP vars and PROJECT_STATE_DIR)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/config.sh"
    # Load config early, needed for LOG_FILE path
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh during sourcing."
        # Use defaults if config fails
        PROJECT_STATE_DIR="/var/lib/vaultwarden"
        ADMIN_EMAIL="root@localhost" # Default recipient
    fi
else
    log_error "CRITICAL: Config library (lib/config.sh) not found."
    # Use defaults if config lib missing
    PROJECT_STATE_DIR="/var/lib/vaultwarden"
    ADMIN_EMAIL="root@localhost"
fi

# --- Library functions follow ---

# Configuration Variables
# Use dynamic path for temp file, ensure it's unique per run
MSMTP_CONFIG_FILE="/tmp/msmtp-vaultwarden-$$-${RANDOM}.conf"
# Log file path using PROJECT_STATE_DIR from loaded config
LOG_FILE="${PROJECT_STATE_DIR:-/var/log/vaultwarden}/logs/notifications.log" # Log inside state/logs

# --- Internal Logging ---
# Log to both console (via logging.sh) and the dedicated notification log file
_nlog() {
    local level_char="$1"; shift
    local level_name="$1"; shift
    local color="$1"; shift
    local message="$*"
    local timestamp log_line

    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    log_line="[${timestamp}] [${level_name}] ${message}"

    # Write to log file if possible (check dir/file writability)
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    # Check only once per script run? Could use a flag. Check every time for robustness.
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || sudo mkdir -p "$log_dir" 2>/dev/null || true
    fi
    if [[ -d "$log_dir" && -w "$log_dir" ]]; then
         # Append to the log file
         echo "$log_line" >> "$LOG_FILE"
    else
         # Log failure to stderr only if file logging fails
         echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Cannot write to notification log file '$LOG_FILE'. Check permissions." >&2
    fi

    # Write formatted message to stderr using functions from logging.sh if available
    case "$level_name" in
        INFO) log_info "$message" ;;
        SUCCESS) log_success "$message" ;;
        WARN) log_warn "$message" ;;
        ERROR) log_error "$message" ;;
        DEBUG) _log_debug "$message" ;; # Use internal debug
        *) echo -e "${color}[${level_name}]${C_RESET:-} ${message}" >&2 ;; # Fallback console log
    esac
}

# Wrapper functions for _nlog
_nlog_info() { _nlog "I" "INFO" "${C_BLUE:-}" "$*"; }
_nlog_warn() { _nlog "W" "WARN" "${C_YELLOW:-}" "$*"; }
_nlog_error() { _nlog "E" "ERROR" "${C_RED:-}" "$*"; }
_nlog_success() { _nlog "S" "SUCCESS" "${C_GREEN:-}" "$*"; }
# Debug logs only go to console debug if enabled by DEBUG=true
# _nlog_debug() { _nlog "D" "DEBUG" "${C_CYAN:-}" "$*"; }


# --- Helper Functions ---

# Ensure log directory exists and is writable
_ensure_log_dir() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then
        # Try creating it (needs sudo potentially)
        _log_debug "Creating notification log directory: $log_dir"
        if ! mkdir -p "$log_dir" 2>/dev/null; then
            if command -v sudo >/dev/null && [[ $EUID -ne 0 ]]; then
                 if ! sudo mkdir -p "$log_dir"; then
                     log_error "Failed to create log directory '$log_dir', even with sudo."
                     return 1
                 fi
                 # Try to set reasonable ownership if created with sudo (e.g., current user/group)
                 local owner_group="${SUDO_USER:-$(id -un)}:${SUDO_GROUP:-$(id -gn)}"
                 _log_debug "Setting ownership of $log_dir to $owner_group"
                 sudo chown "$owner_group" "$log_dir" 2>/dev/null || true
            else
                 log_error "Failed to create log directory '$log_dir'. Check permissions."
                 return 1
            fi
        fi
        # Set permissions? Maybe 775?
        chmod 775 "$log_dir" 2>/dev/null || sudo chmod 775 "$log_dir" 2>/dev/null || true
    fi
     # Ensure the log file itself is writable (or can be created)
     touch "$LOG_FILE" 2>/dev/null || sudo touch "$LOG_FILE" 2>/dev/null || {
         log_warn "Cannot write to notification log file '$LOG_FILE'. File logging disabled for this run."
         # Don't fail hard, just log warning
     }
     return 0
}

# Cleanup temporary msmtp config file on exit
_cleanup_msmtp_config() {
    if [[ -f "$MSMTP_CONFIG_FILE" ]]; then
        _log_debug "Cleaning up temporary msmtp config: $MSMTP_CONFIG_FILE"
        # Securely remove the file containing the password
        if command -v shred >/dev/null; then
             shred -uzn 1 "$MSMTP_CONFIG_FILE" 2>/dev/null || rm -f "$MSMTP_CONFIG_FILE"
        else
             rm -f "$MSMTP_CONFIG_FILE"
        fi
    fi
}
# Register cleanup function to run on script exit (normal or error)
# Use a different trap name to avoid conflicts if sourced multiple times? No, trap replaces.
trap _cleanup_msmtp_config EXIT


# Configure msmtp dynamically from secrets/config.
# Returns 0 on success, 1 on failure.
_configure_msmtp() {
    _log_debug "Configuring msmtp dynamically..."

    # Check dependencies
    if ! command -v msmtp >/dev/null 2>&1; then _nlog_error "msmtp command not found. Please install it (e.g., sudo apt install msmtp)."; return 1; fi
    if [[ "$SOPS_AVAILABLE" != "true" ]]; then _nlog_error "SOPS library not available. Cannot load SMTP secrets."; return 1; fi

    # Ensure secrets are loaded (idempotent call)
    if ! load_secrets; then
        _nlog_error "Failed to load secrets using SOPS library. Cannot configure SMTP."
        return 1
    fi
    # Config should already be loaded from top sourcing

    # Extract SMTP settings using get_config_value (for .env) and get_secret (for secrets.yaml)
    local smtp_host smtp_port smtp_from smtp_user smtp_pass smtp_security
    smtp_host=$(get_config_value "SMTP_HOST" "")
    smtp_port=$(get_config_value "SMTP_PORT" "587")
    smtp_from=$(get_config_value "SMTP_FROM" "")
    smtp_user=$(get_config_value "SMTP_USERNAME" "") # Username might be in .env or secrets, check both? Assume .env for now.
    smtp_security=$(get_config_value "SMTP_SECURITY" "starttls" | tr '[:upper:]' '[:lower:]')
    smtp_pass=$(get_secret "smtp_password" || echo "") # Password MUST be in secrets

    # Validate required settings
    local missing_vars=()
    [[ -z "$smtp_host" ]] && missing_vars+=("SMTP_HOST (in .env)")
    [[ -z "$smtp_from" ]] && missing_vars+=("SMTP_FROM (in .env)")
    [[ -z "$smtp_user" ]] && missing_vars+=("SMTP_USERNAME (in .env)")
    [[ -z "$smtp_pass" ]] && missing_vars+=("smtp_password (in secrets.yaml)")

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        _nlog_error "Missing required SMTP configuration variables: ${missing_vars[*]}"
        _nlog_info "Ensure these are set correctly in '.env' and 'secrets/secrets.yaml'."
        return 1
    fi

    # Create temporary msmtp configuration content
    local tls_setting="on" auth_setting="on" starttls_setting="" tls_certcheck="on"
    case "$smtp_security" in
        starttls) starttls_setting="on" ;;
        ssl|tls) starttls_setting="off" ;; # TLS wrapper mode
        none) tls_setting="off"; auth_setting="off"; tls_certcheck="off" ;; # No TLS, no auth, no cert check
        *) _nlog_warn "Unknown SMTP_SECURITY value '$smtp_security'. Defaulting to STARTTLS."; starttls_setting="on";;
    esac

    # Ensure log directory exists before writing config that references it
     _ensure_log_dir || return 1 # Exit if log dir cannot be ensured

    # Write the config file securely (mode 600)
    (
        umask 0177 # Ensure file is created with 600 permissions
        cat > "$MSMTP_CONFIG_FILE" <<-EOF
		# msmtp configuration for VaultWarden-OCI-NG notifications (temporary)
		defaults
		auth           ${auth_setting}
		tls            ${tls_setting}
		tls_starttls   ${starttls_setting:-off}
		tls_trust_file /etc/ssl/certs/ca-certificates.crt
		tls_certcheck  ${tls_certcheck}
		logfile        $LOG_FILE
		syslog         off

		account        vaultwarden_default
		host           ${smtp_host}
		port           ${smtp_port}
		from           "${smtp_from}"
		user           ${smtp_user}
		password       ${smtp_pass}

		# Use this account by default
		account default : vaultwarden_default
		EOF
    ) || { _nlog_error "Failed to write temporary msmtp config file '$MSMTP_CONFIG_FILE'"; return 1; }

    _log_debug "msmtp configured successfully using temporary file: $MSMTP_CONFIG_FILE"
    return 0
}

# Get notification recipient (usually the admin email)
_get_notification_recipient() {
    # ADMIN_EMAIL should be loaded into the environment by load_config()
    # Use get_config_value for robustness
    local recipient
    recipient=$(get_config_value "ADMIN_EMAIL" "")
    if [[ -n "$recipient" ]]; then
        echo "$recipient"
        return 0
    else
        _nlog_error "Could not determine notification recipient (ADMIN_EMAIL is not set in .env)."
        return 1
    fi
}


# --- Public Functions ---

# Send basic notification email
# Usage: send_notification <category> <subject> <body>
send_notification() {
    local category="$1"
    local subject="$2"
    local body="$3"

    _ensure_log_dir || return 1 # Ensure log dir exists first
    _nlog_info "Preparing to send '$category' notification: $subject"

    # Configure msmtp (creates temp file, loads secrets)
    if ! _configure_msmtp; then
        _nlog_error "SMTP configuration failed. Cannot send notification."
        return 1
    fi

    # Get recipient email address
    local recipient
    recipient=$(_get_notification_recipient) || return 1

    # Determine priority header based on category
    local priority="Normal" priority_code=3
    case "$category" in
        critical|failure|backup-failure|emergency|alert) priority="High"; priority_code=1 ;;
        maintenance|info|test|success|recovery) priority="Low"; priority_code=5 ;;
        *) priority="Normal"; priority_code=3 ;; # Default
    esac

    # Get hostname safely
    local host
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UnknownHost")

    # Create email content (using printf for headers, then body)
    local email_content
    # Use a clear subject prefix
    local subject_prefix="[Vaultwarden][${host}]"
    case "$category" in
         critical|failure|backup-failure|emergency|alert) subject_prefix="❌ $subject_prefix [CRITICAL]";;
         success|recovery) subject_prefix="✅ $subject_prefix [SUCCESS]";;
         warn*) subject_prefix="⚠️ $subject_prefix [WARN]";;
         *) subject_prefix="ℹ️ $subject_prefix [${category^^}]";; # Default info prefix
    esac

    # Construct headers and body separately for clarity
    local headers body_content timestamp server_info footer
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    server_info="Server: $host"
    footer=$(printf "\n---\nVaultWarden-OCI-NG Notification System\nGenerated: %s\n%s\nCategory: %s" "$timestamp" "$server_info" "$category")

    headers=$(printf "To: %s\nSubject: %s %s\nContent-Type: text/plain; charset=UTF-8\nX-Priority: %s (%s)\nX-VaultWarden-Category: %s\nX-VaultWarden-Host: %s" \
        "$recipient" \
        "$subject_prefix" \
        "$subject" \
        "$priority_code" "$priority" \
        "$category" \
        "$host"
    )
    body_content=$(printf "%s\n%s" "$body" "$footer")

    email_content=$(printf "%s\n\n%s" "$headers" "$body_content")

    # Send email using the temporary config file, pass recipient as argument to msmtp
    _nlog_info "Sending notification to '$recipient'..."
    _log_debug "Email Headers:\n$headers"
    # Pipe content to msmtp
    if echo -e "$email_content" | msmtp --file="$MSMTP_CONFIG_FILE" -t "$recipient"; then
        _nlog_success "Notification sent successfully to '$recipient'."
        # Temp config file cleaned up by EXIT trap
        return 0
    else
        _nlog_error "Failed to send notification email using msmtp. Check msmtp config and logs ($LOG_FILE)."
        # Temp config file cleaned up by EXIT trap
        return 1
    fi
}

# Send notification with a file attachment (for emergency kits)
# Usage: send_notification_with_attachment <category> <subject> <body> <attachment_file>
send_notification_with_attachment() {
    local category="$1"
    local subject="$2"
    local body="$3"
    local attachment_file="$4"

    _ensure_log_dir || return 1 # Ensure log dir exists first
    _nlog_info "Preparing to send '$category' notification with attachment: $subject"

    # Validate attachment file
    if [[ ! -f "$attachment_file" ]]; then
        _nlog_error "Attachment file not found: '$attachment_file'"
        return 1
    fi
    if [[ ! -r "$attachment_file" ]]; then
        _nlog_error "Attachment file not readable: '$attachment_file'"
        return 1
    fi

    local attachment_basename attachment_size_human file_size_bytes
    attachment_basename=$(basename "$attachment_file")
    # Get size using stat, fallback to du
    file_size_bytes=$(stat -c%s "$attachment_file" 2>/dev/null || du -b "$attachment_file" | cut -f1 || echo 0)
    # Use numfmt if available for human readable size
    if command -v numfmt >/dev/null; then
         attachment_size_human=$(numfmt --to=iec --suffix=B "$file_size_bytes" 2>/dev/null || echo "${file_size_bytes}B")
    else
         attachment_size_human="${file_size_bytes} Bytes"
    fi

    # Warn if attachment is large (e.g., > 20MB)
    local max_size_bytes=$(( 20 * 1024 * 1024 )) # 20 MB
    if [[ "$file_size_bytes" -gt "$max_size_bytes" ]]; then
        _nlog_warn "Attachment '$attachment_basename' is large ($attachment_size_human). Email delivery might fail due to size limits."
    fi

    # Configure msmtp (loads secrets etc.)
    if ! _configure_msmtp; then
        _nlog_error "SMTP configuration failed. Cannot send notification with attachment."
        return 1
    fi

    # Get recipient email address
    local recipient
    recipient=$(_get_notification_recipient) || return 1

    # Generate boundary for multipart message
    local boundary="----=_Part_Vaultwarden_$(date +%s)_${RANDOM}"

    # Get hostname safely
    local host
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UnknownHost")

    # Determine priority
    local priority="Normal" priority_code=3
    case "$category" in
        critical|failure|backup-failure|emergency|alert) priority="High"; priority_code=1 ;;
        *) priority="Normal"; priority_code=3 ;;
    esac

    # Use subject prefix
    local subject_prefix="[Vaultwarden][${host}]"
    [[ "$priority" == "High" ]] && subject_prefix="🚨 $subject_prefix [EMERGENCY]" || subject_prefix="📎 $subject_prefix [${category^^}]"


    # Create the MIME structure using printf and base64. Pipe directly to msmtp.
    # Check for base64 command
    if ! command -v base64 >/dev/null; then
         _nlog_error "base64 command not found. Cannot encode attachment."
         return 1
    fi

    _nlog_info "Sending notification with attachment '$attachment_basename' ($attachment_size_human) to '$recipient'..."

    # Use a subshell to pipe the MIME content directly to msmtp
    (
        # --- Headers ---
        printf "To: %s\n" "$recipient"
        printf "Subject: %s %s\n" "$subject_prefix" "$subject"
        printf "MIME-Version: 1.0\n"
        printf "Content-Type: multipart/mixed; boundary=\"%s\"\n" "$boundary"
        printf "X-Priority: %s (%s)\n" "$priority_code" "$priority"
        printf "X-VaultWarden-Category: %s\n" "$category"
        printf "X-VaultWarden-Host: %s\n\n" "$host"
        # Initial boundary before text part
        printf -- "--%s\n" "$boundary"

        # --- Body Part (Text) ---
        printf "Content-Type: text/plain; charset=UTF-8\n"
        printf "Content-Transfer-Encoding: quoted-printable\n\n" # Use quoted-printable for body text safety
        # Encode body using a simple quoted-printable approach (basic, might need improvement)
        echo "$body" | sed -e 's/=\([0-9A-F][0-9A-F]\)/=3D\1/g' -e 's/$/=/' | fold -w 76 -s | sed '$ s/=$/\n/'
        # Add footer (needs similar encoding)
        local timestamp server_info footer
        timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
        server_info="Server: $host"
        footer=$(printf "\n---\nVaultWarden-OCI-NG Notification System\nGenerated: %s\n%s\nCategory: %s\nAttachment: %s (%s)" "$timestamp" "$server_info" "$category" "$attachment_basename" "$attachment_size_human")
        echo "$footer" | sed -e 's/=\([0-9A-F][0-9A-F]\)/=3D\1/g' -e 's/$/=/' | fold -w 76 -s | sed '$ s/=$/\n/'
        printf "\n\n" # End of text part

        # --- Attachment Part (Base64 encoded) ---
        printf -- "--%s\n" "$boundary"
        # Determine MIME type heuristically? Or use application/octet-stream?
        local mime_type="application/octet-stream" # Default binary type
        # Add simple checks for common types
        case "$attachment_basename" in
             *.txt|*.md|*.log) mime_type="text/plain" ;;
             *.pdf) mime_type="application/pdf" ;;
             *.zip) mime_type="application/zip" ;;
             *.gz) mime_type="application/gzip" ;;
             *.tar.gz|*.tgz) mime_type="application/gzip" ;; # Often used, though x-gzip etc exist
             *.age) mime_type="application/octet-stream" ;; # No standard MIME type for .age
        esac
        printf "Content-Type: %s; name=\"%s\"\n" "$mime_type" "$attachment_basename"
        printf "Content-Transfer-Encoding: base64\n"
        printf "Content-Disposition: attachment; filename=\"%s\"\n\n" "$attachment_basename"
        # Encode the attachment file using base64
        if ! base64 "$attachment_file"; then
             _nlog_error "Base64 encoding failed for '$attachment_file'"
             # Need a way to signal failure to the outer pipe/msmtp? Difficult.
             # Exit subshell might work.
             exit 1 # Exit subshell on base64 failure
        fi
        printf "\n" # Ensure newline after base64 block

        # --- End boundary ---
        printf -- "\n--%s--\n" "$boundary"

    # Pipe the generated MIME content to msmtp
    ) | msmtp --file="$MSMTP_CONFIG_FILE" -t "$recipient"

    local send_result=$? # Capture msmtp exit code
    if [[ $send_result -eq 0 ]]; then
        _nlog_success "Notification with attachment '$attachment_basename' sent successfully to '$recipient'."
        # Temp config file cleaned up by EXIT trap
        return 0
    else
        _nlog_error "Failed to send notification with attachment using msmtp (Exit code: $send_result). Check logs ($LOG_FILE)."
        # Temp config file cleaned up by EXIT trap
        return 1
    fi
}


# Test SMTP connectivity by sending a simple email
# Usage: test_smtp_connection
test_smtp_connection() {
    _nlog_info "Testing SMTP connection..."

    # Configure msmtp (will load secrets etc.)
    if ! _configure_msmtp; then
        _nlog_error "SMTP configuration setup failed. Cannot perform test."
        return 1
    fi

    # Get hostname
    local host
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UnknownHost")

    local test_subject="VaultWarden SMTP Test - $(date '+%Y-%m-%d %H:%M:%S')"
    local test_body="This is a test message from the VaultWarden-OCI-NG notification system on server '$host'.

If you receive this email, your SMTP settings configured in '.env' and 'secrets/secrets.yaml' appear to be working correctly.

Test Details:
- Server: $host
- Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
- SMTP Test: Initiated via script

No action is required."

    # Use the standard send_notification function with category 'test'
    if send_notification "test" "$test_subject" "$test_body"; then
        _nlog_success "SMTP test email sent successfully. Please check the recipient mailbox."
        return 0
    else
        _nlog_error "SMTP test failed. Could not send email."
        _nlog_info "Check SMTP credentials (username/password/host/port/security) in config/secrets, and firewall rules."
        _nlog_info "Review the notification log for details: $LOG_FILE"
        return 1
    fi
}

# --- Direct Execution / CLI ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     # Ensure log dir exists if run directly
     _ensure_log_dir || exit 1

    case "${1:-}" in
        test)
            test_smtp_connection
            ;;
        send)
            if [[ $# -ge 4 ]]; then
                shift # Remove 'send'
                send_notification "$@" # Pass remaining args
            else
                echo "Usage: $0 send <category> <subject> <body>" >&2
                exit 1
            fi
            ;;
        send-attach|send-with-attachment)
            if [[ $# -ge 5 ]]; then
                 shift # Remove 'send-attach'
                 send_notification_with_attachment "$@" # Pass remaining args
            else
                echo "Usage: $0 send-attach <category> <subject> <body> <attachment_file>" >&2
                exit 1
            fi
            ;;
        *)
            cat >&2 << EOF
VaultWarden-OCI-NG Simple Notification System CLI
Usage: $0 {test|send|send-attach} [arguments...]

Commands:
  test                           - Send a test email to the configured admin address.
  send <cat> <subj> <body>       - Send a basic notification email.
  send-attach <cat> <subj> <body> <file> - Send an email with a file attachment.

Requires SMTP configuration in .env and secrets/secrets.yaml.
Logs to console and ${LOG_FILE:-/var/log/vaultwarden/logs/notifications.log}
EOF
            # Try loading config just to show log file path accurately if possible
            load_config >/dev/null 2>&1
            echo "Logs to console and ${LOG_FILE:-/var/log/vaultwarden/logs/notifications.log}" >&2
            exit 1
            ;;
    esac
    exit $?
else
      _log_debug "lib/notifications.sh loaded successfully as a library."
fi
