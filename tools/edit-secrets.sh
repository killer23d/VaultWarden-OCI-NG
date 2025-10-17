#!/usr/bin/env bash
# tools/edit-secrets.sh - Consolidated SOPS+Age encrypted secrets manager.
#
# Provides a secure interface for editing, viewing, validating,
# and rotating encrypted secrets using SOPS with Age encryption.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/validation.sh"
source "$ROOT_DIR/lib/config.sh" # Needed for rotate-admin-token logic

_set_log_prefix "secrets"

readonly SECRETS_FILE="$ROOT_DIR/secrets/secrets.yaml"
readonly AGE_KEY_FILE="$ROOT_DIR/secrets/keys/age-key.txt"
readonly SETTINGS_FILE="$ROOT_DIR/settings.env"

# --- Core Functions ---

_validate_sops_environment() {
    _log_info "Validating SOPS environment..."
    if ! command -v sops >/dev/null 2>&1 || ! command -v age >/dev/null 2>&1; then
        _log_error "SOPS or Age not found. Run: ./tools/init-setup.sh"; exit 1;
    fi
    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        _log_error "Age private key not found. Run: ./tools/init-setup.sh"; exit 1;
    fi
    chmod 600 "$AGE_KEY_FILE"
    if [[ ! -f "$SECRETS_FILE" ]]; then
        _log_warning "Secrets file not found, creating a new one..."; _create_secrets_template;
    fi
    _log_success "SOPS environment is healthy."
}

_create_secrets_template() {
    local admin_token backup_passphrase
    admin_token=$(openssl rand -base64 32)
    backup_passphrase=$(openssl rand -base64 32)
    cat > "/tmp/secrets.yaml" <<EOF
# VaultWarden Encrypted Secrets
admin_token: "$admin_token"
smtp_password: ""
backup_passphrase: "$backup_passphrase"
cloudflare_api_token: ""
push_installation_key: ""
EOF
    if sops -e "/tmp/secrets.yaml" > "$SECRETS_FILE"; then
        shred -u "/tmp/secrets.yaml" 2>/dev/null || rm -f "/tmp/secrets.yaml"
        _log_success "New encrypted secrets file created."
    else
        _log_error "Failed to create encrypted secrets file."; exit 1;
    fi
}

_pre_edit_backup() {
    if [[ -f "$SECRETS_FILE" ]]; then
        local backup_file="$SECRETS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$SECRETS_FILE" "$backup_file"
        _log_info "Backup created: $backup_file"
    fi
}

_validate_secrets_format() {
    _log_info "Validating secrets format..."
    if ! sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
        _log_error "Failed to decrypt secrets file. Format may be corrupted."; exit 1;
    fi
    _log_success "Secrets format validated successfully."
}

_restart_services() {
    _log_info "Restarting services to apply changes..."
    if ! "$ROOT_DIR/startup.sh"; then
        _log_error "Stack failed to restart. Please check the logs."
        return 1
    fi
    _log_success "Stack restarted successfully."
}

# --- Workflows ---

_edit_secrets_workflow() {
    _log_header "Encrypted Secrets Editor"
    _validate_sops_environment
    _pre_edit_backup
    _log_info "Opening SOPS editor. Make your changes, save, and close the file."
    export SOPS_AGE_KEY_FILE="$AGE_KEY_FILE"
    if sops "$SECRETS_FILE"; then
        _log_success "Secrets file saved."; _validate_secrets_format;
    else
        _log_error "Failed to edit secrets file."; exit 1;
    fi
}

_rotate_single_secret_workflow() {
    local key="$1" value="$2" random="$3" restart="$4"
    _log_header "Rotate Single Secret: $key"
    _validate_sops_environment

    local new_val="$value"
    if [[ "$random" == "true" ]]; then
        new_val=$(openssl rand -base64 32 | tr -d '\n')
    fi
    [[ -n "$new_val" ]] || { _log_error "No value provided (use --random or --value)"; exit 1; }

    _log_info "Updating '$key' in encrypted secrets..."
    export SOPS_AGE_KEY_FILE="$AGE_KEY_FILE"
    if ! sops --set "[\"$key\"] = \"$new_val\"" "$SECRETS_FILE" > "$SECRETS_FILE.tmp"; then
        _log_error "Failed to update secrets file using sops."; rm -f "$SECRETS_FILE.tmp"; exit 1;
    fi
    mv "$SECRETS_FILE.tmp" "$SECRETS_FILE"
    _log_success "Secret '$key' rotated successfully."

    if [[ "$restart" == "true" ]]; then
        _restart_services
    fi
}

_rotate_all_secrets_workflow() {
    local restart="$1"
    _log_header "Rotate All Secrets"
    _validate_sops_environment
    _pre_edit_backup

    local default_keys=("admin_token" "backup_passphrase" "smtp_password" "push_installation_key" "cloudflare_api_token")
    local failures=0

    # Decrypt once
    local tmp_plain; tmp_plain="$(mktemp)"
    if ! sops -d "$SECRETS_FILE" > "$tmp_plain"; then
        _log_error "Failed to decrypt secrets."; rm -f "$tmp_plain"; exit 1;
    fi
    
    for key in "${default_keys[@]}"; do
        if yq eval "has(\"$key\")" "$tmp_plain" | grep -q "true"; then
            _log_info "Rotating '$key'..."
            local new_val; new_val=$(openssl rand -base64 32 | tr -d '\n')
            if ! yq eval -i ".$key = \"$new_val\"" "$tmp_plain"; then
                _log_error "Failed to update '$key' in temporary file."; ((failures++));
            else
                _log_success "Prepared new value for '$key'."
            fi
        fi
    done

    if [[ $failures -eq 0 ]]; then
        _log_info "Re-encrypting all rotated secrets..."
        if sops -e "$tmp_plain" > "$SECRETS_FILE"; then
            _log_success "All secrets rotated and re-encrypted successfully."
        else
            _log_error "Failed to re-encrypt secrets. Your original file is backed up."; ((failures++));
        fi
    fi
    
    rm -f "$tmp_plain"

    if [[ $failures -eq 0 && "$restart" == "true" ]]; then
        _restart_services
    elif [[ $failures -gt 0 ]]; then
        _log_error "$failures secret(s) failed to rotate. Please check the backup."
        exit 1
    fi
}

_rotate_admin_token_workflow() {
    local restart="$1"
    _log_header "Rotate Admin Token & Caddy Basic Auth"
    _validate_sops_environment

    if ! docker compose ps --services --filter "status=running" | grep -q "caddy"; then
        _log_error "The 'caddy' service is not running. Please start the stack first with ./startup.sh"; exit 1;
    fi

    # Step 1: Generate new credentials
    _log_info "Generating new admin token and basic auth password..."
    local new_admin_token; new_admin_token=$(openssl rand -base64 32)
    local new_basic_password; new_basic_password=$(openssl rand -base64 16)
    _log_success "New credentials generated."

    # Step 2: Hash the password using the Caddy container
    _log_info "Hashing new basic auth password using the Caddy container..."
    local new_basic_hash; new_basic_hash=$(docker compose exec -T caddy caddy hash-password --plaintext "$new_basic_password" 2>/dev/null)
    if [ -z "$new_basic_hash" ]; then
        _log_error "Failed to hash password using the Caddy container."; exit 1;
    fi
    _log_success "Password hashed successfully."

    # Step 3: Update secrets.yaml
    _log_info "Updating secrets.yaml with new admin token..."
    if ! sops --set "[\"admin_token\"] = \"$new_admin_token\"" "$SECRETS_FILE" > "$SECRETS_FILE.tmp"; then
        _log_error "Failed to update secrets.yaml using sops."; rm -f "$SECRETS_FILE.tmp"; exit 1;
    fi
    mv "$SECRETS_FILE.tmp" "$SECRETS_FILE"
    _log_success "secrets.yaml updated."

    # Step 4: Update settings.env
    _log_info "Updating settings.env with new basic auth hash..."
    if grep -q "^ADMIN_BASIC_AUTH_HASH=" "$SETTINGS_FILE"; then
        sed -i'' -e "s/^ADMIN_BASIC_AUTH_HASH=.*/ADMIN_BASIC_AUTH_HASH=$new_basic_hash/" "$SETTINGS_FILE"
    else
        echo -e "\nADMIN_BASIC_AUTH_HASH=$new_basic_hash" >> "$SETTINGS_FILE"
    fi
    chmod 600 "$SETTINGS_FILE"
    _log_success "settings.env updated."
    
    # Step 5: Restart if requested
    if [[ "$restart" == "true" ]]; then
        if _restart_services; then
            # Step 6: Display new credentials
            echo
            _log_header "New Admin Credentials (Save These Securely!)"
            _log_info "These will only be displayed once."
            echo
            _print_key_value "New Basic Auth Username" "admin"
            _print_key_value "New Basic Auth Password" "$new_basic_password"
            echo
            _log_info "The new admin token is stored in secrets.yaml and is required for the admin panel."
            echo
        fi
    else
        _log_warning "Services not restarted. Run ./startup.sh to apply changes."
        _log_info "New Caddy basic auth password: $new_basic_password"
    fi
}


# --- Main Argument Parser ---
main() {
    # If no arguments, default to interactive edit
    if [[ $# -eq 0 ]]; then
        _edit_secrets_workflow
        exit 0
    fi

    local key_to_rotate=""
    local value_to_set=""
    local use_random=false
    local do_restart=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                cat <<EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
  (no command)        Edit secrets interactively (default).
  --view              View decrypted secrets (read-only).
  --validate          Validate secrets format and environment.
  --rotate            Rotate a specific secret. Requires --key.
  --rotate-all        Rotate all known secrets with random values.
  --rotate-admin      Rotate the admin_token and Caddy basic auth password.

OPTIONS for --rotate:
  --key <name>        The secret key to rotate (e.g., admin_token).
  --value <val>       The explicit new value to set for the key.
  --random            Generate a random value for the key (overrides --value).
  
GENERAL OPTIONS:
  --restart           Restart services after a rotation command.
  --help, -h          Show this help message.

Examples:
  ./tools/edit-secrets.sh
  ./tools/edit-secrets.sh --view
  ./tools/edit-secrets.sh --rotate --key smtp_password --value "new-pass" --restart
  ./tools/edit-secrets.sh --rotate --key admin_token --random
  ./tools/edit-secrets.sh --rotate-all --restart
  ./tools/edit-secrets.sh --rotate-admin --restart
EOF
                exit 0
                ;;
            --view)
                _log_header "Encrypted Secrets (Read-Only)"
                _validate_sops_environment
                sops -d "$SECRETS_FILE" 2>/dev/null || _log_error "Failed to decrypt."
                exit 0
                ;;
            --validate)
                _log_header "Secrets Validation"
                _validate_sops_environment
                _validate_secrets_format
                exit 0
                ;;
            --rotate)
                # This is the action, next args are options for it
                shift
                break
                ;;
            --rotate-all)
                # This is a standalone action
                shift
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --restart) do_restart=true; shift;;
                        *) _log_error "Unknown option for --rotate-all: $1"; exit 1;;
                    esac
                done
                _rotate_all_secrets_workflow "$do_restart"
                exit 0
                ;;
            --rotate-admin)
                # This is a standalone action
                shift
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --restart) do_restart=true; shift;;
                        *) _log_error "Unknown option for --rotate-admin: $1"; exit 1;;
                    esac
                done
                _rotate_admin_token_workflow "$do_restart"
                exit 0
                ;;
            *)
                _log_error "Unknown command or option: $1"; exit 1;;
        esac
    done

    # Parse options for --rotate
    if [[ ${#@} -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --key) key_to_rotate="${2:-}"; shift 2;;
                --value) value_to_set="${2:-}"; shift 2;;
                --random) use_random=true; shift;;
                --restart) do_restart=true; shift;;
                *) _log_error "Unknown option for --rotate: $1"; exit 1;;
            esac
        done
        
        [[ -n "$key_to_rotate" ]] || { _log_error "--key is required for --rotate"; exit 1; }
        _rotate_single_secret_workflow "$key_to_rotate" "$value_to_set" "$use_random" "$do_restart"
    else
        _log_error "The --rotate command requires options like --key. Use --help for more info."
        exit 1
    fi
}

main "$@"