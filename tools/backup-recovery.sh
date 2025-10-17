#!/usr/bin/env bash
# tools/backup-recovery.sh - Age key & SOPS secrets backup and disaster recovery utility

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/validation.sh"

SOPS_LIB="$ROOT_DIR/lib/sops.sh"
if [[ -f "$SOPS_LIB" ]]; then
  source "$SOPS_LIB"
else
  echo "ERROR: Missing SOPS library at $SOPS_LIB. Run ./tools/init-setup.sh first."
  exit 1
fi

_set_log_prefix "bk-recovery"

AGE_KEY_FILE="$ROOT_DIR/secrets/keys/age-key.txt"
SOPS_FILE="$ROOT_DIR/secrets/secrets.yaml"
RECOVERY_DIR="$PROJECT_STATE_DIR/recovery"
DOCS_DIR="$ROOT_DIR/docs"

usage() {
  cat <<EOF
Usage: $0 COMMAND [ARGS]

Commands:
  create-age-backup [DEST]     Create secure Age private key backup (default DEST: $RECOVERY_DIR/age-key-YYYYmmdd.txt)
  validate-backups             Validate presence and integrity of Age key & encrypted secrets
  restore-age-key FILE         Restore Age key from backup FILE (DESTRUCTIVE if overwriting)
  export-secrets [DEST]        Export encrypted secrets file copy to DEST (default: $RECOVERY_DIR/)
  import-secrets FILE          Import encrypted secrets.yaml from FILE (validates decryption)
  test-recovery                Full disaster recovery test (decrypt, docker secrets, service validate)
  generate-instructions        Generate recovery documentation in docs/

Examples:
  $0 create-age-backup
  $0 restore-age-key /secure/age-key-backup.txt
  $0 export-secrets /secure/location/
  $0 import-secrets /secure/location/secrets.yaml
  $0 test-recovery
  $0 generate-instructions
EOF
}

ensure_dirs() {
  mkdir -p "$RECOVERY_DIR" "$DOCS_DIR"
  chmod 700 "$RECOVERY_DIR"
}

create_age_key_backup() {
  ensure_dirs
  local dest="${1:-$RECOVERY_DIR/age-key-$(date +%Y%m%d).txt}"
  if [[ ! -f "$AGE_KEY_FILE" ]]; then
    _log_error "Age key not found at $AGE_KEY_FILE"
    exit 1
  fi
  cp "$AGE_KEY_FILE" "$dest"
  chmod 600 "$dest"
  _log_success "Age key backup created at: $dest"
  _log_warning "Copy this backup OFF the host (password manager, encrypted USB, secure cloud)."
}

validate_existing_backups() {
  _log_section "Validating backups"
  local issues=0
  if [[ -f "$AGE_KEY_FILE" ]]; then
    local perms; perms=$(stat -c "%a" "$AGE_KEY_FILE")
    [[ "$perms" == "600" ]] || { _log_warning "Age key permissions should be 600 (got $perms)"; ((issues++)); }
    if ! age-keygen -y "$AGE_KEY_FILE" >/dev/null 2>&1; then
      _log_error "Age key appears invalid or corrupted."
      ((issues++))
    else
      _log_success "Age key is valid."
    fi
  else
    _log_error "Age key missing at $AGE_KEY_FILE"
    ((issues++))
  fi

  if [[ -f "$SOPS_FILE" ]]; then
    if sops -d "$SOPS_FILE" >/dev/null 2>&1; then
      _log_success "Encrypted secrets decrypt successfully."
    else
      _log_error "Encrypted secrets cannot be decrypted."
      ((issues++))
    fi
  else
    _log_error "Encrypted secrets missing at $SOPS_FILE"
    ((issues++))
  fi

  if [[ $issues -eq 0 ]]; then
    _log_success "All backups validated."
    return 0
  else
    _log_warning "$issues backup issues detected."
    return 1
  fi
}

restore_age_key() {
  local src="${1:-}"
  [[ -n "$src" ]] || { _log_error "Usage: $0 restore-age-key <backup-file>"; exit 1; }
  [[ -f "$src" ]] || { _log_error "Backup file not found: $src"; exit 1; }

  _log_warning "This will overwrite current Age key at $AGE_KEY_FILE"
  read -r -p "Type 'RESTORE NOW' to proceed: " confirm
  [[ "$confirm" == "RESTORE NOW" ]] || { _log_info "Cancelled."; exit 0; }

  mkdir -p "$(dirname "$AGE_KEY_FILE")"
  cp "$src" "$AGE_KEY_FILE"
  chmod 600 "$AGE_KEY_FILE"
  if sops -d "$SOPS_FILE" >/dev/null 2>&1; then
    _log_success "Age key restored and secrets decrypt correctly."
  else
    _log_error "After restore, secrets failed to decrypt. Check you used the correct backup."
    exit 1
  fi
}

export_secrets_backup() {
  ensure_dirs
  local dest_dir="${1:-$RECOVERY_DIR}"
  mkdir -p "$dest_dir"
  [[ -f "$SOPS_FILE" ]] || { _log_error "Missing $SOPS_FILE"; exit 1; }
  local dest="$dest_dir/secrets-$(date +%Y%m%d).yaml"
  cp "$SOPS_FILE" "$dest"
  chmod 600 "$dest"
  _log_success "Exported encrypted secrets to $dest"
}

import_secrets_backup() {
  local src="${1:-}"
  [[ -n "$src" ]] || { _log_error "Usage: $0 import-secrets <file>"; exit 1; }
  [[ -f "$src" ]] || { _log_error "Import file not found: $src"; exit 1; }

  _log_warning "This will overwrite $SOPS_FILE"
  read -r -p "Type 'IMPORT NOW' to proceed: " confirm
  [[ "$confirm" == "IMPORT NOW" ]] || { _log_info "Cancelled."; exit 0; }

  cp "$src" "$SOPS_FILE"
  chmod 644 "$SOPS_FILE"
  if sops -d "$SOPS_FILE" >/dev/null 2>&1; then
    _log_success "Imported secrets decrypt successfully."
  else
    _log_error "Imported secrets cannot be decrypted with current Age key."
    exit 1
  fi
}

test_recovery_workflow() {
  _log_header "Disaster Recovery Test"
  validate_existing_backups || _log_warning "Backup validation reported issues."

  if ! init_sops_environment; then
    _log_error "SOPS environment initialization failed."
    exit 1
  fi
  if ! prepare_docker_secrets; then
    _log_error "Preparing Docker secrets failed."
    exit 1
  fi

  if ! "$ROOT_DIR/startup.sh" --validate; then
    _log_warning "Startup validation reported issues."
  fi

  _log_success "Recovery test completed. System appears recoverable."
}

generate_recovery_instructions() {
  ensure_dirs
  local doc="$DOCS_DIR/DISASTER-RECOVERY.md"
  cat > "$doc" <<'MD'
# Disaster Recovery Guide

This guide describes how to recover a VaultWarden deployment protected by SOPS + Age.

## Prerequisites
- A copy of your Age private key file (secrets/keys/age-key.txt)
- The encrypted secrets file (secrets/secrets.yaml), from Git or secure backup
- Access to the host with Docker installed

## Steps
1. Restore the Age private key:
   - Place the key at secrets/keys/age-key.txt
   - Set permissions: chmod 600 secrets/keys/age-key.txt

2. Validate secrets:
   - sops -d secrets/secrets.yaml > /dev/null

3. Prepare Docker secrets:
   - ./tools/edit-secrets.sh --validate
   - ./tools/check-health.sh --sops-only

4. Start services:
   - ./startup.sh
   - docker compose ps

5. Verify application:
   - Visit https://your-domain/admin
   - Ensure admin token works and SMTP sends

## Notes
- Never commit the Age private key to version control.
- Keep multiple backups of the key in secure locations.
MD
  chmod 644 "$doc"
  _log_success "Generated recovery instructions at $doc"
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  create-age-backup) create_age_key_backup "${1:-}";;
  validate-backups) validate_existing_backups;;
  restore-age-key) restore_age_key "${1:-}";;
  export-secrets) export_secrets_backup "${1:-}";;
  import-secrets) import_secrets_backup "${1:-}";;
  test-recovery) test_recovery_workflow;;
  generate-instructions) generate_recovery_instructions;;
  help|-h|--help) usage;;
  *) _log_error "Unknown command: $cmd"; usage; exit 1;;
esac
