#!/usr/bin/env bash
# tools/restore.sh — unified interactive restore (DB-only or Full)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="$ROOT_DIR/lib"

# shellcheck source=/dev/null
source "$LIB_DIR/config.sh"
load_config
# shellcheck source=/dev/null
source "$LIB_DIR/restore-lib.sh"

log() { printf '[restore] %s\n' "$*" >&2; }
die() { printf '[restore][error] %s\n' "$*" >&2; exit 1; }

: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"

choose_file() {
  local prompt="$1" pattern="${2:-*}"
  echo "$prompt" >&2
  select f in $(ls -1 $pattern 2>/dev/null); do
    [ -n "${f:-}" ] && printf '%s' "$f" && return 0
  done
  return 1
}

restore_db_flow() {
  local src="${1:-}"
  if [ -z "$src" ]; then
    src="$(find_latest_db_encrypted || true)"
    [ -n "$src" ] || die "No encrypted DB backup found"
  fi
  log "Selected DB backup: $src"

  log "Stopping VaultWarden service"
  (cd "$ROOT_DIR" && docker compose stop vaultwarden) || true

  # Detect type by suffix
  local dec uncompressed
  if echo "$src" | grep -q '.sqlite3.gz.gpg$'; then
    dec="$(decrypt_to_tmp "$src" "$BACKUP_PASSPHRASE" "$ROOT_DIR")"
    uncompressed="${dec%.gz}"
    gunzip -c "$dec" > "$uncompressed"
    restore_db_sqlite "$uncompressed"
    shred -u "$dec" "$uncompressed" || rm -f "$dec" "$uncompressed"
  elif echo "$src" | grep -q '.sql.gz.gpg$'; then
    dec="$(decrypt_to_tmp "$src" "$BACKUP_PASSPHRASE" "$ROOT_DIR")"
    uncompressed="${dec%.gz}"
    gunzip -c "$dec" > "$uncompressed"
    restore_db_from_sql_dump "$uncompressed"
    shred -u "$dec" "$uncompressed" || rm -f "$dec" "$uncompressed"
  else
    die "Unknown DB backup format"
  fi

  log "Starting VaultWarden"
  (cd "$ROOT_DIR" && docker compose up -d vaultwarden)
  health_check 30 5 || die "VaultWarden health check failed after DB restore"

  log "Database restore complete"
}

restore_full_flow() {
  local src="${1:-}"
  if [ -z "$src" ]; then
    src="$(find_latest_full_encrypted || true)"
    [ -n "$src" ] || die "No encrypted full backup found"
  fi
  log "Selected full backup: $src"

  log "Stopping entire stack"
  compose_down

  # Decrypt archive to staging
  local dec tarfile
  dec="$(decrypt_to_tmp "$src" "$BACKUP_PASSPHRASE" "$ROOT_DIR")"
  tarfile="${dec%.gz}"
  gunzip -c "$dec" > "$tarfile"
  local stage; stage="$(mktemp -d -p "$ROOT_DIR" restore-stage.XXXXXX)"
  tar -C "$stage" -xf "$tarfile"

  # Restore volumes (if present)
  [ -f "$stage/volume-caddy_data.tar.gz" ] && restore_volume_from_tar "caddy_data" "$stage/volume-caddy_data.tar.gz"
  [ -f "$stage/volume-caddy_config.tar.gz" ] && restore_volume_from_tar "caddy_config" "$stage/volume-caddy_config.tar.gz"

  # Restore project configs (best-effort)
  if [ -d "$stage/project" ]; then
    cp -a "$stage/project/caddy" "$ROOT_DIR/" 2>/dev/null || true
    cp -a "$stage/project/fail2ban" "$ROOT_DIR/" 2>/dev/null || true
    cp -a "$stage/project/templates" "$ROOT_DIR/" 2>/dev/null || true
    cp -a "$stage/project/docker-compose.yml" "$ROOT_DIR/" 2>/dev/null || true
  fi

  # Restore DB from embedded db backup if available
  if [ -d "$stage/db" ]; then
    # Prefer sqlite3 artifact if present
    local sqlite_enc sql_enc
    sqlite_enc="$(find "$stage/db" -type f -name 'db-*.sqlite3.gz.gpg' | sort | tail -n1 || true)"
    sql_enc="$(find "$stage/db" -type f -name 'db-*.sql.gz.gpg' | sort | tail -n1 || true)"
    if [ -n "$sqlite_enc" ]; then
      local dec2 uncompressed2; dec2="$(decrypt_to_tmp "$sqlite_enc" "$BACKUP_PASSPHRASE" "$stage")"
      uncompressed2="${dec2%.gz}"
      gunzip -c "$dec2" > "$uncompressed2"
      restore_db_sqlite "$uncompressed2"
      shred -u "$dec2" "$uncompressed2" || rm -f "$dec2" "$uncompressed2"
    elif [ -n "$sql_enc" ]; then
      local dec3 uncompressed3; dec3="$(decrypt_to_tmp "$sql_enc" "$BACKUP_PASSPHRASE" "$stage")"
      uncompressed3="${dec3%.gz}"
      gunzip -c "$dec3" > "$uncompressed3"
      restore_db_from_sql_dump "$uncompressed3"
      shred -u "$dec3" "$uncompressed3" || rm -f "$dec3" "$uncompressed3"
    fi
  fi

  # Cleanup decrypted materials
  shred -u "$dec" "$tarfile" || rm -f "$dec" "$tarfile"
  rm -rf "$stage"

  log "Starting stack"
  compose_up
  health_check 40 5 || die "Stack health check failed after full restore"

  log "Full restore complete"
}

usage() {
  cat <<EOF
Usage: $0 [--db <db-backup.gpg>] [--full <full-archive.gpg>] [--interactive]
  --db     Restore database only from the specified encrypted file (or latest)
  --full   Restore full system from the specified encrypted file (or latest)
  --interactive  Run an interactive menu
EOF
}

if [ "${1:-}" = "--interactive" ] || [ $# -eq 0 ]; then
  echo "Select restore mode:"
  echo "1) Database-only restore"
  echo "2) Full system restore"
  read -r -p "Choice [1/2]: " choice
  case "$choice" in
    1) restore_db_flow ;;
    2) restore_full_flow ;;
    *) die "Invalid choice" ;;
  esac
  exit 0
fi

case "${1:-}" in
  --db) restore_db_flow "${2:-}";;
  --full) restore_full_flow "${2:-}";;
  *) usage; exit 1;;
esac