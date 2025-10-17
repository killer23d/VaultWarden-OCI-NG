#!/usr/bin/env bash
# lib/restore-lib.sh — shared restore helpers (stop/start, decrypt, restore db/volumes, health)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rlog() { printf '[restore-lib] %s\n' "$*" >&2; }
rdie() { printf '[restore-lib][error] %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || rdie "Missing command: $1"; }

need docker
need gpg
need sqlite3

# Source config to get dynamic container names for health check
if [[ -f "$ROOT_DIR/lib/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$ROOT_DIR/lib/config.sh"
    if ! load_config >/dev/null 2>&1; then
        rdie "Could not load configuration for health check container names."
    fi
else
    rdie "Critical library lib/config.sh not found."
fi

# Define container names from loaded configuration
BW_VW="${CONTAINER_NAME_VAULTWARDEN:?}"
BW_CADDY="${CONTAINER_NAME_CADDY:?}"


# Decrypt to a secure temp file; caller must remove
decrypt_to_tmp() {
  local src="$1"
  local pass="${2:?passphrase required}"
  local tmp
  tmp="$(mktemp -p "${3:-$ROOT_DIR}" dec.XXXXXX)"
  gpg --batch --yes --pinentry-mode loopback --passphrase "$pass" -o "$tmp" -d "$src"
  printf '%s' "$tmp"
}

compose_down() { (cd "$ROOT_DIR" && docker compose down) || rdie "compose down failed"; }
compose_up() { (cd "$ROOT_DIR" && docker compose up -d) || rdie "compose up failed"; }
compose_restart() { (cd "$ROOT_DIR" && docker compose restart) || rdie "compose restart failed"; }

health_check() {
  local retries="${1:-30}"
  local sleep_s="${2:-5}"
  local ok=0
  rlog "Performing health check on containers: $BW_VW, $BW_CADDY"
  for _ in $(seq 1 "$retries"); do
    # Use dynamic container names for the health check
    if docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$BW_VW" 2>/dev/null | grep -q healthy \
       && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$BW_CADDY" 2>/dev/null | grep -q healthy; then
      ok=1; break
    fi
    sleep "$sleep_s"
  done
  [ "$ok" -eq 1 ] || return 1
}

restore_db_sqlite() {
  # Restores from a decrypted .sqlite3 file into data/bwdata/db.sqlite3
  local decrypted_sqlite="$1"
  local target="$ROOT_DIR/data/bwdata/db.sqlite3"
  mkdir -p "$(dirname "$target")"
  # Move atomically
  cp -f "$decrypted_sqlite" "$target.tmp"
  sqlite3 "$target.tmp" "PRAGMA integrity_check;" | grep -q '^ok$' || rdie "restored db integrity failed"
  mv -f "$target.tmp" "$target"
}

restore_db_from_sql_dump() {
  # Restores from a decrypted .sql dump by creating a new db file
  local decrypted_sql="$1"
  local target="$ROOT_DIR/data/bwdata/db.sqlite3"
  mkdir -p "$(dirname "$target")"
  rm -f "$target"
  sqlite3 "$target" < "$decrypted_sql"
  sqlite3 "$target" "PRAGMA integrity_check;" | grep -q '^ok$' || rdie "restored db integrity failed"
}

restore_volume_from_tar() {
  local vol="$1" tarfile="$2"
  docker volume create "$vol" >/dev/null 2>&1 || true
  docker run --rm -v "$vol":/v -v "$(dirname "$tarfile")":/backup alpine:3.19 \
    sh -lc "cd /v && tar -xzf /backup/$(basename "$tarfile")"
}

find_latest_db_encrypted() {
  local root="${1:-$ROOT_DIR/backups/db}"
  find "$root" -type f -name 'db-*.sqlite3.gz.gpg' | sort | tail -n1
}

find_latest_full_encrypted() {
  local root="${1:-$ROOT_DIR/backups/full}"
  find "$root" -type f -name 'full-*.tar.gz.gpg' | sort | tail -n1
}