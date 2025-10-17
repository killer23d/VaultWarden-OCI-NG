#!/usr/bin/env bash
# tools/create-full-backup.sh — Enhanced full system backup with resource management and improved error handling

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$ROOT_DIR/lib"

# Load libraries
# shellcheck source=/dev/null
source "$LIB_DIR/logging.sh"
# shellcheck source=/dev/null
source "$LIB_DIR/config.sh"
# shellcheck source=/dev/null
source "$LIB_DIR/backup-core.sh"

# Load configuration
load_config

# Set log prefix
_set_log_prefix "full-backup"

init_full_backup() {
  _log_info "Initializing enhanced full system backup"
  init_backup_core

  : "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required in settings}"

  TS="$(date +%Y%m%d-%H%M%S)"
  BASE_DIR="${FULL_BACKUP_DIR:-$ROOT_DIR/backups/full}"
  WORK_DIR="$BASE_DIR/$TS"
  STAGE="$WORK_DIR/stage"
  mkdir -p "$STAGE"

  _log_success "Full backup initialized - Output: $WORK_DIR"
}

export_docker_volumes() {
  local stage_dir="${1:?Stage directory required}"
  _log_info "Exporting Docker volumes with resource management"

  local volumes=("caddy_data" "caddy_config")
  local exported=()
  local failed=()

  for vol in "${volumes[@]}"; do
    _log_debug "Processing volume: $vol"
    if ! docker volume ls --format "{{.Name}}" | grep -q "^${vol}$"; then
      _log_warning "Volume $vol not found, skipping"
      continue
    fi
    local output_file="$stage_dir/volume-${vol}.tar.gz"
    local base_run=(docker run --rm -v "$vol":/source:ro -v "$stage_dir":/backup --name "backup-${vol}-$$" alpine:3.19 sh -c "tar -C /source -czf /backup/volume-${vol}.tar.gz . 2>/dev/null")
    if [[ "${USE_LOW_PRIORITY:-0}" = "1" && -x "$(command -v nice || true)" ]]; then
      _log_debug "Using low priority for volume export: $vol"
      if timeout 600 nice -n 10 "${base_run[@]}"; then
        exported+=("$vol"); _log_success "✓ Exported volume: $vol"
      else
        failed+=("$vol"); _log_error "✗ Failed to export volume: $vol"; rm -f "$output_file"
      fi
    else
      if timeout 600 "${base_run[@]}"; then
        exported+=("$vol"); _log_success "✓ Exported volume: $vol"
      else
        failed+=("$vol"); _log_error "✗ Failed to export volume: $vol"; rm -f "$output_file"
      fi
    fi
    sleep 2
  done

  [[ ${#exported[@]} -gt 0 ]] && _log_info "Successfully exported volumes: ${exported[*]}"
  if [[ ${#failed[@]} -gt 0 ]]; then
    _log_warning "Failed to export volumes: ${failed[*]}"
    return 1
  fi
  return 0
}

copy_project_configs() {
  local stage_dir="${1:?Stage directory required}"
  _log_info "Copying project configuration files"

  local project_dir="$stage_dir/project"
  mkdir -p "$project_dir"

  local config_files=(
    "docker-compose.yml"
    "startup.sh"
  )
  local config_dirs=(
    "caddy"
    "fail2ban"
    "templates"
    "action.d"
  )

  local copied=()
  local failed=()

  for file in "${config_files[@]}"; do
    if [[ -f "$ROOT_DIR/$file" ]]; then
      if cp -a "$ROOT_DIR/$file" "$project_dir/"; then
        copied+=("$file")
      else
        failed+=("$file")
      fi
    else
      _log_warning "Configuration file not found: $file"
    fi
  done

  for dir in "${config_dirs[@]}"; do
    if [[ -d "$ROOT_DIR/$dir" ]]; then
      if cp -a "$ROOT_DIR/$dir" "$project_dir/"; then
        copied+=("$dir/")
      else
        failed+=("$dir/")
      fi
    else
      _log_warning "Configuration directory not found: $dir"
    fi
  done

  cat > "$project_dir/config-manifest.json" <<JSON
{
  "copied": [$(printf '"%s"' "${copied[@]}" | paste -sd ',')] ,
  "failed": [$(printf '"%s"' "${failed[@]}" | paste -sd ',')] ,
  "excluded": ["settings.json", "data/", "logs/", "backups/"],
  "note": "settings.json intentionally excluded to avoid secret sprawl."
}
JSON

  _log_info "Configuration backup completed: ${#copied[@]} items copied"
  [[ ${#failed[@]} -gt 0 ]] && _log_warning "Some configuration copies failed: ${failed[*]}"
}

include_database_backup() {
  local stage_dir="${1:?Stage directory required}"
  _log_info "Including database backup in full backup"

  local db_backup_root="${BACKUP_DIR:-$ROOT_DIR/backups/db}"
  local db_stage_dir="$stage_dir/database"
  mkdir -p "$db_stage_dir"

  local latest_db_dir
  latest_db_dir="$(find "$db_backup_root" -maxdepth 1 -type d -name '20*' 2>/dev/null | sort -r | head -n1 || true)"

  if [[ -n "${latest_db_dir:-}" && -d "$latest_db_dir" ]]; then
    local age_h
    if stat --version >/dev/null 2>&1; then
      age_h=$(( ( $(date +%s) - $(stat -c %Y "$latest_db_dir") ) / 3600 ))
    else
      age_h=$(( ( $(date +%s) - $(stat -f %m "$latest_db_dir") ) / 3600 ))
    fi
    if [[ "$age_h" -le 24 ]]; then
      _log_info "Using existing recent database backup (${age_h}h old)"
      if ! cp -a "$latest_db_dir"/* "$db_stage_dir/"; then
        _log_warning "Failed to copy existing database backup, creating new one"
        create_fresh_database_backup "$db_stage_dir"
      else
        _log_success "✓ Database backup included from: $(basename "$latest_db_dir")"
      fi
    else
      _log_info "Existing backup is old (${age_h}h), creating fresh backup"
      create_fresh_database_backup "$db_stage_dir"
    fi
  else
    _log_info "No existing database backup found, creating new one"
    create_fresh_database_backup "$db_stage_dir"
  fi
}

create_fresh_database_backup() {
  local db_stage_dir="${1:?Database stage directory required}"
  _log_info "Creating fresh database backup for full backup inclusion"

  local temp_backup_dir
  temp_backup_dir="$(mktemp -d -p "${TMPDIR:-/tmp}" db-backup-temp.XXXXXX)"
  if BACKUP_DIR="$temp_backup_dir" "$ROOT_DIR/tools/db-backup.sh" >/dev/null 2>&1; then
    local created_backup
    created_backup="$(find "$temp_backup_dir" -maxdepth 1 -type d -name '20*' | head -n1 || true)"
    if [[ -n "$created_backup" && -d "$created_backup" ]]; then
      if cp -a "$created_backup"/* "$db_stage_dir/"; then
        _log_success "✓ Fresh database backup created and included"
      else
        _log_error "Failed to include fresh database backup"
      fi
    else
      _log_error "Fresh database backup creation failed - no output directory found"
    fi
  else
    _log_error "Fresh database backup creation failed"
  fi
  rm -rf "$temp_backup_dir"
}

create_data_snapshot() {
  local stage_dir="${1:?Stage directory required}"
  if [[ -d "$PROJECT_STATE_DIR/data/bwdata" ]]; then
    _log_info "Creating VaultWarden data directory snapshot"
    local data_archive="$stage_dir/bwdata-snapshot.tar.gz"
    if [[ "${USE_LOW_PRIORITY:-0}" = "1" && -x "$(command -v nice || true)" ]]; then
      _log_debug "Using low priority for data snapshot creation"
      if nice -n 10 tar -C "$PROJECT_STATE_DIR" -czf "$data_archive" "data/bwdata" 2>/dev/null; then
        _log_success "✓ Data snapshot created: $(du -h "$data_archive" | cut -f1)"
      else
        _log_error "✗ Data snapshot creation failed"; rm -f "$data_archive"; return 1
      fi
    else
      if tar -C "$PROJECT_STATE_DIR" -czf "$data_archive" "data/bwdata" 2>/dev/null; then
        _log_success "✓ Data snapshot created: $(du -h "$data_archive" | cut -f1)"
      else
        _log_error "✗ Data snapshot creation failed"; rm -f "$data_archive"; return 1
      fi
    fi
  else
    _log_warning "VaultWarden data directory not found, skipping data snapshot"
  fi
}

assemble_final_archive() {
  local work_dir="${1:?Work directory required}"
  local stage_dir="${2:?Stage directory required}"
  _log_info "Assembling final backup archive"

  local archive_base="$work_dir/full-$TS"
  local tar_file="${archive_base}.tar"

  _log_debug "Creating tar archive from staged files"
  if tar -C "$stage_dir" -cf "$tar_file" . 2>/dev/null; then
    _log_debug "Tar archive created: $(du -h "$tar_file" | cut -f1)"
  else
    _log_error "Failed to create tar archive"; exit 1
  fi

  _log_debug "Compressing archive"
  compress_with_resource_limits "$tar_file" "${tar_file}.gz"

  _log_debug "Encrypting final archive"
  encrypt_backup_file "${tar_file}.gz" "$BACKUP_PASSPHRASE" "${tar_file}.gz.gpg"

  _log_success "✓ Final encrypted archive: $(basename "${tar_file}.gz.gpg")"

  rm -rf "$stage_dir"
  echo "${tar_file}.gz.gpg"
}

upload_full_backup() {
  local work_dir="${1:?Work directory required}"
  if [[ -n "${RCLONE_REMOTE:-}" && -n "${RCLONE_PATH:-}" && -x "$(command -v rclone || true)" ]]; then
    _log_info "Uploading full backup to cloud storage"
    local upload_path="$RCLONE_REMOTE:$RCLONE_PATH/full/$TS"
    if rclone copy "$work_dir" "$upload_path" --transfers=2 --checkers=2 --progress --exclude="stage/**" 2>/dev/null; then
      _log_success "✓ Cloud upload completed successfully"
      local local_files remote_files
      local_files="$(find "$work_dir" -name "*.gpg" | wc -l)"
      remote_files="$(rclone lsf "$upload_path" --files-only | grep -c '\.gpg$' || echo "0")"
      if [[ "$local_files" -eq "$remote_files" ]]; then
        _log_success "Cloud upload verification passed"
      else
        _log_warning "Cloud upload verification failed (local: $local_files, remote: $remote_files)"
      fi
    else
      _log_error "Cloud upload failed"
      return 1
    fi
  else
    _log_debug "Cloud storage not configured, skipping upload"
  fi
}

manage_full_backup_retention() {
  local base_dir="${1:?Base directory required}"
  local keep="${BACKUP_KEEP_FULL:-8}"
  if [[ "$keep" -gt 0 ]]; then
    _log_info "Managing full backup retention (keeping $keep recent backups)"
    local current_count
    current_count="$(find "$base_dir" -maxdepth 1 -type d -name '20*' | wc -l)"
    if [[ "$current_count" -gt "$keep" ]]; then
      local to_remove=$((current_count - keep))
      _log_info "Removing $to_remove old full backup(s)"
      find "$base_dir" -maxdepth 1 -type d -name '20*' | sort | head -n "$to_remove" | xargs -r rm -rf
    fi
    current_count="$(find "$base_dir" -maxdepth 1 -type d -name '20*' | wc -l)"
    _log_info "Full backup retention: $current_count backup directories"
  fi
}

main() {
  local start_time end_time duration
  start_time="$(date +%s)"
  _log_header "VaultWarden Enhanced Full System Backup"

  init_full_backup

  check_system_resources "$PROJECT_STATE_DIR/data/bwdata/db.sqlite3" "$WORK_DIR" 2>/dev/null || true

  local component_failures=()

  if export_docker_volumes "$STAGE"; then
    _log_success "✓ Docker volumes exported successfully"
  else
    component_failures+=("docker_volumes")
    _log_warning "Docker volume export had issues"
  fi

  copy_project_configs "$STAGE"
  include_database_backup "$STAGE"
  
  if ! create_data_snapshot "$STAGE"; then
      _log_warning "Data snapshot creation failed, the full backup may be incomplete."
  fi

  local final_archive
  final_archive="$(assemble_final_archive "$WORK_DIR" "$STAGE")"

  upload_full_backup "$WORK_DIR" || _log_warning "Cloud upload failed, but local backup completed"
  manage_full_backup_retention "$BASE_DIR"

  end_time="$(date +%s)"
  duration=$((end_time - start_time))
  _log_header "Full Backup Complete"
  _log_info "Duration: ${duration}s"
  _log_info "Output: $WORK_DIR"

  if [[ -f "$final_archive" ]]; then
    _log_info "Final archive: $(basename "$final_archive") ($(du -h "$final_archive" | cut -f1))"
  fi

  if [[ ${#component_failures[@]} -gt 0 ]]; then
    _log_warning "Some components had issues: ${component_failures[*]}"
    return 1
  fi

  _log_success "All backup components completed successfully"
  return 0
}

main "$@"