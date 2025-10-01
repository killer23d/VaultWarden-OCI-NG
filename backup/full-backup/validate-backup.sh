#!/usr/bin/env bash
# backup/full-backup/validate-backup.sh - Validate backup files and test restoration readiness
# This script performs comprehensive backup validation without actually restoring

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration - Updated for /backup/full-backup/ directory structure
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKUP_DIR="$(dirname "$SCRIPT_DIR")"  # /backup
readonly PROJECT_ROOT="$(dirname "$BACKUP_DIR")"  # project root (two levels up)

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
Backup Validation Script

Usage: $0 [OPTIONS] [backup-file.tar.gz]

Options:
  --all              Validate all backup files found
  --latest           Validate only the latest backup file
  --deep             Perform deep validation (extract and verify contents)
  --integrity        Check file integrity and checksums only
  --help, -h         Show this help message

Examples:
  $0 --latest                                    # Validate latest backup
  $0 --all                                       # Validate all backups
  $0 vaultwarden_full_20241001_143000.tar.gz   # Validate specific backup
  $0 --deep backup.tar.gz                      # Deep validation with extraction

EOF
}

# Find backup files - Updated for new directory structure
find_backups() {
    local backup_locations=(
        "$PROJECT_ROOT/migration_backups"
        "$PROJECT_ROOT/data/backups"
        "$PROJECT_ROOT"
        "."
    )

    local all_backups=()
    for location in "${backup_locations[@]}"; do
        if [[ -d "$location" ]]; then
            while IFS= read -r -d '' backup; do
                all_backups+=("$backup")
            done < <(find "$location" -name "vaultwarden_full_*.tar.gz" -type f -print0 2>/dev/null)
        fi
    done

    printf '%s\n' "${all_backups[@]}" | sort -r
}

# Get latest backup
get_latest_backup() {
    local backups
    mapfile -t backups < <(find_backups)

    if [[ ${#backups[@]} -gt 0 ]]; then
        echo "${backups[0]}"
    else
        return 1
    fi
}

# Validate file format
validate_file_format() {
    local file="$1"

    log_info "Validating file format: $(basename "$file")"

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi

    # Check file size (should be at least 1MB for a valid backup)
    local file_size
    file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
    if [[ $file_size -lt 1048576 ]]; then
        log_error "File too small (${file_size} bytes) - likely corrupted"
        return 1
    fi

    # Check if it's a gzipped tar file
    if ! file "$file" | grep -q "gzip compressed"; then
        log_error "Invalid file format - not a gzipped tar archive"
        return 1
    fi

    log_success "File format validation passed"
    return 0
}

# Validate checksums
validate_checksums() {
    local file="$1"
    local file_dir
    file_dir="$(dirname "$file")"
    local file_name
    file_name="$(basename "$file" .tar.gz)"

    log_info "Checking integrity checksums..."

    local sha_file="$file_dir/${file_name}.sha256"
    local md5_file="$file_dir/${file_name}.md5"

    local checksum_found=false

    # Check SHA256
    if [[ -f "$sha_file" ]]; then
        log_info "Verifying SHA256 checksum..."
        cd "$file_dir"
        if sha256sum -c "$(basename "$sha_file")" --quiet 2>/dev/null; then
            log_success "SHA256 checksum verified"
            checksum_found=true
        else
            log_error "SHA256 checksum verification failed!"
            return 1
        fi
    fi

    # Check MD5 if no SHA256
    if [[ "$checksum_found" != "true" && -f "$md5_file" ]]; then
        log_info "Verifying MD5 checksum..."
        cd "$file_dir"
        if md5sum -c "$(basename "$md5_file")" --quiet 2>/dev/null; then
            log_success "MD5 checksum verified"
            checksum_found=true
        else
            log_error "MD5 checksum verification failed!"
            return 1
        fi
    fi

    if [[ "$checksum_found" != "true" ]]; then
        log_warning "No checksum files found - cannot verify integrity"
        return 0
    fi

    return 0
}

# Validate archive structure
validate_archive_structure() {
    local file="$1"

    log_info "Validating archive structure..."

    # List archive contents
    local contents
    contents=$(tar -tzf "$file" 2>/dev/null)

    if [[ -z "$contents" ]]; then
        log_error "Cannot read archive contents"
        return 1
    fi

    # Expected files/directories
    local expected_components=(
        "data_directories.tar.gz"
        "configuration.tar.gz"
        "system_info.txt"
    )

    local missing_components=()
    for component in "${expected_components[@]}"; do
        if ! echo "$contents" | grep -q "$component"; then
            missing_components+=("$component")
        fi
    done

    if [[ ${#missing_components[@]} -gt 0 ]]; then
        log_warning "Missing backup components: ${missing_components[*]}"
    else
        log_success "All expected components found"
    fi

    # Check for database backup
    if echo "$contents" | grep -q "db_backup_.*\.sql"; then
        log_success "Database backup found in archive"
    else
        log_warning "Database backup not found in archive"
    fi

    return 0
}

# Deep validation with extraction
deep_validate() {
    local file="$1"

    log_info "Performing deep validation with extraction..."

    local temp_dir
    temp_dir=$(mktemp -d)

    # Cleanup function
    cleanup_temp() {
        rm -rf "$temp_dir"
    }
    trap cleanup_temp EXIT

    # Extract archive
    if ! tar -xzf "$file" -C "$temp_dir" 2>/dev/null; then
        log_error "Failed to extract archive"
        return 1
    fi

    # Find extracted directory
    local extracted_dir
    extracted_dir=$(find "$temp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)

    if [[ -z "$extracted_dir" || ! -d "$extracted_dir" ]]; then
        log_error "Could not find extracted directory"
        return 1
    fi

    log_info "Archive extracted successfully"

    # Validate components
    local components_ok=true

    # Check data directories backup
    if [[ -f "$extracted_dir/data_directories.tar.gz" ]]; then
        if tar -tzf "$extracted_dir/data_directories.tar.gz" >/dev/null 2>&1; then
            log_success "Data directories backup is valid"
        else
            log_error "Data directories backup is corrupted"
            components_ok=false
        fi
    else
        log_warning "Data directories backup not found"
        components_ok=false
    fi

    # Check configuration backup
    if [[ -f "$extracted_dir/configuration.tar.gz" ]]; then
        if tar -tzf "$extracted_dir/configuration.tar.gz" >/dev/null 2>&1; then
            log_success "Configuration backup is valid"

            # Check for critical config files
            local config_contents
            config_contents=$(tar -tzf "$extracted_dir/configuration.tar.gz" 2>/dev/null)

            if echo "$config_contents" | grep -q "settings.env"; then
                log_success "settings.env found in configuration backup"
            else
                log_warning "settings.env not found in configuration backup"
            fi

            if echo "$config_contents" | grep -q "docker-compose.yml"; then
                log_success "docker-compose.yml found in configuration backup"
            else
                log_warning "docker-compose.yml not found in configuration backup"
            fi
        else
            log_error "Configuration backup is corrupted"
            components_ok=false
        fi
    else
        log_warning "Configuration backup not found"
        components_ok=false
    fi

    # Check SSL certificates backup
    if [[ -f "$extracted_dir/ssl_certificates.tar.gz" ]]; then
        if tar -tzf "$extracted_dir/ssl_certificates.tar.gz" >/dev/null 2>&1; then
            log_success "SSL certificates backup is valid"
        else
            log_warning "SSL certificates backup is corrupted"
        fi
    else
        log_info "SSL certificates backup not present (will be regenerated)"
    fi

    # Check system info
    if [[ -f "$extracted_dir/system_info.txt" ]]; then
        log_success "System information file found"

        # Show some key info
        if grep -q "Backup Date:" "$extracted_dir/system_info.txt"; then
            local backup_date
            backup_date=$(grep "Backup Date:" "$extracted_dir/system_info.txt" | cut -d: -f2- | xargs)
            log_info "Backup created: $backup_date"
        fi
    else
        log_warning "System information file not found"
    fi

    if [[ "$components_ok" == "true" ]]; then
        log_success "Deep validation passed"
        return 0
    else
        log_error "Deep validation found issues"
        return 1
    fi
}

# Validate single backup file
validate_backup() {
    local file="$1"
    local deep="${2:-false}"

    echo ""
    echo "========================================="
    echo "🔍 Validating: $(basename "$file")"
    echo "========================================="

    local validation_passed=true

    # Basic validations
    if ! validate_file_format "$file"; then
        validation_passed=false
    fi

    if ! validate_checksums "$file"; then
        validation_passed=false
    fi

    if ! validate_archive_structure "$file"; then
        validation_passed=false
    fi

    # Deep validation if requested
    if [[ "$deep" == "true" ]]; then
        if ! deep_validate "$file"; then
            validation_passed=false
        fi
    fi

    # Show file information
    log_info "Backup file information:"
    echo "  Size: $(du -h "$file" | cut -f1)"
    echo "  Created: $(stat -f%Sm "$file" 2>/dev/null || stat -c%y "$file" 2>/dev/null)"

    # Final result
    echo ""
    if [[ "$validation_passed" == "true" ]]; then
        log_success "✅ Backup validation PASSED"
        return 0
    else
        log_error "❌ Backup validation FAILED"
        return 1
    fi
}

# Main execution
main() {
    local validate_all=false
    local validate_latest=false
    local deep_validation=false
    local integrity_only=false
    local specific_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                validate_all=true
                shift
                ;;
            --latest)
                validate_latest=true
                shift
                ;;
            --deep)
                deep_validation=true
                shift
                ;;
            --integrity)
                integrity_only=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                specific_file="$1"
                shift
                ;;
        esac
    done

    echo "=============================================="
    echo "🔍 VaultWarden Backup Validation"
    echo "=============================================="

    local files_to_validate=()
    local validation_results=()

    # Determine which files to validate
    if [[ -n "$specific_file" ]]; then
        files_to_validate=("$specific_file")
    elif [[ "$validate_latest" == "true" ]]; then
        local latest
        if latest=$(get_latest_backup); then
            files_to_validate=("$latest")
        else
            log_error "No backup files found"
            exit 1
        fi
    elif [[ "$validate_all" == "true" ]]; then
        mapfile -t files_to_validate < <(find_backups)
        if [[ ${#files_to_validate[@]} -eq 0 ]]; then
            log_error "No backup files found"
            exit 1
        fi
    else
        show_usage
        exit 1
    fi

    log_info "Found ${#files_to_validate[@]} backup file(s) to validate"

    # Validate each file
    local total_files=${#files_to_validate[@]}
    local passed_files=0

    for file in "${files_to_validate[@]}"; do
        if validate_backup "$file" "$deep_validation"; then
            validation_results+=("PASSED")
            ((passed_files++))
        else
            validation_results+=("FAILED")
        fi
    done

    # Show summary
    echo ""
    echo "=============================================="
    echo "📊 Validation Summary"
    echo "=============================================="
    echo ""
    echo "Total files validated: $total_files"
    echo "Passed: $passed_files"
    echo "Failed: $((total_files - passed_files))"
    echo ""

    # Show individual results
    for i in "${!files_to_validate[@]}"; do
        local status="${validation_results[$i]}"
        local file="${files_to_validate[$i]}"

        if [[ "$status" == "PASSED" ]]; then
            echo -e "✅ ${GREEN}PASSED${NC}: $(basename "$file")"
        else
            echo -e "❌ ${RED}FAILED${NC}: $(basename "$file")"
        fi
    done

    echo ""

    # Final status
    if [[ $passed_files -eq $total_files ]]; then
        log_success "🎉 All backup validations passed!"
        echo ""
        echo "Your backups are ready for disaster recovery."
        echo "Use ./backup/full-backup/restore-full-backup.sh <backup-file> to restore."
        exit 0
    else
        log_error "⚠️  Some backup validations failed!"
        echo ""
        echo "Please check failed backups before relying on them for recovery."
        exit 1
    fi
}

# Execute main function with all arguments
main "$@"
