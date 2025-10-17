# Script Reference Guide

> **🎯 Script Philosophy**: Comprehensive reference for all scripts in VaultWarden-OCI-Minimal, providing detailed usage, parameters, and integration information for operational excellence.

## 📋 **Script Architecture Overview**

VaultWarden-OCI-Minimal uses a **modular script architecture** with shared libraries and specialized tools:

```bash
Script Organization:
├── Entry Points
│   ├── startup.sh - Main service orchestration
│   └── init-setup.sh - Initial system setup
│
├── Core Libraries (/lib/)
│   ├── config.sh - Configuration management
│   ├── logging.sh - Centralized logging
│   ├── validation.sh - System validation
│   ├── system.sh - OS operations
│   └── monitoring.sh - Health monitoring
│
├── Operational Tools (/tools/)
│   ├── Database Management
│   ├── Backup and Recovery
│   ├── Monitoring and Health
│   ├── Security and Updates
│   └── Configuration Management
│
└── Integration Scripts
    ├── OCI Vault integration
    ├── CloudFlare automation  
    └── System service management
```

### **Script Execution Context**
```bash
Execution Requirements:
├── Root Privileges: Required for system-level operations
├── Working Directory: Must be project root directory
├── Environment: Ubuntu 24.04 LTS (primary), other Linux (compatible)
├── Dependencies: Automatically installed by init-setup.sh
└── Network: Internet connectivity for external integrations
```

## 🚀 **Entry Point Scripts**

### **startup.sh** - Main Service Controller

#### **Overview**
The primary entry point for VaultWarden-OCI-Minimal operations. Handles configuration loading, environment preparation, service orchestration, and health validation.

#### **Usage Syntax**
```bash
./startup.sh [OPTIONS]

OPTIONS:
  --help, -h        Show help information
  --validate        Validate configuration and prerequisites only
  --debug           Enable debug logging output
  --force           Skip confirmations and safety checks
  --dry-run         Show what would be done without execution
```

#### **Execution Examples**
```bash
# Standard service startup
./startup.sh

# Configuration validation only
./startup.sh --validate

# Debug mode for troubleshooting
DEBUG=1 ./startup.sh

# Validate system before making changes
./startup.sh --validate --debug
```

#### **Internal Workflow**
```bash
Startup Process Flow:
1. System validation (prerequisites, Docker, networking)
2. Configuration loading (OCI Vault → Local → Interactive)
3. Environment preparation (directories, permissions, exports)
4. Pre-startup tasks (CloudFlare updates, DDNS config)
5. Service orchestration (dependency-aware container startup)
6. Health validation (container health, endpoint checks)
7. Post-startup reporting (service info, troubleshooting)
```

#### **Exit Codes**
```bash
Exit Code Meanings:
0  - Success: All operations completed successfully
1  - Configuration Error: Invalid or missing configuration
2  - System Error: System prerequisites not met
3  - Docker Error: Docker daemon or compose issues
4  - Network Error: Connectivity or DNS problems
5  - Service Error: Container startup or health check failures
```

#### **Integration Points**
```bash
Dependencies:
├── lib/config.sh - Configuration loading and validation
├── lib/validation.sh - System prerequisite checking
├── lib/system.sh - Service and process management
├── lib/logging.sh - Consistent logging output
└── docker-compose.yml - Container orchestration definition

External Integration:
├── OCI Vault API (if OCI_SECRET_OCID configured)
├── Docker daemon and Docker Compose
├── SystemD service management
└── CloudFlare API (if credentials configured)
```

---

### **tools/init-setup.sh** - System Initialization

#### **Overview**
Comprehensive system initialization script that prepares a fresh system for VaultWarden-OCI-Minimal deployment with full automation.

#### **Usage Syntax**
```bash
sudo ./tools/init-setup.sh [OPTIONS]

OPTIONS:
  --auto            Non-interactive mode with sensible defaults
  --oci-optimized   Apply OCI A1 Flex specific optimizations
  --generic         Standard configuration for generic VPS/cloud
  --development     Development-friendly configuration
  --maximum-security Enhanced security hardening
  --proxy-mode      Configure for reverse proxy deployment
  --help, -h        Show detailed help and usage examples
```

#### **Execution Examples**
```bash
# Interactive setup with guided configuration
sudo ./tools/init-setup.sh

# Automated setup for scripted deployments
sudo ./tools/init-setup.sh --auto

# OCI A1 Flex optimized deployment
sudo ./tools/init-setup.sh --oci-optimized

# Maximum security configuration
sudo ./tools/init-setup.sh --maximum-security
```

#### **Setup Categories**
```bash
System Preparation:
├── Package installation (Docker, security tools, utilities)
├── User and permission configuration
├── Firewall setup (UFW) and security hardening
├── System service configuration (Docker, fail2ban)

Application Configuration:
├── Dynamic path and project name detection
├── Secure configuration file generation
├── SSL certificate and domain setup
├── Database initialization and optimization

Security Configuration:
├── Fail2ban setup with VaultWarden integration
├── CloudFlare integration (optional)
├── File permission hardening
├── Audit logging configuration

Automation Setup:
├── Cron job installation for maintenance
├── Monitoring and health check automation
├── Backup system configuration
├── Update and cleanup automation
```

#### **Configuration File Generation**
```bash
Generated Configuration Structure:
{
  "DOMAIN": "https://vault.yourdomain.com",
  "ADMIN_EMAIL": "admin@yourdomain.com", 
  "ADMIN_TOKEN": "cryptographically-secure-token",
  "BACKUP_PASSPHRASE": "aes-256-encryption-key",
  "SMTP_HOST": "smtp.gmail.com",
  "SMTP_FROM": "vaultwarden@yourdomain.com",
  "CLOUDFLARE_EMAIL": "user@cloudflare.com",
  "CLOUDFLARE_API_KEY": "global-api-key",
  "DATABASE_URL": "sqlite:///data/db.sqlite3",
  "CONTAINER_NAME_*": "dynamic-container-names"
}

Security Features:
├── Random token generation (OpenSSL, 32 bytes, base64)
├── File permissions (600 for configs, 700 for data)
├── Configuration validation and syntax checking
└── Backup creation before any modifications
```

## 📚 **Library Scripts (/lib/)**

### **lib/config.sh** - Configuration Management

#### **Overview** 
Centralized configuration management with support for multiple sources, dynamic path generation, and secure secret handling.

#### **Key Functions**
```bash
Public Functions:
├── _load_configuration() - Load config from OCI Vault or local file
├── get_config_value(key) - Retrieve specific configuration value
├── set_config_value(key, value) - Update configuration value
├── _display_config_summary() - Show configuration overview
├── validate_configuration() - Validate configuration completeness
├── backup_current_config() - Create versioned configuration backup
└── get_project_paths() - Get dynamic project paths

Internal Functions:
├── _load_from_oci_vault() - OCI Vault secret retrieval
├── _load_from_local_file() - Local settings.json loading
├── _parse_json_config() - JSON parsing and validation
├── _export_configuration() - Environment variable export
└── _validate_oci_environment() - OCI CLI validation
```

#### **Dynamic Path System**
```bash
Path Generation Logic:
PROJECT_NAME="$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
PROJECT_STATE_DIR="/var/lib/${PROJECT_NAME}"
SERVICE_NAME="${PROJECT_NAME}.service"

Generated Paths:
├── Data: /var/lib/project-name/
├── Logs: /var/lib/project-name/logs/
├── Backups: /var/lib/project-name/backups/
├── Config Backups: /var/lib/project-name/config-backups/
└── Service: project-name.service
```

#### **Configuration Priority**
```bash
Configuration Loading Order:
1. OCI Vault (if OCI_SECRET_OCID environment variable exists)
2. Local settings.json file (if exists and readable)
3. SystemD environment file (if exists)
4. Interactive prompts (fallback for missing critical values)

Validation Steps:
├── JSON syntax validation
├── Required key presence checking
├── Value format validation (URLs, emails, etc.)
├── Security validation (file permissions, token strength)
└── Integration testing (OCI connectivity, SMTP validation)
```

---

### **lib/logging.sh** - Centralized Logging

#### **Overview**
Provides consistent, color-coded logging across all scripts with multiple output levels and formatting options.

#### **Logging Functions**
```bash
Core Logging Functions:
├── _log_info(message) - General information (blue)
├── _log_success(message) - Success messages (green)
├── _log_warning(message) - Warning messages (yellow)
├── _log_error(message) - Error messages (red)
├── _log_debug(message) - Debug messages (gray, if DEBUG=1)

Formatting Functions:
├── _log_header(title) - Section headers with formatting
├── _log_section(title) - Subsection headers
├── _print_key_value(key, value) - Formatted key-value pairs
├── _log_confirm(prompt, default) - Interactive confirmation
├── _log_prompt(prompt, default) - Interactive input prompts
└── _log_numbered_item(num, text) - Numbered list items
```

#### **Usage Examples**
```bash
# Basic logging
_log_info "Starting configuration validation"
_log_success "Database connection successful"
_log_warning "SSL certificate expires in 30 days"
_log_error "Failed to connect to OCI Vault"

# Debug logging (only shown if DEBUG=1)
_log_debug "Configuration loaded: ${#CONFIG_VALUES[@]} keys"

# Formatted output
_log_header "VaultWarden Health Check"
_print_key_value "Status" "Healthy"
_print_key_value "Response Time" "89ms"

# Interactive prompts
_log_confirm "Proceed with database optimization?" "Y"
read -r response
```

#### **Color and Format Codes**
```bash
Color Variables:
├── RED='\033[0;31m' - Error messages
├── GREEN='\033[0;32m' - Success messages  
├── YELLOW='\033[1;33m' - Warning messages
├── BLUE='\033[0;34m' - Information messages
├── CYAN='\033[0;36m' - Prompts and questions
├── GRAY='\033[0;37m' - Debug messages
└── NC='\033[0m' - No color (reset)

Format Variables:
├── BOLD='\033[1m' - Bold text
├── UNDERLINE='\033[4m' - Underlined text
└── ITALIC='\033[3m' - Italic text
```

---

### **lib/validation.sh** - System Validation

#### **Overview**
Comprehensive system validation functions for prerequisites, health checks, and environment verification.

#### **Validation Categories**
```bash
System Validation:
├── _validate_running_as_root() - Root privilege check
├── _validate_os_compatibility() - Operating system compatibility
├── _validate_system_resources() - RAM, disk, CPU validation
├── _validate_required_commands() - Command availability check
└── _validate_network_connectivity() - Internet connectivity test

Docker Validation:
├── _validate_docker_daemon() - Docker service validation
├── _validate_docker_compose() - Docker Compose availability
├── _validate_compose_file(file) - Compose file syntax validation
└── _validate_port_availability(port) - Port binding check

Security Validation:
├── _validate_secure_permissions(file) - File permission audit
├── _validate_no_world_writable(dir) - World-writable file check
├── _validate_file_permissions(file, expected) - Specific permission check
└── _validate_directory_writable(dir) - Write permission check

Configuration Validation:
├── _validate_json_file(file) - JSON syntax validation
├── _validate_json_keys(file, keys) - Required key validation
├── _validate_file_exists(file) - File existence check
└── _validate_directory_exists(dir) - Directory existence check
```

#### **Resource Requirements**
```bash
Minimum System Requirements:
├── RAM: 512MB (2GB recommended)
├── Disk: 5GB available (20GB recommended)
├── CPU: 1 core (ARM64 or x86_64)
└── Network: Internet connectivity for setup

Required Commands:
├── curl - HTTP client for API calls
├── jq - JSON processing
├── docker - Container runtime
├── systemctl - Service management
└── openssl - Cryptographic operations
```

---

### **lib/system.sh** - System Operations

#### **Overview**
Operating system interaction functions for package management, service control, and system administration.

#### **System Management Functions**
```bash
Package Management:
├── _update_package_index() - Update apt package lists
├── _install_package(package) - Install individual package
├── _install_packages(packages...) - Install multiple packages
├── _package_installed(package) - Check package installation
└── _clean_package_cache() - Clean apt cache and autoremove

Service Management:  
├── _enable_service(service) - Enable systemd service
├── _disable_service(service) - Disable systemd service
├── _start_service(service) - Start systemd service
├── _stop_service(service) - Stop systemd service
├── _restart_service(service) - Restart systemd service
└── _service_status(service) - Check service status

File and Directory Operations:
├── _create_directory_secure(path, perms) - Create directory with permissions
├── _create_file_secure(path, perms, content) - Create file with content
├── _backup_file(source, destination) - Create file backup
├── _set_file_permissions(file, perms) - Set specific permissions
└── _ensure_directory_exists(path) - Create directory if needed
```

#### **Usage Examples**
```bash
# Package management
_install_package "docker.io"
_install_packages "jq" "curl" "fail2ban"

# Service management
_enable_service "docker"
_start_service "docker"
_restart_service "fail2ban"

# File operations
_create_directory_secure "/var/lib/vaultwarden" "700"
_create_file_secure "/etc/config" "600" "configuration content"
```

## 🛠️ **Operational Tools (/tools/)**

### **Database Management Scripts**

#### **tools/db-backup.sh** - Database Backup

**Overview**: Creates encrypted database backups in multiple formats with integrity verification.

**Usage**:
```bash
./tools/db-backup.sh [OPTIONS]

OPTIONS:
  --format FORMAT   Backup format: binary|sql|json|csv|all (default: binary)
  --output PATH     Output directory (default: auto-detected)
  --verify PATH     Verify existing backup file
  --dry-run         Show what would be done
  --help, -h        Show help information

EXAMPLES:
  ./tools/db-backup.sh                    # Standard binary backup
  ./tools/db-backup.sh --format sql       # Human-readable SQL dump
  ./tools/db-backup.sh --format json      # Structured JSON export
  ./tools/db-backup.sh --verify latest    # Verify most recent backup
```

**Backup Formats**:
```bash
Binary Format (default):
├── Fastest backup and restore
├── Native SQLite format preservation
├── Optimal compression ratio
└── Best for routine automated backups

SQL Format:
├── Human-readable SQL statements
├── Cross-platform compatibility
├── Easy partial restoration
└── Good for migrations and debugging

JSON Format:
├── Structured data export
├── API-friendly format
├── Programmatic data access
└── Good for data analysis

CSV Format:
├── Individual table exports
├── Spreadsheet compatibility
├── Easy data analysis
└── Good for reporting and auditing
```

---

#### **tools/sqlite-maintenance.sh** - Database Optimization

**Overview**: Database maintenance, optimization, and integrity checking for VaultWarden SQLite database.

**Usage**:
```bash
./tools/sqlite-maintenance.sh [OPTIONS]

OPTIONS:
  -t, --type TYPE      Maintenance type: quick|full|integrity|repair
  --analyze            Update database statistics
  --check              Integrity check only  
  --vacuum             Reclaim unused space
  --help, -h           Show help information

EXAMPLES:
  ./tools/sqlite-maintenance.sh -t quick    # Quick maintenance (5min)
  ./tools/sqlite-maintenance.sh -t full     # Full optimization (15min)
  ./tools/sqlite-maintenance.sh --check     # Integrity check only
  ./tools/sqlite-maintenance.sh --repair    # Attempt database repair
```

**Maintenance Types**:
```bash
Quick Maintenance (daily):
├── Integrity check (PRAGMA integrity_check)
├── Statistics update (ANALYZE)
├── WAL checkpoint (PRAGMA wal_checkpoint)
└── Basic performance metrics

Full Maintenance (weekly):
├── All quick maintenance operations
├── Database vacuum (VACUUM)
├── Index optimization
├── Fragmentation analysis
└── Performance benchmarking

Integrity Check:
├── Database corruption detection
├── Foreign key constraint validation
├── Index consistency verification
└── Table structure validation

Repair Operations:
├── Database recovery attempts
├── Corruption repair (limited)
├── Index rebuilding
└── Emergency data recovery
```

### **Backup and Recovery Scripts**

#### **tools/create-full-backup.sh** - System Backup

**Overview**: Creates comprehensive encrypted backups of the entire VaultWarden system including configuration, data, and system state.

**Usage**:
```bash
./tools/create-full-backup.sh [OPTIONS]

OPTIONS:
  --emergency         Quick backup with minimal validation
  --migration         Include migration-specific data
  --pre-update        Backup before system updates
  --forensic          Preserve system state for investigation
  --help, -h          Show help information

EXAMPLES:
  ./tools/create-full-backup.sh              # Standard full backup
  ./tools/create-full-backup.sh --emergency  # Fast emergency backup
  ./tools/create-full-backup.sh --migration  # Migration-ready backup
```

**Backup Components**:
```bash
Full Backup Includes:
├── Database and all user data
├── Configuration files (settings.json, etc.)
├── SSL certificates and keys
├── Caddy and reverse proxy configuration
├── Fail2ban rules and security configuration
├── Log files (recent, size-limited)
├── Docker volumes and persistent data
└── System service configurations

Backup Features:
├── AES-256-GCM encryption
├── Compression (typically 70% size reduction)
├── Integrity verification (SHA-256 checksums)
├── Metadata preservation (timestamps, permissions)
└── Incremental backup capability (future enhancement)
```

---

#### **tools/restore.sh** - Data Recovery

**Overview**: Interactive and automated restoration system with multiple recovery scenarios and validation.

**Usage**:
```bash
./tools/restore.sh [PATH] [OPTIONS]

OPTIONS:
  --database-only     Restore database data only
  --config-only       Restore configuration only
  --dry-run          Preview restore without making changes
  --verify PATH      Verify backup integrity
  --list             List available backups
  --force            Skip confirmations
  --help, -h         Show help information

EXAMPLES:
  ./tools/restore.sh                           # Interactive restore wizard
  ./tools/restore.sh /path/to/backup.tar.gz   # Direct restore
  ./tools/restore.sh --verify latest          # Verify recent backup
  ./tools/restore.sh --list                   # Show available backups
```

**Restore Scenarios**:
```bash
Complete System Restore:
├── Stop all services safely
├── Restore database and user data
├── Restore configuration files
├── Restore SSL certificates
├── Apply correct file permissions
├── Restart services with validation
└── Verify system functionality

Database-Only Restore:
├── Stop VaultWarden service
├── Backup current database
├── Restore database from backup
├── Validate database integrity
├── Restart VaultWarden service
└── Verify user data accessibility

Configuration Restore:
├── Backup current configuration
├── Restore configuration files
├── Validate configuration syntax
├── Restart affected services
└── Verify configuration applied correctly

Disaster Recovery:
├── Complete system restoration on new server
├── Network and DNS reconfiguration
├── SSL certificate regeneration
├── Service validation and testing
└── User notification and testing
```

### **Monitoring and Health Scripts**

#### **tools/monitor.sh** - System Monitoring

**Overview**: Comprehensive system health monitoring with automated recovery, alerting, and reporting capabilities.

**Usage**:
```bash
./tools/monitor.sh [OPTIONS]

OPTIONS:
  --summary           Quick health overview
  --verbose           Detailed health information
  --daily-report      Daily operations summary
  --security-check    Security-focused monitoring
  --performance       Performance metrics analysis
  --test-all          Test all monitoring functions
  --help, -h          Show help information

EXAMPLES:
  ./tools/monitor.sh --summary        # Quick status check
  ./tools/monitor.sh --verbose        # Detailed health report
  ./tools/monitor.sh --security-check # Security event analysis
```

**Monitoring Categories**:
```bash
Health Monitoring:
├── Container health status (Docker health checks)
├── Database connectivity and performance
├── SSL certificate validity and expiration
├── Disk space and storage utilization
├── Memory and CPU usage patterns
└── Network connectivity and DNS resolution

Security Monitoring:
├── Failed authentication attempts
├── Fail2ban activity and blocked IPs
├── Firewall rule effectiveness
├── SSL configuration security
├── File permission auditing
└── Access pattern analysis

Performance Monitoring:
├── Response time measurements
├── Database query performance
├── Resource utilization trends
├── Throughput and capacity metrics
├── Error rate tracking
└── Service availability metrics
```

#### **Automated Recovery Features**
```bash
Self-Healing Capabilities:
├── Container restart for failed services
├── Log rotation when disk space low
├── Database optimization when performance degrades
├── Memory cleanup during pressure
├── Network connectivity restoration
└── Configuration validation and repair

Recovery Escalation:
├── Immediate: Automated recovery (3 attempts)
├── Warning: Email notification to administrators
├── Critical: Service degradation alerts
├── Emergency: Fail-safe mode activation
└── Manual: Escalation to human intervention
```

### **Security and Update Scripts**

#### **tools/update-cloudflare-ips.sh** - CloudFlare Integration

**Overview**: Maintains current CloudFlare IP ranges for proper reverse proxy configuration and security.

**Usage**:
```bash
./tools/update-cloudflare-ips.sh [OPTIONS]

OPTIONS:
  --quiet        Suppress non-error output
  --force        Force update even if recent
  --verify       Verify current configuration
  --help, -h     Show help information

EXAMPLES:
  ./tools/update-cloudflare-ips.sh          # Update IP ranges
  ./tools/update-cloudflare-ips.sh --quiet  # Silent operation (cron)
  ./tools/update-cloudflare-ips.sh --verify # Check current config
```

**Integration Points**:
```bash
CloudFlare IP Management:
├── Fetch current IPv4 and IPv6 ranges from CloudFlare API
├── Generate Caddy configuration for trusted proxy IPs  
├── Update real IP detection for accurate logging
├── Maintain security rule compatibility
└── Validate configuration before applying

Generated Configuration:
├── trusted_proxies directives for Caddy
├── Real IP header processing rules
├── Security rule IP range updates
└── Fail2ban integration maintenance
```

---

#### **tools/update-secrets.sh** - Secret Management

**Overview**: Secure secret rotation and synchronization between OCI Vault and local configuration.

**Usage**:
```bash
./tools/update-secrets.sh [OPTIONS]

OPTIONS:
  --rotate-admin      Generate new admin token
  --rotate-backup     Generate new backup passphrase
  --sync-to-oci       Upload local config to OCI Vault
  --sync-from-oci     Download OCI config to local file
  --compare           Compare OCI and local configurations
  --help, -h          Show help information

EXAMPLES:
  ./tools/update-secrets.sh --rotate-admin    # New admin token
  ./tools/update-secrets.sh --sync-to-oci     # Upload to OCI Vault
  ./tools/update-secrets.sh --compare         # Check for drift
```

**Secret Management Features**:
```bash
Secret Rotation:
├── Cryptographically secure token generation
├── Automatic backup before rotation
├── Service restart with new credentials
├── Validation of new credentials
└── Rollback capability if needed

Synchronization:
├── Bi-directional sync (OCI ↔ Local)
├── Configuration drift detection
├── Conflict resolution procedures
├── Backup before synchronization
└── Validation after sync completion
```

### **OCI Integration Scripts**

#### **tools/oci-setup.sh** - OCI Vault Integration

**Overview**: Configure and manage OCI Vault integration for enterprise secret management.

**Usage**:
```bash
./tools/oci-setup.sh [OPTIONS]

OPTIONS:
  --update-ocid OCID     Update secret OCID
  --systemd-only OCID    Configure systemd integration only
  --test-connection      Test OCI Vault connectivity
  --help, -h             Show help information

EXAMPLES:
  ./tools/oci-setup.sh                        # Interactive OCI setup
  ./tools/oci-setup.sh --test-connection      # Test current setup
  ./tools/oci-setup.sh --update-ocid NEW_OCID # Update secret reference
```

**OCI Integration Features**:
```bash
Setup Process:
├── OCI CLI validation and authentication
├── Secret creation or connection to existing
├── SystemD service integration
├── Environment variable configuration
├── Fallback mechanism setup
└── Connection testing and validation

Management Capabilities:
├── Secret rotation coordination
├── Access permission management
├── Audit log integration
├── Disaster recovery procedures
└── Multi-region deployment support
```

## 🔧 **Script Integration and Automation**

### **Cron Job Integration**

#### **Automated Execution Schedule**
```bash
# Installed by init-setup.sh
# Health monitoring (every 5 minutes)
*/5 * * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/monitor.sh --silent

# Daily database backup (1:00 AM)
0 1 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/db-backup.sh

# Weekly full backup (Sunday 12:00 AM)
0 0 * * 0 root cd /opt/VaultWarden-OCI-Minimal && ./tools/create-full-backup.sh

# Weekly database optimization (Monday 2:00 AM)
0 2 * * 1 root cd /opt/VaultWarden-OCI-Minimal && ./tools/sqlite-maintenance.sh -t full

# Daily CloudFlare IP updates (3:00 AM)
0 3 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/update-cloudflare-ips.sh --quiet

# Daily cleanup (4:00 AM)
0 4 * * * root find /var/lib/*/logs -name "*.log" -size +50M -exec truncate -s 10M {} \\;
0 4 * * * root find /var/lib/*/backups -name "*.backup*" -mtime +30 -delete
```

### **SystemD Service Integration**

#### **Service Definition**
```bash
# Created by tools/oci-setup.sh
[Unit]
Description=VaultWarden-OCI-Minimal Stack
Documentation=https://github.com/killer23d/VaultWarden-OCI-Minimal
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
Restart=on-failure
RestartSec=30
TimeoutStartSec=300

# Environment configuration
EnvironmentFile=-/etc/systemd/system/vaultwarden-oci-minimal.env
WorkingDirectory=/opt/VaultWarden-OCI-Minimal
Environment=COMPOSE_PROJECT_NAME=vaultwarden-oci-minimal

# Execution
ExecStart=/opt/VaultWarden-OCI-Minimal/startup.sh
ExecStop=/usr/bin/docker compose -f /opt/VaultWarden-OCI-Minimal/docker-compose.yml down
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

## 🚨 **Emergency Script Usage**

### **Critical Recovery Procedures**

#### **Emergency Service Recovery**
```bash
# If all services are down
./startup.sh --force --debug

# If startup fails, try emergency restoration
./tools/restore.sh --emergency

# If database is corrupted
./tools/sqlite-maintenance.sh --repair

# If configuration is corrupted
./tools/restore.sh --config-only /path/to/backup
```

#### **Emergency Backup Creation**
```bash
# Create immediate backup before risky operations
./tools/create-full-backup.sh --emergency

# Create forensic backup during security incident  
./tools/create-full-backup.sh --forensic --preserve-logs

# Database-only emergency backup
./tools/db-backup.sh --emergency --format binary
```

### **Diagnostic Script Usage**

#### **System Diagnostics**
```bash
# Comprehensive system diagnostic
./tools/monitor.sh --verbose --debug

# Performance issue investigation
./tools/monitor.sh --performance --detailed

# Security incident analysis
./tools/monitor.sh --security-check --incident-mode

# Configuration validation
./startup.sh --validate --debug
```

## 📋 **Script Development Guidelines**

### **Coding Standards**

#### **Script Structure**
```bash
Standard Script Template:
#!/usr/bin/env bash
# script-name.sh - Brief description
# Longer description of purpose and functionality

set -euo pipefail  # Error handling

# Auto-detect paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"  # Adjust based on script location

# Source required libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/config.sh"  # If needed

# Set logging prefix
_set_log_prefix "script-name"

# Script constants
readonly SCRIPT_VERSION="1.0.0"

# Main functions
main() {
    # Script implementation
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

#### **Error Handling**
```bash
Error Handling Patterns:
├── Use set -euo pipefail for strict error handling
├── Validate all parameters and prerequisites
├── Use meaningful exit codes (0=success, 1-255=various errors)
├── Log errors before exiting with _log_error
└── Provide recovery suggestions in error messages

Example:
if ! command -v docker >/dev/null 2>&1; then
    _log_error "Docker not found. Please install Docker first."
    _log_info "Run: sudo ./tools/init-setup.sh"
    exit 2
fi
```

This comprehensive script reference provides detailed information for effectively using and understanding all scripts in the VaultWarden-OCI-Minimal project."""
