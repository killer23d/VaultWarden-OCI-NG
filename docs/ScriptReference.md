# Script Reference Guide

This document provides comprehensive reference documentation for all scripts included in the VaultWarden-OCI-NG project. Each script is designed for specific operational tasks and follows consistent patterns for logging, error handling, and security.

## Core Scripts

### `startup.sh`
**Primary entry point for starting the VaultWarden stack**

**Purpose**: Orchestrates the complete startup process including secret management, service initialization, and health validation.

**Usage**:
```bash
./startup.sh [OPTIONS]
```

**Options**:
- `--help, -h`: Display help information
- `--validate`: Validate configuration and prerequisites only (no service start)
- `--secrets-info`: Show encrypted secrets information and management commands

**Functionality**:
1. **Secret Management**: Decrypts SOPS+Age encrypted secrets and prepares Docker secrets
2. **Environment Preparation**: Creates required directories with secure permissions
3. **Pre-startup Tasks**: Updates CloudFlare IPs, renders configuration templates
4. **Service Orchestration**: Starts Docker Compose services in dependency order
5. **Health Validation**: Verifies all services are healthy before completion
6. **Status Reporting**: Displays service URLs and management commands

**Example Output**:
```
[startup] VaultWarden-OCI-NG - Enhanced Startup with SOPS+Age
[startup] Loading Encrypted Secrets
[startup] ✅ Encrypted secrets accessible
[startup] ✅ Docker secrets prepared
[startup] ✅ VaultWarden is healthy
[startup] ✅ Services started successfully
```

**Important Notes**:
- Always use this script instead of `docker compose up` directly
- Requires prior execution of `./tools/init-setup.sh`
- Automatically handles secret decryption and container secret injection

---

## Setup and Installation Scripts

### `tools/init-setup.sh`
**One-time system setup and configuration script**

**Purpose**: Transforms a fresh Ubuntu server into a production-ready VaultWarden host with complete security hardening and automation.

**Usage**:
```bash
sudo ./tools/init-setup.sh [OPTIONS]
```

**Options**:
- `--auto`: Non-interactive mode using environment variables
- `--help`: Display detailed usage information

**Prerequisites**:
- Fresh Ubuntu 24.04 LTS installation
- Root or sudo access
- Internet connectivity

**Complete Functionality**:

#### System Dependencies
- Docker Engine and Docker Compose installation
- Essential system packages (curl, jq, unzip, etc.)
- System service configuration

#### Security Hardening  
- UFW firewall configuration with minimal attack surface
- Fail2ban installation with VaultWarden-specific jails
- Secure directory structure creation
- File permission hardening

#### Secret Management Setup
- SOPS (Secrets OPerationS) installation
- Age encryption key generation
- Encrypted secrets file initialization
- Docker secrets directory preparation

#### Automation Configuration
- Cron job installation for automated backups
- System monitoring cron jobs
- Log rotation configuration
- Update automation setup

**Interactive Prompts**:
```bash
Domain name (e.g., https://vault.company.com): 
Administrator email address: 
SMTP host (optional): 
CloudFlare API token (optional):
```

**Non-Interactive Environment Variables**:
```bash
export DOMAIN="https://vault.company.com"
export ADMIN_EMAIL="admin@company.com"
export SMTP_HOST="smtp.gmail.com"
export SMTP_FROM="noreply@company.com"
export CLOUDFLARE_API_TOKEN="your-token"
```

---

## Secret Management Scripts

### `tools/edit-secrets.sh`  
**Secure encrypted secrets editor**

**Purpose**: Provides secure editing of the SOPS+Age encrypted secrets file with automatic encryption/decryption.

**Usage**:
```bash
sudo ./tools/edit-secrets.sh [OPTIONS]
```

**Options**:
- `--view`: Display decrypted secrets without editing
- `--help`: Show usage information

**Security Features**:
- Temporary decryption in memory only
- Automatic re-encryption on save
- Editor process isolation
- Secure file permission maintenance

**Managed Secrets**:
- `admin_token`: VaultWarden admin panel access token
- `smtp_password`: SMTP authentication password  
- `backup_passphrase`: Backup encryption passphrase
- `push_installation_key`: Push notification service key
- `cloudflare_api_token`: CloudFlare API token for fail2ban integration

**Example Workflow**:
```bash
# Edit secrets securely
sudo ./tools/edit-secrets.sh

# View current secrets
sudo ./tools/edit-secrets.sh --view

# Check specific secret
sudo ./tools/edit-secrets.sh --view | grep admin_token
```

---

## Backup and Recovery Scripts

### `tools/create-full-backup.sh`
**Comprehensive system backup creation**

**Purpose**: Creates encrypted, compressed backups of the entire VaultWarden system including database, attachments, configuration, and logs.

**Usage**:
```bash
./tools/create-full-backup.sh [OPTIONS]
```

**Options**:
- `--output-dir PATH`: Specify custom backup destination
- `--compression LEVEL`: Set compression level (1-9, default: 6)
- `--exclude-logs`: Skip log files in backup
- `--dry-run`: Show what would be backed up without creating files

**Backup Contents**:
- VaultWarden SQLite database
- User attachments and vault data
- Configuration files (settings.json)
- SSL certificates and keys
- Log files (optional)
- Docker Compose configuration

**Backup Format**:
```
backup-full-YYYYMMDD-HHMMSS.tar.gz.enc
```

**Encryption**: Uses the `backup_passphrase` from encrypted secrets for AES-256 encryption.

**Example**:
```bash
# Create standard full backup
./tools/create-full-backup.sh

# Create backup excluding logs  
./tools/create-full-backup.sh --exclude-logs

# Test backup creation
./tools/create-full-backup.sh --dry-run
```

### `tools/db-backup.sh`
**Database-specific backup utility**

**Purpose**: Creates encrypted backups of the VaultWarden SQLite database with optional compression and retention management.

**Usage**:
```bash
./tools/db-backup.sh [OPTIONS]
```

**Options**:
- `--output-dir PATH`: Custom backup location
- `--retention-days N`: Keep backups for N days (default: 30)
- `--compress`: Apply gzip compression
- `--dry-run`: Show backup plan without execution

**Functionality**:
- SQLite database consistency checks
- Atomic backup creation (no corruption risk)
- Automatic old backup cleanup
- Backup integrity verification

**Backup Format**:
```
db-backup-YYYYMMDD-HHMMSS.sqlite3.enc
```

**Automated Schedule**: Runs daily at 2:00 AM via cron job.

### `tools/restore.sh`
**System and database restoration utility**

**Purpose**: Restores VaultWarden system or database from encrypted backup files.

**Usage**:
```bash
./tools/restore.sh [OPTIONS] <backup-file>
```

**Options**:
- `--list`: Show available backup files
- `--verify BACKUP`: Verify backup integrity without restoring
- `--dry-run BACKUP`: Show restoration plan without execution
- `--force`: Skip confirmation prompts
- `--database-only`: Restore only database, skip configuration

**Safety Features**:
- Pre-restore system validation
- Automatic service stopping during restore
- Current state backup before restoration
- Post-restore health verification

**Example Usage**:
```bash
# List available backups
./tools/restore.sh --list

# Verify backup integrity
./tools/restore.sh --verify /path/to/backup.tar.gz.enc

# Perform full restoration
./tools/restore.sh /path/to/backup.tar.gz.enc

# Database-only restoration
./tools/restore.sh --database-only /path/to/db-backup.sqlite3.enc
```

---

## Monitoring and Maintenance Scripts

### `tools/check-health.sh`
**Comprehensive system health monitoring**

**Purpose**: Performs detailed health checks across all system components and services.

**Usage**:
```bash
./tools/check-health.sh [OPTIONS]
```

**Options**:
- `--verbose`: Detailed output with diagnostic information
- `--sops-only`: Check only SOPS+Age secret management
- `--services-only`: Check only running services
- `--json`: Output results in JSON format

**Health Check Categories**:

#### Container Health
- Service running status
- Container health check status
- Resource utilization monitoring
- Docker daemon connectivity

#### SSL Certificate Monitoring  
- Certificate validity and expiration
- Certificate chain verification
- Let's Encrypt renewal status

#### Database Health
- SQLite database integrity
- Database file permissions
- Query performance metrics
- Backup system status

#### Security Status
- UFW firewall rule verification
- Fail2ban jail status and activity
- File permission auditing
- Secret management verification

#### System Resources
- Disk space monitoring
- Memory utilization
- CPU load assessment
- Network connectivity

**Example Output**:
```bash
[health] System Health Check Report
[health] ✅ All containers healthy
[health] ✅ SSL certificate valid (expires: 2024-04-15)
[health] ✅ Database integrity verified
[health] ✅ Firewall active with proper rules
[health] ✅ Backup system operational
[health] ⚠️  Disk usage: 78% (monitor closely)
```

### `tools/monitor.sh`
**Automated monitoring and self-healing**

**Purpose**: Continuous monitoring script that runs via cron to detect and automatically resolve common issues.

**Usage**:
```bash
./tools/monitor.sh [OPTIONS]
```

**Options**:
- `--summary`: Brief health status summary
- `--test-email`: Send test notification email
- `--no-restart`: Check health but don't restart failed services

**Monitoring Capabilities**:

#### Service Monitoring
- Container health status verification  
- Automatic restart of failed services
- Resource limit breach detection
- Performance degradation alerts

#### Security Monitoring
- Failed authentication attempt tracking
- Unusual access pattern detection
- SSL certificate expiration warnings
- Firewall rule compliance verification

#### System Monitoring  
- Disk space threshold monitoring
- Memory leak detection
- Database performance tracking
- Backup success verification

#### Automated Recovery Actions
- Service restart for failed containers
- Database optimization on performance issues
- Log rotation for disk space management
- Email notifications for critical issues

**Automated Schedule**: Runs every 5 minutes via cron job.

### `tools/sqlite-maintenance.sh`
**SQLite database optimization and maintenance**

**Purpose**: Performs comprehensive SQLite database maintenance including optimization, integrity checks, and performance tuning.

**Usage**:
```bash
./tools/sqlite-maintenance.sh [OPTIONS]
```

**Options**:
- `--full`: Complete maintenance including VACUUM and optimization
- `--check`: Database integrity verification only
- `--optimize`: Performance optimization only  
- `--stats`: Display database statistics
- `--dry-run`: Show maintenance plan without execution

**Maintenance Operations**:

#### Integrity Verification
- Database corruption detection
- Foreign key constraint validation
- Index consistency verification
- Schema validation

#### Performance Optimization
- VACUUM operation for space reclamation
- Index rebuilding and optimization
- Query plan analysis
- Statistics update

#### Space Management
- WAL (Write-Ahead Logging) checkpoint
- Temporary file cleanup
- Free page management
- Database size reporting

**Example Output**:
```bash
[sqlite] Database Maintenance Report
[sqlite] ✅ Integrity check passed
[sqlite] ✅ VACUUM completed - 2.3MB reclaimed  
[sqlite] ✅ Indexes rebuilt - 15% performance improvement
[sqlite] ✅ Statistics updated
[sqlite] Database size: 45.7MB (was 48.0MB)
```

**Automated Schedule**: Runs weekly on Saturday nights at 1:00 AM.

---

## Utility Scripts

### `tools/update-cloudflare-ips.sh`
**CloudFlare IP range updater**

**Purpose**: Updates Caddy reverse proxy configuration with current CloudFlare IP ranges for enhanced security.

**Usage**:  
```bash
./tools/update-cloudflare-ips.sh [OPTIONS]
```

**Options**:
- `--quiet`: Suppress output messages
- `--force`: Update even if ranges haven't changed
- `--output PATH`: Specify output file path

**Functionality**:
- Downloads current CloudFlare IP ranges (IPv4 and IPv6)
- Updates Caddy configuration files
- Validates IP range formats
- Triggers Caddy configuration reload

**Automated Execution**: Runs automatically during `startup.sh` execution.

### `tools/render-ddclient-conf.sh`
**Dynamic DNS configuration renderer**

**Purpose**: Generates ddclient configuration files from templates with secure secret injection.

**Usage**:
```bash
./tools/render-ddclient-conf.sh <template> <output>
```

**Parameters**:
- `template`: Path to template file  
- `output`: Generated configuration file path

**Template Variables**:
- `{{CLOUDFLARE_API_TOKEN}}`: CloudFlare API token from secrets
- `{{DOMAIN}}`: Configured domain name
- `{{DDCLIENT_HOST}}`: DNS hostname to update

---

## Library Functions

### `lib/logging.sh`
**Centralized logging functionality**

**Functions**:
- `_log_info()`: Information messages
- `_log_warning()`: Warning messages  
- `_log_error()`: Error messages
- `_log_success()`: Success confirmation messages
- `_log_header()`: Section headers
- `_set_log_prefix()`: Set logging prefix for script identification

### `lib/config.sh`  
**Configuration management**

**Functions**:
- `load_config()`: Load and validate configuration
- `get_config_value()`: Retrieve specific configuration values
- `validate_configuration()`: Comprehensive configuration validation

### `lib/validation.sh`
**System validation functions**

**Functions**:
- `_validate_docker_daemon()`: Docker service verification
- `_validate_network_connectivity()`: Network access validation
- `_validate_compose_file()`: Docker Compose file validation

### `lib/system.sh`
**System utility functions**  

**Functions**:
- `_create_directory_secure()`: Secure directory creation
- `_create_file_secure()`: Secure file creation with permissions
- `_compose_service_running()`: Docker service status checking

### `lib/sops.sh`
**SOPS+Age integration**

**Functions**:
- `sops_decrypt()`: Secure secret decryption
- `sops_encrypt()`: Secret encryption
- `age_key_exists()`: Age key validation

## Script Usage Patterns

### Common Command Patterns

```bash
# System startup and management
./startup.sh                    # Start all services
./startup.sh --validate         # Validate configuration only
docker compose down             # Stop all services

# Backup operations
./tools/create-full-backup.sh   # Full system backup
./tools/db-backup.sh           # Database backup only
./tools/restore.sh --list      # List available backups

# Monitoring and health
./tools/check-health.sh        # Comprehensive health check
./tools/monitor.sh --summary   # Brief status summary

# Secret management
sudo ./tools/edit-secrets.sh   # Edit encrypted secrets
sudo ./tools/edit-secrets.sh --view  # View secrets

# Maintenance
./tools/sqlite-maintenance.sh --full  # Database optimization
```

### Error Handling

All scripts implement consistent error handling:
- Exit codes: 0 for success, non-zero for failures
- Structured logging with timestamps
- Error message clarity and actionable guidance
- Rollback capabilities where applicable

### Security Considerations

- Scripts requiring elevated privileges use `sudo` explicitly
- Temporary files are created with secure permissions
- Sensitive operations log to secure locations only
- Secret exposure is prevented in process lists and logs

This script reference provides comprehensive documentation for operational management of VaultWarden-OCI-NG. Each script is designed for reliability, security, and ease of use in production environments.
