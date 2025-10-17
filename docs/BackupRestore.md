# Backup and Restore Guide

> **🎯 Data Protection Philosophy**: Comprehensive, automated backup strategy with multiple formats, encryption, and tested recovery procedures for maximum data safety.

## 🛡️ **Backup Strategy Overview**

VaultWarden-OCI-Minimal implements a **multi-layered backup strategy** designed for small teams with enterprise-grade data protection:

```bash
Backup Architecture:
├── Automated Daily Backups (Database + Configurations)
├── Automated Weekly Backups (Full System Snapshots)
├── Manual On-Demand Backups (Pre-maintenance, Emergency)
├── Multiple Format Support (Binary, SQL, JSON, CSV)
├── Encryption & Compression (AES-256-GCM + gzip)
├── Integrity Verification (Checksums + Test Restoration)
├── Retention Management (Configurable Cleanup Policies)
└── Off-Site Capabilities (Cloud Storage Ready)
```

### **Backup Types and Schedules**

#### **Automated Backup Schedule**
```bash
# Configured automatically during init-setup.sh
# Database backups: Daily at 1:00 AM
0 1 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/db-backup.sh

# Full system backups: Weekly on Sunday at 12:00 AM
0 0 * * 0 root cd /opt/VaultWarden-OCI-Minimal && ./tools/create-full-backup.sh

# Backup verification: Daily at 1:30 AM (after database backup)
30 1 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/restore.sh --verify-recent

# Cleanup old backups: Daily at 4:00 AM
0 4 * * * root find /var/lib/*/backups -name "*.backup*" -mtime +30 -delete
```

#### **Backup Content Coverage**
```bash
Database Backups Include:
├── SQLite database file (db.sqlite3)
├── Database integrity verification
├── User vault data and metadata
├── Organization data and settings
├── File attachments and sends
├── Authentication tokens and sessions
└── Application configuration data

Full System Backups Include:
├── Complete database backup
├── Application configuration (settings.json)
├── SSL certificates and keys
├── Caddy configuration and custom settings
├── Fail2ban rules and IP lists
├── Log files and system state
├── Docker volumes and container data
└── Cron jobs and systemd configurations
```

## 💾 **Database Backup System**

### **Database Backup Script**

#### **Basic Database Backup**
```bash
# Create immediate database backup
./tools/db-backup.sh

# Expected output:
🔍 Starting VaultWarden database backup...
✅ Container health verified
✅ Database accessibility confirmed
✅ Backup directory prepared: /var/lib/vaultwarden-oci-minimal/backups/db/
📦 Creating backup: vaultwarden-db-20241014-173025.backup
✅ Database copied successfully (2.3MB)
🔐 Encrypting backup with AES-256-GCM...
✅ Backup encrypted (892KB after compression)
🔍 Verifying backup integrity...
✅ Backup verification successful
📊 Backup completed: vaultwarden-db-20241014-173025.backup
   Size: 892KB (compressed from 2.3MB)
   Location: /var/lib/vaultwarden-oci-minimal/backups/db/
   Encryption: AES-256-GCM
   Integrity: SHA-256 verified
```

#### **Multiple Format Backups**
```bash
# Binary format (default - fastest)
./tools/db-backup.sh --format binary

# SQL format (portable, human-readable)
./tools/db-backup.sh --format sql

# JSON format (structured data export)
./tools/db-backup.sh --format json

# CSV format (individual table exports)
./tools/db-backup.sh --format csv

# All formats (comprehensive backup)
./tools/db-backup.sh --format all
```

#### **Backup Verification**
```bash
# Verify specific backup file
./tools/db-backup.sh --verify /var/lib/*/backups/db/vaultwarden-db-20241014-173025.backup

# Test backup without restoration (dry run)
./tools/db-backup.sh --test-restore /var/lib/*/backups/db/latest.backup

# Integrity check for all recent backups
./tools/db-backup.sh --verify-all

# Expected verification output:
🔍 Verifying backup: vaultwarden-db-20241014-173025.backup
✅ File exists and readable
✅ Encryption verified (AES-256-GCM)
✅ Decompression successful
✅ SQLite integrity check passed
✅ Data structure validation passed
✅ Backup is valid and restorable
```

### **Backup Format Details**

#### **Binary Format** (Default)
```bash
# Fastest backup method - direct SQLite file copy
# Advantages:
# - Fastest backup and restore
# - Preserves all SQLite-specific features
# - Smallest compressed size
# - Native format compatibility

# Use case: Regular automated backups
./tools/db-backup.sh --format binary

# File structure:
vaultwarden-db-YYYYMMDD-HHMMSS.backup
├── Encrypted container (AES-256-GCM)
├── Compressed SQLite database (gzip)
├── Integrity checksum (SHA-256)
└── Metadata (timestamps, version info)
```

#### **SQL Format** (Portable)
```bash
# Human-readable SQL dump
# Advantages:
# - Cross-platform compatibility
# - Human-readable and editable
# - Easy to analyze or partially restore
# - Good for migrations

# Use case: Migration between servers, debugging
./tools/db-backup.sh --format sql

# Contents include:
# - CREATE TABLE statements
# - INSERT statements with data
# - Index and constraint definitions
# - Transaction boundaries for consistency
```

#### **JSON Format** (Structured)
```bash
# Structured JSON export
# Advantages:
# - Easy programmatic access
# - Good for integration with other tools
# - Selective data extraction possible
# - API-friendly format

# Use case: Data analysis, integration, selective restore
./tools/db-backup.sh --format json

# Structure:
{
  "metadata": {
    "backup_time": "2024-10-14T17:30:25Z",
    "version": "1.30.1",
    "format": "json"
  },
  "users": [...],
  "organizations": [...],
  "ciphers": [...],
  "folders": [...]
}
```

#### **CSV Format** (Individual Tables)
```bash
# Individual CSV files per table
# Advantages:
# - Spreadsheet compatible
# - Easy data analysis
# - Selective table restoration
# - Good for auditing

# Use case: Data analysis, reporting, auditing
./tools/db-backup.sh --format csv

# Creates multiple files:
backup-YYYYMMDD-HHMMSS/
├── users.csv
├── organizations.csv
├── ciphers.csv
├── folders.csv
├── attachments.csv
└── metadata.json
```

## 🔄 **Full System Backup**

### **Complete System Snapshot**

#### **Full System Backup Creation**
```bash
# Create comprehensive system backup
./tools/create-full-backup.sh

# Backup process and output:
🔍 Starting full system backup for VaultWarden-OCI-Minimal...
📋 Pre-backup validation...
✅ All containers healthy
✅ Database accessible
✅ Configuration files secure
✅ Sufficient disk space available

📦 Creating system snapshot...
📄 Backing up configurations...
   ✅ settings.json (600 bytes)
   ✅ Caddy configuration (2.1KB)
   ✅ Fail2ban rules (5.4KB)
   ✅ Cron jobs (1.2KB)

💾 Backing up data...
   ✅ VaultWarden database (2.3MB)
   ✅ SSL certificates (15.2KB) 
   ✅ User attachments (892KB)
   ✅ Application logs (234KB)

🔐 Encrypting and compressing...
   📊 Original size: 3.8MB
   📊 Compressed size: 1.2MB
   🔒 Encryption: AES-256-GCM
   
✅ Full backup completed: vaultwarden-full-20241014-173025.tar.gz
   Location: /var/lib/vaultwarden-oci-minimal/backups/full/
   Size: 1.2MB (compressed from 3.8MB)
   Backup time: 23 seconds
```

#### **Full Backup Contents**
```bash
# Full backup includes everything needed for complete restoration
Full Backup Archive Contents:
├── database/
│   ├── db.sqlite3                    # Main database
│   ├── attachments/                  # User file attachments
│   └── sends/                        # Bitwarden Send files
├── config/
│   ├── settings.json                 # Main configuration
│   ├── caddy/                        # Reverse proxy config
│   ├── fail2ban/                     # Security configuration
│   └── ssl/                          # Certificate backups
├── logs/
│   ├── vaultwarden/                  # Application logs
│   ├── caddy/                        # Access logs
│   └── system/                       # System logs
├── metadata/
│   ├── backup-info.json              # Backup metadata
│   ├── system-info.json              # System information
│   └── version-info.json             # Version tracking
└── scripts/
    ├── restore-instructions.md        # Recovery guide
    └── validation-checksums.sha256     # Integrity verification
```

#### **Emergency Backup**
```bash
# Create emergency backup (faster, essential data only)
./tools/create-full-backup.sh --emergency

# Emergency backup prioritizes:
# - Database integrity
# - Configuration files
# - SSL certificates
# - Recent logs only
# - Skip large log files
# - Faster completion time

# Use case: Before risky operations, incident response
```

## 🔧 **Restore Procedures**

### **Interactive Restore System**

#### **Guided Restoration Process**
```bash
# Launch interactive restore wizard
./tools/restore.sh

# Interactive restore flow:
🔍 VaultWarden-OCI-Minimal Restore Wizard

Available backup files:
[1] vaultwarden-full-20241014-173025.tar.gz (1.2MB) - Full system
[2] vaultwarden-full-20241013-000015.tar.gz (1.1MB) - Full system  
[3] vaultwarden-db-20241014-173025.backup (892KB) - Database only
[4] vaultwarden-db-20241014-010030.backup (891KB) - Database only
[5] Browse custom path...

Select backup to restore [1-5]: 1

🔍 Analyzing backup: vaultwarden-full-20241014-173025.tar.gz
✅ Backup file accessible and valid
✅ Encryption verified
✅ Integrity check passed
📊 Backup contains:
   - Database: 2.3MB (1,247 vault entries)
   - Configuration: 8.7KB (4 files)
   - SSL certificates: 15.2KB (2 domains)
   - Logs: 234KB (7 days)

⚠️  IMPORTANT: This will replace current data
   Current database: 2.1MB (1,189 vault entries)
   Data difference: +58 vault entries from backup

Restore options:
[1] Complete restoration (replace everything)
[2] Database only (keep current configuration)
[3] Configuration only (keep current database)
[4] Preview contents (no changes made)
[5] Cancel restoration

Select restoration type [1-5]: 1

🛑 Final confirmation required
This will REPLACE all current VaultWarden data with backup from:
Date: 2024-10-14 17:30:25 UTC
Size: 1.2MB compressed (3.8MB uncompressed)

Type 'RESTORE' to confirm: RESTORE

🔧 Stopping services...
✅ VaultWarden stopped gracefully
✅ Related services stopped

📦 Extracting backup...
✅ Backup decrypted successfully
✅ Archive extracted to temporary location
✅ Integrity verification passed

🔄 Restoring data...
✅ Database restored (2.3MB)
✅ Configuration restored (4 files)
✅ SSL certificates restored
✅ Permissions applied

🚀 Restarting services...
✅ Configuration validated
✅ Services started successfully
✅ Health checks passed

✅ Restoration completed successfully!
   Restored data from: 2024-10-14 17:30:25 UTC
   Database entries: 1,247 vault items
   Users affected: 8 accounts
   Time taken: 45 seconds

🔍 Post-restore verification:
✅ VaultWarden accessible at https://your-domain.com
✅ Database integrity confirmed
✅ SSL certificates valid
✅ All services healthy

📋 Next steps:
1. Test login with existing accounts
2. Verify vault data accessibility
3. Check admin panel functionality
4. Notify users of any data changes (if applicable)
```

### **Command-Line Restore Options**

#### **Direct Restore Commands**
```bash
# Restore specific backup file
./tools/restore.sh /var/lib/*/backups/full/vaultwarden-full-20241014-173025.tar.gz

# Database-only restoration
./tools/restore.sh --database-only /var/lib/*/backups/db/latest.backup

# Configuration-only restoration  
./tools/restore.sh --config-only /var/lib/*/backups/full/latest.tar.gz

# Dry run (test without making changes)
./tools/restore.sh --dry-run /path/to/backup

# Force restore (skip confirmations)
./tools/restore.sh --force /path/to/backup
```

#### **Selective Restore Operations**
```bash
# Restore specific components
./tools/restore.sh --components="database,config" /path/to/backup

# Restore to different location (for analysis)
./tools/restore.sh --target-dir=/tmp/restore-test /path/to/backup

# Restore with time point recovery
./tools/restore.sh --before="2024-10-14 16:00:00" /path/to/backup

# Restore user data only (exclude system config)
./tools/restore.sh --user-data-only /path/to/backup
```

### **Advanced Restore Scenarios**

#### **Cross-Server Migration**
```bash
# Complete system migration to new server

# On source server:
./tools/create-full-backup.sh --migration
# Creates: migration-backup-TIMESTAMP.tar.gz

# Transfer to new server:
scp /var/lib/*/backups/full/migration-backup-*.tar.gz user@new-server:/tmp/

# On new server:
# 1. Install VaultWarden-OCI-Minimal
git clone https://github.com/killer23d/VaultWarden-OCI-Minimal.git
cd VaultWarden-OCI-Minimal
chmod +x startup.sh tools/*.sh

# 2. Run migration restore
sudo ./tools/restore.sh --migration /tmp/migration-backup-*.tar.gz

# 3. Update DNS/domain configuration
sudo nano settings.json  # Update DOMAIN if needed

# 4. Start services
./startup.sh
```

#### **Disaster Recovery**
```bash
# Complete disaster recovery from off-site backup

# Prerequisites:
# - Fresh Ubuntu 24.04 server
# - VaultWarden-OCI-Minimal repository
# - Off-site backup file accessible

# Recovery procedure:
# 1. Basic system setup
sudo apt update && sudo apt upgrade -y
git clone https://github.com/killer23d/VaultWarden-OCI-Minimal.git
cd VaultWarden-OCI-Minimal
chmod +x startup.sh tools/*.sh

# 2. Disaster recovery restoration
sudo ./tools/restore.sh --disaster-recovery /path/to/offsite/backup.tar.gz

# The disaster recovery mode:
# - Skips certain validation checks
# - Automatically installs missing dependencies
# - Recreates system structure from backup
# - Handles potential hostname/IP changes
# - Provides detailed recovery logging

# 3. Post-recovery validation
./startup.sh --validate
./tools/monitor.sh --comprehensive-check
```

#### **Partial Data Recovery**
```bash
# Recover specific user data or vault items

# Extract backup for analysis
./tools/restore.sh --extract-only /path/to/backup /tmp/analysis/

# Convert to JSON for selective recovery
./tools/db-backup.sh --format json --input /tmp/analysis/database/db.sqlite3

# Selectively restore specific users/organizations
./tools/restore.sh --selective-users="user1@example.com,user2@example.com" /path/to/backup

# Merge data from backup (add missing entries without replacement)
./tools/restore.sh --merge-mode /path/to/backup
```

## 🔐 **Backup Security and Encryption**

### **Encryption Implementation**

#### **Backup Encryption Details**
```bash
# Encryption specifications:
Algorithm: AES-256-GCM (Galois/Counter Mode)
Key Derivation: PBKDF2 with 100,000 iterations
Salt: 32 bytes random (unique per backup)
Authentication: Built-in GCM authentication tag
Compression: gzip before encryption (reduces size ~70%)

# Passphrase management:
# - Generated during init-setup.sh (32 bytes, base64 encoded)
# - Stored securely in settings.json (600 permissions)
# - Can be rotated without affecting existing backups
# - Each backup can use different passphrase if needed
```

#### **Encryption Verification**
```bash
# Verify backup encryption
./tools/db-backup.sh --test-encryption

# Test encryption/decryption cycle
BACKUP_FILE="/var/lib/*/backups/db/latest.backup"
./tools/restore.sh --verify-encryption "$BACKUP_FILE"

# Expected output:
🔐 Testing backup encryption for: latest.backup
✅ File header indicates AES-256-GCM encryption
✅ Passphrase authentication successful
✅ Decryption completed without errors
✅ Data integrity verified post-decryption
✅ Re-encryption test successful
🔒 Backup encryption is functioning correctly
```

#### **Passphrase Management**
```bash
# View current backup passphrase (secure environment only)
sudo jq -r '.BACKUP_PASSPHRASE' settings.json

# Generate new backup passphrase
NEW_PASSPHRASE=$(openssl rand -base64 32)

# Update configuration with new passphrase
sudo jq --arg pass "$NEW_PASSPHRASE" '.BACKUP_PASSPHRASE = $pass' settings.json > temp.json
sudo mv temp.json settings.json
sudo chmod 600 settings.json

# Note: Existing backups use their original passphrase
# New backups will use the updated passphrase
```

### **Backup Integrity and Verification**

#### **Multi-Layer Integrity Checking**
```bash
# Integrity verification layers:
1. File-level checksums (SHA-256)
2. Encryption authentication (GCM tag)
3. Compression integrity (gzip CRC)
4. Database integrity (SQLite PRAGMA)
5. Data structure validation
6. Application-level consistency checks

# Comprehensive integrity verification
./tools/restore.sh --verify-all

# Expected verification levels:
🔍 Comprehensive Backup Verification

Level 1 - File System:
✅ All backup files exist and readable
✅ File sizes match expected ranges
✅ Timestamps within acceptable bounds
✅ No filesystem corruption detected

Level 2 - Encryption & Compression:
✅ All backups decrypt successfully
✅ GCM authentication tags valid
✅ Compression integrity verified
✅ No data corruption in transit/storage

Level 3 - Database Integrity:
✅ SQLite integrity checks passed
✅ Foreign key constraints satisfied
✅ Index consistency verified
✅ Transaction log clean

Level 4 - Application Consistency:
✅ User account data consistent
✅ Organization relationships valid
✅ Vault item encryption verifiable
✅ Attachment references correct

Level 5 - System Integration:
✅ Configuration syntax valid
✅ SSL certificate chains complete
✅ Service dependencies satisfied
✅ Version compatibility confirmed

🎯 All verification levels passed
   Total backups verified: 15
   Issues found: 0
   Verification time: 2m 34s
```

## 📋 **Backup Maintenance and Management**

### **Automated Backup Management**

#### **Retention Policy Management**
```bash
# Default retention policies (configured during setup):
Database Backups: 30 days (configurable via BACKUP_KEEP_DB)
Full System Backups: 8 weeks (configurable via BACKUP_KEEP_FULL)
Emergency Backups: 90 days (manual cleanup)
Migration Backups: Indefinite (manual cleanup)

# View current retention settings
jq -r '.BACKUP_KEEP_DB, .BACKUP_KEEP_FULL' settings.json

# Custom retention policy
sudo jq '.BACKUP_KEEP_DB = 45 | .BACKUP_KEEP_FULL = 12' settings.json > temp.json
sudo mv temp.json settings.json

# Manual cleanup with custom retention
find /var/lib/*/backups/db -name "*.backup" -mtime +45 -delete
find /var/lib/*/backups/full -name "*.tar.gz" -mtime +84 -delete
```

#### **Backup Space Management**
```bash
# Monitor backup storage usage
./tools/monitor.sh --backup-space

# Expected output:
📊 Backup Storage Analysis

Location: /var/lib/vaultwarden-oci-minimal/backups/
Total Size: 45.2MB
Available Space: 12.3GB (99.6% free)

Database Backups (db/):
- Count: 30 files
- Size: 25.1MB (avg: 837KB per backup)
- Oldest: 28 days ago
- Growth: +28KB/day average

Full Backups (full/):
- Count: 8 files  
- Size: 20.1MB (avg: 2.5MB per backup)
- Oldest: 56 days ago
- Growth: +2.1MB/week average

Recommendations:
✅ Storage usage healthy
✅ Growth rate sustainable
✅ Retention policy appropriate
⚠️  Consider off-site storage for disaster recovery
```

#### **Backup Health Monitoring**
```bash
# Automated backup health checks (via cron)
30 1 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/restore.sh --verify-recent 2>&1 | logger -t backup-verify

# Manual backup health assessment
./tools/create-full-backup.sh --health-check

# Backup system diagnostics
./tools/monitor.sh --backup-diagnostics

# Expected diagnostics output:
🏥 Backup System Health Diagnostics

Backup Schedule Status:
✅ Daily database backup: Active (next in 6h 23m)
✅ Weekly full backup: Active (next in 2d 6h 23m)  
✅ Backup verification: Active (last run 30m ago)
✅ Cleanup job: Active (last run 4h 30m ago)

Recent Backup Activity:
✅ Last database backup: 23h ago (success)
✅ Last full backup: 6d 23h ago (success)
✅ Last verification: 30m ago (15 backups verified)
✅ Last cleanup: 4h 30m ago (2 old files removed)

Backup Quality Metrics:
✅ Success rate (30 days): 100% (30/30)
✅ Average backup time: 18 seconds
✅ Average backup size: 892KB (database)
✅ Compression ratio: 71% average
✅ Verification success rate: 100%

Storage Health:
✅ Backup directory accessible
✅ Sufficient disk space (12.3GB available)
✅ No filesystem errors detected
✅ Backup permissions secure (700)

Issues Found: None
Recommendations: Consider implementing off-site backup storage
```

### **Off-Site Backup Integration**

#### **Cloud Storage Integration**
```bash
# The backup system creates local encrypted backups
# For off-site storage, use standard cloud sync tools:

# Example: Rclone integration for cloud storage
# 1. Install rclone
sudo apt install rclone

# 2. Configure cloud provider (interactive)
rclone config

# 3. Create off-site sync script
cat > /opt/VaultWarden-OCI-Minimal/tools/offsite-sync.sh << 'EOF'
#!/bin/bash
# Sync backups to cloud storage
BACKUP_DIR="/var/lib/$(basename $(pwd))/backups"
CLOUD_REMOTE="mycloud:vaultwarden-backups"

# Sync recent backups only (last 7 days)
rclone sync "$BACKUP_DIR" "$CLOUD_REMOTE" \
  --max-age 7d \
  --progress \
  --log-file /var/log/offsite-backup.log

# Verify cloud backup integrity
rclone check "$BACKUP_DIR" "$CLOUD_REMOTE" \
  --max-age 7d \
  --one-way
EOF

chmod +x /opt/VaultWarden-OCI-Minimal/tools/offsite-sync.sh

# 4. Add to cron (daily off-site sync)
echo "0 6 * * * root /opt/VaultWarden-OCI-Minimal/tools/offsite-sync.sh" >> /etc/crontab
```

#### **Backup Testing and Validation**
```bash
# Regular backup testing procedures (monthly recommended)

# 1. Complete backup verification
./tools/restore.sh --verify-all

# 2. Test restoration to temporary environment
mkdir -p /tmp/restore-test
./tools/restore.sh --target-dir /tmp/restore-test --test-mode /path/to/recent/backup

# 3. Cross-server restoration test
# Transfer backup to test server and perform full restoration

# 4. Data integrity verification
./tools/restore.sh --data-integrity-check /path/to/backup

# 5. Performance testing
./tools/restore.sh --performance-test /path/to/backup

# 6. Document test results
./tools/create-backup-test-report.sh
```

This comprehensive backup and restore system ensures your VaultWarden data is protected with enterprise-grade reliability while maintaining simplicity for small team operations."""
