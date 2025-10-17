# Backup and Recovery Guide

This comprehensive guide covers backup strategies, recovery procedures, and disaster recovery planning for the VaultWarden-OCI-NG stack.

## Backup Strategy Overview

### Multi-Tier Backup Architecture
The VaultWarden-OCI-NG stack implements a comprehensive backup strategy with multiple tiers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Backup Tier Structure                    │
├─────────────────────────────────────────────────────────────┤
│ Tier 1: Real-time Protection                              │
│   • SQLite WAL (Write-Ahead Logging) mode                 │
│   • Immediate data durability                             │
│   • Transaction-level recovery capability                 │
├─────────────────────────────────────────────────────────────┤
│ Tier 2: Daily Automated Backups                           │
│   • Encrypted database dumps                              │
│   • 30-day retention policy                               │
│   • Integrity verification included                       │
├─────────────────────────────────────────────────────────────┤
│ Tier 3: Weekly Full System Backups                        │
│   • Complete system state capture                         │
│   • Configuration and certificates                        │
│   • 8-week retention policy                               │
├─────────────────────────────────────────────────────────────┤
│ Tier 4: Manual/Off-site Backups                           │
│   • On-demand backup creation                             │
│   • Cloud storage integration                             │
│   • Long-term archival storage                            │
└─────────────────────────────────────────────────────────────┘
```

### Backup Principles
- **Encryption First**: All backups encrypted with AES-256
- **Verification Required**: Every backup includes integrity checks
- **Automated Scheduling**: Minimal manual intervention required
- **Multiple Recovery Points**: Various granularity options
- **Secure Storage**: Backups protected with same security as live data

## Automated Backup System

### Backup Schedule Configuration
The init-setup script automatically configures the backup schedule:

```bash
# View current backup schedule
crontab -l | grep backup

# Expected automated schedule:
# 0 2 * * *   Daily database backup at 2:00 AM
# 0 3 * * 0   Weekly full backup every Sunday at 3:00 AM
# 0 1 * * 6   Weekly database maintenance on Saturday at 1:00 AM
```

### Daily Database Backups

#### Automated Database Backup Process
```bash
# Manual database backup (same process as automated)
./tools/db-backup.sh

# Backup process includes:
# 1. Database integrity verification
# 2. Consistent backup creation (no corruption risk)
# 3. AES-256 encryption with backup passphrase
# 4. Compression for storage efficiency
# 5. Automatic cleanup of old backups
```

#### Database Backup Configuration
```bash
# View database backup settings
grep -E "(BACKUP_KEEP_DB|backup)" settings.env.example

# Default settings:
# BACKUP_KEEP_DB=30          # Keep 30 days of database backups
# Backup location: $PROJECT_STATE_DIR/backups/daily/
# Encryption: AES-256-CBC with backup_passphrase from secrets
```

#### Database Backup Format
```bash
# Backup file naming convention
db-backup-YYYYMMDD-HHMMSS.sqlite3.enc

# Example files:
db-backup-20241016-020001.sqlite3.enc
db-backup-20241015-020001.sqlite3.enc
db-backup-20241014-020001.sqlite3.enc
```

### Weekly Full System Backups

#### Comprehensive System Backup
```bash
# Manual full system backup
./tools/create-full-backup.sh

# Full backup includes:
# • VaultWarden database and attachments
# • Configuration files (settings.json)
# • SSL certificates and private keys
# • Docker Compose configuration
# • Log files (optional)
# • Service configurations (Caddy, Fail2ban)
```

#### Full Backup Configuration
```bash
# Full backup options
./tools/create-full-backup.sh --help

# Available options:
--output-dir PATH       # Custom backup destination
--compression LEVEL     # Compression level (1-9, default: 6)
--exclude-logs         # Skip log files in backup
--dry-run              # Preview backup contents
```

#### Full Backup Format
```bash
# Full backup file naming
backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# Backup contents structure:
backup-full-20241016-030001.tar.gz.enc
├── data/bwdata/           # VaultWarden database and attachments
├── settings.json          # Configuration file
├── caddy_data/           # SSL certificates
├── caddy_config/         # Caddy runtime configuration
├── secrets/              # Encrypted secrets (keys excluded)
├── docker-compose.yml    # Service configuration
└── logs/                 # Service logs (if included)
```

## Manual Backup Operations

### On-Demand Backup Creation

#### Database-Only Backup
```bash
# Create immediate database backup
./tools/db-backup.sh

# Custom database backup location
./tools/db-backup.sh --output-dir /custom/backup/path/

# Database backup with custom retention
./tools/db-backup.sh --retention-days 60

# Test backup creation (dry run)
./tools/db-backup.sh --dry-run
```

#### Full System Backup
```bash
# Create immediate full system backup
./tools/create-full-backup.sh

# Full backup excluding logs (faster, smaller)
./tools/create-full-backup.sh --exclude-logs

# Full backup with maximum compression
./tools/create-full-backup.sh --compression 9

# Custom backup location
./tools/create-full-backup.sh --output-dir /external/storage/
```

### Pre-Maintenance Backups
```bash
# Create backup before system changes
echo "Creating pre-maintenance backup..."
./tools/create-full-backup.sh --output-dir /tmp/pre-maintenance/

# Verify backup before proceeding
./tools/restore.sh --verify /tmp/pre-maintenance/backup-full-*.tar.gz.enc

# Proceed with maintenance only if backup verified
if [ $? -eq 0 ]; then
    echo "Backup verified. Proceeding with maintenance."
    # Perform maintenance tasks
else
    echo "Backup verification failed. Aborting maintenance."
    exit 1
fi
```

## Backup Security and Encryption

### Encryption Implementation

#### Backup Encryption Details
- **Algorithm**: AES-256-CBC (Advanced Encryption Standard)
- **Key Derivation**: PBKDF2 with SHA-256
- **Key Source**: `backup_passphrase` from encrypted secrets
- **IV Generation**: Cryptographically secure random initialization vectors
- **Authentication**: HMAC verification for integrity

#### Managing Backup Passphrases
```bash
# View current backup passphrase
sudo ./tools/edit-secrets.sh --view | grep backup_passphrase

# Update backup passphrase (affects new backups only)
sudo ./tools/edit-secrets.sh
# Update backup_passphrase value

# Important: Keep old passphrases to access existing backups
# Document passphrase changes with dates for backup access
```

### Backup Storage Security

#### Local Storage Security
```bash
# Verify backup directory permissions
ls -la $PROJECT_STATE_DIR/backups/
# Should show 755 permissions (readable by owner and group)

# Individual backup file permissions
ls -la $PROJECT_STATE_DIR/backups/daily/*.enc
# Should show 644 permissions (readable by owner)

# Secure backup directory (if needed)
chmod 755 $PROJECT_STATE_DIR/backups/
find $PROJECT_STATE_DIR/backups/ -name "*.enc" -exec chmod 644 {} \;
```

#### Off-site Backup Security
```bash
# Example: Secure cloud storage upload
# Using rclone for encrypted cloud storage

# Configure rclone with encryption (one-time setup)
rclone config create backup-encrypted crypt \
  remote=your-cloud-storage: \
  filename_encryption=standard \
  directory_name_encryption=true \
  password=$(echo "$BACKUP_PASSPHRASE" | base64)

# Upload backups to encrypted cloud storage
rclone copy $PROJECT_STATE_DIR/backups/ backup-encrypted:vaultwarden-backups/ \
  --transfers 1 --checkers 1 --bwlimit 10M
```

## Recovery Procedures

### Database Recovery

#### Database-Only Recovery
```bash
# List available database backups
./tools/restore.sh --list

# Verify database backup integrity
./tools/restore.sh --verify /path/to/db-backup-YYYYMMDD-HHMMSS.sqlite3.enc

# Restore database only (preserves configuration)
./tools/restore.sh --database-only /path/to/db-backup-YYYYMMDD-HHMMSS.sqlite3.enc

# Recovery process:
# 1. Stops VaultWarden service
# 2. Backs up current database
# 3. Decrypts and restores backup
# 4. Verifies database integrity
# 5. Restarts VaultWarden service
```

#### Database Recovery Verification
```bash
# After database recovery, verify integrity
./tools/sqlite-maintenance.sh --check

# Verify user data accessibility
./tools/check-health.sh

# Test user authentication
curl -X POST https://your-domain.com/identity/accounts/prelogin \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

### Full System Recovery

#### Complete System Recovery
```bash
# List available full system backups
./tools/restore.sh --list

# Verify full backup integrity before recovery
./tools/restore.sh --verify /path/to/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# Perform complete system recovery
./tools/restore.sh /path/to/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# Full recovery process:
# 1. Stops all services
# 2. Creates current state backup
# 3. Extracts backup contents
# 4. Restores all components
# 5. Verifies system integrity
# 6. Restarts services
# 7. Performs health checks
```

#### Post-Recovery Verification
```bash
# Comprehensive post-recovery verification
./tools/check-health.sh --verbose

# Service status verification
docker compose ps

# Configuration integrity check
./startup.sh --validate

# SSL certificate verification
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# User access verification
curl -I https://your-domain.com
```

### Selective Recovery Options

#### Configuration-Only Recovery
```bash
# Extract only configuration from full backup
./tools/restore.sh --config-only /path/to/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# This restores:
# • settings.json
# • docker-compose.yml
# • Caddy configuration
# • Fail2ban configuration
# But preserves current database
```

#### Certificate Recovery
```bash
# Extract SSL certificates from backup
./tools/restore.sh --certificates-only /path/to/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# Manually extract certificates if needed
openssl enc -d -aes-256-cbc -in backup-full-YYYYMMDD-HHMMSS.tar.gz.enc \
  -pass pass:$BACKUP_PASSPHRASE | \
  tar -xzf - caddy_data/

# Restart Caddy to use restored certificates
docker compose restart caddy
```

## Disaster Recovery Planning

### Recovery Time Objectives (RTO)

#### Target Recovery Times
- **Database Recovery**: < 15 minutes
- **Full System Recovery**: < 30 minutes
- **Service Restoration**: < 5 minutes (after recovery)
- **User Access Restoration**: < 45 minutes total

#### Recovery Scenarios and Procedures

**Scenario 1: Database Corruption**
```bash
# 1. Immediate Response (< 2 minutes)
docker compose stop vaultwarden
cp $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 /tmp/corrupted-db.sqlite3

# 2. Recovery Execution (< 10 minutes)
./tools/restore.sh --database-only /path/to/recent/db-backup.sqlite3.enc

# 3. Verification and Service Restart (< 3 minutes)
./tools/sqlite-maintenance.sh --check
./startup.sh
```

**Scenario 2: Complete Server Failure**
```bash
# 1. New Server Setup (< 15 minutes)
# Deploy fresh Ubuntu 24.04 server
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG
chmod +x startup.sh tools/*.sh lib/*.sh

# 2. Restore Age Keys (< 2 minutes)
# Restore age-key.txt from secure offline storage
sudo mkdir -p secrets/keys/
sudo cp /secure/storage/age-key.txt secrets/keys/
sudo chmod 600 secrets/keys/age-key.txt

# 3. System Recovery (< 10 minutes)
sudo ./tools/init-setup.sh --auto
./tools/restore.sh /path/to/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# 4. Final Verification (< 3 minutes)
./startup.sh
./tools/check-health.sh
```

### Backup Testing and Validation

#### Regular Backup Testing Schedule
- **Weekly**: Verify one random backup file integrity
- **Monthly**: Perform database recovery test (in test environment)
- **Quarterly**: Full disaster recovery simulation

#### Backup Testing Procedures
```bash
# Create backup testing script
cat > tools/test-backups.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

BACKUP_DIR="$PROJECT_STATE_DIR/backups"
TEST_DIR="/tmp/backup-test-$$"

# Test random backup file integrity
random_backup=$(find $BACKUP_DIR -name "*.enc" -type f | shuf -n 1)
if [ -n "$random_backup" ]; then
    _log_info "Testing backup: $(basename $random_backup)"

    if ./tools/restore.sh --verify "$random_backup"; then
        _log_success "Backup integrity verified"
    else
        _log_error "Backup integrity test FAILED: $random_backup"
        exit 1
    fi
else
    _log_warning "No backup files found for testing"
fi

# Test backup decryption (without restoration)
mkdir -p $TEST_DIR
if echo "$BACKUP_PASSPHRASE" | openssl enc -d -aes-256-cbc -in "$random_backup" -pass stdin > $TEST_DIR/test-extract 2>/dev/null; then
    _log_success "Backup decryption successful"
    rm -rf $TEST_DIR
else
    _log_error "Backup decryption FAILED"
    rm -rf $TEST_DIR
    exit 1
fi
EOF

chmod +x tools/test-backups.sh

# Schedule weekly backup testing
echo "0 4 * * 1 /path/to/tools/test-backups.sh >> /var/log/backup-tests.log 2>&1" | crontab -
```

## Advanced Backup Configurations

### Cloud Storage Integration

#### AWS S3 Backup Integration
```bash
# Install AWS CLI
sudo apt install awscli

# Configure AWS credentials
aws configure
# AWS Access Key ID: YOUR_ACCESS_KEY
# AWS Secret Access Key: YOUR_SECRET_KEY
# Default region: us-east-1

# Create S3 backup sync script
cat > tools/s3-backup-sync.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

S3_BUCKET="your-vaultwarden-backups"
BACKUP_DIR="$PROJECT_STATE_DIR/backups"

# Sync backups to S3 with encryption
aws s3 sync $BACKUP_DIR s3://$S3_BUCKET/$(hostname)/ \
    --exclude "*" \
    --include "*.enc" \
    --storage-class STANDARD_IA \
    --delete

if [ $? -eq 0 ]; then
    _log_success "Backup sync to S3 completed"
else
    _log_error "Backup sync to S3 failed"
    exit 1
fi
EOF

chmod +x tools/s3-backup-sync.sh

# Schedule daily S3 sync after backups
echo "30 2 * * * /path/to/tools/s3-backup-sync.sh >> /var/log/s3-sync.log 2>&1" | crontab -
```

#### Google Cloud Storage Integration
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# Create GCS backup sync script
cat > tools/gcs-backup-sync.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

GCS_BUCKET="your-vaultwarden-backups"
BACKUP_DIR="$PROJECT_STATE_DIR/backups"

# Sync to Google Cloud Storage
gsutil -m rsync -r -x ".*\.(?!enc$)" $BACKUP_DIR gs://$GCS_BUCKET/$(hostname)/

if [ $? -eq 0 ]; then
    _log_success "Backup sync to GCS completed"
else
    _log_error "Backup sync to GCS failed"
    exit 1
fi
EOF

chmod +x tools/gcs-backup-sync.sh
```

### PostgreSQL Migration Backup

#### Preparing for PostgreSQL Migration
```bash
# Create PostgreSQL migration backup
cat > tools/postgres-migration-backup.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

BACKUP_DIR="$PROJECT_STATE_DIR/backups/migration"
mkdir -p $BACKUP_DIR

# Stop services
docker compose down

# Create comprehensive migration backup
_log_info "Creating PostgreSQL migration backup..."

# SQLite database export
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 .dump > $BACKUP_DIR/sqlite-dump.sql

# Full system backup
./tools/create-full-backup.sh --output-dir $BACKUP_DIR

# Create migration documentation
cat > $BACKUP_DIR/migration-info.txt << EOL
Migration Backup Created: $(date)
Original Database: SQLite
Target Database: PostgreSQL
SQLite File Size: $(du -h $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 | cut -f1)
User Count: $(echo "SELECT COUNT(*) FROM users;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3)
Vault Items: $(echo "SELECT COUNT(*) FROM cipher;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3)
EOL

_log_success "PostgreSQL migration backup completed"
EOF

chmod +x tools/postgres-migration-backup.sh
```

## Troubleshooting Backup Issues

### Common Backup Problems

#### Backup Creation Failures
```bash
# Diagnose backup creation issues
./tools/create-full-backup.sh --dry-run

# Check available disk space
df -h $PROJECT_STATE_DIR

# Verify backup directory permissions
ls -la $PROJECT_STATE_DIR/backups/

# Test backup encryption
echo "test" | openssl enc -aes-256-cbc -pass pass:test -out /tmp/test.enc
openssl enc -d -aes-256-cbc -pass pass:test -in /tmp/test.enc
rm /tmp/test.enc
```

#### Backup Corruption Issues
```bash
# Test backup file integrity
./tools/restore.sh --verify /path/to/suspected/backup.enc

# Manual backup verification
file /path/to/backup.enc
# Should show: "data" (encrypted file)

# Test decryption without restoration
openssl enc -d -aes-256-cbc -in backup.enc -pass pass:PASSPHRASE | tar -tzf -
```

#### Recovery Failures
```bash
# Diagnose recovery issues
./tools/restore.sh --dry-run /path/to/backup.enc

# Check backup passphrase
sudo ./tools/edit-secrets.sh --view | grep backup_passphrase

# Verify sufficient disk space for recovery
df -h $PROJECT_STATE_DIR

# Manual decryption test
openssl enc -d -aes-256-cbc -in backup.enc -pass pass:PASSPHRASE -out test-extract.tar.gz
tar -tzf test-extract.tar.gz | head -20
rm test-extract.tar.gz
```

This comprehensive backup and recovery guide ensures your VaultWarden-OCI-NG deployment is protected against data loss and provides reliable recovery procedures for various failure scenarios.
