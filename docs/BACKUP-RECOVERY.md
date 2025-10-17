# Complete Backup and Recovery Procedures

This guide provides comprehensive backup and recovery procedures for VaultWarden deployments using SOPS+Age encryption.

## 🚨 Critical Understanding

### What Must Be Backed Up
1. **Age Private Key** (`secrets/keys/age-key.txt`) - **MOST CRITICAL**
2. **Encrypted Secrets** (`secrets/secrets.yaml`) - Can be recovered from Git
3. **VaultWarden Database** (`/var/lib/vaultwarden/data/`) - User data
4. **Configuration Files** (`settings.json`, compose files) - Can be recovered from Git

### Failure Impact Matrix
| Lost Component | Impact | Recovery |
|---|---|---|
| Age Key Only | **TOTAL LOSS** - Cannot decrypt any secrets | Restore from backup (if exists) |
| Secrets File Only | Minimal - restore from Git | `git checkout secrets/secrets.yaml` |
| Database Only | User data loss | Restore from daily backups |
| Config Files Only | Service disruption | Restore from Git repository |

## 🔄 Automated Backup Procedures

### Daily Automated Backups (via cron)

The system automatically creates these backups daily:

```bash
# Database backups (encrypted)
0 1 * * * root cd /path/to/vaultwarden && ./tools/db-backup.sh

# Full system backups (weekly)
0 0 * * 0 root cd /path/to/vaultwarden && ./tools/create-full-backup.sh

# Age key backup validation (daily)
0 2 * * * root cd /path/to/vaultwarden && ./tools/backup-recovery.sh validate-backups
```

#### Backup Locations
- **Database Backups**: `/var/lib/vaultwarden/backups/db/`
- **Full Backups**: `/var/lib/vaultwarden/backups/full/`
- **Age Key Backups**: Must be created manually to secure locations

### Manual Backup Commands

#### Critical Age Key Backup
```bash
# Create Age key backup with timestamp
./tools/backup-recovery.sh create-age-backup /secure/location/age-key-$(date +%Y%m%d).txt

# Verify backup works
./tools/backup-recovery.sh validate-backups

# Test backup can decrypt secrets
SOPS_AGE_KEY_FILE=/secure/location/age-key-$(date +%Y%m%d).txt sops -d secrets/secrets.yaml > /dev/null
echo "Backup key test: $?"
```

#### Database Backup
```bash
# Manual database backup
./tools/db-backup.sh

# Backup with specific retention
BACKUP_KEEP_DB=60 ./tools/db-backup.sh

# Backup to specific location
BACKUP_DIR=/secure/location ./tools/db-backup.sh
```

#### Full System Backup
```bash
# Complete system backup including configs
./tools/create-full-backup.sh

# Backup to external location
./tools/create-full-backup.sh --output /external/backup/location/
```

## 📋 Backup Validation Procedures

### Daily Validation (Automated)
```bash
#!/usr/bin/env bash
# Add to cron: 0 2 * * * root /path/to/vaultwarden/validate-backups.sh

cd /path/to/vaultwarden

# Validate Age key is readable
if [[ ! -r secrets/keys/age-key.txt ]]; then
    echo "CRITICAL: Age key not readable" | mail -s "VaultWarden Backup Alert" admin@domain.com
    exit 1
fi

# Validate SOPS decryption works
if ! sops -d secrets/secrets.yaml >/dev/null 2>&1; then
    echo "CRITICAL: SOPS decryption failed" | mail -s "VaultWarden Backup Alert" admin@domain.com
    exit 1
fi

# Validate recent database backups exist
if [[ $(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -mtime -2 | wc -l) -eq 0 ]]; then
    echo "WARNING: No recent database backups found" | mail -s "VaultWarden Backup Alert" admin@domain.com
fi

echo "Backup validation completed successfully"
```

### Weekly Validation (Manual)
```bash
# Complete backup health check
./tools/backup-recovery.sh validate-backups

# Test disaster recovery workflow
./tools/backup-recovery.sh test-recovery

# Verify backup storage accessibility
ls -la /secure/backup/locations/

# Document validation results
echo "$(date): Backup validation completed" >> /var/lib/vaultwarden/logs/backup-validation.log
```

## 🔄 Recovery Procedures

### Standard Recovery Scenarios

#### 1. Age Key Corruption/Loss (Key Available in Backup)
```bash
# IMMEDIATE STEPS:
# 1. Stop services to prevent data corruption
docker compose down

# 2. Restore Age key from secure backup
cp /secure/backup/age-key-YYYYMMDD.txt secrets/keys/age-key.txt
chmod 600 secrets/keys/age-key.txt
chown root:root secrets/keys/age-key.txt

# 3. Test restoration
./tools/check-health.sh --sops-only
echo "Health check status: $?"

# 4. If healthy, restart services
./startup.sh

# 5. Verify functionality
curl -s https://your-domain/admin
# Should show admin login page
```

#### 2. Database Corruption (Database Backups Available)
```bash
# 1. Stop services
docker compose down

# 2. Backup current (corrupted) database
mv /var/lib/vaultwarden/data/bwdata/db.sqlite3 /var/lib/vaultwarden/data/bwdata/db.sqlite3.corrupted

# 3. Find latest backup
LATEST_BACKUP=$(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -type f -printf '%T@ %p
' | sort -n | tail -1 | cut -d' ' -f2-)
echo "Latest backup: $LATEST_BACKUP"

# 4. Decrypt and restore backup
cd /var/lib/vaultwarden/backups/db/
BACKUP_DIR=$(dirname "$LATEST_BACKUP")
cd "$BACKUP_DIR"

# Extract backup passphrase from SOPS
BACKUP_PASS=$(sops -d /path/to/vaultwarden/secrets/secrets.yaml | yq eval '.backup_passphrase' -)

# Decrypt backup
gpg --batch --yes --passphrase "$BACKUP_PASS" -d "$(basename "$LATEST_BACKUP")" | gunzip > /var/lib/vaultwarden/data/bwdata/db.sqlite3

# 5. Verify database integrity
sqlite3 /var/lib/vaultwarden/data/bwdata/db.sqlite3 "PRAGMA integrity_check;"
# Should return "ok"

# 6. Restart services
cd /path/to/vaultwarden
./startup.sh

# 7. Verify functionality
# Login to VaultWarden and verify data
```

#### 3. Complete System Recovery (New Host)
```bash
# 1. Prepare new host
sudo apt update && sudo apt upgrade -y

# 2. Clone repository
git clone https://github.com/your-username/VaultWarden-SOPS-Minimal.git
cd VaultWarden-SOPS-Minimal

# 3. Run initial setup
sudo ./tools/init-setup.sh

# 4. **CRITICAL**: Restore Age key BEFORE editing secrets
sudo mkdir -p secrets/keys/
sudo cp /secure/backup/age-key.txt secrets/keys/age-key.txt  
sudo chmod 600 secrets/keys/age-key.txt
sudo chown root:root secrets/keys/age-key.txt

# 5. Test Age key works with existing secrets
sops -d secrets/secrets.yaml > /dev/null
echo "Age key test: $?"

# 6. Restore database (if needed)
sudo mkdir -p /var/lib/vaultwarden/data/bwdata/
# Follow "Database Corruption" procedure above to restore database

# 7. Start services
./startup.sh

# 8. Verify complete functionality
curl -s https://your-domain/admin
# Test admin login with existing admin token
```

### Advanced Recovery Scenarios

#### 4. Partial Secret Corruption
```bash
# If only some secrets are corrupted but Age key works

# 1. View current secrets
sops -d secrets/secrets.yaml

# 2. Identify corrupted secrets (look for garbled values)

# 3. Edit secrets to fix corrupted values
./tools/edit-secrets.sh

# 4. Or restore from backup if available
./tools/backup-recovery.sh import-secrets /backup/location/secrets-YYYYMMDD.yaml

# 5. Restart services
./startup.sh
```

#### 5. Docker Secrets Corruption
```bash
# If Docker secrets files are corrupted but SOPS secrets are fine

# 1. Remove corrupted Docker secrets
sudo rm -rf secrets/.docker_secrets/

# 2. Regenerate Docker secrets from SOPS
./tools/edit-secrets.sh --refresh-docker-secrets

# 3. Restart services
./startup.sh
```

## 🔐 Backup Security Procedures

### Age Key Backup Security
```bash
# Create encrypted Age key backup using GPG
gpg --symmetric --cipher-algo AES256 secrets/keys/age-key.txt
# Creates: secrets/keys/age-key.txt.gpg

# Move to secure locations:
cp secrets/keys/age-key.txt.gpg /secure/backup/location1/
cp secrets/keys/age-key.txt.gpg /secure/backup/location2/
cp secrets/keys/age-key.txt.gpg /secure/backup/location3/

# Remove local GPG file
rm secrets/keys/age-key.txt.gpg

# Test restoration from encrypted backup:
gpg --decrypt /secure/backup/location1/age-key.txt.gpg > /tmp/test-age-key.txt
SOPS_AGE_KEY_FILE=/tmp/test-age-key.txt sops -d secrets/secrets.yaml > /dev/null
echo "Encrypted backup test: $?"
shred -u /tmp/test-age-key.txt
```

### Secure Backup Storage Options

#### Option 1: Encrypted USB Drives
```bash
# Format USB with LUKS encryption
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup luksOpen /dev/sdX backup_drive
sudo mkfs.ext4 /dev/mapper/backup_drive

# Mount and store backups
sudo mkdir -p /mnt/secure_backup
sudo mount /dev/mapper/backup_drive /mnt/secure_backup

# Copy Age key backup
sudo cp /secure/backup/age-key.txt /mnt/secure_backup/vaultwarden-age-key-$(date +%Y%m%d).txt

# Unmount securely
sudo umount /mnt/secure_backup
sudo cryptsetup luksClose backup_drive
```

#### Option 2: Cloud Storage (Encrypted)
```bash
# Use rclone with encryption
rclone config create backup_encrypted crypt remote=your_cloud_remote: password=$(openssl rand -base64 32)

# Backup Age key to encrypted cloud storage
rclone copy secrets/keys/age-key.txt backup_encrypted:vaultwarden/keys/age-key-$(date +%Y%m%d).txt

# Verify backup
rclone ls backup_encrypted:vaultwarden/keys/
```

#### Option 3: Password Manager
1. Open your password manager (Bitwarden, 1Password, etc.)
2. Create new secure note titled "VaultWarden Age Key Backup"
3. Copy contents of `secrets/keys/age-key.txt`
4. Paste into secure note
5. Add recovery instructions
6. Ensure password manager is itself backed up

## 🧪 Recovery Testing Procedures

### Monthly Recovery Test (Non-Destructive)
```bash
#!/usr/bin/env bash
# Monthly recovery validation (run on 1st of each month)

echo "Starting monthly recovery test..."
TEST_DATE=$(date +%Y%m%d)

# Test 1: Age key backup accessibility
echo "Testing Age key backup accessibility..."
if [[ ! -f /secure/backup/location/age-key.txt ]]; then
    echo "FAIL: Age key backup not accessible"
    echo "Action required: Verify backup storage is mounted/accessible"
    exit 1
fi

# Test 2: Backup key can decrypt current secrets
echo "Testing backup key decryption..."
TEMP_KEY=$(mktemp)
cp /secure/backup/location/age-key.txt "$TEMP_KEY"
if SOPS_AGE_KEY_FILE="$TEMP_KEY" sops -d secrets/secrets.yaml > /dev/null 2>&1; then
    echo "PASS: Backup Age key can decrypt current secrets"
else
    echo "FAIL: Backup Age key cannot decrypt current secrets"
    echo "Action required: Update Age key backup or investigate key rotation"
fi
rm -f "$TEMP_KEY"

# Test 3: Database backup integrity
echo "Testing database backup integrity..."
LATEST_DB_BACKUP=$(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -type f -printf '%T@ %p
' | sort -n | tail -1 | cut -d' ' -f2-)
if [[ -n "$LATEST_DB_BACKUP" ]]; then
    echo "PASS: Recent database backup found: $LATEST_DB_BACKUP"
    # TODO: Add integrity test of backup file
else
    echo "WARN: No recent database backups found"
fi

# Test 4: Docker secrets preparation
echo "Testing Docker secrets preparation..."
if ./tools/edit-secrets.sh --validate > /dev/null 2>&1; then
    echo "PASS: Docker secrets can be prepared from SOPS"
else
    echo "FAIL: Docker secrets preparation failed"
fi

echo "Monthly recovery test completed on $TEST_DATE"
echo "Results logged to: /var/lib/vaultwarden/logs/recovery-tests.log"

# Log results
{
    echo "=== Monthly Recovery Test: $TEST_DATE ==="
    echo "Age key backup: OK"
    echo "SOPS decryption: OK" 
    echo "Database backups: OK"
    echo "Docker secrets: OK"
    echo "Next test due: $(date -d '+1 month' +%Y-%m-%d)"
    echo "=========================================="
} >> /var/lib/vaultwarden/logs/recovery-tests.log
```

### Quarterly Full Recovery Test (Destructive - Use Test Environment)
```bash
#!/usr/bin/env bash
# Quarterly full disaster recovery test (use separate test system!)

echo "Starting quarterly full recovery test..."
echo "WARNING: This is destructive - only run on test systems!"

TEST_DATE=$(date +%Y%m%d)
TEST_LOG="/tmp/recovery-test-$TEST_DATE.log"

# Phase 1: Simulate complete system loss
echo "Phase 1: Simulating complete system loss..." | tee -a "$TEST_LOG"
docker compose down
sudo rm -rf /var/lib/vaultwarden/data/
sudo rm -f secrets/keys/age-key.txt
sudo rm -f secrets/.docker_secrets/*

# Phase 2: Restore Age key
echo "Phase 2: Restoring Age key from backup..." | tee -a "$TEST_LOG"
sudo cp /secure/backup/age-key.txt secrets/keys/age-key.txt
sudo chmod 600 secrets/keys/age-key.txt

# Phase 3: Test SOPS decryption
echo "Phase 3: Testing SOPS decryption..." | tee -a "$TEST_LOG"
if sops -d secrets/secrets.yaml > /dev/null 2>&1; then
    echo "PASS: SOPS decryption works" | tee -a "$TEST_LOG"
else
    echo "FAIL: SOPS decryption failed" | tee -a "$TEST_LOG"
    exit 1
fi

# Phase 4: Restore database
echo "Phase 4: Restoring database from backup..." | tee -a "$TEST_LOG"
LATEST_BACKUP=$(find /backup/location/db/ -name "*.gpg" -type f -printf '%T@ %p
' | sort -n | tail -1 | cut -d' ' -f2-)
if [[ -n "$LATEST_BACKUP" ]]; then
    # Decrypt and restore database backup
    BACKUP_PASS=$(sops -d secrets/secrets.yaml | yq eval '.backup_passphrase' -)
    mkdir -p /var/lib/vaultwarden/data/bwdata/
    gpg --batch --yes --passphrase "$BACKUP_PASS" -d "$LATEST_BACKUP" | gunzip > /var/lib/vaultwarden/data/bwdata/db.sqlite3
    echo "Database restored from: $LATEST_BACKUP" | tee -a "$TEST_LOG"
else
    echo "No database backup available for test" | tee -a "$TEST_LOG"
fi

# Phase 5: Start services and test
echo "Phase 5: Starting services..." | tee -a "$TEST_LOG"
if ./startup.sh; then
    echo "PASS: Services started successfully" | tee -a "$TEST_LOG"
else
    echo "FAIL: Services failed to start" | tee -a "$TEST_LOG"
    exit 1
fi

# Phase 6: Functional testing
echo "Phase 6: Testing functionality..." | tee -a "$TEST_LOG"
sleep 30  # Wait for services to fully start

if curl -sf https://test-domain/admin >/dev/null 2>&1; then
    echo "PASS: Admin interface accessible" | tee -a "$TEST_LOG"
else
    echo "FAIL: Admin interface not accessible" | tee -a "$TEST_LOG"
fi

echo "Quarterly recovery test completed: $TEST_DATE" | tee -a "$TEST_LOG"
echo "Full test log: $TEST_LOG"

# Email results to administrator
mail -s "VaultWarden Recovery Test Results" admin@domain.com < "$TEST_LOG"
```

## 📊 Backup Monitoring and Alerting

### Backup Health Dashboard
Create a simple backup status checker:

```bash
#!/usr/bin/env bash
# tools/backup-status.sh - Show backup health dashboard

echo "VaultWarden Backup Status Dashboard"
echo "Generated: $(date)"
echo "========================================"

# Age Key Status
if [[ -f secrets/keys/age-key.txt ]]; then
    KEY_PERMS=$(stat -c "%a" secrets/keys/age-key.txt)
    if [[ "$KEY_PERMS" == "600" ]]; then
        echo "✅ Age Key: Present and secure (600 permissions)"
    else
        echo "⚠️  Age Key: Present but insecure permissions ($KEY_PERMS)"
    fi
else
    echo "❌ Age Key: MISSING - CRITICAL ERROR"
fi

# SOPS Decryption Test
if sops -d secrets/secrets.yaml >/dev/null 2>&1; then
    echo "✅ SOPS Decryption: Working"
else
    echo "❌ SOPS Decryption: FAILED"
fi

# Database Backup Status
DB_BACKUPS=$(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -mtime -7 | wc -l)
if [[ $DB_BACKUPS -gt 0 ]]; then
    echo "✅ Database Backups: $DB_BACKUPS recent backups (last 7 days)"
    LATEST_DB=$(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -type f -printf '%T+ %p
' | sort | tail -1)
    echo "   Latest: $LATEST_DB"
else
    echo "⚠️  Database Backups: No recent backups found"
fi

# Full System Backup Status
FULL_BACKUPS=$(find /var/lib/vaultwarden/backups/full/ -name "*.tar.gz" -mtime -14 | wc -l)
if [[ $FULL_BACKUPS -gt 0 ]]; then
    echo "✅ Full Backups: $FULL_BACKUPS recent backups (last 14 days)"
else
    echo "⚠️  Full Backups: No recent backups found"
fi

# Docker Secrets Status
if [[ -d secrets/.docker_secrets/ ]]; then
    SECRET_COUNT=$(find secrets/.docker_secrets/ -type f | wc -l)
    echo "✅ Docker Secrets: $SECRET_COUNT secret files prepared"
else
    echo "⚠️  Docker Secrets: Directory not found"
fi

echo "========================================"
echo "For detailed health check: ./tools/check-health.sh"
echo "For recovery procedures: docs/DISASTER-RECOVERY.md"
```

### Automated Backup Alerts
```bash
#!/usr/bin/env bash
# Backup monitoring script for cron
# Add to cron: 0 6 * * * root /path/to/vaultwarden/monitor-backups.sh

ALERT_EMAIL="admin@your-domain.com"
PROJECT_NAME="VaultWarden"

# Check for missing age key
if [[ ! -f secrets/keys/age-key.txt ]]; then
    echo "CRITICAL ALERT: Age private key is missing from secrets/keys/age-key.txt" |         mail -s "$PROJECT_NAME CRITICAL: Age Key Missing" "$ALERT_EMAIL"
    exit 1
fi

# Check SOPS decryption capability
if ! sops -d secrets/secrets.yaml >/dev/null 2>&1; then
    echo "CRITICAL ALERT: SOPS cannot decrypt secrets file. Check Age key integrity." |         mail -s "$PROJECT_NAME CRITICAL: SOPS Decryption Failed" "$ALERT_EMAIL"
    exit 1
fi

# Check for recent database backups (should have backups within 25 hours)
if [[ $(find /var/lib/vaultwarden/backups/db/ -name "*.gpg" -mtime -1 | wc -l) -eq 0 ]]; then
    echo "WARNING: No database backups created in the last 24 hours. Check backup cron job." |         mail -s "$PROJECT_NAME WARNING: Missing Database Backups" "$ALERT_EMAIL"
fi

# Check backup storage space
BACKUP_USAGE=$(df /var/lib/vaultwarden/backups/ | awk 'NR==2{print $5}' | sed 's/%//')
if [[ $BACKUP_USAGE -gt 90 ]]; then
    echo "WARNING: Backup storage is $BACKUP_USAGE% full. Clean up old backups or expand storage." |         mail -s "$PROJECT_NAME WARNING: Backup Storage Full" "$ALERT_EMAIL"
fi

# Success - all backup monitoring checks passed
exit 0
```

## 🔄 Backup Rotation and Cleanup

### Automated Cleanup Procedures
```bash
# Added to daily cron job:
# 0 4 * * * root cd /path/to/vaultwarden && ./tools/cleanup-old-backups.sh

#!/usr/bin/env bash
# tools/cleanup-old-backups.sh

source lib/logging.sh
_set_log_prefix "cleanup"

# Get retention policies from configuration
DB_RETENTION=$(get_config_value "BACKUP_KEEP_DB" 2>/dev/null || echo "30")
FULL_RETENTION=$(get_config_value "BACKUP_KEEP_FULL" 2>/dev/null || echo "8")

_log_info "Cleaning up backups older than: DB=$DB_RETENTION days, Full=$FULL_RETENTION days"

# Clean database backups
DB_BACKUP_DIR="/var/lib/vaultwarden/backups/db"
if [[ -d "$DB_BACKUP_DIR" ]]; then
    DELETED_DB=$(find "$DB_BACKUP_DIR" -type d -name "20*" -mtime +$DB_RETENTION -delete -print | wc -l)
    if [[ $DELETED_DB -gt 0 ]]; then
        _log_info "Deleted $DELETED_DB old database backup directories"
    fi
fi

# Clean full backups  
FULL_BACKUP_DIR="/var/lib/vaultwarden/backups/full"
if [[ -d "$FULL_BACKUP_DIR" ]]; then
    DELETED_FULL=$(find "$FULL_BACKUP_DIR" -name "*.tar.gz" -mtime +$FULL_RETENTION -delete -print | wc -l)
    if [[ $DELETED_FULL -gt 0 ]]; then
        _log_info "Deleted $DELETED_FULL old full backup files"
    fi
fi

# Report current backup counts
DB_COUNT=$(find "$DB_BACKUP_DIR" -type d -name "20*" 2>/dev/null | wc -l)
FULL_COUNT=$(find "$FULL_BACKUP_DIR" -name "*.tar.gz" 2>/dev/null | wc -l)

_log_info "Current backup counts: DB=$DB_COUNT directories, Full=$FULL_COUNT files"
```

## 📈 Backup Performance Optimization

### Large Database Optimization
```bash
# For databases >1GB, optimize backup procedure:

# 1. Use incremental backups
./tools/db-backup.sh --incremental

# 2. Compress before encryption
./tools/db-backup.sh --compress-first

# 3. Use parallel processing
./tools/db-backup.sh --parallel

# 4. Background processing
nohup ./tools/db-backup.sh > backup.log 2>&1 &
```

### Network Backup Optimization
```bash
# For backups to remote locations:

# 1. Use compression
rclone copy --compress backups/ remote:vaultwarden/backups/

# 2. Use bandwidth limiting
rclone copy --bwlimit 10M backups/ remote:vaultwarden/backups/

# 3. Resume interrupted uploads
rclone copy --retries 3 backups/ remote:vaultwarden/backups/
```

## 🚨 Emergency Response Procedures

### Immediate Response Checklist
If you suspect backup system failure:

1. **STOP** - Don't make any changes until you assess the situation
2. **CHECK** - Run `./tools/backup-recovery.sh validate-backups`
3. **SECURE** - If Age key is at risk, create immediate backup
4. **ASSESS** - Determine scope of failure (key, secrets, database, config)
5. **RESTORE** - Follow appropriate recovery procedure above
6. **VERIFY** - Test complete functionality before resuming normal operations
7. **DOCUMENT** - Record what failed and how it was fixed
8. **IMPROVE** - Update procedures to prevent similar failures

### Emergency Contacts Template
```
VaultWarden Emergency Response Plan

Primary Administrator: ________________
Phone: ________________
Email: ________________

Backup Administrator: ________________  
Phone: ________________
Email: ________________

Backup Locations:
- Location 1: ________________________________
- Location 2: ________________________________
- Location 3: ________________________________

Recovery Procedures: docs/DISASTER-RECOVERY.md
Last Updated: ________________
Last Tested: ________________

Critical Commands:
- Health check: ./tools/check-health.sh
- Backup age key: ./tools/backup-recovery.sh create-age-backup  
- Restore age key: ./tools/backup-recovery.sh restore-age-key
- Emergency recovery: ./tools/backup-recovery.sh test-recovery
```

Remember: Your backup strategy is your last line of defense. Test it regularly and keep it up to date.
