#!/usr/bin/env bash
# backup/backup.sh
# Enhanced Vaultwarden backup script with rclone cloud storage and email notifications
# Works with any rclone-supported cloud provider

# New: Add interactive check for manual runs
if [[ $- == *i* && "$1" != "-n" ]]; then # Check if shell is interactive and no "-n" flag
    read -p "Are you sure you want to run a manual backup now? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        echo "Backup cancelled by user."
        exit 0
    fi
fi

set -e

# Configuration
BACKUP_DIR="/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname)
ARCHIVE_FILENAME="vaultwarden_backup_${HOSTNAME}_${TIMESTAMP}"
TEMP_ARCHIVE="${BACKUP_DIR}/${ARCHIVE_FILENAME}.tar.gz"
ENCRYPTED_ARCHIVE="${BACKUP_DIR}/${ARCHIVE_FILENAME}.tar.gz.gpg"
BACKUP_START_TIME=$(date)

echo "Starting Vaultwarden backup process..."
echo "Start time: $BACKUP_START_TIME"

# Create MySQL dump
echo "Creating database backup..."
mysqldump \
    --host=mariadb \
    --user=root \
    --password="$MARIADB_ROOT_PASSWORD" \
    --single-transaction \
    --routines \
    --triggers \
    "$MARIADB_DATABASE" > "${BACKUP_DIR}/database.sql"

# Create compressed archive
echo "Creating compressed archive..."
tar -czf "$TEMP_ARCHIVE" \
    -C /data . \
    -C "$BACKUP_DIR" database.sql

# Remove temporary database dump
rm "${BACKUP_DIR}/database.sql"

# Encrypt the archive
echo "Encrypting backup archive..."
gpg --batch --yes --cipher-algo AES256 --compress-algo 2 --symmetric \
    --passphrase "$BACKUP_PASSPHRASE" \
    --output "$ENCRYPTED_ARCHIVE" \
    "$TEMP_ARCHIVE"

# Remove unencrypted archive
rm "$TEMP_ARCHIVE"

# Get file size for reporting
BACKUP_SIZE=$(du -h "$ENCRYPTED_ARCHIVE" | cut -f1)
echo "Encrypted backup created: $ENCRYPTED_ARCHIVE ($BACKUP_SIZE)"

# Upload to cloud storage
echo "Uploading backup to ${RCLONE_REMOTE_NAME}..."
REMOTE_PATH="${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_PATH}/${ARCHIVE_FILENAME}.tar.gz.gpg"
UPLOAD_START_TIME=$(date)

if rclone copy "$ENCRYPTED_ARCHIVE" "${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_PATH}/" --progress; then
    UPLOAD_END_TIME=$(date)
    echo "✓ Backup successfully uploaded to ${RCLONE_REMOTE_NAME}."
    UPLOAD_SUCCESS=true
else
    UPLOAD_END_TIME=$(date)
    echo "✗ Failed to upload backup to ${RCLONE_REMOTE_NAME}."
    UPLOAD_SUCCESS=false
fi

# Clean up old cloud backups (retention policy)
if [[ "$UPLOAD_SUCCESS" == true && -n "$BACKUP_RETENTION_DAYS" ]]; then
    echo "Cleaning up backups older than $BACKUP_RETENTION_DAYS days..."
    CLEANUP_COUNT=$(rclone delete "${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_PATH}/" \
        --min-age "${BACKUP_RETENTION_DAYS}d" \
        --include "vaultwarden_backup_*.tar.gz.gpg" \
        --dry-run 2>/dev/null | grep -c "Deleted" || echo "0")
    
    rclone delete "${RCLONE_REMOTE_NAME}:${RCLONE_REMOTE_PATH}/" \
        --min-age "${BACKUP_RETENTION_DAYS}d" \
        --include "vaultwarden_backup_*.tar.gz.gpg" || echo "Warning: Cleanup failed"
fi

# Clean up local backups older than 7 days
echo "Cleaning up local backups older than 7 days..."
find "$BACKUP_DIR" -name "vaultwarden_backup_*.tar.gz.gpg" -mtime +7 -delete || true

BACKUP_END_TIME=$(date)

# Send comprehensive notification email
echo "Sending backup completion notification email..."

if [[ "$UPLOAD_SUCCESS" == true ]]; then
    EMAIL_SUBJECT="✅ Vaultwarden Backup Completed Successfully - $(date '+%Y-%m-%d %H:%M')"
    EMAIL_BODY="Your Vaultwarden backup has completed successfully and has been uploaded to your cloud storage.

📋 BACKUP SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🖥️  Server: $HOSTNAME
📅 Start Time: $BACKUP_START_TIME
📅 End Time: $BACKUP_END_TIME
📦 Backup Size: $BACKUP_SIZE
🔐 Encryption: GPG AES256
☁️  Cloud Storage: $RCLONE_REMOTE_NAME

📁 FILE LOCATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Local: $ENCRYPTED_ARCHIVE
☁️  Remote: $REMOTE_PATH

🧹 MAINTENANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🗑️  Retention Policy: $BACKUP_RETENTION_DAYS days"

    if [[ -n "$CLEANUP_COUNT" && "$CLEANUP_COUNT" -gt 0 ]]; then
        EMAIL_BODY="$EMAIL_BODY
🗑️  Old Backups Cleaned: $CLEANUP_COUNT files"
    fi

    EMAIL_BODY="$EMAIL_BODY

✅ Status: All operations completed successfully.
🔧 Next Backup: Scheduled for tomorrow night.

This backup is encrypted and ready for restore if needed."

else
    EMAIL_SUBJECT="❌ Vaultwarden Backup Upload Failed - $(date '+%Y-%m-%d %H:%M')"
    EMAIL_BODY="Your Vaultwarden backup was created successfully but failed to upload to your cloud storage.

📋 BACKUP SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🖥️  Server: $HOSTNAME
📅 Start Time: $BACKUP_START_TIME
📅 End Time: $BACKUP_END_TIME
📦 Backup Size: $BACKUP_SIZE
🔐 Encryption: GPG AES256

📁 LOCAL BACKUP AVAILABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 Location: $ENCRYPTED_ARCHIVE

❌ UPLOAD FAILURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
☁️  Target: $RCLONE_REMOTE_NAME
🕐 Upload Started: $UPLOAD_START_TIME
🕐 Upload Failed: $UPLOAD_END_TIME

⚠️  REQUIRED ACTION: Please check the backup container logs and verify your cloud storage connection and credentials.

The local backup is secure and available for manual upload if needed."
fi

# Send the email using msmtp
{
    echo "From: ${SMTP_FROM}"
    echo "To: ${BACKUP_NOTIFICATION_EMAIL}"
    echo "Subject: ${EMAIL_SUBJECT}"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo ""
    echo "$EMAIL_BODY"
} | msmtp -t

echo "✅ Backup process completed. Notification email sent to ${BACKUP_NOTIFICATION_EMAIL}"
