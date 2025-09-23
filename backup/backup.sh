#!/bin/bash
set -euo pipefail

DATE=$(date +'%Y%m%d-%H%M%S')
BACKUP_DIR=/backups
TMP_DIR=/tmp/bitwarden_backup_$DATE
ARCHIVE=$BACKUP_DIR/bitwarden_backup_$DATE.tar.gz
ENCRYPTED=$ARCHIVE.gpg

mkdir -p "$TMP_DIR"

# Dump MariaDB
mysqldump -h db -u${MARIADB_USER} -p${MARIADB_PASSWORD} ${MARIADB_DATABASE} > $TMP_DIR/db.sql

# Backup Bitwarden data
tar -C /etc/bitwarden -cf $TMP_DIR/bwdata.tar .

# Package
tar -czf "$ARCHIVE" -C "$TMP_DIR" .

# Encrypt
if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
    gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" -o "$ENCRYPTED" "$ARCHIVE"
elif [ -n "${BACKUP_PASSPHRASE:-}" ]; then
    gpg --batch --yes --passphrase "$BACKUP_PASSPHRASE" --symmetric -o "$ENCRYPTED" "$ARCHIVE"
else
    echo "⚠️ No GPG recipient or passphrase provided, skipping encryption!"
    ENCRYPTED=$ARCHIVE
fi

# Cleanup
rm -rf "$TMP_DIR" "$ARCHIVE"

# Email if SMTP configured
if [ -n "${SMTP_TO:-}" ]; then
    echo "Bitwarden backup $DATE attached" | mailx -s "Bitwarden Backup $DATE" -a "$ENCRYPTED" "$SMTP_TO"
fi

echo "✅ Backup completed: $ENCRYPTED"
