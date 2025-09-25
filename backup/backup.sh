#!/bin/sh
set -e
DATE=$(date +'%Y%m%d-%H%M%S')
BACKUP_DIR=/backups
TMP_DIR=/tmp/bitwarden_backup_$DATE
ARCHIVE=$BACKUP_DIR/bitwarden_backup_$DATE.tar.gz
ENCRYPTED=$ARCHIVE.gpg

mkdir -p "$TMP_DIR"

mysqldump -h db -u "$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" > "$TMP_DIR/db.sql"
tar -C /data -cf "$TMP_DIR/bwdata.tar" .
tar -czf "$ARCHIVE" -C "$TMP_DIR" .

if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
    gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" -o "$ENCRYPTED" "$ARCHIVE"
elif [ -n "${BACKUP_PASSPHRASE:-}" ]; then
    gpg --batch --yes --passphrase "$BACKUP_PASSPHRASE" --symmetric -o "$ENCRYPTED" "$ARCHIVE"
else
    echo "⚠️ No GPG recipient or passphrase provided, skipping encryption!" >&2
    ENCRYPTED=$ARCHIVE
fi

find "$BACKUP_DIR" -name "*.gpg" -mtime +7 -delete

rm -rf "$TMP_DIR" "$ARCHIVE"

if [ -n "${SMTP_TO:-}" ]; then
    echo "Bitwarden backup $DATE completed" | mailx -s "Bitwarden Backup $DATE" -a "$ENCRYPTED" "$SMTP_TO" || echo "⚠️ Failed to email backup!" >&2
fi

echo "✅ Backup completed: $ENCRYPTED" >> /var/log/backup.log
