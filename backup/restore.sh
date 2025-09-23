#!/bin/sh
set -e
if [ $# -lt 1 ]; then
    echo "Usage: restore.sh <backup_file.gpg>" >&2
    exit 1
fi

BACKUP_FILE=$1
TMP_DIR=/tmp/bitwarden_restore

mkdir -p "$TMP_DIR"

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
        gpg --batch --yes --decrypt -o "$TMP_DIR/restore.tar.gz" "$BACKUP_FILE"
    elif [ -n "${BACKUP_PASSPHRASE:-}" ]; then
        gpg --batch --yes --passphrase "$BACKUP_PASSPHRASE" --decrypt -o "$TMP_DIR/restore.tar.gz" "$BACKUP_FILE"
    else
        echo "⚠️ No decryption method provided!" >&2
        exit 1
    fi
else
    cp "$BACKUP_FILE" "$TMP_DIR/restore.tar.gz"
fi

tar -xzf "$TMP_DIR/restore.tar.gz" -C "$TMP_DIR"
mysql -h db -u "$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" < "$TMP_DIR/db.sql"
tar -xf "$TMP_DIR/bwdata.tar" -C /etc/bitwarden

if [ -n "${SMTP_TO:-}" ]; then
    echo "Bitwarden restore $1 completed" | mailx -s "Bitwarden Restore" "$SMTP_TO"
fi

echo "✅ Restore completed: $1" >> /var/log/backup.log
