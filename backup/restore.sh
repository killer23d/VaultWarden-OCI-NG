#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: restore.sh <backup_file.gpg>"
    exit 1
fi

BACKUP_FILE=$1
TMP_DIR=/tmp/bitwarden_restore

mkdir -p "$TMP_DIR"

# Decrypt if necessary
if [[ "$BACKUP_FILE" == *.gpg ]]; then
    if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
        gpg --batch --yes --decrypt -o $TMP_DIR/restore.tar.gz "$BACKUP_FILE"
    elif [ -n "${BACKUP_PASSPHRASE:-}" ]; then
        gpg --batch --yes --passphrase "$BACKUP_PASSPHRASE" --decrypt -o $TMP_DIR/restore.tar.gz "$BACKUP_FILE"
    else
        echo "⚠️ No decryption method provided!"
        exit 1
    fi
else
    cp "$BACKUP_FILE" $TMP_DIR/restore.tar.gz
fi

# Extract archive
tar -xzf $TMP_DIR/restore.tar.gz -C $TMP_DIR

# Restore MariaDB
mysql -h db -u${MARIADB_USER} -p${MARIADB_PASSWORD} ${MARIADB_DATABASE} < $TMP_DIR/db.sql

# Restore Bitwarden data
tar -xf $TMP_DIR/bwdata.tar -C /etc/bitwarden

echo "✅ Restore completed."
