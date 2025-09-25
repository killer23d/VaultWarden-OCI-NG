#!/usr/bin/env bash
# backup/restore.sh
set -euo pipefail

: "${1:?Usage: $0 /backups/bitwarden_backup_YYYYMMDD...tar.gz.gpg}"
: "${GPG_PASSPHRASE:?GPG_PASSPHRASE must be set to restore}"

BACKUP_FILE="$1"
TMPDIR=$(mktemp -d /tmp/bwrestore.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Decrypting $BACKUP_FILE ..."
gpg --batch --yes --passphrase "$GPG_PASSPHRASE" -o "$TMPDIR"/backup.tar.gz --decrypt "$BACKUP_FILE"
echo "Extracting ..."
tar -xzf "$TMPDIR"/backup.tar.gz -C /  # BE SURE THIS IS RUN WHERE /data and /var/lib/mysql are intended to be restored
echo "Restore complete. Please restart containers and verify DB and data."
