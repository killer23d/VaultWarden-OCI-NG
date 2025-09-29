#!/usr/bin/env bash
# backup/restore.sh
set -euo pipefail

: "${GPG_PASSPHRASE:?GPG_PASSPHRASE must be set to restore. See usage hint by running script without arguments.}"

# Ensure we are in the project root directory where the 'data' directory exists
if [ ! -d "./data/backups" ]; then
    echo "ERROR: This script must be run from the project's root directory,"
    echo "       and the './data/backups' directory must exist."
    exit 1
fi

# --- New Automated Selection Block ---
echo "--> Searching for available backups..."

# Find all backup files, sort them newest first, and store in an array
mapfile -t backups < <(find ./data/backups -maxdepth 1 -type f -name "bitwarden_backup_*.tar.gz.gpg" | sort -r)

if [ ${#backups[@]} -eq 0 ]; then
  echo "No backup files found in ./data/backups. Nothing to restore."
  exit 0
fi

echo "--> Please select a backup to restore:"
PS3="Enter a number (or press Ctrl+C to cancel): "
select backup_file in "${backups[@]}"; do
    if [[ -n "$backup_file" ]]; then
        break
    else
        echo "Invalid selection. Please try again."
    fi
done
# --- End of Automated Selection Block ---


BACKUP_FILE="$backup_file" # Use the selected file
# Use a temporary directory within the project for safety
TMPDIR=$(mktemp -d ./bwrestore.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

echo "--> Decrypting $BACKUP_FILE ..."
gpg --batch --yes --passphrase "$GPG_PASSPHRASE" -o "$TMPDIR"/backup.tar.gz --decrypt "$BACKUP_FILE"

echo "--> Extracting backup to a temporary location..."
# Extract to a 'restore' subdirectory for clarity
mkdir "$TMPDIR/restore"
tar -xzf "$TMPDIR"/backup.tar.gz -C "$TMPDIR/restore"

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!!! WARNING: About to overwrite existing data. !!!"
echo "!!! It is highly recommended to STOP your containers now. !!!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
read -p "Type 'YES' to proceed with the restore: " CONFIRMATION

if [[ "$CONFIRMATION" != "YES" ]]; then
    echo "Restore cancelled by user."
    exit 0
fi

echo "--> Restoring data..."
# Copy the restored data to the correct volume locations
# Use rsync for efficiency and to preserve permissions
rsync -a "$TMPDIR/restore/data/" "./data/bwdata/"
rsync -a "$TMPDIR/restore/var/lib/mysql/" "./data/mariadb/"

echo ""
echo -e "\033[0;32m--> Restore complete.\033[0m"
echo "Please restart your containers ('docker compose up -d') if they were stopped."
echo -e "It is highly recommended to run the diagnostic script to verify the stack's health:"
echo -e "\033[1;33m./diagnose.sh\033[0m"
