#!/usr/bin/env bash
# backup/backup.sh
# Usage: this script expects environment variables in settings.env to be exported before running:
#   GPG_PASSPHRASE, SMTP_USER, SMTP_PASSWORD, SMTP_HOST, SMTP_FROM, BACKUP_EMAIL_RECIPIENT, APP_DOMAIN
#
# Must be run as non-root (Dockerfile uses user 'backup'), and /backups must be writable by this user.
set -euo pipefail

LOGDIR=${LOGDIR:-/var/log/backup}
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/backup.log"
exec >> "$LOGFILE" 2>&1

timestamp() { date -u +"%Y%m%dT%H%M%SZ"; }

die() {
  echo "$(timestamp) ERROR: $*" >&2
  exit 1
}

info() {
  echo "$(timestamp) INFO: $*"
}

# Ensure required env vars
: "${GPG_PASSPHRASE:?GPG_PASSPHRASE must be set (from settings.env)}"
: "${BACKUP_EMAIL_RECIPIENT:?BACKUP_EMAIL_RECIPIENT must be set}"
: "${SMTP_HOST:?SMTP_HOST must be set}"
: "${SMTP_USER:?SMTP_USER must be set}"
: "${SMTP_PASSWORD:?SMTP_PASSWORD must be set}"
: "${SMTP_FROM:?SMTP_FROM must be set}"

BACKUP_DIR=${BACKUP_DIR:-/backups}
DATA_DIRS=(/data /var/lib/mysql)
TMPDIR=$(mktemp -d -p /tmp bwbackup.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

info "Starting backup for ${APP_DOMAIN:-(unknown)}"

# Create tarball of data directories (readonly mounts expected)
TARFILE="$TMPDIR/bitwarden_backup_$(timestamp).tar.gz"
info "Creating tarball $TARFILE"
tar -czf "$TARFILE" -C / --warning=no-file-changed "${DATA_DIRS[@]/#/}" || die "tar failed"

# Encrypt with GPG symmetric AES256
ENCRYPTED="$BACKUP_DIR/bitwarden_backup_$(timestamp).tar.gz.gpg"
info "Encrypting to $ENCRYPTED"
gpg --batch --yes --passphrase "$GPG_PASSPHRASE" --symmetric --cipher-algo AES256 -o "$ENCRYPTED" "$TARFILE" || die "gpg encryption failed"

# Set safe permissions
chmod 600 "$ENCRYPTED"

# Rotate local backups: keep last 14 (configurable)
KEEP=${KEEP:-14} # <-- This value has been changed from 7 to 14
info "Rotating backups, keeping last $KEEP"
ls -1t "$BACKUP_DIR"/bitwarden_backup_*.tar.gz.gpg 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f --

# --- New Email Section with Attachment ---
info "Sending backup file via email to $BACKUP_EMAIL_RECIPIENT"
# Prepare temporary msmtp config. Mutt will use this config file.
MSMTP_CONFIG="/tmp/msmtp.conf.$$"
trap 'rm -f "$MSMTP_CONFIG"' EXIT # The existing trap will clean this up
cat > "$MSMTP_CONFIG" <<EOF
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/backup/msmtp.log

account default
host ${SMTP_HOST}
port 587
from "${SMTP_FROM}"
user "${SMTP_USER}"
passwordeval "echo ${SMTP_PASSWORD}"
EOF

# Define email subject and body
SUBJECT="[Backup] Vaultwarden backup for \"${APP_DOMAIN:-(unknown)}\" on $(date -u +'%Y-%m-%d')"
BODY="Encrypted backup file is attached.\n\nFile: $(basename "$ENCRYPTED")\nTimestamp: $(timestamp)"

# Send email with mutt, using the temporary msmtp config
# The -a flag attaches the file. The '--' signifies the end of options.
echo -e "$BODY" | mutt -s "$SUBJECT" \
  -F "$MSMTP_CONFIG" \
  -a "$ENCRYPTED" \
  -- "$BACKUP_EMAIL_RECIPIENT" || info "Warning: mutt reported a failure. Email with attachment may not have been sent."

info "Backup completed successfully: $(basename "$ENCRYPTED")"
exit 0
