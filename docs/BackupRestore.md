# Backup & Recovery Guide

**Encrypted, verified backups with Age + SOPS; updated for non-root containers and validation-aware restores**

## 📦 Backup Types

- Database backups (daily)
- Full backups (weekly)
- Emergency Kits (on change + manual)

## 🔄 How Backups Work

1. Database backup using SQLite `.backup`
2. Tarball created in secure temp dir (umask 077)
3. SHA256 integrity files generated
4. Archive encrypted with Age to `.age`
5. Optional email notification on success/failure

## 🗓 Schedules (Defaults)

- DB Backup: daily at 02:00
- Full Backup: Sunday at 01:00
- Kit Generation: when secrets/keys updated

## ▶️ Manual Backups

```bash
# Database only
./tools/backup-monitor.sh --db-only

# Full backup
./tools/create-full-backup.sh

# Send test email
./tools/backup-monitor.sh --test-email
```

## ✅ Verify Backup Integrity

```bash
# Verify latest DB backup
LATEST=$(ls -t backups/db/*.age | head -1)
./tools/backup-recovery.sh --verify "$LATEST"

# Verify latest full backup
LATEST_FULL=$(ls -t backups/full/*.age | head -1)
./tools/backup-recovery.sh --verify "$LATEST_FULL"
```

## 🔐 Keys & Security

- Age key: `secrets/keys/age-key.txt` (600 permissions)
- Public key: `secrets/keys/age-public-key.txt`
- SOPS `.sops.yaml` auto-generated

```bash
# Check key health
ls -la secrets/keys/
chmod 600 secrets/keys/age-key.txt
```

## 🧪 DR Test (Safe Verify)

```bash
# Decrypt into temp and list
TEST=$(ls -t backups/db/*.age | head -1)
./tools/backup-recovery.sh --verify "$TEST"
```

## ♻️ Restore Procedure (Non-Root Aware)

```bash
# 1) Stop services
docker compose down

# 2) Restore from backup
./tools/backup-recovery.sh --restore backups/db/your-file.age --confirm

# 3) Fix permissions for non-root containers
sudo chown -R 1000:1000 /var/lib/vaultwarden/

# 4) Start services
./startup.sh

# 5) Verify
./tools/check-health.sh --comprehensive
docker compose exec vaultwarden sqlite3 /data/db.sqlite3 ".tables"
```

## 📧 Notifications

- SMTP settings in secrets
- Use `--test-email` to validate

## 🧹 Retention

- DB: 14 days default
- Full: 4 weeks default
- Tune in `lib/constants.sh`
