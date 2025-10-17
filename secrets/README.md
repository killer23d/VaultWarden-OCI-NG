# ⚠️ CRITICAL: Age Key Management - READ THIS FIRST

## 🚨 SINGLE POINT OF FAILURE WARNING

Your Age private key (`secrets/keys/age-key.txt`) is the **ONLY** way to decrypt your VaultWarden secrets.

**IF YOU LOSE THIS FILE, YOU LOSE ALL SECRETS PERMANENTLY.**
**THERE IS NO RECOVERY POSSIBLE WITHOUT THIS KEY.**

## ✅ REQUIRED ACTIONS (Complete These NOW)

### Before Using This System:
□ **BACKUP CREATED**: Age key copied to secure offline location(s)
□ **BACKUP TESTED**: Verified you can restore from backup
□ **LOCATION DOCUMENTED**: Backup location(s) written down securely  
□ **ACCESS VERIFIED**: You can access backup when needed
□ **RECOVERY TESTED**: Tested complete recovery procedure at least once

### Emergency Contact Information:
- **Backup Location 1**: _________________________
- **Backup Location 2**: _________________________  
- **Last Backup Date**: _________________________
- **Last Recovery Test**: _________________________

## 🔥 EMERGENCY RECOVERY SCENARIOS

### If age-key.txt is Lost or Corrupted:
1. **STOP** - Do not restart any services
2. Restore age-key.txt from your secure backup
3. Verify file permissions: `chmod 600 secrets/keys/age-key.txt`
4. Test decryption: `./tools/check-health.sh`
5. If successful, restart services: `./startup.sh`

### If No Backup Exists (DISASTER SCENARIO):
1. **ALL ENCRYPTED SECRETS ARE PERMANENTLY LOST**
2. You must regenerate all secrets manually:
   - New admin token for VaultWarden
   - New SMTP password
   - New backup passphrase
   - New push installation key
   - New Cloudflare API token (if used)
3. Reconfigure all external services
4. **THIS IS WHY BACKUP IS CRITICAL**

## 📋 REGULAR MAINTENANCE CHECKLIST

### Monthly Tasks:
□ Run health check: `./tools/check-health.sh`
□ Verify age key backup is accessible
□ Test secret decryption works
□ Check backup storage integrity

### Quarterly Tasks:
□ **Test complete disaster recovery procedure**
□ Update backup locations if changed
□ Review and rotate secrets if needed
□ Verify documentation is current

### Annual Tasks:
□ **Full disaster recovery test from scratch**
□ Review and update security procedures
□ Audit secret usage and access
□ Update backup strategy if needed

## 🛠️ QUICK REFERENCE COMMANDS

```bash
# Check system health
./tools/check-health.sh

# Edit secrets safely
./tools/edit-secrets.sh

# Backup age key manually
./tools/backup-recovery.sh create-age-backup

# Test recovery procedure
./tools/backup-recovery.sh test-recovery

# Validate backup integrity
./tools/backup-recovery.sh validate-backups
```

## 🔒 SECURITY REMINDERS

- **NEVER** commit age-key.txt to Git (it's in .gitignore)
- **NEVER** share age-key.txt via email/chat/cloud
- **NEVER** store age-key.txt on the same server as encrypted secrets
- **ALWAYS** use secure, offline storage for backups
- **ALWAYS** test recovery procedures regularly

## 📁 Directory Structure

```
secrets/
├── README.md                    # This file - read it first!
├── secrets.yaml                 # Encrypted secrets (SOPS+Age) - safe to commit
├── secrets.yaml.example         # Template for new secrets
├── keys/
│   ├── README.md               # Age key documentation  
│   ├── age-key.txt             # Private key (NEVER COMMIT!)
│   └── backup-info.txt         # Backup status tracking
└── .docker_secrets/            # Temporary Docker secret files (auto-generated)
    ├── admin_token             # Generated at startup from encrypted secrets
    ├── smtp_password           # Generated at startup from encrypted secrets
    ├── backup_passphrase       # Generated at startup from encrypted secrets
    ├── push_installation_key   # Generated at startup from encrypted secrets
    └── cloudflare_api_token    # Generated at startup from encrypted secrets
```

## 🚀 Quick Start Workflow

### First Time Setup:
1. Run: `sudo ./tools/init-setup.sh`
2. **IMMEDIATELY** backup your age key: `./tools/backup-recovery.sh create-age-backup`
3. Edit secrets: `./tools/edit-secrets.sh`
4. Start services: `./startup.sh`

### Regular Operations:
```bash
# Check health
./tools/check-health.sh

# Edit secrets (admin token, SMTP, etc.)
./tools/edit-secrets.sh

# Rotate individual secret
./tools/rotate-secrets.sh --key admin_token --random --restart

# Rotate all secrets
./tools/rotate-all-secrets.sh
```

### Emergency Recovery:
```bash
# If age key is lost - restore from backup
./tools/backup-recovery.sh restore-age-key /path/to/backup/age-key.txt

# If secrets file is corrupted - restore from backup
./tools/backup-recovery.sh import-secrets /path/to/backup/secrets.yaml

# Test complete recovery workflow
./tools/backup-recovery.sh test-recovery
```

## 📖 Additional Documentation

- [Complete Setup Guide](../docs/SETUP.md)
- [Secret Management Guide](../docs/SECRET-MANAGEMENT.md)
- [Backup & Recovery Procedures](../docs/BACKUP-RECOVERY.md)
- [Disaster Recovery Guide](../docs/DISASTER-RECOVERY.md)
- [Troubleshooting Guide](../docs/TROUBLESHOOTING-SOPS.md)
- [Migration from OCI Vault](../docs/MIGRATION-GUIDE.md)

## ⚡ EMERGENCY CONTACTS

**Before you start using this system:**

1. **Document your backup locations**
2. **Test the recovery procedure** 
3. **Create offline instructions** for key recovery
4. **Share recovery info** with trusted person (if applicable)

---

**Remember: Your backup strategy is the only thing between you and permanent data loss.**

## 🆘 If You Need Help

1. **First**: Check if your age key backup is accessible
2. **Second**: Run `./tools/check-health.sh --sops-only` 
3. **Third**: Check [Troubleshooting Guide](../docs/TROUBLESHOOTING-SOPS.md)
4. **Last**: Create GitHub issue with health report attached

**🔥 FOR EMERGENCY RECOVERY**: See [Disaster Recovery Guide](../docs/DISASTER-RECOVERY.md)
