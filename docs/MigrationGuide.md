# Migration Guide

**Migrating to VaultWarden-OCI-NG from other VaultWarden deployments with security enhancements**

## 🎯 Migration Overview

This guide helps you migrate from:
- Official VaultWarden Docker deployments
- Vaultwarden_RS legacy installations
- Other containerized VaultWarden setups

Now includes validation for migrated configuration and automatic non-root container setup.

## 📋 Pre-Migration Checklist

- [ ] Backup current VaultWarden database
- [ ] Export/document current environment variables
- [ ] Note current domain and admin email (will be validated)
- [ ] Document SMTP settings
- [ ] Prepare Cloudflare API token (if using)
- [ ] Plan for brief downtime (15-30 minutes)

## 🔄 Migration Steps

### 1) Backup Current System
```bash
# On your current system
docker exec vaultwarden sqlite3 /data/db.sqlite3 ".backup '/tmp/vw-migration-backup.sqlite3'"
docker cp vaultwarden:/tmp/vw-migration-backup.sqlite3 ./vw-migration-backup.sqlite3

# Backup attachments if you have them
docker cp vaultwarden:/data/attachments ./vw-attachments-backup/
```

### 2) Document Current Configuration
```bash
# Export current environment
docker inspect vaultwarden | grep -A 50 "Env"

# Note these key values for validation:
# - DOMAIN (will need clean format like vault.example.com)
# - ADMIN_EMAIL (will be validated for proper format)
# - SMTP settings
```

### 3) Setup VaultWarden-OCI-NG
```bash
cd /opt
git clone https://github.com/killer23d/VaultWarden-OCI-NG
cd VaultWarden-OCI-NG
chmod +x startup.sh tools/*.sh lib/*.sh

# Install dependencies
sudo ./tools/install-deps.sh --auto

# Initialize with validated inputs (use clean domain format)
sudo ./tools/init-setup.sh --domain vault.example.com --email admin@example.com
```

### 4) Configure Secrets (Validated)
```bash
./tools/edit-secrets.sh
```

Migrate your settings:
```yaml
# Use exact values from your current system
DOMAIN: "vault.example.com"  # Clean format, no https://
ADMIN_EMAIL: "admin@example.com"  # Will be validated
SMTP_HOST: "your-smtp-host"
SMTP_PORT: "587"
SMTP_USERNAME: "your-username" 
SMTP_PASSWORD: "your-password"
SMTP_FROM: "vault@yourdomain.com"
SMTP_SECURITY: "starttls"

# Copy other settings from your current deployment
SIGNUPS_ALLOWED: "false"
INVITATIONS_ALLOWED: "true"
# ... etc
```

### 5) Stop Current VaultWarden
```bash
# On your current system
docker stop vaultwarden
docker stop your-reverse-proxy
```

### 6) Migrate Database
```bash
# Copy backup to new system
scp vw-migration-backup.sqlite3 new-server:/opt/VaultWarden-OCI-NG/

# On new system - stop services and restore
cd /opt/VaultWarden-OCI-NG
docker compose down

# Create data directory and restore
sudo mkdir -p /var/lib/vaultwarden/data/bwdata/
sudo cp vw-migration-backup.sqlite3 /var/lib/vaultwarden/data/bwdata/db.sqlite3

# Set proper ownership for non-root container
sudo chown -R 1000:1000 /var/lib/vaultwarden/

# Restore attachments if you have them
sudo cp -r vw-attachments-backup/ /var/lib/vaultwarden/data/bwdata/attachments/
sudo chown -R 1000:1000 /var/lib/vaultwarden/data/bwdata/attachments/
```

### 7) Start New System
```bash
./startup.sh

# Verify container security
docker compose exec vaultwarden whoami  # Should show user 1000
docker compose exec caddy whoami        # Should show user 1000

# Check health
./tools/check-health.sh --comprehensive
```

### 8) Verify Migration
```bash
# Test web interface
curl -I https://vault.example.com

# Test admin panel
curl -u admin:your-password https://vault.example.com/admin

# Verify database integrity
docker compose exec vaultwarden sqlite3 /data/db.sqlite3 ".tables"
./tools/sqlite-maintenance.sh --integrity-check
```

### 9) Update DNS
```bash
# Point your domain to the new server IP
# If using Cloudflare, update A record

# Verify DNS propagation
dig vault.example.com
```

### 10) Post-Migration Cleanup
```bash
# Generate new emergency kit
./tools/create-emergency-kit.sh --email

# Run comprehensive health check
./tools/check-health.sh --comprehensive

# Test backup system
./tools/backup-monitor.sh --test-email
```

## 🔧 Common Migration Issues

### Domain/Email Validation Errors
**Issue:** `init-setup.sh` rejects your domain or email  
**Fix:** 
```bash
# Wrong: https://vault.example.com
# Right: vault.example.com

# Wrong: admin@
# Right: admin@example.com

# Test validation manually
source lib/validation.sh
validate_domain_format "vault.example.com"
validate_email_format "admin@example.com"
```

### Container Permission Issues
**Issue:** Database access denied, file permission errors  
**Fix:**
```bash
# Fix ownership for non-root containers
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/
docker compose restart
```

### SMTP Configuration Migration
**Issue:** Email notifications not working after migration  
**Fix:**
```bash
# Test SMTP configuration
./tools/backup-monitor.sh --test-email

# Common Gmail fix - use App Password
SMTP_HOST: "smtp.gmail.com"
SMTP_PORT: "587"
SMTP_SECURITY: "starttls"
SMTP_PASSWORD: "your-app-specific-password"  # Not regular password
```

### Certificate Issues
**Issue:** SSL certificates not working  
**Fix:**
```bash
# Reset certificates
docker compose down
docker volume rm vaultwarden-oci-ng_caddy_data
docker volume rm vaultwarden-oci-ng_caddy_config
./startup.sh

# Verify DNS and accessibility
dig vault.example.com
curl -I http://vault.example.com/.well-known/acme-challenge/
```

## 📊 Migration Validation Checklist

After migration, verify:

- [ ] Web interface accessible at your domain
- [ ] Admin panel works with credentials
- [ ] Users can log in with existing passwords
- [ ] Email notifications work
- [ ] Backup system operational
- [ ] Container security: VaultWarden and Caddy run as user 1000
- [ ] Database integrity check passes
- [ ] Emergency kit generation works
- [ ] SSL certificate valid and auto-renewing

## 🔄 Rollback Plan

If migration fails:

1. Stop new system: `docker compose down`
2. Restart old system with original database
3. Update DNS back to old server
4. Investigate issues and retry migration

## 📚 Additional Resources

- [Troubleshooting Guide](Troubleshooting.md) for migration issues
- [Security Configuration](Security.md) for hardening post-migration
- [Operations Runbook](OperationsRunbook.md) for ongoing maintenance

## 💡 Pro Tips

- Test migration on a staging environment first
- Keep old system running until migration is verified
- Use Cloudflare's flexibility to quickly switch between systems
- Document any custom configurations for future reference
- The new system's security defaults are more restrictive - this is intentional
