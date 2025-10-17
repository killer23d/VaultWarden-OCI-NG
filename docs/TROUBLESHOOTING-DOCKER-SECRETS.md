# Docker Secrets & SOPS Integration Troubleshooting

This guide provides comprehensive troubleshooting for Docker Secrets and SOPS+Age integration issues in VaultWarden.

## Quick Diagnostics

### Run Health Check
```bash
# Full system health check
./tools/check-health.sh

# SOPS-specific checks only
./tools/check-health.sh --sops-only

# Startup validation without starting services
./startup.sh --validate
```

### Check Integration Status
```bash
# Show SOPS and Docker secrets status
./startup.sh --secrets-info

# Show SOPS integration details
./startup.sh --sops-status
```

## Common Issues and Solutions

### 1. SOPS Decryption Failures

#### Symptoms
- Error: "Failed to decrypt secrets file"
- Error: "SOPS age key not found"
- Error: "no age identity found"

#### Diagnosis
```bash
# Check Age key exists and has correct permissions
ls -la secrets/keys/age-key.txt
# Should show: -rw------- 1 root root

# Test Age key validity
age-keygen -y secrets/keys/age-key.txt
# Should display public key, not error

# Test SOPS decryption manually
sops -d secrets/secrets.yaml
# Should show decrypted YAML content
```

#### Solutions
```bash
# Fix Age key permissions
sudo chmod 600 secrets/keys/age-key.txt
sudo chown root:root secrets/keys/age-key.txt

# Restore Age key from backup
./tools/backup-recovery.sh restore-age-key /path/to/backup/age-key.txt

# Regenerate Age key (DESTRUCTIVE - will lose existing secrets)
sudo rm secrets/keys/age-key.txt secrets/secrets.yaml
sudo ./tools/init-setup.sh
```

### 2. Docker Secrets Not Accessible

#### Symptoms
- Containers start but can't read secrets
- Error: "No such file or directory: /run/secrets/admin_token"
- VaultWarden shows "Admin token not set" despite SOPS having it

#### Diagnosis
```bash
# Check Docker secrets directory exists and has files
ls -la secrets/.docker_secrets/
# Should show secret files with 644 permissions

# Check secrets are being prepared
./tools/edit-secrets.sh --validate

# Check Docker compose secrets configuration
docker compose config | grep -A 10 "^secrets:"

# Inspect running container secrets
docker compose exec vaultwarden ls -la /run/secrets/
```

#### Solutions
```bash
# Recreate Docker secrets from SOPS
./tools/edit-secrets.sh --refresh-docker-secrets

# Fix Docker secrets permissions
sudo chmod 755 secrets/.docker_secrets/
sudo find secrets/.docker_secrets/ -type f -exec chmod 644 {} \;

# Restart services to remount secrets
docker compose down
./startup.sh
```

### 3. Service Startup Failures

#### Symptoms
- Services fail to start after SOPS migration
- Container exits immediately
- Health checks failing

#### Diagnosis
```bash
# Check service logs for secret-related errors
docker compose logs vaultwarden | grep -i secret
docker compose logs vaultwarden | grep -i admin

# Check container environment variables
docker compose exec vaultwarden env | grep -E "(ADMIN|SMTP|BACKUP)"

# Validate compose file
docker compose config --quiet
echo "Config validation: $?"
```

#### Solutions
```bash
# Restart with verbose logging
DEBUG=1 ./startup.sh

# Reset Docker secrets and restart
sudo rm -rf secrets/.docker_secrets/
./startup.sh

# Check for conflicting environment variables
unset ADMIN_TOKEN SMTP_PASSWORD BACKUP_PASSPHRASE
./startup.sh
```

### 4. Permission and Access Issues

#### Symptoms
- Error: "Permission denied" when accessing secrets
- SOPS commands fail with permission errors
- Docker can't read secret files

#### Diagnosis
```bash
# Check all file permissions in secrets directory
find secrets/ -ls

# Check current user and groups
id
groups

# Check SELinux context (if enabled)
ls -Z secrets/keys/age-key.txt
```

#### Solutions
```bash
# Fix all secrets permissions
sudo chown -R root:root secrets/
sudo chmod 700 secrets/keys/
sudo chmod 600 secrets/keys/age-key.txt
sudo chmod 644 secrets/secrets.yaml
sudo chmod 755 secrets/.docker_secrets/
sudo find secrets/.docker_secrets/ -type f -exec chmod 644 {} \;

# Fix SELinux contexts (if applicable)
sudo restorecon -R secrets/
```

### 5. Migration from OCI Vault Issues

#### Symptoms
- Migration script fails
- Secrets not properly extracted from OCI
- Services won't start after migration

#### Diagnosis
```bash
# Test OCI Vault access
oci vault secret get-secret-bundle --secret-id "$OCI_SECRET_OCID"     --query 'data."secret-bundle-content".content' --raw-output | base64 -d | jq .

# Check migration backups
ls -la /var/lib/*/migration-backups/

# Validate migration result
./tools/migrate-from-oci.sh --validate
```

#### Solutions
```bash
# Rollback migration
sudo ./tools/migrate-from-oci.sh --rollback

# Re-run migration with debugging
DEBUG=1 sudo ./tools/migrate-from-oci.sh

# Manual secret extraction and setup
# Extract secrets manually:
oci vault secret get-secret-bundle --secret-id "$OCI_SECRET_OCID"     --query 'data."secret-bundle-content".content' --raw-output |     base64 -d > /tmp/oci-secrets.json

# Edit secrets manually with extracted values
./tools/edit-secrets.sh
```

### 6. Docker Compose Secrets Configuration

#### Symptoms
- Compose validation fails
- Secrets not properly defined in compose file
- Services can't find secret files

#### Diagnosis
```bash
# Validate compose configuration
docker compose -f docker-compose.yml config

# Check secrets section specifically
docker compose config | yq eval '.secrets' -

# Verify secret file paths in compose
grep -A 5 "secrets:" docker-compose.yml
```

#### Solutions
```bash
# Regenerate compose file from template
# (If you have a template system)

# Fix secret file paths in compose
# Edit docker-compose.yml and ensure:
# secrets:
#   admin_token:
#     file: secrets/.docker_secrets/admin_token

# Validate and test
docker compose config --quiet && echo "Config OK"
```

## Advanced Troubleshooting

### Debug Mode
```bash
# Enable debug mode for all scripts
export DEBUG=1

# Enable verbose SOPS output
export SOPS_DEBUG=1

# Enable Age debug output
export AGE_DEBUG=1
```

### Manual Secret Operations
```bash
# Manually decrypt secrets
sops -d secrets/secrets.yaml

# Manually encrypt secrets
echo "test_secret: value" | sops -e /dev/stdin

# Test Docker secrets mounting
docker run --rm -v $(pwd)/secrets/.docker_secrets:/run/secrets:ro     alpine:latest ls -la /run/secrets/
```

### Container Inspection
```bash
# Check container secret mounts
docker compose exec vaultwarden mount | grep secrets

# Check container environment
docker compose exec vaultwarden env | sort

# Check processes in container
docker compose exec vaultwarden ps aux
```

## Recovery Procedures

### Complete Secret Recovery
```bash
# 1. Stop services
docker compose down

# 2. Restore Age key from backup
./tools/backup-recovery.sh restore-age-key /path/to/age-key-backup.txt

# 3. Restore secrets from backup
./tools/backup-recovery.sh import-secrets /path/to/secrets-backup.yaml

# 4. Test decryption
sops -d secrets/secrets.yaml

# 5. Prepare Docker secrets
./tools/edit-secrets.sh --refresh-docker-secrets

# 6. Start services
./startup.sh
```

### Emergency Local Configuration
```bash
# If SOPS completely fails, create emergency local config
sudo tee settings.json > /dev/null <<EOF
{
  "DOMAIN": "https://your-domain.com",
  "ADMIN_EMAIL": "admin@your-domain.com",
  "ADMIN_TOKEN": "$(openssl rand -base64 32)",
  "DATABASE_URL": "sqlite:///data/db.sqlite3",
  "BACKUP_PASSPHRASE": "$(openssl rand -base64 32)"
}
EOF
sudo chmod 600 settings.json

# Start with local config
./startup.sh
```

## Monitoring and Maintenance

### Regular Health Checks
```bash
# Add to cron for regular monitoring
# */5 * * * * root cd /path/to/vaultwarden && ./tools/check-health.sh --sops-only
```

### Log Monitoring
```bash
# Monitor for secret-related errors
tail -f /var/lib/vaultwarden/logs/vaultwarden/*.log | grep -i secret

# Monitor Docker logs for secret access
docker compose logs -f | grep -E "(secret|age|sops)"
```

### Backup Validation
```bash
# Weekly backup validation
./tools/backup-recovery.sh validate-backups

# Test recovery workflow
./tools/backup-recovery.sh test-recovery
```

## Prevention

### Security Best Practices
1. **Regular Backups**: Backup Age keys to multiple secure locations
2. **Permission Monitoring**: Regularly verify file permissions
3. **Access Logging**: Monitor who accesses secret files
4. **Key Rotation**: Rotate secrets periodically
5. **Update Monitoring**: Keep SOPS and Age updated

### Monitoring Setup
```bash
# Set up monitoring for secret file changes
sudo tee /etc/systemd/system/vaultwarden-secrets-monitor.service > /dev/null <<EOF
[Unit]
Description=VaultWarden Secrets Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=inotifywait -m /path/to/vaultwarden/secrets/ -e modify -e delete
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now vaultwarden-secrets-monitor.service
```

## Getting Help

### Information Gathering
Before seeking help, gather:
```bash
# System information
./tools/check-health.sh > health-report.txt

# SOPS status
./startup.sh --sops-status > sops-status.txt

# Docker status
docker compose ps --format table > docker-status.txt
docker compose logs --tail=100 > docker-logs.txt

# File permissions
find secrets/ -ls > permissions-report.txt
```

### Support Resources
- GitHub Issues: Report bugs and feature requests
- Documentation: Check `docs/` directory for additional guides
- Community: Join VaultWarden community forums
- Professional Support: Consider professional consulting for critical deployments

### Emergency Contacts
Keep these prepared:
- Backup locations and access credentials
- Recovery procedures documentation
- Emergency contact information
- Rollback procedures checklist
