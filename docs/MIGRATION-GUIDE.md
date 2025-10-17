# VaultWarden OCI → SOPS+Age Migration Guide

This guide provides complete step-by-step instructions for migrating from OCI Vault to SOPS+Age encrypted secrets with Docker Compose Secrets integration.

## Pre-Migration Checklist

### System Requirements
- [ ] Ubuntu 20.04+ or compatible Linux distribution
- [ ] Docker 20.10+ with Compose plugin
- [ ] Root access for system configuration
- [ ] 5GB available disk space for backups
- [ ] Current VaultWarden deployment running with OCI Vault

### Dependencies Installation
```bash
# Install SOPS
sudo wget https://github.com/mozilla/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64 -O /usr/local/bin/sops
sudo chmod +x /usr/local/bin/sops

# Install Age
sudo apt update && sudo apt install age -y

# Verify installations
sops --version    # Should show v3.8.1
age --version     # Should show 1.0.0+
```

## Migration Process

### Phase 1: Backup and Validation

#### 1.1 Create Complete System Backup
```bash
# Stop services for consistent backup
docker compose down

# Create backup directory
sudo mkdir -p /secure/vaultwarden-migration-$(date +%Y%m%d)
cd /secure/vaultwarden-migration-$(date +%Y%m%d)

# Backup configuration files
sudo cp -r /path/to/vaultwarden/* ./vaultwarden-backup/
sudo cp /etc/systemd/system/vaultwarden.env ./systemd-backup/

# Backup database
sudo cp -r /var/lib/vaultwarden/data ./database-backup/

# Create backup manifest
echo "Backup created: $(date)" > backup-manifest.txt
echo "OCI_SECRET_OCID: ${OCI_SECRET_OCID}" >> backup-manifest.txt
```

#### 1.2 Validate OCI Vault Access
```bash
# Test OCI CLI access
oci iam region list > /dev/null
echo "OCI CLI Status: $?"

# Test secret retrieval
oci vault secret get-secret-bundle --secret-id "$OCI_SECRET_OCID" --query 'data."secret-bundle-content".content' --raw-output | base64 -d | jq . > oci-secrets-backup.json
echo "Secret retrieval test complete"
```

### Phase 2: SOPS+Age Setup

#### 2.1 Initialize SOPS Environment
```bash
cd /path/to/vaultwarden

# Run enhanced setup (includes SOPS+Age initialization)
sudo ./tools/init-setup.sh

# Verify SOPS configuration created
ls -la .sops.yaml secrets/keys/age-key.txt
```

#### 2.2 Create Initial Secrets Template
```bash
# Edit secrets interactively
sudo ./tools/edit-secrets.sh

# Template will be created with placeholders:
# admin_token: "CHANGE_ME_RANDOM_32_CHARS"
# smtp_password: ""
# backup_passphrase: "CHANGE_ME_RANDOM_32_CHARS"
# push_installation_key: ""
# cloudflare_api_token: ""
```

### Phase 3: Migration Execution

#### 3.1 Automated Migration
```bash
# Run migration with dry-run first
sudo ./tools/migrate-from-oci.sh --dry-run

# Review planned changes, then execute
sudo ./tools/migrate-from-oci.sh

# Migration will:
# 1. Backup current configuration
# 2. Extract secrets from OCI Vault
# 3. Create encrypted secrets.yaml
# 4. Update settings.json (remove sensitive values)
# 5. Archive OCI configuration
# 6. Test complete workflow
```

#### 3.2 Validate Migration Success
```bash
# Check SOPS secrets accessibility
sops -d secrets/secrets.yaml

# Validate Docker secrets preparation
./tools/check-health.sh --sops-only

# Test service startup
./startup.sh --validate
```

### Phase 4: Service Integration Testing

#### 4.1 Start Services with SOPS Secrets
```bash
# Start stack with new secrets workflow
./startup.sh

# Verify all services running
docker compose ps

# Check service logs for secret mounting
docker compose logs vaultwarden | grep -i secret
```

#### 4.2 Functional Validation
```bash
# Test admin access
curl -s https://your-domain/admin
# Should redirect to login (not show error)

# Test SMTP (if configured)
# Send test email through VaultWarden admin panel

# Test backups with new encryption
./tools/db-backup.sh --test
```

### Phase 5: Cleanup and Finalization

#### 5.1 Archive OCI Configuration
```bash
# OCI configuration automatically archived to:
ls -la /var/lib/vaultwarden/migration-backups/*/

# Remove OCI environment variables
sudo systemctl edit vaultwarden --full
# Remove OCI_SECRET_OCID from systemd unit

sudo systemctl daemon-reload
```

#### 5.2 Security Validation
```bash
# Check file permissions
find secrets/ -ls
# age-key.txt should be 600
# secrets.yaml should be 644

# Verify no plaintext secrets in environment
env | grep -E "(ADMIN_TOKEN|SMTP_PASSWORD)" || echo "Good - no sensitive vars in env"

# Run complete health check
./tools/check-health.sh
```

## Post-Migration Tasks

### Backup Strategy Implementation
```bash
# Create Age key backup
./tools/backup-recovery.sh create-age-backup /secure/location/age-key-backup.txt

# Test backup restoration
./tools/backup-recovery.sh validate-backups

# Export encrypted secrets backup
./tools/backup-recovery.sh export-secrets /secure/location/
```

### Documentation Generation
```bash
# Generate recovery instructions
./tools/backup-recovery.sh generate-instructions

# Created: docs/DISASTER-RECOVERY.md
```

## Rollback Procedures

### Complete Rollback to OCI
```bash
# Stop current services
docker compose down

# Execute rollback
sudo ./tools/migrate-from-oci.sh --rollback

# Restore systemd environment
sudo cp /secure/vaultwarden-migration-*/systemd-backup/vaultwarden.env /etc/systemd/system/
sudo systemctl daemon-reload

# Start with OCI configuration
./startup.sh
```

### Partial Rollback (Secrets Only)
```bash
# Restore just the secrets configuration
sudo cp /secure/vaultwarden-migration-*/vaultwarden-backup/settings.json ./

# Remove SOPS files
rm -f secrets/secrets.yaml secrets/keys/age-key.txt

# Restart with original config
./startup.sh
```

## Troubleshooting

### Common Issues

#### SOPS Decryption Fails
```bash
# Check Age key permissions
stat -c "%a %n" secrets/keys/age-key.txt
# Should be 600

# Test key validity
age-keygen -y secrets/keys/age-key.txt

# Verify SOPS config
yq eval '.creation_rules[0].age' .sops.yaml
```

#### Docker Secrets Not Mounting
```bash
# Check secrets directory
ls -la secrets/.docker_secrets/

# Verify Docker secrets preparation
./tools/edit-secrets.sh --validate

# Check compose file secrets section
docker compose config | grep -A 20 secrets:
```

#### Service Fails to Start
```bash
# Check specific service logs
docker compose logs vaultwarden

# Validate configuration
./startup.sh --validate

# Check system resources
free -h && df -h
```

### Recovery Procedures

#### Complete System Recovery
```bash
# 1. Restore from backup
sudo rsync -av /secure/vaultwarden-migration-*/vaultwarden-backup/ ./

# 2. Restore database
sudo rsync -av /secure/vaultwarden-migration-*/database-backup/ /var/lib/vaultwarden/data/

# 3. Test system
./tools/check-health.sh
```

## Validation Checkpoints

Use this checklist to verify successful migration:

- [ ] OCI Vault secrets successfully extracted
- [ ] Age key generated and secured (600 permissions)
- [ ] secrets.yaml created and encrypted with SOPS
- [ ] Docker secrets prepared and mounted correctly
- [ ] VaultWarden admin panel accessible
- [ ] SMTP configuration working (if configured)
- [ ] Database backups working with new encryption
- [ ] All services health checks passing
- [ ] OCI configuration archived safely
- [ ] Recovery procedures tested and documented
- [ ] Age key backups created and secured off-host

## Support and Resources

### Additional Documentation
- `docs/DISASTER-RECOVERY.md` - Complete disaster recovery procedures
- `docs/TROUBLESHOOTING-SOPS.md` - SOPS-specific troubleshooting
- `docs/DOCKER-SECRETS-INTEGRATION.md` - Docker secrets implementation details

### Migration Support Commands
```bash
# Health monitoring during migration
watch -n 5 './tools/check-health.sh'

# Log monitoring
tail -f /var/lib/vaultwarden/logs/vaultwarden/*.log

# Resource monitoring
htop  # Install with: sudo apt install htop
```

### Emergency Contacts and Procedures
- Keep OCI vault backups for 30 days minimum
- Document all customizations in migration log
- Test recovery procedures within 7 days of migration
- Update monitoring systems with new secret paths
