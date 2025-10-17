# Disaster Recovery Guide

This guide describes how to recover a VaultWarden deployment protected by SOPS + Age encryption in various failure scenarios.

## Prerequisites

Before any disaster recovery, ensure you have:
- [ ] A copy of your Age private key file (secrets/keys/age-key.txt)
- [ ] The encrypted secrets file (secrets/secrets.yaml), from Git or secure backup
- [ ] Access to the target host with Docker and required dependencies installed
- [ ] Root/sudo access on the recovery system
- [ ] Network connectivity to download required tools

## Recovery Scenarios

### Scenario 1: Complete System Loss (New Host)

This covers complete server replacement or new deployment from backups.

#### Prerequisites for Recovery
1. Age private key backup in secure location
2. Repository clone or backup of all configuration files
3. Database backup files (if applicable)
4. List of required environment variables or settings

#### Step-by-Step Recovery

##### 1. System Preparation
```bash
# Clone or restore repository
git clone https://github.com/your-username/VaultWarden-OCI-Minimal.git
cd VaultWarden-OCI-Minimal

# Or restore from backup
tar -xzf vaultwarden-backup.tar.gz
cd vaultwarden-backup/

# Install dependencies
sudo apt update
sudo ./tools/init-setup.sh
```

##### 2. Restore Age Private Key
```bash
# Create secrets directory structure
sudo mkdir -p secrets/keys/
sudo chmod 700 secrets/keys/

# Restore Age key from secure backup
sudo cp /path/to/secure/backup/age-key.txt secrets/keys/age-key.txt
sudo chmod 600 secrets/keys/age-key.txt
sudo chown root:root secrets/keys/age-key.txt
```

##### 3. Validate Secret Access
```bash
# Test Age key validity
age-keygen -y secrets/keys/age-key.txt
# Should display public key without errors

# Test SOPS decryption
sops -d secrets/secrets.yaml
# Should display decrypted YAML content

# Run SOPS health check
./tools/check-health.sh --sops-only
```

##### 4. Restore Database (if needed)
```bash
# Create data directory
sudo mkdir -p /var/lib/vaultwarden/data/bwdata/

# Restore database from backup
sudo cp /path/to/backup/db.sqlite3 /var/lib/vaultwarden/data/bwdata/
sudo chown root:root /var/lib/vaultwarden/data/bwdata/db.sqlite3
sudo chmod 644 /var/lib/vaultwarden/data/bwdata/db.sqlite3

# Verify database integrity
sqlite3 /var/lib/vaultwarden/data/bwdata/db.sqlite3 "PRAGMA integrity_check;"
# Should return "ok"
```

##### 5. Start Services
```bash
# Validate configuration
./startup.sh --validate

# Start services
./startup.sh

# Verify services are running
docker compose ps

# Check logs for any issues
docker compose logs vaultwarden
```

##### 6. Functional Verification
```bash
# Test admin access
curl -s https://your-domain/admin
# Should redirect to login page (not show error)

# Test database connectivity
# Log into admin panel and verify data is accessible

# Test SMTP (if configured)
# Send a test email through the admin interface
```

### Scenario 2: Age Key Corruption/Loss

This covers cases where the Age private key is corrupted but you have a backup.

#### Recovery Steps
```bash
# Stop services to prevent write conflicts
docker compose down

# Backup current corrupted key (for investigation)
sudo cp secrets/keys/age-key.txt secrets/keys/age-key.txt.corrupted

# Restore from backup
sudo cp /path/to/backup/age-key.txt secrets/keys/age-key.txt
sudo chmod 600 secrets/keys/age-key.txt
sudo chown root:root secrets/keys/age-key.txt

# Test restoration
sops -d secrets/secrets.yaml > /dev/null
echo "Decryption test: $?"

# If test passes, restart services
./startup.sh
```

#### If No Age Key Backup Available
```bash
# This is a critical failure - secrets are permanently lost
# You must recreate all secrets manually

# Generate new Age key
sudo rm secrets/keys/age-key.txt
age-keygen -o secrets/keys/age-key.txt
sudo chmod 600 secrets/keys/age-key.txt

# Update SOPS configuration with new key
NEW_PUBKEY=$(age-keygen -y secrets/keys/age-key.txt)
sed -i "s/age1[a-z0-9]*/$NEW_PUBKEY/g" .sops.yaml

# Recreate secrets file
./tools/edit-secrets.sh
# You must manually enter all secret values:
# - Admin token: Generate new with openssl rand -base64 32
# - SMTP password: Your email provider app password
# - Backup passphrase: Generate new with openssl rand -base64 32
# - Other secrets as needed

# Test and restart
./startup.sh --validate
./startup.sh
```

### Scenario 3: Encrypted Secrets File Corruption

This covers cases where secrets.yaml is corrupted but Age key is intact.

#### Recovery with Backup
```bash
# Restore secrets file from backup
sudo cp /path/to/backup/secrets.yaml secrets/secrets.yaml
sudo chmod 644 secrets/secrets.yaml

# Test decryption
sops -d secrets/secrets.yaml > /dev/null
echo "Decryption test: $?"

# If successful, restart services
docker compose down
./startup.sh
```

#### Recovery without Backup
```bash
# Create new secrets file template
./tools/edit-secrets.sh

# This will create a new encrypted file with placeholder values
# You must manually enter all secret values
# Refer to your password manager or documentation for correct values

# Common required secrets:
# - admin_token: Used for /admin access
# - smtp_password: Email server app password  
# - backup_passphrase: Used for backup encryption
# - push_installation_key: Bitwarden push service key (optional)
# - cloudflare_api_token: CloudFlare API token (if using CF integration)
```

### Scenario 4: Docker Configuration Loss

This covers cases where docker-compose.yml or related files are lost.

#### Recovery Steps
```bash
# Restore from Git repository
git checkout docker-compose.yml startup.sh

# Or restore from backup
cp /path/to/backup/docker-compose.yml .
cp /path/to/backup/startup.sh .

# Ensure scripts are executable
chmod +x startup.sh tools/*.sh

# Validate configuration
./startup.sh --validate

# Test Docker secrets preparation
./tools/check-health.sh --sops-only

# Restart services
./startup.sh
```

### Scenario 5: Partial Service Failure

This covers cases where some services fail but others work.

#### Diagnosis
```bash
# Check service status
docker compose ps

# Check specific service logs
docker compose logs vaultwarden
docker compose logs caddy
docker compose logs fail2ban

# Check system resources
free -h
df -h
```

#### Recovery
```bash
# Restart specific failed service
docker compose restart vaultwarden

# Or restart all services
docker compose down
./startup.sh

# Check for resource constraints
# If memory issues: reduce container memory limits in docker-compose.yml
# If disk issues: clean up old logs and backups
```

## Recovery Testing

### Periodic Recovery Tests

Schedule regular recovery tests to ensure your backup procedures work:

#### Monthly Test (Non-Destructive)
```bash
# Test Age key backup validity
age-keygen -y /path/to/backup/age-key.txt

# Test secrets decryption with backup key  
SOPS_AGE_KEY_FILE=/path/to/backup/age-key.txt sops -d secrets/secrets.yaml > /dev/null

# Test backup restoration tools
./tools/backup-recovery.sh validate-backups

# Document test results with date and any issues found
```

#### Quarterly Test (Full Recovery Simulation)
```bash
# Create test environment (separate from production)
# Follow "Complete System Loss" recovery procedure
# Verify all functionality works correctly
# Document time required and any issues encountered
```

## Emergency Procedures

### Emergency Contact List
Keep this information readily available:
- [ ] Backup storage access credentials
- [ ] DNS provider access (for domain changes if needed)
- [ ] Email provider details
- [ ] CloudFlare account access (if used)
- [ ] VPS/hosting provider support contacts

### Emergency Access Setup
```bash
# Create emergency admin user in VaultWarden before disaster
# Document emergency admin credentials in secure location
# Test emergency admin access periodically

# Create emergency local configuration template
sudo tee emergency-config.json > /dev/null <<EOF
{
  "DOMAIN": "https://your-domain.com",
  "ADMIN_EMAIL": "admin@your-domain.com",
  "ADMIN_TOKEN": "EMERGENCY_TOKEN_REPLACE_ME",
  "DATABASE_URL": "sqlite:///data/db.sqlite3",
  "BACKUP_PASSPHRASE": "EMERGENCY_PASSPHRASE_REPLACE_ME"
}
EOF
sudo chmod 600 emergency-config.json
```

## Backup Strategy Recommendations

### Age Key Backups
1. **Multiple Locations**: Store copies in at least 3 different secure locations
2. **Different Media**: USB drives, password managers, encrypted cloud storage
3. **Regular Updates**: Update backups immediately after key rotation
4. **Access Testing**: Verify you can retrieve backups when needed

### Secrets File Backups
1. **Version Control**: Keep encrypted secrets.yaml in Git repository
2. **Automated Backups**: Include in regular system backup procedures
3. **Off-site Storage**: Store copies in different geographic locations
4. **Format Documentation**: Document the structure and expected values

### Database Backups
```bash
# Automated daily database backups (already included in system)
./tools/db-backup.sh

# Weekly full system backups
./tools/create-full-backup.sh

# Test backup restoration monthly
./tools/restore.sh --test
```

## Recovery Time Objectives

### Expected Recovery Times
- **Age Key Restoration**: 5-10 minutes
- **Secrets File Recovery**: 5-10 minutes  
- **Complete System Recovery**: 30-60 minutes
- **Database Restoration**: 10-30 minutes (depending on size)
- **Full Functional Verification**: 15-30 minutes

### Factors Affecting Recovery Time
- **Network Speed**: Download time for dependencies and Docker images
- **Backup Location**: Time to retrieve backups from secure storage
- **System Resources**: Host performance affects container startup time
- **Database Size**: Larger databases take longer to restore and verify

## Post-Recovery Checklist

After completing any recovery procedure:

- [ ] Verify all services are running: `docker compose ps`
- [ ] Test admin panel access: Visit `/admin` URL
- [ ] Test user authentication: Log in with test account
- [ ] Verify SMTP functionality: Send test email
- [ ] Check SSL certificates: Ensure HTTPS works correctly
- [ ] Test backup procedures: Run `./tools/db-backup.sh`
- [ ] Verify integrations: Check fail2ban, ddclient, watchtower
- [ ] Update documentation: Record any lessons learned
- [ ] Notify stakeholders: Inform users of any service impacts
- [ ] Schedule follow-up: Plan additional testing if needed

## Prevention Measures

### Automated Monitoring
```bash
# Set up monitoring for critical components
*/5 * * * * root cd /path/to/vaultwarden && ./tools/check-health.sh --sops-only | logger -t vw-health

# Monitor backup job success
0 2 * * * root cd /path/to/vaultwarden && ./tools/db-backup.sh && echo "Backup successful" | mail -s "VaultWarden Backup" admin@domain.com
```

### Regular Maintenance
- Weekly health checks: `./tools/check-health.sh`
- Monthly secret rotation: `./tools/rotate-all-secrets.sh`  
- Quarterly recovery testing: Full recovery simulation
- Semi-annual backup validation: Test all backup procedures

### Documentation Maintenance
- Keep recovery procedures updated with any system changes
- Document all customizations and their recovery requirements
- Update contact information and access credentials regularly
- Review and test emergency procedures annually

Remember: The best disaster recovery plan is one that's tested regularly and kept up to date with your system changes.
