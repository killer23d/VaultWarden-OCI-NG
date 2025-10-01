# **VaultWarden Disaster Recovery & VM Migration Guide**

This guide covers the complete process for disaster recovery and migrating your VaultWarden instance to a new VM using the full-backup system located in `/backup/full-backup/`.

## **Overview**

The disaster recovery process involves three main phases:
1. **Pre-Migration**: Creating comprehensive backups on the current system
2. **VM Setup**: Preparing the new virtual machine
3. **Restoration**: Restoring all data, configurations, and services

## **Script Locations**

All disaster recovery scripts are located in the `/backup/full-backup/` directory:

```
VaultWarden-OCI-NG/
├── backup/
│   ├── db-backup.sh              # Regular database backups
│   ├── db-restore.sh             # Database restoration
│   ├── verify-backup.sh          # Database backup verification
│   ├── config/                   # rclone configuration
│   └── full-backup/              # Full system disaster recovery
│       ├── create-full-backup.sh    # Complete system backup
│       ├── restore-full-backup.sh   # Complete system restoration
│       ├── rebuild-vm.sh            # Automated disaster recovery
│       └── validate-backup.sh       # Backup integrity validation
└── migration_backups/            # Output directory for full backups
```

## **Phase 1: Pre-Migration Backup (Current VM)**

### **Step 1: Create Complete System Backup**

Before anything goes wrong, create a comprehensive backup that includes everything:

```bash
# Navigate to project root
cd /path/to/VaultWarden-OCI-NG

# Create comprehensive backup (includes database, configs, SSL, attachments)
./backup/full-backup/create-full-backup.sh
```

This script creates a complete backup including:
- ✅ **Database content** (all user data, organizations, ciphers)
- ✅ **Configuration files** (settings.env, docker-compose.yml, scripts)
- ✅ **SSL certificates** (Let's Encrypt certs from Caddy)
- ✅ **User attachments** (file uploads)
- ✅ **Application data** (VaultWarden data directory)
- ✅ **Security configs** (fail2ban rules, Cloudflare IPs)

### **Step 2: Verify Backup Integrity**

```bash
# Test the latest backup before you need it
./backup/full-backup/validate-backup.sh --latest

# Validate all backup files
./backup/full-backup/validate-backup.sh --all

# Deep validation with extraction test
./backup/full-backup/validate-backup.sh --deep backup_file.tar.gz

# Check backup size and contents
ls -la ./migration_backups/
tar -tzf ./migration_backups/vaultwarden_full_YYYYMMDD_HHMMSS.tar.gz | head -20
```

### **Step 3: Secure Backup Storage**

```bash
# Upload to remote storage (if rclone configured)
docker compose exec bw_backup rclone copy /backups/ your-remote:vaultwarden-backups/full/

# Or manually copy to secure location
scp ./migration_backups/vaultwarden_full_*.tar.gz user@backup-server:/safe/location/

# Verify backup files are complete
ls -la ./migration_backups/
# Should see: .tar.gz, .sha256, .md5, _manifest.txt files
```

## **Phase 2: New VM Setup**

### **Step 1: Provision New VM**

**For OCI A1 Flex:**
- ✅ **1 OCPU ARM64, 6GB RAM** (same as original)
- ✅ **Ubuntu 22.04 LTS** (consistent OS)
- ✅ **Boot volume**: 50GB minimum
- ✅ **Security Lists**: Allow ports 80/443
- ✅ **SSH Access**: Configure your SSH keys

### **Step 2: Basic System Setup**

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl git unzip htop

# Configure timezone (match your original)
sudo timedatectl set-timezone America/Los_Angeles  # Use your timezone

# Set up swap (important for 6GB RAM)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Verify swap is active
free -h
```

### **Step 3: Clone Repository and Run init-setup**

```bash
# Clone the project
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG

# Run automated setup (installs Docker, creates directories)
./init-setup.sh
```

## **Phase 3: Complete System Restoration**

### **Option A: Automated Recovery (Recommended)**

Use the automated rebuild script for hands-off disaster recovery:

```bash
# Transfer backup file to new VM first
scp user@old-vm:/path/to/vaultwarden_full_*.tar.gz ./

# Run complete automated recovery
./backup/full-backup/rebuild-vm.sh vaultwarden_full_YYYYMMDD_HHMMSS.tar.gz
```

The automated script will:
1. ✅ Validate VM environment (memory, disk, architecture)
2. ✅ Initialize VM with Docker if needed
3. ✅ Guide network configuration setup
4. ✅ Restore all backup components
5. ✅ Guide configuration updates for new VM
6. ✅ Start services and run diagnostics
7. ✅ Provide final verification steps

### **Option B: Manual Recovery Process**

If you prefer step-by-step control:

#### **Step 1: Transfer Backup to New VM**

```bash
# Option A: Download from remote storage
docker compose run --rm bw_backup rclone copy your-remote:vaultwarden-backups/full/ /backups/

# Option B: Direct transfer (from old VM)
scp user@old-vm:/path/to/backup/vaultwarden_full_*.tar.gz ./migration_backups/

# Option C: Local upload
scp ./local/backup/vaultwarden_full_*.tar.gz user@new-vm:/home/user/VaultWarden-OCI-NG/migration_backups/
```

#### **Step 2: Run Complete Restoration**

```bash
# Make the restoration script executable
chmod +x ./backup/full-backup/restore-full-backup.sh

# Run interactive restoration
./backup/full-backup/restore-full-backup.sh migration_backups/vaultwarden_full_YYYYMMDD_HHMMSS.tar.gz
```

**The restoration script will:**
1. ✅ Verify backup integrity (checksum validation)
2. ✅ Extract all data directories
3. ✅ Restore configuration files
4. ✅ Set proper file permissions
5. ✅ Validate configuration consistency

#### **Step 3: Configuration Updates for New VM**

```bash
# Edit settings for new environment
nano settings.env
```

**Critical settings to verify/update:**
- ✅ **APP_DOMAIN**: Should stay the same (vault.yourdomain.com)
- ✅ **ADMIN_EMAIL**: Update if needed
- ✅ **TZ**: Verify timezone matches new VM
- ⚠️ **SMTP settings**: Update if server-specific
- ⚠️ **Backup paths**: Verify remote storage access

#### **Step 4: DNS Updates**

**Update your DNS records to point to the new VM:**

```bash
# Get new VM's public IP
curl -s ifconfig.me

# Update DNS (example for Cloudflare)
# Point vault.yourdomain.com to NEW_VM_IP
```

#### **Step 5: Launch Services**

```bash
# Validate configuration before starting
./startup.sh --debug

# Launch the complete stack
./startup.sh
```

#### **Step 6: Verify Complete Restoration**

```bash
# Run comprehensive diagnostics
./diagnose.sh

# Check all services are healthy
docker compose ps
./dashboard.sh

# Test web access
curl -I https://vault.yourdomain.com

# Verify database restoration
docker compose exec vaultwarden ls -la /data/
```

## **Phase 4: Post-Migration Verification**

### **Step 1: Functional Testing**

1. ✅ **Web Access**: Visit https://vault.yourdomain.com
2. ✅ **Admin Panel**: Access https://vault.yourdomain.com/admin
3. ✅ **User Login**: Test existing user accounts
4. ✅ **Mobile Apps**: Verify mobile app synchronization
5. ✅ **File Attachments**: Test downloading existing attachments

### **Step 2: Security Verification**

```bash
# Verify SSL certificates
curl -I https://vault.yourdomain.com | grep -i "strict-transport"

# Check fail2ban is protecting
docker compose exec bw_fail2ban fail2ban-client status

# Verify backup system
docker compose exec bw_backup /backup/db-backup.sh --test
```

### **Step 3: Performance Baseline**

```bash
# Run performance benchmarks
./benchmark.sh run all

# Monitor resource usage
./perf-monitor.sh monitor

# Test backup system
./backup/full-backup/validate-backup.sh --latest
```

## **Emergency Recovery Procedures**

### **If Migration Fails Mid-Process**

1. **Stop all services**:
   ```bash
   docker compose down
   ```

2. **Clean data directories**:
   ```bash
   sudo rm -rf ./data/*
   ```

3. **Re-run restoration**:
   ```bash
   ./backup/full-backup/restore-full-backup.sh backup_file.tar.gz
   ./startup.sh
   ```

### **Rollback to Previous VM**

1. **Update DNS** back to old VM IP
2. **Restart services** on old VM:
   ```bash
   ./startup.sh
   ```
3. **Verify functionality** before decommissioning new VM

## **Backup Management Commands**

### **Regular Backup Operations**

```bash
# Create full system backup
./backup/full-backup/create-full-backup.sh

# Validate latest backup
./backup/full-backup/validate-backup.sh --latest

# Validate all backups
./backup/full-backup/validate-backup.sh --all

# Deep validation (with extraction test)
./backup/full-backup/validate-backup.sh --deep backup_file.tar.gz
```

### **Backup File Management**

```bash
# List all full backups
ls -la ./migration_backups/

# Check backup integrity
./backup/full-backup/validate-backup.sh backup_file.tar.gz

# View backup manifest
cat ./migration_backups/vaultwarden_full_*_manifest.txt

# Clean old backups (keep last 5)
cd ./migration_backups/
ls -t vaultwarden_full_*.tar.gz | tail -n +6 | xargs rm -f
ls -t vaultwarden_full_*.sha256 | tail -n +6 | xargs rm -f
ls -t vaultwarden_full_*.md5 | tail -n +6 | xargs rm -f
```

## **Best Practices for Disaster Recovery**

### **Regular Testing Schedule**
```bash
# Monthly: Test backup creation and validation
./backup/full-backup/create-full-backup.sh
./backup/full-backup/validate-backup.sh --latest

# Quarterly: Full disaster recovery drill on test VM
./backup/full-backup/rebuild-vm.sh backup_file.tar.gz

# Annually: Document updates and procedure review
```

### **Backup Strategy**
- ✅ **Daily automated database backups** via cron (existing system)
- ✅ **Weekly full system backups** for disaster recovery
- ✅ **Monthly backup verification** and cleanup
- ✅ **Quarterly restore testing** on isolated VM

### **Documentation Maintenance**
- ✅ Keep this guide updated with any custom configurations
- ✅ Document any infrastructure changes (domains, IPs, etc.)
- ✅ Maintain emergency contact information
- ✅ Record backup passphrases securely (GPG key backup)

## **Time Estimates**

| Phase | Estimated Time | Critical Path |
|-------|----------------|---------------|
| **Pre-Migration Backup** | 30 minutes | Backup creation + verification |
| **VM Provisioning** | 15 minutes | OCI console + SSH setup |
| **System Setup** | 20 minutes | init-setup.sh + basic config |
| **Automated Recovery** | 45 minutes | rebuild-vm.sh execution |
| **Manual Recovery** | 60 minutes | restore + configure + launch |
| **Verification** | 30 minutes | Comprehensive testing |
| **Total Downtime** | **2-3 hours** | DNS propagation dependent |

## **Recovery Checklist**

### **Pre-Migration**
- [ ] Create full system backup: `./backup/full-backup/create-full-backup.sh`
- [ ] Verify backup integrity: `./backup/full-backup/validate-backup.sh --latest`
- [ ] Upload to secure remote location
- [ ] Document current configuration and DNS settings

### **New VM Setup**
- [ ] Provision VM with identical specs (OCI A1 Flex: 1 OCPU, 6GB RAM)
- [ ] Configure basic system (swap, timezone, firewall)
- [ ] Clone repository and run `./init-setup.sh`
- [ ] Transfer backup files to new VM

### **Restoration**
- [ ] Run automated recovery: `./backup/full-backup/rebuild-vm.sh backup.tar.gz`
- [ ] OR manual process: `./backup/full-backup/restore-full-backup.sh backup.tar.gz`
- [ ] Update settings.env for new environment
- [ ] Update DNS records to point to new VM
- [ ] Launch services with `./startup.sh`
- [ ] Verify all functionality with `./diagnose.sh`

### **Post-Migration**
- [ ] Test web access and admin panel
- [ ] Verify user accounts and data integrity
- [ ] Test mobile app synchronization
- [ ] Validate backup system operation
- [ ] Update monitoring and documentation
- [ ] Monitor system for 24-48 hours

## **Troubleshooting Common Issues**

### **Backup Creation Issues**
```bash
# If backup service not running
docker compose up -d bw_backup

# If rclone upload fails
docker compose exec bw_backup rclone config

# If backup size seems too small
./backup/full-backup/validate-backup.sh --deep backup_file.tar.gz
```

### **Restoration Issues**
```bash
# Database connection failures after restore
grep DATABASE_URL settings.env
docker compose logs bw_mariadb

# Permission problems
sudo chown -R 1000:1000 ./data/bwdata ./data/caddy_*
sudo chown -R 999:999 ./data/mariadb ./data/redis

# SSL certificate issues
docker compose logs bw_caddy
# Certificates will be regenerated automatically on first run
```

### **Service Startup Issues**
```bash
# Check service dependencies
docker compose ps

# View detailed logs
docker compose logs vaultwarden
docker compose logs bw_caddy

# Test configuration
./startup.sh --debug
```

### **Network and DNS Issues**
```bash
# Check DNS propagation
nslookup vault.yourdomain.com
dig vault.yourdomain.com

# Verify firewall rules
sudo ufw status
curl -I http://$(curl -s ifconfig.me)

# Test SSL certificate generation
curl -I https://vault.yourdomain.com
```

## **Advanced Recovery Scenarios**

### **Partial Data Recovery**
If you only need specific components:

```bash
# Extract only configuration files
tar -xzf backup.tar.gz
tar -xzf extracted_dir/configuration.tar.gz

# Extract only database backup
tar -xzf backup.tar.gz
cp extracted_dir/db_backup_*.sql* ./data/backups/
```

### **Cross-Platform Migration**
Moving between different architectures:

```bash
# Backup includes system info for validation
./backup/full-backup/validate-backup.sh --deep backup.tar.gz

# Check platform compatibility in system_info.txt
tar -xzf backup.tar.gz
cat extracted_dir/system_info.txt
```

### **Multiple VM Deployment**
For staging/production environments:

```bash
# Create environment-specific settings
cp settings.env settings.env.production
cp settings.env settings.env.staging

# Deploy to different VMs with appropriate configs
./backup/full-backup/rebuild-vm.sh backup.tar.gz
# Then manually update settings.env for each environment
```

---

**Remember**: The key to successful disaster recovery is **regular testing and validation**. Don't wait for an emergency to discover issues with your backup and restoration procedures!

## **Quick Reference Commands**

```bash
# Create full backup
./backup/full-backup/create-full-backup.sh

# Validate backup
./backup/full-backup/validate-backup.sh --latest

# Automated disaster recovery
./backup/full-backup/rebuild-vm.sh backup_file.tar.gz

# Manual restoration
./backup/full-backup/restore-full-backup.sh backup_file.tar.gz

# Post-restoration verification
./diagnose.sh
./dashboard.sh
```
