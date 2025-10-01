# **VaultWarden-OCI-NG**
*Comprehensive, Secure, and Automated Vaultwarden Deployment for Oracle Cloud Infrastructure*

This project provides a production-ready, comprehensive setup for self-hosting Vaultwarden (a Bitwarden-compatible password manager server) using Docker Compose. While optimized for Oracle Cloud Infrastructure (OCI) A1 Flex ARM64 instances, it's fully portable to other Linux environments.

## **🌟 Key Features**

### **Core Stack Components**
- **Vaultwarden**: Latest Bitwarden-compatible password manager server
- **MariaDB 11**: High-performance database with ARM64 optimization  
- **Redis 7**: Advanced caching layer for improved performance
- **Caddy v2**: Modern reverse proxy with automatic HTTPS and HTTP/3 support
- **Fail2ban**: Intelligent intrusion detection with custom Vaultwarden rules
- **Automated Backups**: Encrypted daily backups to cloud storage via rclone
- **Watchtower**: Automatic container updates with configurable scheduling
- **Comprehensive Management**: Suite of monitoring, diagnostic, and maintenance scripts

### **Advanced Security & Management**
- **OCI Vault Integration**: Enterprise-grade secret management
- **Profile-Based Architecture**: Modular service deployment (core, backup, security, DNS, maintenance)
- **Resource Optimization**: Memory limits and CPU allocation optimized for OCI A1 Flex
- **Cloudflare Integration**: Auto-updating IP ranges for enhanced security
- **Email Notifications**: Comprehensive alerting system for backups, security, and system health
- **Performance Monitoring**: Built-in metrics collection and alerting
- **Full Disaster Recovery**: Complete VM migration and restoration system

## **⚠️ Important Setup Notice**

This project requires **manual configuration** before first use. Simply cloning and running will not work. You must:

1. **Create and configure `settings.env`** from the provided template
2. **Set up rclone configuration** for cloud backups (optional but recommended)  
3. **Configure your domain DNS** to point to your server
4. **Follow the complete setup process** outlined below

## **📋 System Requirements**

### **Hardware Requirements**
- **Oracle A1 Flex**: 1 OCPU ARM64, 6GB RAM (free tier) - *recommended*
- **Alternative**: Any Linux ARM64/x64 system with 2GB+ RAM and 20GB+ storage
- **Network**: Public IP address with HTTP/HTTPS access

### **Software Prerequisites**
- **Operating System**: Ubuntu 22.04 LTS (recommended) or compatible Linux distribution
- **Docker**: Version 20.10+ 
- **Docker Compose**: Version 2.0+
- **Domain Name**: Owned domain with DNS management access
- **SMTP Provider**: Email service for notifications (MailerSend, SendGrid, Gmail, etc.)
- **Cloud Storage**: rclone-compatible provider (optional but recommended)

### **Service Requirements**
- **DNS Provider**: Cloudflare recommended (free tier sufficient)
- **SSL Certificates**: Automatically managed by Caddy via Let's Encrypt
- **Backup Storage**: Backblaze B2, AWS S3, Google Drive, or any rclone-compatible provider

## **🚀 Quick Start Guide**

### **1. System Preparation**

#### **For Fresh OCI A1 Flex Instance:**
```bash
# Run the automated setup script
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG
chmod +x *.sh
./init-setup.sh
```

#### **Manual Setup (Any Linux System):**

**Install Docker & Docker Compose:**
```bash
# Update system
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key and repository
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Configure Docker for current user
sudo usermod -aG docker $USER && newgrp docker
```

**Configure Memory Swap (OCI A1 Flex):**
```bash
# Create 2GB swap file
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

**Configure Firewall:**
```bash
# OCI Console: Add ingress rules for ports 80 and 443 (source: 0.0.0.0/0)
# Local firewall (if enabled):
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload
```

### **2. Environment Configuration**

**Create Configuration File:**
```bash
cp settings.env.example settings.env
nano settings.env  # or use your preferred editor
```

**Critical Configuration Values:**

```bash
# Domain Configuration (REQUIRED)
DOMAIN_NAME=yourdomain.com
APP_DOMAIN=vault.yourdomain.com
DOMAIN=https://vault.yourdomain.com
ADMIN_EMAIL=admin@yourdomain.com

# Generate Strong Passwords (REQUIRED)
ADMIN_TOKEN=$(openssl rand -base64 32)
MARIADB_ROOT_PASSWORD=$(openssl rand -base64 32) 
MARIADB_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
BACKUP_PASSPHRASE=$(openssl rand -base64 32)

# Ensure Database URL matches MariaDB password exactly
DATABASE_URL=mysql://vaultwarden:${MARIADB_PASSWORD}@bw_mariadb:3306/vaultwarden

# SMTP Configuration (for notifications)
SMTP_HOST=smtp.youremailprovider.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=vault@yourdomain.com

# Profile Control (adjust as needed)
ENABLE_BACKUP=true
ENABLE_SECURITY=true  
ENABLE_DNS=false
ENABLE_MAINTENANCE=true
```

### **3. Backup Configuration (Recommended)**

**Setup rclone for Cloud Backups:**
```bash
# Copy template and configure
cp backup/templates/rclone.conf.example backup/config/rclone.conf

# Interactive configuration (run after first startup)
docker compose --profile backup up -d bw_backup
docker compose exec bw_backup rclone config

# Test configuration
docker compose exec bw_backup rclone lsd your-remote-name:
```

### **4. Deploy the Stack**

**Validate Configuration:**
```bash
./diagnose.sh  # Comprehensive pre-flight check
```

**Launch Services:**
```bash
./startup.sh  # Automatic profile-based deployment
```

**Verify Deployment:**
```bash
./monitor.sh  # Real-time status dashboard
```

Your Vaultwarden instance will be available at `https://vault.yourdomain.com`

## **🛠️ Advanced Configuration**

### **OCI Vault Integration (Production Recommended)**

For enhanced security, store all secrets in Oracle Cloud Vault:

```bash
# Automated OCI setup (installs OCI CLI if needed)
./oci_setup.sh

# Deploy using OCI Vault
export OCI_SECRET_OCID="ocid1.vaultsecret.oc1..."
./startup.sh
```

**Benefits:**
- Secrets never stored in plaintext on disk
- Hardware-backed encryption via OCI KMS
- Centralized secret management
- Audit trail for all secret access

### **Profile-Based Architecture**

The system uses Docker Compose profiles for modular deployment:

```bash
# Core services only (minimal deployment)
docker compose up -d

# Full production deployment
./startup.sh  # Auto-detects enabled profiles

# Manual profile selection
docker compose --profile backup --profile security --profile maintenance up -d
```

**Available Profiles:**
- **core**: Essential services (always enabled) - Vaultwarden, MariaDB, Redis, Caddy
- **backup**: Database backup and restore system
- **security**: Fail2ban intrusion protection
- **dns**: ddclient for dynamic DNS updates
- **maintenance**: Watchtower auto-updates and log rotation

### **Performance Optimization**

**OCI A1 Flex Optimized Settings:**
```bash
# Resource allocation (settings.env)
VAULTWARDEN_WORKERS=2
DATABASE_MAX_CONNECTIONS=15
REDIS_MAX_CONNECTIONS=25

# Memory limits (docker-compose.yml)
# MariaDB: 1GB, Vaultwarden: 512MB, Redis: 256MB
# Total: ~2GB used, ~4GB free for system overhead
```

## **📊 Management Scripts**

| Script | Purpose | Usage |
|--------|---------|-------|
| **init-setup.sh** | Automated fresh system setup | `./init-setup.sh` |
| **startup.sh** | Main deployment script with profile management | `./startup.sh [--debug] [--force-ip-update]` |
| **monitor.sh** | Real-time service monitoring dashboard | `./monitor.sh` |
| **diagnose.sh** | Comprehensive system health check | `./diagnose.sh [--docker] [--network]` |
| **dashboard.sh** | Interactive management dashboard | `./dashboard.sh` |
| **perf-monitor.sh** | Performance monitoring and metrics | `./perf-monitor.sh [status\|monitor\|report]` |
| **alerts.sh** | Alert system management | `./alerts.sh [setup\|test\|status]` |
| **benchmark.sh** | System performance benchmarking | `./benchmark.sh` |
| **oci_setup.sh** | OCI Vault integration setup | `./oci_setup.sh [setup\|update]` |

## **🔐 Security Features**

### **Built-in Security**
- **Automatic HTTPS**: Let's Encrypt certificates with auto-renewal
- **Security Headers**: HSTS, CSP, X-Frame-Options, referrer policy
- **Fail2ban Protection**: Custom rules for Vaultwarden with IP blocking
- **Cloudflare Integration**: Auto-updating IP trust lists
- **Network Isolation**: Secure Docker bridge networks
- **User Isolation**: Non-root container execution where possible

### **Advanced Security Options**
- **OCI Vault**: Hardware-backed secret encryption
- **Encrypted Backups**: GPG encryption with configurable retention
- **Memory-only Secrets**: Configuration wiped from disk after startup
- **Audit Logging**: Comprehensive access and security logging

## **💾 Backup & Restore**

### **Backup System Architecture**

VaultWarden-OCI-NG includes two complementary backup systems:

1. **Regular Database Backups** (`/backup/`) - Daily automated encrypted backups
2. **Full System Backups** (`/backup/full-backup/`) - Complete disaster recovery for VM migration

### **Regular Database Backups**
- **Daily Schedule**: Automatic encrypted backups at 2 AM UTC
- **Cloud Upload**: Secure upload to configured rclone remote
- **Email Notifications**: Success/failure alerts
- **Retention Management**: Configurable local and remote retention
- **Verification**: Backup integrity checks

### **Full System Disaster Recovery**

The `/backup/full-backup/` directory contains comprehensive disaster recovery tools for complete VM migration and system restoration.

#### **Full Backup Scripts**

| Script | Purpose | Usage |
|--------|---------|-------|
| **create-full-backup.sh** | Create complete system backup for migration | `./backup/full-backup/create-full-backup.sh` |
| **restore-full-backup.sh** | Restore complete system from backup | `./backup/full-backup/restore-full-backup.sh backup.tar.gz` |
| **rebuild-vm.sh** | Automated complete disaster recovery | `./backup/full-backup/rebuild-vm.sh backup.tar.gz` |
| **validate-backup.sh** | Comprehensive backup integrity validation | `./backup/full-backup/validate-backup.sh --latest` |

#### **What's Included in Full Backups**

A complete system backup includes:
- ✅ **Database Content** (all user data, organizations, ciphers, attachments)
- ✅ **Configuration Files** (settings.env, docker-compose.yml, all scripts)  
- ✅ **SSL Certificates** (Let's Encrypt certificates from Caddy)
- ✅ **User Attachments** (uploaded files)
- ✅ **Application Data** (complete VaultWarden data directory)
- ✅ **Security Configurations** (fail2ban rules, Cloudflare IP lists)
- ✅ **System Information** (environment details for troubleshooting)

#### **Creating Full System Backups**

```bash
# Create comprehensive backup (recommended before major changes)
./backup/full-backup/create-full-backup.sh

# Backup is saved to: ./migration_backups/vaultwarden_full_YYYYMMDD_HHMMSS.tar.gz
# Includes checksums: .sha256, .md5, and _manifest.txt files
```

**Backup Contents:**
- **Size**: Typically 50MB-500MB depending on data and attachments
- **Location**: `./migration_backups/` directory
- **Format**: Compressed tar.gz with integrity checksums
- **Encryption**: Database components are GPG encrypted with `BACKUP_PASSPHRASE`

#### **Disaster Recovery Process**

**Option A - Automated Recovery (Recommended):**
```bash
# Transfer backup to new VM
scp backup_file.tar.gz user@new-vm:/path/to/VaultWarden-OCI-NG/

# Run complete automated recovery
./backup/full-backup/rebuild-vm.sh vaultwarden_full_YYYYMMDD_HHMMSS.tar.gz
```

**Option B - Manual Step-by-Step Recovery:**
```bash
# 1. Prepare new VM with init-setup.sh
./init-setup.sh

# 2. Restore from backup  
./backup/full-backup/restore-full-backup.sh backup_file.tar.gz

# 3. Update configuration for new environment
nano settings.env  # Update domain, IPs, etc.

# 4. Update DNS records to point to new VM

# 5. Start services
./startup.sh

# 6. Verify restoration
./diagnose.sh
```

#### **Backup Validation and Testing**

```bash
# Validate latest backup
./backup/full-backup/validate-backup.sh --latest

# Validate all backups  
./backup/full-backup/validate-backup.sh --all

# Deep validation with extraction test
./backup/full-backup/validate-backup.sh --deep backup_file.tar.gz

# Check specific backup integrity
./backup/full-backup/validate-backup.sh backup_file.tar.gz
```

### **Manual Database Operations**
```bash
# Manual database backup
docker compose exec bw_backup /backup/db-backup.sh

# Force backup (ignore recency check)
docker compose exec bw_backup /backup/db-backup.sh --force

# Local backup only (no upload)
docker compose exec bw_backup /backup/db-backup.sh --no-upload

# Verify database backup integrity
docker compose exec bw_backup /backup/verify-backup.sh --file /backups/filename.sql.gpg
```

### **Database Restore Process**
```bash
# Stop services
docker compose down

# Interactive restore (lists available backups)
./backup/db-restore.sh

# Restart services
./startup.sh
```

### **VM Migration Timeline**

| Phase | Time Required | Description |
|-------|---------------|-------------|
| **Backup Creation** | 15-30 minutes | Create full system backup with validation |
| **VM Provisioning** | 10-15 minutes | Set up new OCI A1 Flex instance |  
| **System Recovery** | 30-45 minutes | Automated rebuild or manual restoration |
| **DNS Propagation** | 5-60 minutes | Update DNS and wait for propagation |
| **Verification** | 15-30 minutes | Complete functionality testing |
| **Total Downtime** | **1.5-3 hours** | Depending on method and DNS provider |

### **Best Practices**

#### **Backup Schedule**
- ✅ **Daily**: Automated database backups (existing system)
- ✅ **Weekly**: Full system backups for disaster recovery  
- ✅ **Monthly**: Backup validation and cleanup
- ✅ **Quarterly**: Complete disaster recovery testing on test VM

#### **Retention Strategy**
```bash
# Clean old full backups (keep last 5)
cd ./migration_backups/
ls -t vaultwarden_full_*.tar.gz | tail -n +6 | xargs rm -f
ls -t vaultwarden_full_*.sha256 | tail -n +6 | xargs rm -f  
ls -t vaultwarden_full_*.md5 | tail -n +6 | xargs rm -f
```

#### **Remote Storage Integration**
Full backups automatically upload to configured rclone remote:
```bash
# Upload location: ${BACKUP_REMOTE}:${BACKUP_PATH}/full/
# Includes: .tar.gz, checksums, and manifest files
```

**⚠️ Critical Security**: Store your `BACKUP_PASSPHRASE` securely. Without it, encrypted database backups cannot be restored.

## **🔧 Maintenance**

### **Automated Operations**
- **Container Updates**: Watchtower checks weekly (configurable)
- **IP Updates**: Cloudflare ranges updated at startup + optional weekly cron
- **Log Rotation**: Automatic log cleanup and rotation
- **Health Monitoring**: Continuous service health checks
- **Resource Monitoring**: Automated alerts for disk/memory usage

### **Manual Operations**
```bash
# Service monitoring
./monitor.sh              # Real-time dashboard
./perf-monitor.sh status   # Performance metrics

# Health diagnostics  
./diagnose.sh             # Full system check
./diagnose.sh --network   # Network connectivity test

# Maintenance tasks
./caddy/update_cloudflare_ips.sh  # Update Cloudflare IPs
docker compose logs [service]     # View service logs

# Resource monitoring
docker stats              # Real-time resource usage
df -h ./data              # Disk usage
```

### **Cloudflare IP Management**
```bash
# Set up weekly automatic updates
(crontab -l 2>/dev/null; echo "0 2 * * 0 $(pwd)/caddy/update_cloudflare_ips.sh") | crontab -

# Manual update
./caddy/update_cloudflare_ips.sh
```

## **🚨 Troubleshooting**

### **Common Issues & Solutions**

| Issue | Symptoms | Solution |
|-------|----------|----------|
| **Container startup failure** | Services fail health checks | Check logs: `docker compose logs [service]` |
| **Database connection errors** | Vaultwarden can't connect to MariaDB | Verify `DATABASE_URL` password matches `MARIADB_PASSWORD` |
| **SMTP authentication failure** | Email notifications not working | Use `SMTP_USERNAME`/`SMTP_PASSWORD` (not `SMTP_USER`) |
| **Backup container won't start** | Backup service fails to initialize | Ensure `backup/config/rclone.conf` exists |
| **SSL certificate issues** | HTTPS not working | Check domain DNS, verify `ADMIN_EMAIL` in settings.env |
| **Memory issues (OCI A1)** | Containers killed by OOM | Configure swap file, monitor with `docker stats` |
| **Blocked by Fail2ban** | Cannot access instance | Check banned IPs: `docker compose exec bw_fail2ban fail2ban-client status vaultwarden` |

### **Diagnostic Commands**
```bash
# Comprehensive diagnostics
./diagnose.sh

# Network connectivity test
./diagnose.sh --network

# Docker environment check
./diagnose.sh --docker

# Performance analysis
./perf-monitor.sh report

# Service logs
docker compose logs --tail=50 --follow [service_name]
```

### **Recovery Procedures**
```bash
# Emergency service restart
docker compose restart [service_name]

# Full stack restart
docker compose down && ./startup.sh

# Reset fail2ban (if locked out)
docker compose exec bw_fail2ban fail2ban-client unban YOUR_IP_ADDRESS

# Database recovery
docker compose down
./backup/db-restore.sh
./startup.sh

# Complete disaster recovery
./backup/full-backup/rebuild-vm.sh backup_file.tar.gz
```

## **📈 Performance Monitoring**

### **Built-in Monitoring**
```bash
# Real-time dashboard
./dashboard.sh

# Performance metrics
./perf-monitor.sh status    # Current status
./perf-monitor.sh monitor   # Live monitoring  
./perf-monitor.sh report    # Detailed analysis

# Resource alerts
./alerts.sh status          # Alert system status
./alerts.sh test            # Test notifications
```

### **Resource Thresholds (OCI A1 Optimized)**
- **Memory**: Alert at 85% usage (~5.1GB of 6GB)
- **CPU**: Alert at 80% sustained load
- **Disk**: Alert at 85% usage
- **Database**: Monitor connection count and query performance
- **Network**: Monitor failed connection attempts

## **🔄 Updates & Upgrades**

### **Automatic Updates**
- **Watchtower**: Manages container image updates
- **Schedule**: Weekly by default (Sunday 3 AM)
- **Safety**: Only updates tagged with `com.centurylinklabs.watchtower.enable=true`

### **Manual Updates**
```bash
# Update specific service
docker compose pull [service_name]
docker compose up -d [service_name]

# Update entire stack
docker compose pull
./startup.sh

# Update management scripts
git pull origin main
chmod +x *.sh
```

## **📚 Additional Resources**

### **Configuration Templates**
- **settings.env.example**: Complete configuration template with explanations
- **backup/templates/rclone.conf.example**: rclone configuration examples for major cloud providers
- **fail2ban/jail.d/jail.local.template**: Fail2ban configuration template

### **External Documentation**
- [Vaultwarden Wiki](https://github.com/dani-garcia/vaultwarden/wiki)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Oracle Cloud Infrastructure Documentation](https://docs.oracle.com/en-us/iaas/Content/home.htm)
- [Cloudflare API Documentation](https://api.cloudflare.com/)

## **🤝 Contributing**

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test thoroughly on OCI A1 Flex
4. Submit a pull request with detailed description

## **📄 License**

This project is released under the MIT License. See LICENSE file for details.

## **⚠️ Disclaimer**

This project is provided as-is for educational and personal use. While designed with security best practices, users are responsible for:
- Securing their own infrastructure
- Managing their domain and DNS settings
- Backing up their data regularly
- Keeping systems updated
- Following their organization's security policies

**Production Use**: Thoroughly test in a non-production environment before deploying in production. Consider professional security auditing for business-critical deployments.

---

**🌟 Star this repository if it helped you deploy Vaultwarden successfully!**

*For issues, feature requests, or questions, please use the GitHub Issues tracker.*
