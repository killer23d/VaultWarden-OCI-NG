
## 🚀 Professional-Grade Vaultwarden Deployment for Oracle Cloud Infrastructure

A comprehensive, security-first, production-ready deployment solution for self-hosting [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible server) on Oracle Cloud Infrastructure (OCI) A1 Flex instances. This project provides enterprise-grade automation, monitoring, backup, and security features optimized for OCI's free tier.

### ✨ Key Features

- **🔒 Security-First Architecture**: Multi-layered security with fail2ban, Cloudflare integration, and automated SSL
- **📦 Production-Ready Stack**: Docker Compose with health checks, resource limits, and service dependencies
- **💾 Automated Backup System**: Encrypted backups to cloud storage with verification and retention policies
- **🔧 Profile-Based Deployment**: Modular service architecture (core, backup, security, dns, maintenance)
- **📊 Comprehensive Monitoring**: Performance monitoring, health checks, and alert management
- **🌐 OCI Optimized**: Specifically tuned for A1 Flex instances (1 OCPU ARM64, 6GB RAM)
- **🤖 Complete Automation**: One-command setup from fresh VM to running service
- **🔐 Enterprise Secrets Management**: Optional OCI Vault integration for secure configuration

## 📋 System Requirements

### Hardware Requirements
- **Oracle A1 Flex Instance**: 1 OCPU ARM64, 6GB RAM (free tier eligible)
- **Storage**: Minimum 20GB available disk space
- **Network**: Public IP with ports 80/443 accessible

### Software Prerequisites
- **Operating System**: Ubuntu 22.04 LTS (recommended) or compatible Linux distribution
- **Domain**: A domain name you control with DNS management access
- **Cloud Storage**: rclone-compatible provider for backups (optional)
- **SMTP Provider**: For email notifications (recommended)

### External Services
- **Cloudflare Account**: For DNS management and DDoS protection (recommended)
- **Email Provider**: SMTP service for notifications (MailerSend, SendGrid, etc.)
- **Backup Storage**: Cloud storage for automated backups (Backblaze B2, AWS S3, Google Drive, etc.)

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Internet Traffic                         │
│                   (Cloudflare CDN)                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  OCI A1 Flex Instance                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │               Docker Network (Bridge)                   │ │
│  │                                                         │ │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────────┐   │ │
│  │  │  Caddy   │  │ Vaultwarden  │  │    MariaDB      │   │ │
│  │  │(Reverse  │◄─┤   (App)      │◄─┤   (Database)   │   │ │
│  │  │ Proxy)   │  └──────┬───────┘  └─────────────────┘   │ │
│  │  └──────────┘         │                                │ │
│  │  ┌──────────┐         ▼                                │ │
│  │  │ fail2ban │  ┌──────────────┐  ┌─────────────────┐   │ │
│  │  │(Security)│  │    Redis     │  │   Backup System │   │ │
│  │  └──────────┘  │   (Cache)    │  │   (Automated)   │   │ │
│  │                └──────────────┘  └─────────────────┘   │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Service Components

| Service | Purpose | Profile | Resources |
|---------|---------|---------|-----------|
| **vaultwarden** | Core password manager application | core | 512MB RAM, 0.5 CPU |
| **bw_mariadb** | Primary database with optimization | core | 1GB RAM, 0.5 CPU |
| **bw_redis** | High-performance caching layer | core | 256MB RAM, 0.25 CPU |
| **bw_caddy** | Reverse proxy with auto-HTTPS | core | 256MB RAM, 0.25 CPU |
| **bw_fail2ban** | Intrusion detection/prevention | security | 128MB RAM, 0.25 CPU |
| **bw_backup** | Automated backup system | backup | 256MB RAM, 0.5 CPU |
| **bw_watchtower** | Container auto-updates | maintenance | 128MB RAM, 0.25 CPU |
| **bw_ddclient** | Dynamic DNS updates | dns | 64MB RAM, 0.1 CPU |

## 🚀 Quick Start

### 1. Initial System Setup

Run the automated setup script on your fresh OCI instance:

```bash
# Clone the repository
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG

# Run the initial setup (installs Docker, creates directories, etc.)
chmod +x init-setup.sh
./init-setup.sh
```

**What this script does:**
- ✅ Validates system requirements
- ✅ Installs Docker and Docker Compose
- ✅ Creates project directory structure
- ✅ Generates configuration templates
- ✅ Sets up proper permissions
- ✅ Optionally installs OCI CLI

### 2. Configure Your Installation

```bash
# Create your configuration from the template
cp settings.env.example settings.env

# Edit your configuration (CRITICAL STEP)
nano settings.env
```

**Required Configuration Changes:**

```bash
# 1. Set your domain
DOMAIN_NAME=yourdomain.com
APP_DOMAIN=vault.yourdomain.com
DOMAIN=https://vault.yourdomain.com

# 2. Generate secure passwords (run: openssl rand -base64 32)
ADMIN_TOKEN=your-generated-secure-token
MARIADB_ROOT_PASSWORD=your-generated-secure-password
MARIADB_PASSWORD=your-generated-secure-password
REDIS_PASSWORD=your-generated-secure-password
BACKUP_PASSPHRASE=your-generated-secure-passphrase

# 3. Configure SMTP for notifications
SMTP_HOST=smtp.yourmailprovider.com
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=vault@yourdomain.com

# 4. Set admin email for SSL certificates
ADMIN_EMAIL=admin@yourdomain.com
```

### 3. Configure DNS

Point your domain to your OCI instance:

```bash
# A record examples:
vault.yourdomain.com.  A  YOUR.OCI.PUBLIC.IP
```

### 4. Deploy VaultWarden

```bash
# Deploy with default profiles (core + security + maintenance)
./startup.sh

# Or deploy with specific profiles
ENABLE_BACKUP=true ENABLE_DNS=false ./startup.sh
```

### 5. Access Your Vault

- **Vault URL**: `https://vault.yourdomain.com`
- **Admin Panel**: `https://vault.yourdomain.com/admin`
- **Admin Token**: Use the `ADMIN_TOKEN` from your `settings.env`

## 🔧 Configuration Profiles

The deployment uses a modular profile system for flexible service management:

### Core Profile (Always Active)
- **vaultwarden**: Main application
- **bw_mariadb**: Database
- **bw_redis**: Cache
- **bw_caddy**: Reverse proxy

### Optional Profiles

| Profile | Services | Purpose | Enable Variable |
|---------|----------|---------|----------------|
| **security** | fail2ban | Intrusion protection | `ENABLE_SECURITY=true` |
| **backup** | backup system | Automated backups | `ENABLE_BACKUP=true` |
| **maintenance** | watchtower, logrotate | Updates & maintenance | `ENABLE_MAINTENANCE=true` |
| **dns** | ddclient | Dynamic DNS | `ENABLE_DNS=true` |

### Profile Usage Examples

```bash
# Core services only
docker compose up -d

# Core + security + backups
docker compose --profile security --profile backup up -d

# All services
ENABLE_BACKUP=true ENABLE_SECURITY=true ENABLE_MAINTENANCE=true ./startup.sh
```

## 💾 Backup System

### Automated Backup Features

- **📅 Scheduled Backups**: Daily database dumps with configurable timing
- **🔐 Encryption**: GPG encryption with passphrase protection
- **📦 Compression**: Automatic compression to save storage space
- **☁️ Cloud Storage**: Upload to any rclone-compatible provider
- **🔍 Verification**: Automatic backup integrity checking
- **📧 Notifications**: Email alerts for backup status
- **🗂️ Retention**: Configurable retention policies

### Setup Backup Storage

```bash
# Configure rclone for your cloud provider
docker compose exec bw_backup rclone config

# Test your backup configuration
docker compose exec bw_backup /scripts/db-backup.sh test

# Manual backup
docker compose exec bw_backup /scripts/db-backup.sh backup
```

### Restore from Backup

```bash
# List available backups
docker compose exec bw_backup /scripts/db-restore.sh list

# Restore specific backup
docker compose exec bw_backup /scripts/db-restore.sh restore backup-20231201-120000.sql.gz
```

## 🔒 Security Features

### Multi-Layer Security Architecture

1. **Application Security**
   - Admin token authentication
   - Configurable user registration
   - Two-factor authentication support
   - Session security headers

2. **Network Security**
   - fail2ban intrusion detection
   - Cloudflare IP whitelisting
   - Rate limiting and DDoS protection
   - Automatic HTTPS with HSTS

3. **Container Security**
   - Non-root user execution
   - Resource limits and isolation
   - Read-only filesystem mounts
   - Network segmentation

4. **Data Security**
   - Database encryption at rest
   - Encrypted backup storage
   - Secure secret management
   - OCI Vault integration (optional)

### fail2ban Configuration

The deployment includes custom fail2ban rules for Vaultwarden:

- **Admin Panel Protection**: Blocks repeated admin login failures
- **API Endpoint Protection**: Monitors suspicious API activity  
- **Rate Limiting**: Prevents brute force attacks
- **Automatic Unban**: Configurable ban duration and retry limits

## 📊 Monitoring & Management

### Built-in Management Tools

```bash
# Interactive monitoring dashboard
./dashboard.sh

# Performance monitoring
./perf-monitor.sh status

# Comprehensive diagnostics
./diagnose.sh

# System health check
./monitor.sh

# Alert management
./alerts.sh check
```

### Health Check Endpoints

- **Application Health**: `https://vault.yourdomain.com/health`
- **Service Status**: `docker compose ps`
- **Logs**: `docker compose logs -f [service-name]`

### Performance Monitoring

The system includes monitoring for:
- **Resource Usage**: CPU, memory, disk, network
- **Service Health**: Container status and health checks
- **Database Performance**: Connection pools, query performance
- **Backup Status**: Success rates, storage usage
- **Security Events**: fail2ban activity, failed login attempts

## 🔐 Advanced Configuration

### OCI Vault Integration

For enterprise deployments, store secrets securely in OCI Vault:

```bash
# Setup OCI Vault integration
./oci_setup.sh setup

# Deploy using OCI Vault
export OCI_SECRET_OCID="ocid1.vaultsecret.oc1..."
./startup.sh
```

### Custom SSL Certificates

If not using automatic HTTPS:

```bash
# Place certificates in caddy directory
./caddy/certs/cert.pem
./caddy/certs/key.pem

# Update Caddyfile to use custom certificates
```

### Database Optimization

MariaDB is pre-configured for OCI A1 Flex, but you can customize:

```bash
# Edit database configuration
nano config/mariadb/my.cnf

# Restart database service
docker compose restart bw_mariadb
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. SSL Certificate Issues
```bash
# Check Caddy logs
docker compose logs bw_caddy

# Verify DNS resolution
nslookup vault.yourdomain.com

# Test certificate generation
docker compose exec bw_caddy caddy validate --config /etc/caddy/Caddyfile
```

#### 2. Database Connection Issues
```bash
# Check database status
docker compose exec bw_mariadb mysqladmin ping

# Verify password configuration
grep DATABASE_URL settings.env
grep MARIADB_PASSWORD settings.env

# Check database logs
docker compose logs bw_mariadb
```

#### 3. Email/SMTP Issues
```bash
# Test SMTP configuration
docker compose exec vaultwarden vaultwarden test-smtp

# Check SMTP logs
docker compose logs vaultwarden | grep -i smtp
```

#### 4. Backup Failures
```bash
# Test rclone configuration
docker compose exec bw_backup rclone ls your-remote:

# Check backup logs
docker compose logs bw_backup
cat data/backup_logs/backup.log
```

### Performance Optimization

For better performance on OCI A1 Flex:

```bash
# Add swap space (recommended)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Optimize Docker daemon
sudo nano /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

## 📈 Maintenance

### Regular Maintenance Tasks

```bash
# Check system health
./monitor.sh

# Update container images (automatic with watchtower)
docker compose pull && docker compose up -d

# Clean up old logs and data
docker system prune -f

# Backup verification
docker compose exec bw_backup /scripts/verify-backup.sh

# Security audit
./diagnose.sh security
```

### Update Strategy

The deployment includes automatic updates via Watchtower:
- **Schedule**: Weekly on Sundays at 3 AM (configurable)
- **Safety**: Only updates when new versions are available
- **Rollback**: Maintains previous images for quick rollback
- **Notifications**: Email notifications for update status

## 🚨 Security Best Practices

### Recommended Security Settings

1. **Strong Passwords**: Use `openssl rand -base64 32` for all passwords
2. **Admin Token**: Generate a strong admin token and store securely
3. **Regular Updates**: Keep all containers updated (automatic with Watchtower)
4. **Backup Encryption**: Always encrypt backups with a strong passphrase
5. **Network Security**: Use Cloudflare for additional DDoS protection
6. **Access Control**: Limit admin panel access by IP if possible

### fail2ban Configuration

```bash
# View banned IPs
docker compose exec bw_fail2ban fail2ban-client status vaultwarden

# Unban an IP address
docker compose exec bw_fail2ban fail2ban-client set vaultwarden unbanip IP_ADDRESS

# View fail2ban logs
docker compose logs bw_fail2ban
```

## 📚 Documentation

### File Structure
```
VaultWarden-OCI-NG/
├── 📄 docker-compose.yml     # Main orchestration file
├── 📄 settings.env.example   # Configuration template
├── 📄 startup.sh            # Main deployment script
├── 📄 init-setup.sh         # Initial system setup
├── 📁 lib/                  # Shared utility functions
├── 📁 caddy/                # Reverse proxy configuration
├── 📁 fail2ban/             # Security configuration
├── 📁 backup/               # Backup system
├── 📁 config/               # Service configurations
└── 📁 data/                 # Persistent data (created at runtime)
```

### Environment Variables Reference

See the comprehensive `settings.env.example` file for all available configuration options organized by:
- **Domain & Security Configuration**
- **Database Configuration** 
- **SMTP Configuration**
- **Backup Configuration**
- **Performance Tuning**
- **Monitoring & Alerts**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/VaultWarden-OCI-NG.git

# Create development branch
git checkout -b feature/your-feature-name

# Test your changes
ENABLE_DEVELOPMENT=true ./startup.sh
```

