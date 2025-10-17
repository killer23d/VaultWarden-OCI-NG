# Deployment Guide

This guide provides comprehensive documentation for deploying the VaultWarden-OCI-NG stack, from initial server setup to a fully operational password management service.

## Overview

The VaultWarden-OCI-NG deployment process is designed around three core principles:

1. **Automation First**: Minimal manual configuration required
2. **Security by Default**: All sensitive data encrypted, secure defaults applied
3. **Operational Simplicity**: One-command deployment and management

## Architecture Components

### Core Services
* **VaultWarden**: Rust-based Bitwarden-compatible server
* **Caddy**: Automatic HTTPS reverse proxy with Let's Encrypt integration  
* **Fail2ban**: Intrusion prevention and IP blocking
* **Watchtower**: Automated container updates
* **ddclient**: Dynamic DNS updates (optional)

### Security Layer
* **SOPS + Age**: End-to-end encryption for secrets management
* **Docker Secrets**: Secure runtime secret injection
* **UFW**: Host-level firewall with minimal attack surface
* **Automated SSL**: Let's Encrypt certificates with automatic renewal

## Pre-Deployment Requirements

### Server Specifications

**Minimum Requirements:**
* OS: Ubuntu 24.04 LTS (fresh installation recommended)
* RAM: 2GB 
* Storage: 20GB SSD
* Network: Public IP with ports 22, 80, 443 accessible

**Recommended for Production:**
* RAM: 4GB+ for teams over 10 users
* Storage: 50GB+ SSD for long-term growth
* Backup solution for off-site data protection

### Network Prerequisites

1. **Domain Configuration:**
   * Registered domain name (e.g., `vault.company.com`)
   * DNS A record pointing to server's public IP
   * Optional: CloudFlare for enhanced DDoS protection

2. **Firewall Planning:**
   * SSH access (port 22) from management networks
   * HTTP (port 80) for Let's Encrypt validation
   * HTTPS (port 443) for application access

## Deployment Process

### Phase 1: Server Preparation

#### Initial Server Setup
```bash
# Connect via SSH
ssh ubuntu@YOUR_SERVER_IP

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required system packages
sudo apt install -y git curl wget unzip
```

#### Repository Setup
```bash
# Clone the repository
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG

# CRITICAL: Set executable permissions
chmod +x startup.sh tools/*.sh lib/*.sh

# Verify permissions
ls -la startup.sh tools/ | grep rwx
```

### Phase 2: Automated Installation

The `init-setup.sh` script performs comprehensive system preparation:

#### What the Script Does
* **Docker Installation**: Latest stable Docker and Docker Compose
* **Security Hardening**: UFW firewall configuration with minimal rules
* **Intrusion Prevention**: Fail2ban installation with VaultWarden-specific jails
* **Secret Management**: SOPS + Age key generation and configuration
* **System Integration**: Cron jobs for automated maintenance
* **Directory Structure**: Secure directory creation with proper permissions

#### Running the Setup
```bash
# Execute the automated setup
sudo ./tools/init-setup.sh

# Follow interactive prompts for:
# - Domain name configuration
# - Administrator email address
# - Optional SMTP settings
# - Optional CloudFlare integration
```

#### Non-Interactive Installation
For automation or CI/CD deployments:
```bash
# Set environment variables first
export DOMAIN="https://vault.company.com"
export ADMIN_EMAIL="admin@company.com"

# Run in non-interactive mode  
sudo ./tools/init-setup.sh --auto
```

### Phase 3: Service Deployment

#### Starting the Stack
```bash
# Launch all services with health checks
./startup.sh

# Monitor startup process
docker compose ps
```

#### Startup Process Details
The `startup.sh` script orchestrates:

1. **Secret Decryption**: SOPS+Age secrets loaded securely
2. **Environment Preparation**: Dynamic paths and network configuration
3. **Pre-flight Checks**: System validation and dependency verification
4. **Service Orchestration**: Containers started in dependency order
5. **Health Validation**: Application readiness confirmed
6. **Status Reporting**: Service information and access details

### Phase 4: Initial Configuration

#### Accessing the Admin Panel
```bash
# Retrieve the admin token
sudo ./tools/edit-secrets.sh --view | grep admin_token
```

Navigate to `https://your-domain.com/admin` and use the retrieved token.

#### Essential Admin Settings
1. **Organization Settings**: Configure organization name and policies
2. **User Registration**: Set signup policies (open/invite-only/disabled)
3. **Security Policies**: Password requirements and two-factor authentication
4. **SMTP Configuration**: Email settings for notifications and invitations

## Post-Deployment Configuration

### Backup System Verification

The deployment automatically configures encrypted backups:

```bash
# Verify backup configuration
crontab -l | grep -E "(backup|maintenance)"

# Test backup creation
./tools/db-backup.sh --dry-run

# Check backup directory
ls -la $PROJECT_STATE_DIR/backups/
```

**Automated Backup Schedule:**
* Database backups: Daily at 2:00 AM
* Full system backups: Weekly on Sundays at 3:00 AM
* SQLite maintenance: Weekly on Saturdays at 1:00 AM

### Monitoring System Setup

Health monitoring runs automatically via cron:

```bash
# View monitoring schedule
crontab -l | grep monitor

# Run manual health check
./tools/check-health.sh

# Check monitoring logs
journalctl -t monitor | tail -20
```

**Monitoring Capabilities:**
* Service health verification
* SSL certificate expiration tracking
* Disk space and resource monitoring
* Automatic service restart on failure
* Email notifications for critical issues

### Security Verification

#### Firewall Status
```bash
sudo ufw status verbose
# Expected: SSH (22), HTTP (80), HTTPS (443) allowed; default deny
```

#### Fail2ban Protection  
```bash
sudo fail2ban-client status
# Should show active jails: sshd, vaultwarden-auth, caddy-limit
```

#### SSL Certificate Validation
```bash
# Check certificate status
docker compose exec caddy caddy list-certificates

# Test SSL security (external tool)
# Visit: https://www.ssllabs.com/ssltest/
# Should achieve A+ rating with proper configuration
```

## Advanced Deployment Options

### CloudFlare Integration

For enhanced security and performance:

#### DNS Configuration
1. Transfer domain to CloudFlare nameservers
2. Configure DNS A record with "Proxied" status (orange cloud)
3. Set SSL/TLS mode to "Full (strict)"

#### API Integration
```bash
# Edit encrypted secrets
sudo ./tools/edit-secrets.sh

# Add CloudFlare credentials:
# cloudflare_api_token: "your-api-token"
```

#### Security Settings
* Enable "Always Use HTTPS"
* Configure Browser Integrity Check
* Set Security Level to "Medium" or higher
* Enable Bot Fight Mode for additional protection

### SMTP Configuration

#### Gmail Integration
```bash
# Edit secrets file
sudo ./tools/edit-secrets.sh

# Add SMTP configuration:
# smtp_password: "your-gmail-app-password"

# Update settings.env file:
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=your-email@gmail.com
# SMTP_FROM=vaultwarden@your-domain.com
```

#### Other SMTP Providers
The stack supports any SMTP provider. Common configurations:
* **Outlook**: smtp-mail.outlook.com:587
* **Yahoo**: smtp.mail.yahoo.com:587  
* **Custom**: Your organization's SMTP server

### Database Options

#### SQLite (Default)
* Suitable for small to medium teams (up to 50 users)
* Zero configuration required
* Automatic backup and maintenance included

#### PostgreSQL Migration
For larger deployments:
```bash
# Update docker-compose.yml to include PostgreSQL service
# Modify DATABASE_URL in configuration
# Use migration tools for data transfer
```

## Deployment Validation

### Comprehensive Health Check
```bash
# Run full system validation
./tools/check-health.sh --verbose

# Expected results:
# ✅ All containers healthy
# ✅ SSL certificate valid
# ✅ Database accessible
# ✅ Backup system functional  
# ✅ Security services active
# ✅ Monitoring operational
```

### Performance Testing
```bash
# Check resource usage
docker stats

# Monitor system performance
htop

# Test application responsiveness
curl -I https://your-domain.com
```

### Security Audit
```bash
# Review firewall rules
sudo ufw status numbered

# Check fail2ban activity
sudo fail2ban-client status vaultwarden-auth

# Verify file permissions
find . -name "*.sh" -exec ls -la {} \;
```

## Troubleshooting Deployment Issues

### Common Problems

#### 1. Permission Errors
**Symptom**: `bash: ./startup.sh: Permission denied`
**Solution**: 
```bash
chmod +x startup.sh tools/*.sh lib/*.sh
```

#### 2. Docker Installation Issues
**Symptom**: `docker: command not found`
**Solution**:
```bash
# Re-run setup script
sudo ./tools/init-setup.sh

# Or manual Docker installation
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

#### 3. SSL Certificate Failures
**Symptom**: Browser SSL warnings
**Causes & Solutions**:
* Domain not publicly accessible → Check DNS and firewall
* Let's Encrypt rate limits → Wait 1 hour or use staging environment
* CloudFlare SSL mode incorrect → Set to "Full (strict)"

#### 4. Service Startup Failures
**Symptom**: Containers not starting or unhealthy
**Diagnosis**:
```bash
# Check container status
docker compose ps

# Review service logs  
docker compose logs service-name

# Check system resources
free -h && df -h

# Validate configuration
./startup.sh --validate
```

#### 5. Database Connection Issues
**Symptom**: VaultWarden cannot connect to database
**Solutions**:
```bash
# Check database file permissions
ls -la $PROJECT_STATE_DIR/data/bwdata/

# Verify SQLite database integrity
./tools/sqlite-maintenance.sh --check

# Restart database service
docker compose restart vaultwarden
```

### Recovery Procedures

#### Complete Stack Restart
```bash
# Stop all services
docker compose down

# Clear any orphaned containers
docker system prune -f

# Restart with full validation
./startup.sh --validate
./startup.sh
```

#### Configuration Reset
```bash
# Backup current configuration
cp settings.json settings.json.backup

# Re-run initial setup
sudo ./tools/init-setup.sh

# Restore specific settings if needed
```

#### Emergency Access Recovery
```bash
# Reset admin token
sudo ./tools/edit-secrets.sh
# Generate new admin_token value

# Restart VaultWarden service
docker compose restart vaultwarden

# Access admin panel with new token
```

## Maintenance and Updates

### Regular Maintenance Tasks

#### Automated Updates
Watchtower handles container updates automatically. Configuration:
```bash
# Check Watchtower logs
docker compose logs watchtower

# Manual update trigger
docker compose restart watchtower
```

#### Database Maintenance
```bash
# Weekly SQLite optimization (automated)
./tools/sqlite-maintenance.sh --full

# Manual database check
./tools/sqlite-maintenance.sh --check --verbose
```

#### Log Management
```bash
# Log rotation is automatic, but manual cleanup:
docker system prune --volumes -f

# Check log sizes
docker compose exec caddy du -sh /var/log/caddy/*
```

### Backup Management

#### Manual Backup Creation
```bash
# Full system backup
./tools/create-full-backup.sh

# Database-only backup
./tools/db-backup.sh

# List available backups
./tools/restore.sh --list
```

#### Backup Verification
```bash
# Test backup integrity
./tools/restore.sh --verify /path/to/backup

# Restore simulation (dry-run)
./tools/restore.sh --dry-run /path/to/backup
```

## Production Considerations

### Scalability Planning
* Monitor user growth and resource utilization
* Plan database migration to PostgreSQL for 50+ users  
* Consider load balancing for high availability deployments

### Security Hardening
* Regular security updates via automated patching
* Periodic security audit of configurations
* Implement network segmentation if required
* Consider additional monitoring tools (e.g., fail2ban, intrusion detection)

### Disaster Recovery
* Off-site backup storage configuration
* Recovery time objective (RTO) planning
* Regular disaster recovery testing
* Documentation of recovery procedures

This deployment guide provides a comprehensive foundation for running VaultWarden-OCI-NG in production environments. For specific use cases or advanced configurations, refer to the additional documentation files in the `docs/` directory.
