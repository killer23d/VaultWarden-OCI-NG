# Deployment Guide

> **🎯 Deployment Philosophy**: Streamlined, automated deployment for production VaultWarden environments with comprehensive validation, security hardening, and operational readiness.

## 🚀 **Deployment Overview**

VaultWarden-OCI-Minimal provides **multiple deployment pathways** optimized for different environments and requirements:

```bash
Deployment Options:
├── Quick Deployment (30 minutes) - Interactive setup with guided configuration
├── Automated Deployment (15 minutes) - Non-interactive with predefined settings  
├── Enterprise Deployment (45 minutes) - OCI Vault integration with enhanced security
├── Migration Deployment (60 minutes) - Migration from existing VaultWarden instances
├── Development Deployment (20 minutes) - Local testing and development setup
└── Production Hardened (90 minutes) - Maximum security with comprehensive validation
```

### **Deployment Readiness Assessment**

#### **Pre-Deployment Validation**
```bash
# Comprehensive pre-deployment check
./tools/init-setup.sh --validate-only

# Expected validation output:
🔍 VaultWarden-OCI-Minimal Deployment Readiness Check

System Requirements:
✅ Operating System: Ubuntu 24.04 LTS (supported)
✅ Available RAM: 4.0GB (exceeds 2GB minimum)
✅ Available Storage: 47.2GB (exceeds 20GB minimum)
✅ CPU Architecture: aarch64 (ARM64 - supported)
✅ Network Connectivity: Internet accessible
✅ DNS Resolution: Functional

Server Access:
✅ Root/sudo privileges: Available
✅ SSH access: Configured and secure
✅ Firewall access: Ports 22,80,443 configurable

Domain and Network:
✅ Domain name: vault.yourdomain.com (configured)
✅ DNS propagation: Complete (A record points to server)
✅ Port accessibility: 80,443 reachable from internet
✅ CloudFlare proxy: Ready (optional)

Dependencies Available:
✅ Package manager: apt (functional)
✅ Internet repositories: Accessible
✅ Container runtime: Docker will be installed
✅ Required tools: curl, jq, openssl available for install

🎯 Deployment Readiness: EXCELLENT
   Ready for production deployment
   Estimated setup time: 25-35 minutes
   Recommended deployment path: Quick Deployment
```

## 🌍 **Environment-Specific Deployments**

### **Oracle Cloud Infrastructure (OCI) A1 Flex**

#### **OCI A1 Flex Optimized Setup**
```bash
# Optimized for OCI Always Free tier ARM instances
# VM.Standard.A1.Flex: 1-4 OCPUs, 1-24GB RAM

Recommended Configuration:
├── Shape: VM.Standard.A1.Flex
├── OCPUs: 2 (sufficient for 10 users)
├── Memory: 12GB (provides comfortable headroom)
├── Boot Volume: 50GB (allows for growth)
├── Network: Public subnet with Internet Gateway
└── Security List: HTTP(80), HTTPS(443), SSH(22)

# OCI-specific optimizations automatically applied:
# - ARM64 container images selected
# - Memory limits optimized for small instances
# - Disk I/O optimization for block storage
# - Network configuration for OCI networking
```

#### **OCI Resource Creation**
```bash
# Using OCI CLI (alternative to web console)
# Create compartment
oci iam compartment create \
    --compartment-id "$TENANCY_OCID" \
    --name "vaultwarden-prod" \
    --description "VaultWarden production environment"

# Create VCN and subnet
oci network vcn create \
    --compartment-id "$COMPARTMENT_OCID" \
    --display-name "vaultwarden-vcn" \
    --cidr-block "10.0.0.0/16"

# Launch A1 Flex instance
oci compute instance launch \
    --compartment-id "$COMPARTMENT_OCID" \
    --availability-domain "AD-1" \
    --display-name "vaultwarden-server" \
    --image-id "$UBUNTU_2404_ARM_IMAGE_OCID" \
    --shape "VM.Standard.A1.Flex" \
    --shape-config '{"ocpus":2,"memoryInGBs":12}' \
    --subnet-id "$SUBNET_OCID" \
    --assign-public-ip true \
    --ssh-authorized-keys-file ~/.ssh/id_rsa.pub

# Configure security list (if not using default)
oci network security-list create \
    --compartment-id "$COMPARTMENT_OCID" \
    --vcn-id "$VCN_OCID" \
    --display-name "vaultwarden-security-list" \
    --ingress-security-rules '[
        {"source":"0.0.0.0/0","protocol":"6","tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},
        {"source":"0.0.0.0/0","protocol":"6","tcpOptions":{"destinationPortRange":{"min":80,"max":80}}},
        {"source":"0.0.0.0/0","protocol":"6","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}}
    ]'
```

#### **OCI-Optimized Deployment Process**
```bash
# Connect to OCI instance
ssh -i ~/.ssh/id_rsa ubuntu@$(oci compute instance get --instance-id $INSTANCE_OCID --query 'data."public-ip"' --raw-output)

# Deploy with OCI optimizations
sudo su -
cd /opt
git clone https://github.com/killer23d/VaultWarden-OCI-Minimal.git
cd VaultWarden-OCI-Minimal
chmod +x startup.sh tools/*.sh

# Run OCI-optimized setup
sudo ./tools/init-setup.sh --oci-optimized

# The OCI-optimized setup includes:
# - ARM64-specific container image selection
# - Memory optimization for A1 Flex instances
# - OCI Vault integration setup (optional)
# - Block storage optimization
# - Network performance tuning for OCI
```

### **Generic Ubuntu Server Deployment**

#### **Standard VPS/Dedicated Server**
```bash
# Suitable for: DigitalOcean, Linode, Vultr, AWS EC2, etc.
# Minimum specs: 1 vCPU, 2GB RAM, 20GB storage

Standard Deployment Process:
1. Server provisioning with Ubuntu 24.04 LTS
2. SSH key configuration and secure access
3. DNS configuration pointing to server IP
4. VaultWarden-OCI-Minimal deployment
5. SSL certificate provisioning via Let's Encrypt
6. Security hardening and monitoring setup

# Generic deployment command
sudo ./tools/init-setup.sh --generic

# Includes optimizations for:
# - Various cloud provider networking
# - Standard x86_64 architecture support
# - Generic Ubuntu package repositories
# - Common VPS provider configurations
```

#### **Behind Existing Reverse Proxy**
```bash
# Deployment behind existing nginx, Apache, or other reverse proxy
# Disables Caddy's SSL termination, uses HTTP only

# Configure for reverse proxy mode
cat > proxy-config.json << 'EOF'
{
  "PROXY_MODE": true,
  "INTERNAL_PORT": "8080",
  "DISABLE_SSL": true,
  "TRUST_PROXY_HEADERS": true,
  "PROXY_IP_RANGES": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}
EOF

# Deploy in proxy mode
sudo ./tools/init-setup.sh --proxy-mode --config proxy-config.json

# Reverse proxy configuration examples provided in templates/
# - nginx.conf.template
# - apache.conf.template  
# - traefik.yml.template
```

### **Development and Testing Deployment**

#### **Local Development Setup**
```bash
# Streamlined setup for development and testing
# Reduces security hardening for easier development

# Development deployment
sudo ./tools/init-setup.sh --development

# Development mode differences:
# - Relaxed firewall rules (all ports open locally)
# - Debug logging enabled by default
# - Shorter SSL certificate validation
# - Development domain support (*.localhost)
# - Hot-reload configuration for testing
```

## 📋 **Step-by-Step Production Deployment**

### **Phase 1: Infrastructure Preparation**

#### **Server Provisioning Checklist**
```bash
Infrastructure Requirements Checklist:

Server Specifications:
- [ ] Ubuntu 24.04 LTS (fresh installation)
- [ ] Minimum 2GB RAM (4GB+ recommended)
- [ ] Minimum 20GB storage (50GB+ recommended) 
- [ ] 1+ vCPU (2+ vCPUs recommended for 10 users)
- [ ] Public IP address assigned
- [ ] SSH access configured with key-based authentication

Network Configuration:
- [ ] Ports 22 (SSH), 80 (HTTP), 443 (HTTPS) accessible
- [ ] Firewall rules configured or configurable
- [ ] Domain name registered and DNS configured
- [ ] DNS A record pointing to server public IP
- [ ] DNS propagation completed (test with: nslookup your-domain.com)

Optional but Recommended:
- [ ] CloudFlare account for enhanced security/performance
- [ ] SMTP service account (Gmail, SendGrid, etc.)
- [ ] Backup storage location (cloud storage, external server)
- [ ] Monitoring service account (uptime monitoring)
```

#### **Initial Server Hardening**
```bash
# Basic server security before VaultWarden deployment
# (init-setup.sh handles additional hardening)

# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Secure SSH configuration (if not already done)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Set up fail2ban for SSH protection (basic)
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### **Phase 2: VaultWarden Deployment**

#### **Repository Setup and Validation**
```bash
# Step 1: Download and prepare VaultWarden-OCI-Minimal
cd /opt
sudo git clone https://github.com/killer23d/VaultWarden-OCI-Minimal.git
cd VaultWarden-OCI-Minimal

# Step 2: Set executable permissions (critical step)
sudo chmod +x startup.sh tools/*.sh lib/*.sh

# Step 3: Validate environment
sudo ./tools/init-setup.sh --validate-only

# Step 4: Review configuration template
cat settings.json.example

# Step 5: Prepare deployment information
echo "Deployment Checklist:"
echo "- Domain: vault.yourdomain.com"
echo "- Admin Email: admin@yourdomain.com"  
echo "- SMTP Host: smtp.gmail.com (or your provider)"
echo "- CloudFlare Email: (if using CloudFlare)"
echo "- CloudFlare API Key: (if using CloudFlare)"
```

#### **Interactive Production Deployment**
```bash
# Execute the comprehensive setup process
sudo ./tools/init-setup.sh

# Follow the interactive prompts:

🔧 VaultWarden-OCI-Minimal Production Setup

Environment Detection:
✅ Ubuntu 24.04 LTS detected
✅ ARM64 architecture (OCI A1 optimizations available)
✅ 12GB RAM available (excellent for small team deployment)
✅ 47GB storage available (sufficient with room for growth)

Setup Configuration:
[1] Quick Setup (recommended for most users)
[2] Advanced Setup (custom configuration options)
[3] Enterprise Setup (OCI Vault integration)
[4] Migration Setup (from existing VaultWarden)

Select setup type [1-4]: 1

🌐 Domain Configuration:
Enter your domain name (e.g., vault.example.com): vault.yourdomain.com
✅ Domain format valid
✅ DNS resolution successful (points to this server)

📧 Email Configuration:
Admin email address: admin@yourdomain.com
✅ Email format valid

SMTP Configuration (for notifications - can be configured later):
SMTP Host [smtp.gmail.com]: smtp.gmail.com
SMTP From Address [noreply@yourdomain.com]: 
SMTP Username (optional): your-email@gmail.com
SMTP Password (optional): [hidden input]
✅ SMTP configuration saved

🔐 CloudFlare Integration (optional but recommended):
Do you want to configure CloudFlare integration? [Y/n]: Y
CloudFlare Email: your-email@cloudflare.com
CloudFlare Global API Key: [hidden input]
✅ CloudFlare credentials validated

🛡️ Security Configuration:
[1] Standard Security (UFW + fail2ban)
[2] Enhanced Security (additional hardening)
[3] Maximum Security (strict rules, may affect usability)

Select security level [1-3]: 2

📦 Installing Dependencies...
✅ Docker and Docker Compose installed
✅ Security packages installed (fail2ban, ufw)
✅ Required tools installed (jq, curl, openssl)

🔧 Configuring Security...
✅ UFW firewall configured (SSH, HTTP, HTTPS allowed)
✅ Fail2ban configured with VaultWarden protection
✅ CloudFlare integration configured
✅ SSL certificate auto-renewal configured

📂 Creating System Structure...
✅ Project directories created with secure permissions
✅ Configuration files generated with random secrets
✅ Backup system configured and tested
✅ Monitoring cron jobs installed

⏰ Automated Maintenance Setup:
✅ Database backups: Daily at 1:00 AM
✅ Full system backups: Weekly on Sunday at 12:00 AM  
✅ Health monitoring: Every 5 minutes
✅ Security monitoring: Continuous
✅ Log rotation: Daily at 4:00 AM

🎯 Setup completed successfully!
Total setup time: 18 minutes

Next steps:
1. Start VaultWarden: ./startup.sh
2. Access web interface: https://vault.yourdomain.com
3. Access admin panel: https://vault.yourdomain.com/admin
4. Admin token: [displayed securely]

Important: Save the admin token securely - it's required for admin access.
```

#### **Service Startup and Validation**
```bash
# Start VaultWarden services
./startup.sh

# Expected startup output:
🚀 Starting VaultWarden-OCI-Minimal Stack

🔍 Pre-startup validation:
✅ System requirements met
✅ Docker daemon running
✅ Configuration valid
✅ Network connectivity confirmed

📂 Preparing environment:
✅ Runtime directories created
✅ Permissions applied
✅ Configuration exported

🔄 Starting services:
✅ VaultWarden container: Started
✅ Caddy reverse proxy: Started
✅ Fail2ban protection: Started  
✅ Watchtower updater: Started
✅ Health checks: All passed

🌐 Service validation:
✅ VaultWarden health endpoint: Responding
✅ HTTPS certificate: Valid (Let's Encrypt)
✅ Domain accessibility: https://vault.yourdomain.com
✅ Admin panel: https://vault.yourdomain.com/admin

🎯 VaultWarden-OCI-Minimal is now running!

Service Information:
- Web Interface: https://vault.yourdomain.com
- Admin Panel: https://vault.yourdomain.com/admin
- Admin Token: [securely displayed]
- Status: docker compose ps
- Logs: docker compose logs -f

Monitoring:
- Health checks running every 5 minutes
- Automated backups configured
- Security monitoring active
- Email notifications configured

Time to production ready: 23 minutes
```

### **Phase 3: Post-Deployment Validation**

#### **Comprehensive Production Readiness Check**
```bash
# Run comprehensive validation
./startup.sh --validate

# Production readiness verification
./tools/monitor.sh --production-check

# Expected production readiness output:
🏭 Production Readiness Assessment

Service Health:
✅ All containers healthy and responsive
✅ Database accessible (response time: 12ms)
✅ SSL certificate valid (expires: 87 days)
✅ Domain resolving correctly from external DNS
✅ Admin panel accessible with authentication

Security Posture:
✅ Firewall active with appropriate rules
✅ Fail2ban protecting all critical services
✅ SSL Labs rating: A+ (verified externally)
✅ Security headers properly configured
✅ File permissions secure (no world-writable files)

Performance Metrics:
✅ Memory usage: 892MB/12GB (7% - excellent)
✅ CPU usage: 2.3% average (low load)
✅ Disk usage: 2.1GB/47GB (4% - plenty of space)
✅ Response time: 89ms average (excellent)

Backup System:
✅ Backup directories created and accessible
✅ Backup encryption functioning correctly
✅ Automated backup schedule active
✅ Backup verification system operational

Monitoring System:
✅ Health checks running every 5 minutes
✅ Automated recovery mechanisms active
✅ Email notifications configured and tested
✅ System monitoring cron jobs installed

Compliance Readiness:
✅ Audit logging configured
✅ Data encryption at rest and in transit
✅ Access controls properly implemented
✅ Incident response procedures documented

🎯 Production Readiness Score: 98/100 (EXCELLENT)
   Minor recommendations:
   - Consider off-site backup storage
   - Set up external uptime monitoring
   
   System is ready for production use with confidence.
   Estimated user capacity: 15+ users (current: 0)
```

#### **User Acceptance Testing**
```bash
# Production acceptance test checklist

Web Interface Testing:
- [ ] Navigate to https://vault.yourdomain.com
- [ ] Verify SSL certificate shows as valid/trusted
- [ ] Create first user account (or enable registration temporarily)
- [ ] Log in to user account successfully
- [ ] Create test vault entries (login, secure note, etc.)
- [ ] Test vault sync across browser refresh
- [ ] Verify password generator functionality

Admin Panel Testing:
- [ ] Navigate to https://vault.yourdomain.com/admin  
- [ ] Authenticate with admin token
- [ ] Review system settings and configuration
- [ ] Test email configuration (send test email)
- [ ] Create user account via admin panel
- [ ] Review user management functionality

Mobile App Testing:
- [ ] Install Bitwarden mobile app
- [ ] Configure with custom server: https://vault.yourdomain.com
- [ ] Log in with test account
- [ ] Verify vault sync with web interface
- [ ] Test offline access functionality
- [ ] Test biometric unlock (if supported)

Security Testing:
- [ ] Verify admin panel requires token authentication
- [ ] Test fail2ban protection (intentional failed logins)
- [ ] Verify firewall blocks unexpected ports
- [ ] Check SSL configuration with external tools
- [ ] Review security headers in browser developer tools

Backup Testing:
- [ ] Create manual backup: ./tools/create-full-backup.sh
- [ ] Verify backup file created and encrypted
- [ ] Test backup verification: ./tools/restore.sh --verify latest
- [ ] Document backup location and passphrase securely
```

## 🔄 **Migration Deployments**

### **Migration from Existing VaultWarden**

#### **Pre-Migration Assessment**
```bash
# Assess existing VaultWarden deployment for migration
./tools/migration-assessment.sh --source-type existing-vaultwarden

# Migration assessment questions:
# 1. Current VaultWarden version?
# 2. Database type (SQLite/PostgreSQL/MySQL)?
# 3. Existing data volume estimate?
# 4. Current backup procedures?
# 5. SSL certificate type (Let's Encrypt/Custom)?
# 6. Existing security configurations?
# 7. User count and organization structure?
# 8. Downtime tolerance for migration?

# Expected assessment output:
🔍 VaultWarden Migration Assessment

Source System Analysis:
✅ VaultWarden Version: 1.30.1 (compatible)
✅ Database Type: SQLite (3.2MB)
✅ User Count: 8 users, 2 organizations
✅ Vault Items: 1,247 entries
✅ Attachments: 15 files (2.3MB)
✅ Configuration: Standard setup

Migration Compatibility:
✅ Database format: Compatible (no conversion needed)
✅ Version compatibility: Full compatibility
✅ Feature parity: All features supported
✅ Data integrity: No conflicts detected

Migration Plan:
- Estimated downtime: 15-30 minutes
- Data migration method: Direct database copy
- Configuration migration: Automated with manual review
- SSL certificate: New Let's Encrypt certificates
- DNS update required: Yes (point to new server)
- Rollback plan: Keep old server online initially

Recommendation: Migration is straightforward with low risk
```

#### **Migration Execution Process**
```bash
# Step 1: Prepare new server with VaultWarden-OCI-Minimal
# (Follow standard deployment process but don't start services yet)

# Step 2: Export data from existing VaultWarden
# On old server:
sudo docker compose exec vaultwarden sqlite3 /data/db.sqlite3 ".backup /data/migration-backup.sqlite3"
sudo tar -czf vaultwarden-migration-$(date +%Y%m%d).tar.gz -C /path/to/vaultwarden /data

# Step 3: Transfer data to new server
scp vaultwarden-migration-*.tar.gz user@new-server:/tmp/

# Step 4: Execute migration on new server
cd /opt/VaultWarden-OCI-Minimal
sudo ./tools/migrate-from-existing.sh /tmp/vaultwarden-migration-*.tar.gz

# Migration process:
🔄 VaultWarden Migration Process

Pre-migration validation:
✅ Migration archive verified and accessible
✅ New server prepared and configured
✅ Database compatibility confirmed
✅ Sufficient storage space available

Data migration:
✅ Database extracted and validated (3.2MB)
✅ User data migrated (8 users)
✅ Vault entries migrated (1,247 items)
✅ File attachments migrated (15 files, 2.3MB)
✅ Organization data migrated (2 organizations)

Configuration migration:
✅ SMTP settings preserved
✅ Admin token regenerated for security
✅ Domain configuration updated
✅ SSL certificates will be regenerated

Post-migration validation:
✅ Database integrity verified
✅ All users accessible
✅ Vault data integrity confirmed
✅ Attachment accessibility verified

🎯 Migration completed successfully!
   Old server can remain online for rollback if needed
   Update DNS to point to new server when ready
   Test thoroughly before decommissioning old server

New system information:
- Domain: https://vault.yourdomain.com (update DNS)
- Admin token: [new secure token displayed]
- Migration backup: /var/lib/*/backups/migration/
```

### **Migration from Bitwarden Cloud**

#### **Bitwarden Cloud Export and Import**
```bash
# Migration from Bitwarden cloud service
# Note: This requires manual export from Bitwarden and import to VaultWarden

# Step 1: Export from Bitwarden Cloud
# Via web vault:
# 1. Log in to https://vault.bitwarden.com
# 2. Go to Tools > Export Vault
# 3. Select format: .json (encrypted) or .csv
# 4. Download export file

# Step 2: Prepare VaultWarden-OCI-Minimal
# (Complete standard deployment process)

# Step 3: Import data to VaultWarden
# Via admin panel:
# 1. Access https://vault.yourdomain.com/admin
# 2. Go to Users > Select user
# 3. Use "Import" functionality if available

# Alternative: User-level import
# 1. User logs in to new VaultWarden
# 2. Goes to Tools > Import Data
# 3. Selects "Bitwarden (json)" format
# 4. Uploads exported file

# Step 4: Validation and cleanup
# - Verify all data imported correctly
# - Test vault functionality
# - Update mobile apps to point to new server
# - Cancel Bitwarden cloud subscription
```

## 🎯 **Production Hardened Deployment**

### **Maximum Security Configuration**

#### **Enhanced Security Deployment**
```bash
# Ultra-secure deployment for sensitive environments
sudo ./tools/init-setup.sh --maximum-security

# Maximum security features:
# - Strict firewall rules with IP whitelisting
# - Enhanced fail2ban configuration with lower thresholds
# - Mandatory OCI Vault integration
# - Enhanced SSL configuration with HSTS preload
# - Comprehensive audit logging
# - Mandatory backup encryption with key rotation
# - Enhanced monitoring with security event correlation
```

#### **Compliance-Ready Configuration**
```bash
# Deployment with compliance features enabled
sudo ./tools/init-setup.sh --compliance-ready

# Compliance features:
# - Extended audit logging (1+ year retention)
# - Data residency controls
# - Access logging and monitoring
# - Backup encryption with compliance-grade key management
# - Regular security scanning and reporting
# - Incident response procedures
# - Documentation for compliance audits
```

## 🔧 **Deployment Troubleshooting**

### **Common Deployment Issues**

#### **DNS and Domain Issues**
```bash
# Issue: Domain not resolving or SSL certificate failures
# Diagnosis:
nslookup vault.yourdomain.com
dig vault.yourdomain.com A
curl -I http://vault.yourdomain.com

# Common solutions:
# 1. Verify DNS A record points to server IP
# 2. Wait for DNS propagation (up to 48 hours)
# 3. Test from different network/location
# 4. Check domain registrar DNS settings
# 5. Verify CloudFlare proxy settings if used
```

#### **Resource Constraints**
```bash
# Issue: Deployment fails due to insufficient resources
# Diagnosis:
free -h          # Check available memory
df -h            # Check disk space
nproc            # Check CPU cores

# Solutions based on constraints:
# Memory: Increase server RAM or adjust container limits
# Storage: Add storage or clean existing files
# CPU: Upgrade server or reduce concurrent processes
```

#### **Permission and Access Issues**
```bash
# Issue: Permission denied errors during deployment
# Common causes and solutions:

# 1. Script execution permissions
chmod +x startup.sh tools/*.sh lib/*.sh

# 2. Running without sudo when required
sudo ./tools/init-setup.sh

# 3. Docker socket permissions
sudo usermod -aG docker $USER
# (requires logout/login to take effect)

# 4. File ownership issues
sudo chown -R root:root /opt/VaultWarden-OCI-Minimal
```

### **Validation and Recovery**

#### **Deployment Validation Failure Recovery**
```bash
# If deployment validation fails, systematic recovery:

# 1. Check system logs
journalctl -u docker
journalctl -xe

# 2. Validate configuration
./startup.sh --validate

# 3. Check container status
docker compose ps
docker compose logs

# 4. Network connectivity test
curl -I https://vault.yourdomain.com

# 5. Clean rebuild if needed
docker compose down
docker system prune -f
./startup.sh
```

#### **Emergency Rollback Procedures**
```bash
# If deployment needs to be rolled back:

# 1. Stop new deployment
docker compose down

# 2. Restore from backup (if migration)
./tools/restore.sh /path/to/previous/backup

# 3. Revert DNS changes (if applicable)
# Update DNS A record to point to old server

# 4. Document issues for troubleshooting
echo "$(date): Rollback executed - $(reason)" >> /var/log/deployment.log
```

This comprehensive deployment guide ensures successful VaultWarden-OCI-Minimal deployment across various environments with proper validation, security, and operational readiness."""
