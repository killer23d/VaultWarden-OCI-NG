# Quick Start Guide

**Get VaultWarden-OCI-NG running in under 30 minutes with enterprise-grade reliability**

This guide provides the fastest path to a production-ready VaultWarden deployment with comprehensive security, automated backups, and self-healing capabilities. Now includes automatic input validation and non-root container security.

## ⚡ **Prerequisites Checklist**

### **Infrastructure Requirements**
- [ ] **Ubuntu 24.04 LTS server** (freshly installed, other distributions not supported)
- [ ] **6GB RAM minimum** (2GB absolute minimum, 4GB+ recommended for stability)
- [ ] **1 vCPU** (ARM64 or x86_64, Oracle Cloud A1 Flex recommended)
- [ ] **50GB storage** (minimum 20GB for backups and system growth)
- [ ] **Public IP address** with ports 80/443 accessible from the internet

### **External Services Required**
- [ ] **Domain name** with DNS management access (for Let's Encrypt certificates)
- [ ] **SMTP credentials** for email notifications (Gmail App Password recommended)
- [ ] **Cloudflare account** with API access (strongly recommended for security)

### **Access Requirements**
- [ ] **SSH access** to the server with sudo privileges
- [ ] **Git installed** on the server (`sudo apt install git`)
- [ ] **Internet connectivity** for package installation and certificate generation

## 🚀 **Rapid Deployment (5 Steps)**

### **Step 1: Repository Setup** (2 minutes)
```bash
# Clone the repository
git clone https://github.com/killer23d/VaultWarden-OCI-NG
cd VaultWarden-OCI-NG

# Make scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh

# Validate system compatibility
./tools/validate-code.sh
```

### **Step 2: Dependency Installation** (5 minutes)
```bash
# Install all required dependencies automatically
sudo ./tools/install-deps.sh --auto

# Verify successful installation
docker --version && age --version && sops --version
```
**Expected output:** Version numbers for Docker, Age, and SOPS

### **Step 3: System Initialization with Input Validation** (8 minutes)
```bash
# Initialize system with your domain and admin email (now includes automatic validation)
sudo ./tools/init-setup.sh --domain vault.yourdomain.com --email admin@yourdomain.com
```

**What happens automatically:**
- ✅ **Input validation** - Email and domain format verification with helpful error messages
- ✅ Age encryption keys generated with secure permissions
- ✅ Basic configuration file created from template
- ✅ Firewall configured with secure defaults
- ✅ Log directories created with proper permissions
- ✅ Initial emergency access kit generated
- ✅ System user and group configuration

**🔒 Enhanced Security Features:**
- **Domain validation:** Automatically strips protocols, validates format, and checks TLD requirements
- **Email validation:** RFC-compliant email format verification prevents setup mistakes
- **Container security:** VaultWarden and Caddy containers run as non-root users (user 1000:1000)
- **Privilege separation:** fail2ban and Watchtower retain root only when required for functionality

### **Step 4: Configuration** (10 minutes)
```bash
# Open encrypted configuration editor
./tools/edit-secrets.sh
```

**Configure these essential settings:**
```yaml
# Core settings (required - now validated automatically)
DOMAIN: "vault.yourdomain.com"  # No protocol needed, automatically validated
ADMIN_EMAIL: "admin@yourdomain.com"  # Format automatically validated

# SMTP for notifications (required for proper operation)
SMTP_HOST: "smtp.gmail.com"
SMTP_PORT: "587"
SMTP_USERNAME: "your-email@gmail.com"
SMTP_PASSWORD: "your-gmail-app-password"
SMTP_FROM: "vault@yourdomain.com"
SMTP_SECURITY: "starttls"

# Cloudflare security (highly recommended)
CLOUDFLARE_ZONE_ID: "your-zone-id"
CLOUDFLARE_API_TOKEN: "your-api-token"
```

**💡 Pro Tips:**
- Use Gmail App Passwords for SMTP (not your regular password)
- Domain validation will warn if you include `https://` - use clean domain only
- Email validation catches common mistakes like missing @ symbols or invalid TLDs
- Get Cloudflare Zone ID from your domain's overview page
- Create Cloudflare API token with Zone:Read and DNS:Edit permissions

### **Step 5: Secure Deployment** (5 minutes)
```bash
# Deploy VaultWarden with comprehensive validation and non-root containers
./startup.sh

# Verify deployment health and container security
./tools/check-health.sh --fix
```

**🎉 Your VaultWarden is now live!** Access it at `https://vault.yourdomain.com`

**🔐 Security Improvements Applied:**
- VaultWarden container runs as user 1000:1000 (non-root)
- Caddy proxy runs as user 1000:1000 (non-root)
- ddclient runs as user 1000 via PUID/PGID
- fail2ban retains root access (required for iptables)
- Watchtower retains default user (required for Docker socket)

## 🔧 **Post-Deployment Verification**

### **Essential Health Checks**
```bash
# Comprehensive system health audit (includes container security checks)
./tools/check-health.sh --comprehensive

# Verify non-root container execution
docker compose ps --format "table {{.Name}}\t{{.Image}}\t{{.Status}}"
docker inspect vaultwarden_vaultwarden | grep -A5 "User"

# Test backup systems
./tools/backup-monitor.sh --test-email

# Verify monitoring systems
./tools/monitor.sh --analysis

# Validate security configuration
sudo ./tools/host-maintenance.sh --security-audit
```

### **Container Security Validation**
```bash
# Verify containers are running as expected users
docker exec vaultwarden_vaultwarden whoami  # Should show: "vaultwarden" or ID 1000
docker exec caddy_container whoami          # Should show: user ID 1000

# Check file permissions are correct for non-root users
ls -la /var/lib/vaultwarden/
```

### **Access Your VaultWarden**
1. **Web Interface:** `https://vault.yourdomain.com`
2. **Admin Panel:** `https://vault.yourdomain.com/admin`
   - Username: `admin`
   - Password: Check `./tools/edit-secrets.sh` for `ADMIN_BASIC_AUTH_PASSWORD`

### **Create Your First User**
1. Access the admin panel using the credentials above
2. Navigate to "Users" → "Invite User"
3. Enter the email address for your first user
4. The user will receive an invitation email to set up their account

## 📋 **Quick Reference Commands**

### **Daily Operations**
```bash
# Check system health (includes container security validation)
./tools/check-health.sh

# View recent logs
docker compose logs --tail=50

# Create manual backup
./tools/backup-monitor.sh --db-only

# Test email notifications
./tools/backup-monitor.sh --test-email
```

### **Security Operations**
```bash
# Verify container users
docker compose exec vaultwarden whoami
docker compose exec caddy whoami

# Check volume permissions for non-root containers
sudo ls -la /var/lib/vaultwarden/

# Fix volume ownership if needed (one-time after upgrade)
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/
```

### **Maintenance Operations**
```bash
# Run system maintenance
sudo ./tools/host-maintenance.sh --auto

# Update Cloudflare IP ranges
./tools/update-cloudflare-ips.sh

# Optimize database
./tools/sqlite-maintenance.sh --optimize
```

### **Emergency Operations**
```bash
# Force restart all services
./startup.sh --force-restart

# Create emergency recovery kit
./tools/create-emergency-kit.sh --email

# Comprehensive troubleshooting
./tools/check-health.sh --fix --comprehensive
```

## 🚨 **Troubleshooting Quick Fixes**

### **Input Validation Errors**
```bash
# If init-setup.sh reports invalid domain format:
# ❌ Error: "https://vault.example.com" (includes protocol)
# ✅ Correct: "vault.example.com" (clean domain only)

# If init-setup.sh reports invalid email format:
# ❌ Error: "admin@" (incomplete)
# ✅ Correct: "admin@example.com" (complete email)

# Test validation manually:
source lib/validation.sh
validate_domain_format "vault.example.com"
validate_email_format "admin@example.com"
```

### **Container Permission Errors**
```bash
# If containers fail to start after upgrade:
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/

# Restart services
docker compose down && docker compose up -d

# Verify fix
docker compose ps
```

### **Services Won't Start**
```bash
# Check Docker service
sudo systemctl status docker

# Force restart with diagnostics
./startup.sh --force-restart

# Check for configuration errors
./tools/validate-code.sh

# Verify container users
docker compose config
```

### **Can't Access Web Interface**
```bash
# Check firewall status
sudo ufw status

# Verify DNS resolution
dig vault.yourdomain.com

# Check certificate status
./tools/check-health.sh

# Verify Caddy is running as non-root
docker exec caddy_container whoami
```

### **Email Notifications Not Working**
```bash
# Test SMTP configuration
./tools/backup-monitor.sh --test-email

# Verify SMTP settings (check for validation errors)
./tools/edit-secrets.sh

# Check notification system logs
docker compose logs caddy
```

### **Emergency Kit Creation Fails**
```bash
# Verify Age key exists
ls -la secrets/keys/

# Check email configuration (validation applied)
./tools/backup-monitor.sh --test-email

# Debug mode for detailed error information
./tools/create-emergency-kit.sh --debug
```

## ⏭️ **Next Steps**

### **Immediate Actions** (First 24 hours)
1. **Verify security hardening** by checking container users with `docker compose exec vaultwarden whoami`
2. **Test input validation** by running setup with intentionally bad inputs
3. **Test the emergency recovery kit** by extracting and validating it
4. **Configure additional users** through the admin panel
5. **Set up mobile apps** by connecting to your VaultWarden instance
6. **Verify backup emails** are being received correctly

### **Security Validation** (First week)
1. **Confirm non-root execution** with container user verification commands
2. **Review file permissions** in data directories
3. **Test fail2ban functionality** (still runs as root for iptables access)
4. **Verify input validation** is working during configuration changes
5. **Review security settings** in [Security Configuration](Security.md)

### **Optimization** (First week)
1. **Review enhanced security settings** in [Security Configuration](Security.md)
2. **Optimize Cloudflare integration** using [Cloudflare Guide](Cloudflare.md)
3. **Customize monitoring alerts** based on your requirements
4. **Fine-tune backup retention** policies for your needs

### **Advanced Configuration** (Ongoing)
1. **Explore advanced features** in [Advanced Configuration](AdvancedConfiguration.md)
2. **Set up advanced monitoring** using external tools if needed
3. **Implement custom backup strategies** for specific requirements
4. **Review and update security policies** quarterly

## 📖 **Additional Resources**

- **[Advanced Configuration](AdvancedConfiguration.md)** - Comprehensive configuration options
- **[Security Configuration](Security.md)** - Detailed security hardening guide (updated with container security)
- **[Cloudflare Integration](Cloudflare.md)** - Advanced DDoS protection setup
- **[Backup & Recovery](BackupRestore.md)** - Comprehensive backup and disaster recovery
- **[Troubleshooting Guide](Troubleshooting.md)** - Detailed problem resolution (includes container issues)
- **[Operations Runbook](OperationsRunbook.md)** - Daily operations and maintenance

## ✅ **Success Indicators**

Your deployment is successful when:
- [ ] **Input validation working**: Domain and email validation during setup shows helpful error messages for bad inputs
- [ ] **Container security active**: VaultWarden and Caddy running as user 1000:1000 (verify with `whoami` commands)
- [ ] **Web interface accessible** at your domain with valid SSL certificate
- [ ] **Admin panel accessible** with correct authentication
- [ ] **First user created** and able to log in
- [ ] **Health checks passing** (`./tools/check-health.sh` shows all green)
- [ ] **Email notifications working** (`./tools/backup-monitor.sh --test-email` succeeds)
- [ ] **Emergency kit received** via email
- [ ] **Backup systems operational** (check `/opt/VaultWarden-OCI-NG/backups/`)
- [ ] **Volume permissions correct** for non-root containers (`ls -la /var/lib/vaultwarden/` shows user 1000)

---

**🎯 Deployment Time:** ~30 minutes for standard setup
**🔧 First User Creation:** ~5 minutes after deployment  
**📧 Emergency Kit Delivery:** Within 10 minutes of setup completion
**🔒 Security Validation:** ~5 minutes to verify container users and permissions

**Need help?** Check the [Troubleshooting Guide](Troubleshooting.md) or review [FAQ & Reference](FAQReferenceGuide.md).
