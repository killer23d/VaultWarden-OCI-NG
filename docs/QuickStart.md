# Quick Start Guide

> **🎯 Goal**: From zero to production VaultWarden in 30 minutes with full automation, monitoring, and security.

## ⚠️ **Critical Prerequisites**

### **Setup Order (MANDATORY)**
```bash
# 1. FIRST: Make scripts executable
chmod +x startup.sh tools/*.sh

# 2. SECOND: Run setup (installs everything)
sudo ./tools/init-setup.sh

# 3. THIRD: Start services (loads config and health checks)
./startup.sh

# ❌ NEVER run 'docker compose up' directly
# ❌ NEVER skip init-setup.sh
# ❌ NEVER run startup.sh before init-setup.sh
```

### **System Requirements**
- **OS**: Ubuntu 24.04 LTS (minimal install OK)
- **RAM**: 2GB minimum (4GB recommended for 10 users)
- **Storage**: 20GB minimum (50GB recommended)
- **Network**: Internet connectivity, ports 22/80/443 accessible
- **Access**: Root or sudo privileges

### **Information You'll Need**
- **Domain name**: `vault.yourdomain.com` (DNS pointing to server)
- **Email address**: For admin notifications
- **SMTP credentials**: (optional, can configure later)
- **CloudFlare account**: (optional, for enhanced security)

## 🚀 **30-Minute Deployment**

### **Phase 1: Server Preparation (5 minutes)**

#### **Connect and Update**
```bash
# SSH to your server
ssh ubuntu@YOUR_SERVER_IP

# Switch to root
sudo su -

# Update system (recommended but optional)
apt update && apt upgrade -y

# Verify requirements
free -h              # Check RAM
df -h                # Check disk space
ping -c 3 google.com # Check connectivity
```

#### **Download Project**
```bash
# Navigate to standard location
cd /opt

# Clone repository (replace URL with your fork if customized)
git clone https://github.com/killer23d/VaultWarden-OCI-Minimal.git

# Enter project directory
cd VaultWarden-OCI-Minimal

# CRITICAL: Make scripts executable (Git doesn't preserve this)
chmod +x startup.sh tools/*.sh

# Verify executable permissions
ls -la tools/ | grep rwx
```

### **Phase 2: Automated Installation (15 minutes)**

#### **Run Complete Setup**
```bash
# Execute the comprehensive setup script
sudo ./tools/init-setup.sh

# This single command handles:
# ✅ Docker and Docker Compose installation
# ✅ UFW firewall configuration (SSH, HTTP, HTTPS)
# ✅ Fail2ban installation and configuration
# ✅ Secure random token generation
# ✅ Directory structure creation with proper permissions
# ✅ Cron jobs for automated maintenance
# ✅ CloudFlare integration setup (if configured)
```

#### **Interactive Configuration**
The setup script will prompt for:

**Required Settings:**
```bash
Domain name: https://vault.yourdomain.com
Admin email: admin@yourdomain.com
```

**Optional Settings (can skip and configure later):**
```bash
SMTP host: smtp.gmail.com
SMTP from: noreply@yourdomain.com
SMTP username: (leave blank if unsure)
SMTP password: (leave blank if unsure)
CloudFlare email: (for fail2ban integration)
CloudFlare API key: (for enhanced security)
```

#### **Non-Interactive Mode**
For automation or if you want defaults:
```bash
sudo ./tools/init-setup.sh --auto
```

#### **Setup Completion Verification**
```bash
# Check that setup completed successfully
ls -la settings.json  # Should exist with 600 permissions
docker --version      # Should show Docker version
sudo ufw status       # Should show active firewall
sudo systemctl status fail2ban  # Should show active service
```

### **Phase 3: Service Launch (5 minutes)**

#### **Start VaultWarden Stack**
```bash
# Launch all services with health checks
./startup.sh

# Expected output sequence:
# 🔍 Loading configuration...
# 🛠️  Preparing runtime environment...
# 🔧 Executing pre-startup tasks...
# 🚀 Starting services...
# ✅ VaultWarden is healthy
# ✅ Caddy is running
# ✅ Fail2ban is running
# ℹ️  Service information displayed
```

#### **Verify Deployment Success**
```bash
# 1. Check container status
docker compose ps
# All containers should show "Up" and VaultWarden should be "healthy"

# 2. Test web connectivity
curl -I https://vault.yourdomain.com
# Should return HTTP/2 200 or HTTP/1.1 200

# 3. Check SSL certificate
echo | openssl s_client -connect vault.yourdomain.com:443 -servername vault.yourdomain.com 2>/dev/null | openssl x509 -noout -text | grep -A 2 "Validity"
# Should show valid certificate dates

# 4. Verify admin access
curl -I https://vault.yourdomain.com/admin
# Should return HTTP 200 (might redirect to login)
```

### **Phase 4: Initial Access (5 minutes)**

#### **Get Admin Credentials**
```bash
# Retrieve the generated admin token
sudo jq -r '.ADMIN_TOKEN' settings.json

# Copy this token - you'll need it for admin panel access
```

#### **Access Admin Panel**
1. **Open browser**: Navigate to `https://vault.yourdomain.com/admin`
2. **Enter admin token**: Use the token from above
3. **Configure initial settings**:
   - Verify domain settings
   - Configure user registration policy
   - Set up organization settings (if needed)
   - Configure SMTP if not done during setup

#### **Create First User**
1. **Access main interface**: `https://vault.yourdomain.com`
2. **Create account**:
   - If signups enabled: Register directly
   - If signups disabled: Create user in admin panel
3. **Test functionality**:
   - Log in to new account
   - Create a test vault item
   - Verify data persistence

## ✅ **Post-Deployment Verification**

### **Automated Health Check**
```bash
# Run comprehensive system validation
./startup.sh --validate

# Run monitoring check
./tools/monitor.sh --summary

# Expected results:
# ✅ All containers healthy
# ✅ Database accessible and optimized
# ✅ SSL certificate valid and auto-renewing
# ✅ Backup system configured and tested
# ✅ Monitoring system operational
# ✅ Security systems (firewall, fail2ban) active
```

### **Security Verification**
```bash
# 1. Firewall status
sudo ufw status verbose
# Should show: SSH (22), HTTP (80), HTTPS (443) allowed, default deny

# 2. Fail2ban protection
sudo fail2ban-client status
# Should list active jails: sshd, vaultwarden, caddy

# 3. File permissions
ls -la settings.json
# Should show: -rw------- 1 root root (600 permissions)

# 4. SSL security test (external)
# Visit: https://www.ssllabs.com/ssltest/
# Enter your domain, should get A+ rating
```

### **Backup System Verification**
```bash
# Test backup creation
./tools/db-backup.sh --dry-run
# Should complete without errors

# Check automated backup schedule
crontab -l | grep backup
# Should show daily and weekly backup cron jobs

# Verify backup directory
ls -la /var/lib/*/backups/
# Should exist with proper permissions
```

## 🔧 **Essential Post-Setup Configuration**

### **SMTP Configuration (Recommended)**

If you skipped SMTP during setup, configure it now:

```bash
# Edit configuration
sudo nano settings.json

# Add/update SMTP settings
{
  "SMTP_HOST": "smtp.gmail.com",
  "SMTP_PORT": 587,
  "SMTP_SECURITY": "starttls",
  "SMTP_USERNAME": "your-email@gmail.com",
  "SMTP_PASSWORD": "your-app-password",
  "SMTP_FROM": "vaultwarden@yourdomain.com"
}

# Restart services to apply changes
./startup.sh

# Test email functionality
./tools/monitor.sh --test-email
```

**Gmail Setup Notes:**
- Use App Password, not regular password
- Generate at: https://myaccount.google.com/apppasswords
- Enable 2FA on your Google account first

### **CloudFlare Configuration (Highly Recommended)**

For enhanced security and performance:

1. **DNS Setup**:
   - Point your domain to CloudFlare nameservers
   - Add A record pointing to your server IP
   - Enable "Proxied" (orange cloud icon)

2. **SSL Configuration**:
   - Set SSL/TLS mode to "Full (strict)"
   - Enable "Always Use HTTPS"
   - Enable HSTS

3. **Security Settings**:
   - Set Security Level to "Medium" or higher
   - Enable Bot Fight Mode
   - Configure Rate Limiting

4. **Fail2ban Integration**:
   ```bash
   # Edit CloudFlare credentials in config
   sudo nano settings.json
   
   # Add CloudFlare API credentials
   {
     "CLOUDFLARE_EMAIL": "your-cf-email@example.com",
     "CLOUDFLARE_API_KEY": "your-global-api-key"
   }
   
   # Restart to enable CloudFlare fail2ban actions
   ./startup.sh
   ```

### **User Registration Policy**

Configure how users can join:

```json
{
  "SIGNUPS_ALLOWED": false,
  "INVITATIONS_ALLOWED": true,
  "INVITATION_EXPIRATION_HOURS": 120
}
```

Options:
- **Open Registration**: `"SIGNUPS_ALLOWED": true`
- **Invite Only**: `"SIGNUPS_ALLOWED": false, "INVITATIONS_ALLOWED": true`
- **Admin Only**: Both false, create users in admin panel

## 🚨 **Common Quick Start Issues**

### **Issue 1: "Permission Denied" on Scripts**

**Symptoms**: `bash: ./startup.sh: Permission denied`

**Solution**:
```bash
# Make scripts executable (required after git clone)
chmod +x startup.sh tools/*.sh

# Verify permissions
ls -la startup.sh tools/
# Should show 'rwx' for owner
```

### **Issue 2: "Cannot Access Web Interface"**

**Symptoms**: Browser shows "connection refused" or timeout

**Root Cause Analysis**:
```bash
# 1. Check if containers are running
docker compose ps
# If down: ./startup.sh

# 2. Check firewall rules
sudo ufw status
# If HTTP/HTTPS not allowed:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# 3. Check if ports are bound
sudo ss -tlnp | grep -E ":(80|443)"
# Should show caddy listening on both ports

# 4. Check DNS resolution
nslookup vault.yourdomain.com
# Should return your server's IP

# 5. Check domain configuration
grep DOMAIN settings.json
# Should match your actual domain exactly
```

### **Issue 3: "SSL Certificate Problems"**

**Symptoms**: Browser SSL warnings, invalid certificate

**Solutions**:
```bash
# 1. Wait for automatic certificate generation (5-10 minutes)
docker compose logs caddy | grep -i certificate

# 2. Check if domain is publicly accessible (required for Let's Encrypt)
# Use external tool: https://www.whatsmydns.net/

# 3. Force certificate renewal
docker compose exec caddy caddy reload

# 4. Check certificate status
docker compose exec caddy caddy list-certificates

# 5. For debugging, check if ACME challenge is accessible
curl -I http://vault.yourdomain.com/.well-known/acme-challenge/test
# Should NOT return 404 (firewall/CloudFlare issue)
```

### **Issue 4: "Admin Panel Access Denied"**

**Symptoms**: "Invalid admin token" or "Unauthorized"

**Solutions**:
```bash
# 1. Get the correct admin token
sudo jq -r '.ADMIN_TOKEN' settings.json
# Copy this exact token

# 2. If token is empty or null, regenerate
openssl rand -base64 32

# 3. Update configuration with new token
sudo jq '.ADMIN_TOKEN = "NEW_TOKEN_HERE"' settings.json > temp.json
sudo mv temp.json settings.json
sudo chmod 600 settings.json

# 4. Restart services
./startup.sh

# 5. Clear browser cache and cookies for the domain
```

### **Issue 5: "Database Lock" or "SQLite Busy"**

**Symptoms**: VaultWarden fails to start, database errors in logs

**Solutions**:
```bash
# 1. Check if another process is using the database
sudo lsof /var/lib/*/data/bwdata/db.sqlite3

# 2. Stop all containers and restart cleanly
docker compose down
./startup.sh

# 3. Check database integrity
./tools/sqlite-maintenance.sh --check

# 4. If corrupted, restore from backup
./tools/restore.sh --list
./tools/restore.sh /path/to/recent/backup
```

### **Issue 6: "Out of Disk Space"**

**Symptoms**: Containers failing, "no space left" errors

**Solutions**:
```bash
# 1. Check disk usage
df -h

# 2. Clean Docker system
docker system prune -f

# 3. Clean old logs
sudo find /var/lib/*/logs -name "*.log" -size +50M -delete

# 4. Clean old backups (if safe)
sudo find /var/lib/*/backups -name "*.backup*" -mtime +30 -delete

# 5. Check if log rotation is working
crontab -l | grep log-cleanup
```

## 📋 **Quick Reference Commands**

### **Essential Operations**
```bash
# Check system status
./tools/monitor.sh --summary

# View all service logs
docker compose logs -f

# Restart all services
./startup.sh

# Stop all services
docker compose down

# Create manual backup
./tools/create-full-backup.sh

# Check service health
docker compose ps

# Get admin token
sudo jq -r '.ADMIN_TOKEN' settings.json
```

### **Maintenance Commands**
```bash
# Database optimization
./tools/sqlite-maintenance.sh --full

# Update CloudFlare IP ranges
./tools/update-cloudflare-ips.sh

# Test backup system
./tools/db-backup.sh --dry-run

# Validate configuration
./startup.sh --validate

# Check security status
sudo ufw status && sudo fail2ban-client status
```

### **Debug Commands**
```bash
# Enable debug mode for any script
export DEBUG=1
./startup.sh

# Check container resource usage
docker stats

# View system logs
journalctl -t monitor
journalctl -t backup
journalctl -f

# Check network connectivity
curl -v https://vault.yourdomain.com
```

## 🎯 **Success Checklist**

After completing this guide, you should have:

- [ ] **Web Access**: Can access `https://vault.yourdomain.com`
- [ ] **Admin Access**: Can access admin panel with generated token
- [ ] **User Account**: Created and tested first user account
- [ ] **SSL Certificate**: Valid, trusted SSL certificate (A+ SSL Labs rating)
- [ ] **Security**: UFW firewall active, fail2ban protecting services
- [ ] **Monitoring**: Health checks running every 5 minutes
- [ ] **Backups**: Daily database backups, weekly full system backups
- [ ] **Email**: SMTP configured for notifications (if desired)
- [ ] **CloudFlare**: Enhanced security and performance (if configured)

## 📚 **Next Steps**

### **Immediate (Within 1 Hour)**
1. **Test User Experience**: Install Bitwarden mobile/desktop apps
2. **Backup Admin Token**: Store securely offline
3. **Create Team Accounts**: Set up accounts for your users
4. **Test Backup System**: Run manual backup and verify

### **Within 24 Hours**
1. **Configure Monitoring**: Test email notifications
2. **Security Audit**: Review fail2ban logs, check SSL rating
3. **Performance Tuning**: Adjust resource limits if needed
4. **Documentation**: Record your specific configuration choices

### **Within 1 Week**
1. **Off-site Backups**: Configure cloud storage for backups
2. **User Training**: Train team on VaultWarden features
3. **Monitoring Review**: Analyze automated health reports
4. **Recovery Testing**: Test restore procedure

## 🆘 **Getting Help**

If you encounter issues not covered here:

1. **Check Logs**: `docker compose logs service-name`
2. **Run Diagnostics**: `./tools/monitor.sh --verbose`
3. **Review Documentation**: See `docs/` directory for detailed guides
4. **Search Issues**: Check GitHub Issues for similar problems
5. **Report Bugs**: Create GitHub Issue with log details

**Remember**: This system is designed to be "set and forget" - most issues are resolved automatically by the monitoring and self-healing systems."""
