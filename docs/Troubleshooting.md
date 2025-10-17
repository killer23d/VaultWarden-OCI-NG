# Troubleshooting Guide

> **🎯 Goal**: Comprehensive troubleshooting guide covering common issues, diagnostic tools, and resolution procedures for VaultWarden-OCI-Minimal.

## 🚨 **Critical Troubleshooting Principles**

### **Always Start Here**
```bash
# 1. NEVER use 'docker compose up' directly
# 2. ALWAYS use startup.sh for service management
# 3. Check setup completion before troubleshooting services
# 4. Enable debug mode for detailed diagnostics
```

### **Common Misconceptions**
- **"Hardcoded paths are broken"** → Paths are dynamic, generated from project directory name
- **"Missing directories cause failures"** → init-setup.sh creates all required directories
- **"Docker network errors"** → Network syntax uses dynamic subnet calculation (valid)
- **"Script permissions issues"** → Git doesn't preserve execute permissions; run `chmod +x` after clone

## 🔍 **Diagnostic Tools and Debug Mode**

### **Enable Debug Mode**
```bash
# Enable debug logging for any script
export DEBUG=1

# Run with debug enabled
DEBUG=1 ./startup.sh
DEBUG=1 ./tools/monitor.sh
DEBUG=1 ./tools/init-setup.sh
```

### **System Health Check**
```bash
# Comprehensive system validation
./startup.sh --validate

# Monitoring system check  
./tools/monitor.sh --verbose

# Configuration validation
source lib/config.sh && _load_configuration && _display_config_summary
```

### **Log Analysis**
```bash
# View all service logs
docker compose logs --tail=100

# Service-specific logs
docker compose logs vaultwarden
docker compose logs caddy  
docker compose logs fail2ban

# System logs
journalctl -t monitor
journalctl -t backup
journalctl -t sqlite-maintenance

# Real-time log monitoring
docker compose logs -f
```

## 🚀 **Setup and Initial Deployment Issues**

### **Issue: "Permission Denied" on Scripts**

**Symptoms**:
```bash
bash: ./startup.sh: Permission denied
-bash: ./tools/init-setup.sh: Permission denied
```

**Root Cause**: Git doesn't preserve executable permissions

**Solution**:
```bash
# Make all scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh

# Verify permissions
ls -la startup.sh tools/ | grep rwx

# Alternative: Bulk permission fix
find . -name "*.sh" -exec chmod +x {} \;
```

**Prevention**: Add to post-clone checklist in documentation

---

### **Issue: "Docker not found" or "Docker daemon not running"**

**Symptoms**:
```bash
docker: command not found
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Root Cause**: Docker not installed or service not started

**Diagnostic Commands**:
```bash
# Check Docker installation
which docker
docker --version

# Check Docker service status
systemctl status docker
systemctl is-active docker

# Check Docker daemon socket
ls -la /var/run/docker.sock
```

**Solution**:
```bash
# Run init-setup.sh to install Docker
sudo ./tools/init-setup.sh

# Manual Docker installation (Ubuntu)
sudo apt update
sudo apt install docker.io docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group (optional)
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

---

### **Issue: "jq: command not found" or Missing Dependencies**

**Symptoms**:
```bash
jq: command not found
curl: command not found
openssl: command not found
```

**Root Cause**: Required packages not installed

**Solution**:
```bash
# Run complete setup (recommended)
sudo ./tools/init-setup.sh

# Manual package installation (Ubuntu)
sudo apt update
sudo apt install jq curl openssl fail2ban ufw

# Verify installation
jq --version && curl --version && openssl version
```

---

### **Issue: "Configuration file not found"**

**Symptoms**:
```bash
Configuration file not found: /path/to/settings.json
Run ./tools/init-setup.sh first
```

**Root Cause**: Attempting to run startup.sh before init-setup.sh

**Solution**:
```bash
# Run setup first (creates settings.json)
sudo ./tools/init-setup.sh

# Verify configuration file exists
ls -la settings.json

# Check configuration validity
jq . settings.json

# If file exists but empty, regenerate
sudo ./tools/init-setup.sh --reconfigure
```

---

### **Issue: Setup Script Fails with Permission Errors**

**Symptoms**:
```bash
mkdir: cannot create directory '/var/lib/project': Permission denied
cp: cannot create regular file '/etc/systemd/system/': Permission denied
```

**Root Cause**: Not running setup script as root

**Solution**:
```bash
# Run setup with proper privileges
sudo ./tools/init-setup.sh

# Verify running as root
whoami  # Should return 'root'

# If using sudo, ensure it's working
sudo whoami  # Should return 'root'
```

## 🌐 **Network and Connectivity Issues**

### **Issue: "Cannot Access Web Interface"**

**Symptoms**:
- Browser shows "This site can't be reached"
- Connection timeout or refused
- `curl -I https://domain.com` fails

**Comprehensive Diagnostic Process**:

#### **Step 1: Container Status Check**
```bash
# Check if containers are running
docker compose ps

# Expected output: All containers "Up", VaultWarden "healthy"
# If containers are down:
./startup.sh

# If containers keep failing:
docker compose logs vaultwarden
```

#### **Step 2: Port Binding Verification**
```bash
# Check if ports are bound correctly
sudo ss -tlnp | grep -E ":(80|443)"

# Expected output:
# *:80 ... users:(("caddy",pid=...))
# *:443 ... users:(("caddy",pid=...))

# If ports not bound:
docker compose logs caddy
```

#### **Step 3: Firewall Configuration**
```bash
# Check UFW status
sudo ufw status verbose

# Expected rules:
# 22/tcp ALLOW IN (SSH)
# 80/tcp ALLOW IN (HTTP)  
# 443/tcp ALLOW IN (HTTPS)

# If rules missing:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload
```

#### **Step 4: DNS Resolution**
```bash
# Test DNS resolution locally
nslookup your-domain.com
dig your-domain.com A

# Test from external source
# Use: https://www.whatsmydns.net/

# Check domain configuration
grep DOMAIN settings.json
# Should match your actual domain exactly
```

#### **Step 5: Network Connectivity Test**
```bash
# Test from server to itself
curl -I http://localhost:80
curl -I https://localhost:443

# Test external connectivity
curl -I http://your-domain.com
curl -I https://your-domain.com

# Test from different network
# Use mobile hotspot or different location
```

**Common Solutions**:
```bash
# Restart networking
sudo systemctl restart networking

# Flush DNS cache
sudo systemctl restart systemd-resolved

# Check for conflicting services
sudo ss -tlnp | grep -E ":(80|443)"
# Kill any conflicting processes

# Verify domain points to correct IP
curl -s http://whatismyip.akamai.com/
# Compare with DNS A record
```

---

### **Issue: SSL Certificate Problems**

**Symptoms**:
- Browser SSL warnings
- "Your connection is not private"
- Certificate appears self-signed or invalid

**Diagnostic Commands**:
```bash
# Check certificate status
docker compose exec caddy caddy list-certificates

# Check certificate details
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | openssl x509 -noout -text

# Check Caddy logs for certificate issues
docker compose logs caddy | grep -i certificate
docker compose logs caddy | grep -i acme
docker compose logs caddy | grep -i error
```

**Root Causes and Solutions**:

#### **Cause 1: Domain Not Publicly Accessible**
```bash
# Let's Encrypt requires public domain accessibility
# Test ACME challenge path
curl -I http://your-domain.com/.well-known/acme-challenge/test

# If 404 or unreachable:
# 1. Check CloudFlare proxy settings (disable temporarily)
# 2. Verify DNS propagation
# 3. Check firewall rules
```

#### **Cause 2: Certificate Generation in Progress**
```bash
# Certificate generation takes 5-10 minutes
# Monitor progress
docker compose logs -f caddy | grep -i certificate

# Wait for completion message
# "successfully obtained certificate"
```

#### **Cause 3: Rate Limiting**
```bash
# Let's Encrypt rate limits
# Check for rate limit errors in logs
docker compose logs caddy | grep -i "rate limit"

# If rate limited, wait or use staging environment
# Edit Caddyfile temporarily:
# acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

#### **Solution Steps**:
```bash
# 1. Verify domain accessibility
curl -I http://your-domain.com

# 2. Reload Caddy configuration
docker compose exec caddy caddy reload

# 3. Force certificate renewal
docker compose exec caddy caddy certificates --renew

# 4. Restart Caddy if needed
docker compose restart caddy

# 5. Check certificate installation
openssl s_client -connect your-domain.com:443 -servername your-domain.com < /dev/null
```

---

### **Issue: CloudFlare Integration Problems**

**Symptoms**:
- Orange cloud (proxied) causing SSL issues
- Real visitor IP not detected correctly
- Fail2ban not blocking at CloudFlare edge

**CloudFlare SSL Configuration**:
```bash
# Required CloudFlare SSL settings:
# SSL/TLS Mode: "Full (strict)"
# Always Use HTTPS: Enabled
# Minimum TLS Version: 1.2

# Check if CloudFlare IPs are updated
cat caddy/cloudflare-ips.caddy

# Update CloudFlare IP ranges
./tools/update-cloudflare-ips.sh

# Verify IP range format
grep -E "trusted_proxies|real_ip" caddy/cloudflare-ips.caddy
```

**Fail2ban CloudFlare Integration**:
```bash
# Check CloudFlare action configuration
cat fail2ban/action.d/cloudflare.conf | grep -A 5 "\[Init\]"

# Verify credentials are set
grep "cfuser\|cftoken" fail2ban/action.d/cloudflare.conf

# Test CloudFlare API connectivity
curl -X GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \
     -H "X-Auth-Email: your-email@example.com" \
     -H "X-Auth-Key: your-api-key"
```

## 📊 **Application and Database Issues**

### **Issue: VaultWarden Admin Panel Access Denied**

**Symptoms**:
- "Invalid admin token" message
- "Unauthorized" error
- Cannot access `/admin` endpoint

**Diagnostic Steps**:

#### **Step 1: Verify Admin Token**
```bash
# Get current admin token
sudo jq -r '.ADMIN_TOKEN' settings.json

# Check if token is empty or null
if [[ "$(sudo jq -r '.ADMIN_TOKEN' settings.json)" == "null" ]]; then
    echo "Admin token is null - needs regeneration"
fi
```

#### **Step 2: Regenerate Admin Token**
```bash
# Generate new secure token
NEW_TOKEN=$(openssl rand -base64 32)

# Update configuration file
sudo jq --arg token "$NEW_TOKEN" '.ADMIN_TOKEN = $token' settings.json > temp.json
sudo mv temp.json settings.json
sudo chmod 600 settings.json

# Restart services
./startup.sh

# Display new token
echo "New admin token: $NEW_TOKEN"
```

#### **Step 3: Browser and Cache Issues**
```bash
# Clear browser data for the domain:
# 1. Open browser developer tools (F12)
# 2. Right-click refresh button → "Empty Cache and Hard Reload"
# 3. Or manually clear cookies/cache for the domain

# Test with different browser or incognito mode
# Test with curl
curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
     https://your-domain.com/admin/config
```

---

### **Issue: Database Lock or SQLite Busy Errors**

**Symptoms**:
```bash
database is locked
SQLite error: database is busy
VaultWarden fails to start with database errors
```

**Diagnostic Commands**:
```bash
# Check processes accessing database
sudo lsof /var/lib/*/data/bwdata/db.sqlite3

# Check database file permissions
ls -la /var/lib/*/data/bwdata/db.sqlite3

# Check database integrity
./tools/sqlite-maintenance.sh --check
```

**Solution Steps**:

#### **Step 1: Stop All Containers**
```bash
# Clean shutdown
docker compose down

# Wait for complete shutdown
sleep 10

# Verify no containers running
docker compose ps
```

#### **Step 2: Check Database Access**
```bash
# Verify no other processes are using database
sudo lsof /var/lib/*/data/bwdata/db.sqlite3

# If processes found, identify and stop them
sudo kill -9 PID_NUMBER
```

#### **Step 3: Database Integrity Check**
```bash
# Test database accessibility
sudo sqlite3 /var/lib/*/data/bwdata/db.sqlite3 "PRAGMA integrity_check;"

# If corruption detected:
sudo sqlite3 /var/lib/*/data/bwdata/db.sqlite3 ".recover" > recovered.sql

# Create new database from recovered data
sudo mv /var/lib/*/data/bwdata/db.sqlite3 db.sqlite3.backup
sudo sqlite3 /var/lib/*/data/bwdata/db.sqlite3 < recovered.sql
```

#### **Step 4: Restart Services**
```bash
# Clean restart
./startup.sh

# Monitor for errors
docker compose logs -f vaultwarden
```

---

### **Issue: Backup and Restore Failures**

**Symptoms**:
- Backup scripts fail with permission errors
- Restore process unable to access files
- Backup files corrupted or unreadable

**Backup Troubleshooting**:

#### **Check Backup Directory Permissions**
```bash
# Verify backup directory exists and is writable
ls -ld /var/lib/*/backups/
# Should show: drwx------ (700 permissions)

# Check available disk space
df -h /var/lib/*/backups/

# Check backup process
./tools/db-backup.sh --dry-run
```

#### **Test Backup Creation**
```bash
# Enable debug mode for detailed output
DEBUG=1 ./tools/db-backup.sh

# Check for specific error types:
# - Permission denied: Check file ownership
# - No space left: Clean old backups or increase storage
# - SQLite busy: Stop VaultWarden temporarily
```

#### **Verify Backup Integrity**
```bash
# List recent backups
ls -la /var/lib/*/backups/db/ | tail -10

# Test backup file integrity
./tools/restore.sh --verify /path/to/backup/file

# Test extraction without restoration
tar -tzf /path/to/backup.tar.gz
```

**Restore Troubleshooting**:

#### **Pre-Restore Checks**
```bash
# Stop services before restore
docker compose down

# Verify backup file exists and is readable
ls -la /path/to/backup/file
file /path/to/backup/file

# Check available disk space
df -h /var/lib/*/
```

#### **Restore Process Debugging**
```bash
# Run restore with debug output
DEBUG=1 ./tools/restore.sh /path/to/backup

# Manual extraction test
cd /tmp
tar -xzf /path/to/backup.tar.gz
ls -la extracted/
```

## 🔧 **System Resource and Performance Issues**

### **Issue: High Memory Usage**

**Symptoms**:
- Containers being killed (OOMKilled)
- System becomes unresponsive
- "Cannot allocate memory" errors

**Diagnostic Commands**:
```bash
# Check overall system memory
free -h

# Check container memory usage
docker stats --no-stream

# Check memory limits
docker compose config | grep -A 5 -B 5 memory

# Check for memory leaks
docker compose exec vaultwarden ps aux
```

**Solutions**:

#### **Adjust Container Limits**
```bash
# Edit docker-compose.yml memory limits
# For larger teams (5-10 users):
services:
  vaultwarden:
    deploy:
      resources:
        limits:
          memory: 1G  # Increase from 512M
          cpus: '2.0'
        reservations:
          memory: 512M
          cpus: '1.0'
```

#### **System Memory Management**
```bash
# Clear page cache (safe)
sudo sync && sudo sysctl vm.drop_caches=1

# Check for memory-intensive processes
ps aux --sort=-%mem | head -10

# Monitor memory usage over time
watch -n 5 'free -h && docker stats --no-stream'
```

---

### **Issue: Disk Space Exhaustion**

**Symptoms**:
- "No space left on device" errors
- Backup failures
- Log files growing indefinitely

**Disk Usage Analysis**:
```bash
# Check overall disk usage
df -h

# Find largest directories
sudo du -sh /var/lib/*/ | sort -rh | head -10
sudo du -sh /var/log/* | sort -rh | head -10

# Check inode usage
df -i
```

**Cleanup Solutions**:

#### **Automated Cleanup**
```bash
# Clean Docker system (removes unused containers, networks, images)
docker system prune -f

# Clean old logs (size-based)
sudo find /var/lib/*/logs -name "*.log" -size +50M -exec truncate -s 10M {} \;

# Clean old backups (age-based)
sudo find /var/lib/*/backups -name "*.backup*" -mtime +30 -delete

# Verify cron cleanup is working
crontab -l | grep cleanup
```

#### **Manual Cleanup**
```bash
# Identify largest log files
sudo find /var/lib/*/logs -name "*.log" -exec du -sh {} \; | sort -rh

# Truncate specific large log files
sudo truncate -s 0 /var/lib/*/logs/caddy/access.log

# Remove old backup files (keep last 10)
cd /var/lib/*/backups/db/
sudo ls -t *.backup | tail -n +11 | xargs rm -f
```

---

### **Issue: Poor Performance or Slow Response Times**

**Symptoms**:
- Web interface loads slowly
- Database queries timeout
- High CPU usage

**Performance Diagnostics**:
```bash
# Check system load
uptime
top -bn1 | head -20

# Check container resource usage
docker stats

# Check database performance
./tools/sqlite-maintenance.sh --analyze

# Check network latency
ping -c 10 your-domain.com
```

**Performance Optimization**:

#### **Database Optimization**
```bash
# Run database maintenance
./tools/sqlite-maintenance.sh --full

# Check database size and structure
sqlite3 /var/lib/*/data/bwdata/db.sqlite3 ".schema" | head -20
sqlite3 /var/lib/*/data/bwdata/db.sqlite3 "PRAGMA database_list;"
```

#### **Resource Allocation**
```bash
# Increase VaultWarden resources for larger teams
# Edit docker-compose.yml:
services:
  vaultwarden:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'

# Restart with new limits
./startup.sh
```

## 🔐 **Security and Access Issues**

### **Issue: Fail2ban Not Working**

**Symptoms**:
- Obvious attacks not being blocked
- fail2ban service not running
- No banned IPs despite suspicious activity

**Diagnostic Commands**:
```bash
# Check fail2ban service status
sudo systemctl status fail2ban

# Check active jails
sudo fail2ban-client status

# Check specific jail status
sudo fail2ban-client status vaultwarden
sudo fail2ban-client status sshd

# Check fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

**Configuration Verification**:
```bash
# Check jail configuration
sudo fail2ban-client get vaultwarden logpath
sudo fail2ban-client get vaultwarden bantime
sudo fail2ban-client get vaultwarden maxretry

# Test log file accessibility
sudo ls -la /var/lib/*/logs/caddy/access.log
sudo ls -la /var/lib/*/logs/vaultwarden/vaultwarden.log

# Verify filter patterns
sudo fail2ban-regex /var/lib/*/logs/vaultwarden/vaultwarden.log /etc/fail2ban/filter.d/vaultwarden.conf
```

**Solutions**:

#### **Restart Fail2ban**
```bash
# Restart fail2ban service
sudo systemctl restart fail2ban

# Check if jails are active after restart
sudo fail2ban-client status

# Reload jail configuration
sudo fail2ban-client reload
```

#### **Fix Configuration Issues**
```bash
# Check jail configuration syntax
sudo fail2ban-client -t

# Verify log file paths
sudo fail2ban-client set vaultwarden addlogpath /var/lib/*/logs/vaultwarden/vaultwarden.log

# Test CloudFlare action (if configured)
sudo fail2ban-client set vaultwarden banip 192.0.2.1
sudo fail2ban-client set vaultwarden unbanip 192.0.2.1
```

---

### **Issue: UFW Firewall Problems**

**Symptoms**:
- Cannot access services despite correct container status
- Firewall blocking legitimate traffic
- UFW rules not applying correctly

**UFW Diagnostics**:
```bash
# Check UFW status and rules
sudo ufw status verbose
sudo ufw status numbered

# Check UFW logging
sudo tail -f /var/log/ufw.log

# Test specific rule functionality
sudo ufw --dry-run allow 443/tcp
```

**Common UFW Issues and Solutions**:

#### **UFW Blocking Container Traffic**
```bash
# Check if UFW is interfering with Docker
sudo ufw status | grep -E "(80|443)"

# Ensure Docker rules are preserved
sudo systemctl restart docker
sudo ufw reload

# Add explicit allow rules if needed
sudo ufw allow in on docker0
sudo ufw allow out on docker0
```

#### **Reset UFW Configuration**
```bash
# If UFW configuration is corrupted, reset
sudo ufw --force reset

# Reconfigure basic rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

## 📋 **Diagnostic Checklists**

### **Complete System Health Check**
```bash
#!/bin/bash
# Comprehensive system diagnostic script

echo "=== System Health Check ==="

# 1. Basic system status
echo "1. System Resources:"
free -h
df -h /var/lib/*/

# 2. Service status
echo "2. Docker Status:"
systemctl is-active docker
docker compose ps

# 3. Network connectivity
echo "3. Network Tests:"
ping -c 3 8.8.8.8
nslookup $(grep DOMAIN settings.json | cut -d'"' -f4)

# 4. Configuration validation
echo "4. Configuration:"
./startup.sh --validate

# 5. Security services
echo "5. Security Status:"
sudo systemctl is-active ufw fail2ban

# 6. Recent errors
echo "6. Recent Errors:"
docker compose logs --tail=10 --since=1h | grep -i error

echo "=== Health Check Complete ==="
```

### **Pre-Deployment Checklist**
```bash
# Run before considering deployment complete
- [ ] chmod +x startup.sh tools/*.sh
- [ ] sudo ./tools/init-setup.sh completed successfully
- [ ] ./startup.sh starts all containers
- [ ] docker compose ps shows all healthy
- [ ] curl -I https://domain.com returns HTTP 200
- [ ] Admin panel accessible with generated token
- [ ] SSL certificate valid (check with browser)
- [ ] UFW firewall active with proper rules
- [ ] Fail2ban active with configured jails
- [ ] Backup system tested and working
- [ ] Monitoring cron jobs installed
- [ ] SMTP notifications configured (optional)
- [ ] CloudFlare integration working (optional)
```

### **Incident Response Checklist**
```bash
# When services are down or malfunctioning
1. Check container status: docker compose ps
2. Review recent logs: docker compose logs --tail=50
3. Check system resources: free -h && df -h
4. Verify configuration: ./startup.sh --validate
5. Check security services: systemctl status ufw fail2ban
6. Test network connectivity: ping domain.com
7. Review automation logs: journalctl -t monitor
8. Create diagnostic backup: ./tools/create-full-backup.sh --emergency
9. Document incident: Record time, symptoms, resolution
10. Post-incident: Review monitoring for prevention
```

## 🆘 **Getting Additional Help**

### **Log Collection for Support**
```bash
# Collect comprehensive diagnostic information
mkdir -p /tmp/vaultwarden-diagnostics
cd /tmp/vaultwarden-diagnostics

# System information
uname -a > system-info.txt
free -h >> system-info.txt
df -h >> system-info.txt

# Configuration (redacted)
sudo jq 'with_entries(if .key | contains("TOKEN") or contains("PASSWORD") or contains("KEY") then .value = "[REDACTED]" else . end)' /opt/VaultWarden-OCI-Minimal/settings.json > config-redacted.json

# Service status
docker compose ps > container-status.txt
systemctl status docker ufw fail2ban > service-status.txt

# Recent logs (last 100 lines)
docker compose logs --tail=100 > container-logs.txt
sudo tail -100 /var/log/syslog > system-logs.txt

# Create archive
tar -czf vaultwarden-diagnostics-$(date +%Y%m%d_%H%M%S).tar.gz *

echo "Diagnostic archive created: $(pwd)/vaultwarden-diagnostics-*.tar.gz"
echo "Share this file when requesting support"
```

### **Support Resources**
- **GitHub Issues**: [Report bugs and request features](https://github.com/killer23d/VaultWarden-OCI-Minimal/issues)
- **Discussions**: [Community Q&A and troubleshooting](https://github.com/killer23d/VaultWarden-OCI-Minimal/discussions)
- **Documentation**: Complete guides in `/docs/` directory
- **VaultWarden Wiki**: [Official VaultWarden documentation](https://github.com/dani-garcia/vaultwarden/wiki)

### **Emergency Recovery**
```bash
# If system is completely broken, emergency recovery:
1. Stop all services: docker compose down
2. Create emergency backup: cp -r /var/lib/* /tmp/emergency-backup/
3. Check available backups: ls -la /var/lib/*/backups/
4. Restore from recent backup: ./tools/restore.sh /path/to/backup
5. If no backups, reinstall: sudo ./tools/init-setup.sh --force
6. Document what went wrong for prevention
```

Remember: The goal is always to maintain the "set and forget" operational model while providing comprehensive diagnostic capabilities when issues do arise."""
