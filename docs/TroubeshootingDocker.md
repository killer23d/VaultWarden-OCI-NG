# Troubleshooting Guide

This comprehensive guide addresses common issues, diagnostic procedures, and solutions for the VaultWarden-OCI-NG stack.

## General Troubleshooting Approach

### Diagnostic Workflow
1. **Identify Symptoms**: What is not working as expected?
2. **Check Service Status**: Are all containers running and healthy?
3. **Review Logs**: What do the service logs reveal?
4. **Verify Configuration**: Is the configuration correct and complete?
5. **Test Components**: Isolate the failing component
6. **Apply Solution**: Implement the appropriate fix
7. **Verify Resolution**: Confirm the issue is resolved

### Essential Diagnostic Commands
```bash
# Quick system health check
./tools/check-health.sh

# Container status overview
docker compose ps

# View all service logs
docker compose logs

# Check system resources
df -h && free -h

# Verify network connectivity
curl -I https://your-domain.com
```

## Installation and Setup Issues

### Issue: Permission Denied on Scripts
**Symptoms**:
```bash
./startup.sh
bash: ./startup.sh: Permission denied
```

**Root Cause**: Git doesn't preserve executable permissions

**Solution**:
```bash
# Make all scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh

# Verify permissions
ls -la startup.sh tools/ | grep rwx

# Expected output shows 'rwx' for owner
-rwxr-xr-x 1 user user 15876 Oct 16 22:00 startup.sh
```

### Issue: init-setup.sh Fails with Docker Installation Error
**Symptoms**:
```bash
sudo ./tools/init-setup.sh
[ERROR] Failed to install Docker
```

**Diagnostic Steps**:
```bash
# Check if Docker is already installed
docker --version

# Check system architecture
uname -m

# Verify internet connectivity
ping -c 3 get.docker.com

# Check available disk space
df -h /var/lib
```

**Solutions**:
```bash
# Manual Docker installation
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Restart session or run:
newgrp docker

# Verify installation
docker run hello-world
```

### Issue: SOPS/Age Installation Failure
**Symptoms**:
```bash
[ERROR] Failed to install SOPS or Age
```

**Solutions**:
```bash
# Manual SOPS installation
SOPS_VERSION="v3.8.1"
wget -O /tmp/sops https://github.com/mozilla/sops/releases/download/$SOPS_VERSION/sops-$SOPS_VERSION.linux.amd64
sudo install /tmp/sops /usr/local/bin/sops

# Manual Age installation  
AGE_VERSION="v1.1.1"
wget -O /tmp/age.tar.gz https://github.com/FiloSottile/age/releases/download/$AGE_VERSION/age-$AGE_VERSION-linux-amd64.tar.gz
tar -xzf /tmp/age.tar.gz -C /tmp/
sudo install /tmp/age/age /usr/local/bin/age
sudo install /tmp/age/age-keygen /usr/local/bin/age-keygen

# Verify installations
sops --version
age --version
```

## Service Startup Issues

### Issue: VaultWarden Container Won't Start
**Symptoms**:
```bash
docker compose ps
# Shows vaultwarden as "Exit 1" or "Restarting"
```

**Diagnostic Commands**:
```bash
# Check VaultWarden logs
docker compose logs vaultwarden

# Check container health
docker compose ps --format "table {{.Name}}	{{.Status}}	{{.Health}}"

# Verify database file permissions
ls -la $PROJECT_STATE_DIR/data/bwdata/db.sqlite3
```

**Common Causes and Solutions**:

#### Database Permission Issues
```bash
# Fix database directory permissions
sudo chown -R 1000:1000 $PROJECT_STATE_DIR/data/bwdata/
sudo chmod 755 $PROJECT_STATE_DIR/data/bwdata/
```

#### Invalid Database File
```bash
# Check database integrity
./tools/sqlite-maintenance.sh --check

# If corrupted, restore from backup
./tools/restore.sh --list
./tools/restore.sh /path/to/recent/backup
```

#### Missing or Invalid Secrets
```bash
# Verify secrets are accessible
sudo ./tools/edit-secrets.sh --view

# Check Docker secrets directory
ls -la secrets/.docker_secrets/

# Regenerate secrets if needed
sudo ./tools/edit-secrets.sh
```

### Issue: Caddy SSL Certificate Problems
**Symptoms**:
- Browser shows "Your connection is not private"
- SSL Labs test fails
- Caddy logs show certificate errors

**Diagnostic Commands**:
```bash
# Check Caddy logs for certificate issues
docker compose logs caddy | grep -i cert

# Check Let's Encrypt rate limits
docker compose logs caddy | grep -i "rate limit"

# Verify domain accessibility
curl -I http://your-domain.com/.well-known/acme-challenge/test
```

**Solutions**:

#### Domain Not Accessible
```bash
# Check DNS resolution
nslookup your-domain.com
dig your-domain.com

# Verify firewall allows HTTP (port 80)
sudo ufw status | grep 80

# Test from external location
curl -I http://your-domain.com
```

#### Let's Encrypt Rate Limits
```bash
# Wait for rate limit reset (1 hour for failures, 1 week for duplicates)
# Or use staging environment for testing

# Check current certificates
docker compose exec caddy caddy list-certificates

# Force certificate reload
docker compose exec caddy caddy reload
```

#### CloudFlare SSL Mode Issues
If using CloudFlare:
1. Set SSL/TLS mode to "Full (strict)" in CloudFlare dashboard
2. Ensure "Always Use HTTPS" is enabled
3. Disable "Authenticated Origin Pulls" temporarily

### Issue: Fail2ban Not Starting
**Symptoms**:
```bash
docker compose logs fail2ban
[ERROR] Failed to start fail2ban
```

**Common Causes and Solutions**:

#### Network Mode Conflict
```bash
# Check if host network is available
docker run --rm --network host alpine ip addr show

# If fails, check Docker daemon configuration
sudo systemctl status docker
```

#### Missing Log Files
```bash
# Create log directories
mkdir -p $PROJECT_STATE_DIR/logs/{caddy,vaultwarden,fail2ban}

# Set proper permissions
chmod 755 $PROJECT_STATE_DIR/logs/
```

## Runtime Issues

### Issue: Cannot Access Web Interface
**Symptoms**:
- Browser shows "This site can't be reached"
- Connection timeout errors
- ERR_CONNECTION_REFUSED

**Diagnostic Workflow**:

#### Step 1: Check Container Status
```bash
docker compose ps

# Expected output:
# NAME                     STATUS
# project_caddy           Up (healthy)
# project_vaultwarden     Up (healthy)
```

#### Step 2: Check Port Binding
```bash
# Verify ports are bound
sudo ss -tlnp | grep -E ":(80|443)"

# Expected output:
# LISTEN 0    4096    *:80     *:*    users:(("docker-proxy"))
# LISTEN 0    4096    *:443    *:*    users:(("docker-proxy"))
```

#### Step 3: Check Firewall
```bash
sudo ufw status

# Should show:
# Status: active
# 80/tcp     ALLOW
# 443/tcp    ALLOW
```

#### Step 4: Test Local Connectivity
```bash
# Test local HTTP
curl -I http://localhost:80

# Test HTTPS (may show certificate error, but should connect)
curl -k -I https://localhost:443
```

**Solutions**:
```bash
# If containers are down
./startup.sh

# If firewall blocks access
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# If ports aren't bound
docker compose down
./startup.sh

# For DNS issues
echo "127.0.0.1 your-domain.com" | sudo tee -a /etc/hosts
```

### Issue: Admin Panel Access Denied
**Symptoms**:
- "Invalid admin token" message
- "Unauthorized" error
- Cannot access /admin URL

**Solutions**:

#### Verify Admin Token
```bash
# Get current admin token
sudo ./tools/edit-secrets.sh --view | grep admin_token

# If empty or invalid, generate new one
sudo ./tools/edit-secrets.sh
# Add new admin_token: "$(openssl rand -base64 32)"

# Restart VaultWarden
docker compose restart vaultwarden
```

#### Clear Browser Cache
```bash
# Clear browser cache and cookies for your domain
# Or use incognito/private browsing mode

# Test with curl
curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" https://your-domain.com/admin/
```

### Issue: Database Performance Problems
**Symptoms**:
- Slow web interface response
- High CPU usage
- Database errors in logs

**Diagnostic Commands**:
```bash
# Check database size and fragmentation
./tools/sqlite-maintenance.sh --stats

# Monitor container resources
docker stats

# Check for database locks
sudo lsof $PROJECT_STATE_DIR/data/bwdata/db.sqlite3
```

**Solutions**:
```bash
# Optimize database
./tools/sqlite-maintenance.sh --full

# If severe issues, restore from backup
./tools/restore.sh --verify /path/to/backup
./tools/restore.sh /path/to/backup

# Check disk space
df -h $PROJECT_STATE_DIR
```

## Backup and Recovery Issues

### Issue: Backup Creation Fails
**Symptoms**:
```bash
./tools/create-full-backup.sh
[ERROR] Backup creation failed
```

**Diagnostic Steps**:
```bash
# Check available disk space
df -h

# Verify backup directory permissions
ls -la $PROJECT_STATE_DIR/backups/

# Test database accessibility
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 ".tables"

# Check backup passphrase
sudo ./tools/edit-secrets.sh --view | grep backup_passphrase
```

**Solutions**:
```bash
# Create backup directory
mkdir -p $PROJECT_STATE_DIR/backups
chmod 755 $PROJECT_STATE_DIR/backups

# Free up disk space
docker system prune -f
sudo find /var/log -name "*.log" -size +50M -delete

# Set backup passphrase if missing
sudo ./tools/edit-secrets.sh
# Add: backup_passphrase: "your-secure-passphrase"
```

### Issue: Restore Operation Fails
**Symptoms**:
```bash
./tools/restore.sh backup.tar.gz.enc
[ERROR] Restore failed
```

**Diagnostic Steps**:
```bash
# Verify backup file integrity
./tools/restore.sh --verify backup.tar.gz.enc

# Check backup format
file backup.tar.gz.enc

# Test decryption
# (Use backup passphrase from secrets)
openssl enc -d -aes-256-cbc -in backup.tar.gz.enc -pass pass:PASSPHRASE | tar -tzf -
```

**Solutions**:
```bash
# If backup is corrupted, try another backup
./tools/restore.sh --list

# If passphrase is wrong
sudo ./tools/edit-secrets.sh --view | grep backup_passphrase

# If restore location has no space
df -h
docker system prune -f
```

## Monitoring and Health Check Issues

### Issue: Health Check Script Errors
**Symptoms**:
```bash
./tools/check-health.sh
[ERROR] Health check failed
```

**Solutions Based on Specific Errors**:

#### SSL Certificate Errors
```bash
# Check certificate expiration
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates

# Force certificate renewal
docker compose exec caddy caddy reload

# Check Let's Encrypt logs
docker compose logs caddy | grep -i acme
```

#### Database Health Errors
```bash
# Run database integrity check
./tools/sqlite-maintenance.sh --check

# If corruption detected
./tools/sqlite-maintenance.sh --repair

# If repair fails, restore from backup
./tools/restore.sh --list
./tools/restore.sh /path/to/recent/backup
```

#### Container Health Errors
```bash
# Check individual container health
docker compose ps

# Restart unhealthy containers
docker compose restart service-name

# If persistent issues, recreate containers
docker compose down
docker compose up -d
```

## Network and Connectivity Issues

### Issue: CloudFlare Integration Problems
**Symptoms**:
- Real IP addresses not detected
- Fail2ban not working with CloudFlare
- SSL errors with CloudFlare

**Solutions**:

#### Real IP Detection
```bash
# Verify CloudFlare IP ranges are updated
./tools/update-cloudflare-ips.sh

# Check Caddy configuration
docker compose exec caddy cat /etc/caddy/Caddyfile

# Should include CloudFlare IP trust
```

#### Fail2ban CloudFlare Integration
```bash
# Verify CloudFlare API token
sudo ./tools/edit-secrets.sh --view | grep cloudflare_api_token

# Test CloudFlare API access
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify"      -H "Authorization: Bearer YOUR_API_TOKEN"      -H "Content-Type: application/json"

# Check fail2ban CloudFlare action
sudo fail2ban-client get vaultwarden-auth actions
```

### Issue: Dynamic DNS Not Updating
**Symptoms**:
- IP address changes but DNS not updated
- ddclient container errors

**Diagnostic Commands**:
```bash
# Check ddclient logs
docker compose logs ddclient

# Verify configuration
cat ddclient/ddclient.conf

# Test IP detection
curl -s https://ipify.org
```

**Solutions**:
```bash
# Update DNS configuration
./tools/render-ddclient-conf.sh templates/ddclient.conf.tmpl ddclient/ddclient.conf

# Restart ddclient
docker compose restart ddclient

# Manual DNS update test
docker compose exec ddclient ddclient -debug -verbose -noquiet
```

## Performance Issues

### Issue: High Memory Usage
**Symptoms**:
```bash
free -h
# Shows very low available memory

docker stats
# Shows high memory usage for containers
```

**Solutions**:
```bash
# Check current memory limits
docker compose config | grep -A2 -B2 memory

# Adjust memory limits in docker-compose.yml or environment
export VAULTWARDEN_MEMORY_LIMIT=1G
export CADDY_MEMORY_LIMIT=256M

# Restart with new limits
./startup.sh

# If system memory is insufficient, consider upgrading hardware
```

### Issue: Slow Performance
**Symptoms**:
- Web interface loads slowly
- High response times
- Database queries taking too long

**Diagnostic Steps**:
```bash
# Check system load
uptime

# Check I/O wait
iostat 1 5

# Check database performance
./tools/sqlite-maintenance.sh --stats

# Monitor container resources
docker stats --no-stream
```

**Solutions**:
```bash
# Optimize database
./tools/sqlite-maintenance.sh --full

# Check for disk space issues
df -h

# Increase container resource limits
# Edit docker-compose.yml or environment variables

# Consider SSD upgrade for storage-intensive workloads
```

## Log Analysis and Debugging

### Useful Log Commands
```bash
# All service logs in real-time
docker compose logs -f

# Specific service logs
docker compose logs -f vaultwarden
docker compose logs -f caddy
docker compose logs -f fail2ban

# System logs
journalctl -f
journalctl -u docker

# Fail2ban specific logs
sudo journalctl -u fail2ban -f
sudo fail2ban-client status
```

### Log File Locations
```bash
# Container logs
/var/lib/docker/containers/*/logs/
# Or via docker compose logs

# Application logs  
$PROJECT_STATE_DIR/logs/vaultwarden/
$PROJECT_STATE_DIR/logs/caddy/
$PROJECT_STATE_DIR/logs/fail2ban/

# System logs
/var/log/syslog
/var/log/auth.log
/var/log/fail2ban.log
```

## Emergency Recovery Procedures

### Complete System Recovery
If the system is severely compromised or corrupted:

```bash
# 1. Stop all services
docker compose down

# 2. Backup current state (if possible)
tar -czf emergency-backup-$(date +%Y%m%d).tar.gz $PROJECT_STATE_DIR

# 3. Restore from last known good backup
./tools/restore.sh --list
./tools/restore.sh /path/to/backup

# 4. Verify restoration
./tools/check-health.sh

# 5. Start services
./startup.sh
```

### Configuration Reset
If configuration is corrupted but data is intact:

```bash
# 1. Backup current configuration
cp settings.json settings.json.backup

# 2. Re-run setup with existing data
sudo ./tools/init-setup.sh

# 3. Restore specific settings if needed
# Edit settings.json manually or restore from backup

# 4. Restart services
./startup.sh
```

### Secret Management Recovery
If secrets are lost or corrupted:

```bash
# 1. Generate new Age key
age-keygen -o secrets/keys/age-key-new.txt

# 2. Create new secrets file
sudo ./tools/edit-secrets.sh
# Recreate all secrets with new values

# 3. Update all dependent services
# Change admin token, SMTP password, etc.

# 4. Restart entire stack
./startup.sh
```

## Getting Additional Help

### Diagnostic Information Collection
When reporting issues, collect this information:

```bash
# System information
uname -a
cat /etc/os-release

# Docker information
docker version
docker compose version

# Service status
./tools/check-health.sh --verbose > health-report.txt

# Configuration (redacted)
docker compose config > compose-config.yaml

# Recent logs
docker compose logs --tail=100 > service-logs.txt
```

### Support Resources
- **Documentation**: Review all files in the `docs/` directory
- **GitHub Issues**: Search existing issues for similar problems
- **Log Analysis**: Enable debug logging for detailed troubleshooting
- **Community Support**: Engage with the VaultWarden community

### Debug Mode
Enable detailed logging for troubleshooting:

```bash
# Enable debug mode for scripts
export DEBUG=1
./startup.sh

# Enable verbose logging in VaultWarden
# Add to settings: LOG_LEVEL=debug

# Enable debug logging in Caddy
# Add global option: debug
```

This troubleshooting guide covers the most common issues encountered with VaultWarden-OCI-NG. For issues not covered here, use the diagnostic commands and procedures to gather information for further investigation.
