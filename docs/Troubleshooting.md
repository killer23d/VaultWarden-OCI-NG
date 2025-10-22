# Troubleshooting Guide

**Comprehensive problem resolution for VaultWarden-OCI-NG deployment and operations**

This guide provides systematic troubleshooting procedures for common and complex issues in VaultWarden-OCI-NG deployments. All procedures follow the self-healing and actionable guidance principles of the system. Now includes troubleshooting for container security and input validation features.

## 🚨 **Emergency Quick Reference**

### **Critical Service Failures**
```bash
# Immediate response for service outages
./tools/check-health.sh --fix --comprehensive
./startup.sh --force-restart
docker compose logs --tail=100
```

### **Cannot Access Web Interface**
```bash
# Quick diagnostic sequence (including container security checks)
sudo ufw status                         # Check firewall
dig vault.yourdomain.com               # Verify DNS
./tools/check-health.sh --component certificates
curl -I https://vault.yourdomain.com   # Test HTTPS response
docker compose exec vaultwarden whoami # Check container user
```

### **Container Security Issues**
```bash
# Quick container security diagnostics
docker compose exec vaultwarden whoami  # Should show user 1000 or vaultwarden
docker compose exec caddy whoami        # Should show user 1000 or caddy
sudo ls -la /var/lib/vaultwarden/       # Check volume permissions
docker inspect vaultwarden_vaultwarden | grep -A3 "User"
```

### **Input Validation Failures**
```bash
# Quick input validation diagnostics
source lib/validation.sh
validate_domain_format "vault.example.com"      # Test domain validation
validate_email_format "admin@example.com"       # Test email validation
./tools/init-setup.sh --domain "test.domain.com" --email "test@example.com"  # Test setup validation
```

## 🔍 **Systematic Troubleshooting Framework**

### **Diagnostic Hierarchy**
1. **System Level** - OS, Docker, network connectivity
2. **Container Security Level** - User privileges, volume permissions, resource limits
3. **Configuration Level** - Environment variables, secrets, input validation
4. **Service Level** - Container health, inter-service communication
5. **Application Level** - VaultWarden functionality, user access
6. **Integration Level** - External services (SMTP, Cloudflare, DNS)

### **Standard Diagnostic Sequence**
```bash
# 1. Validate system integrity
./tools/validate-code.sh

# 2. Check container security status
docker compose exec vaultwarden whoami
docker compose exec caddy whoami

# 3. Check overall health with auto-fix
./tools/check-health.sh --fix

# 4. Verify configuration and input validation
./startup.sh --dry-run

# 5. Analyze service logs
docker compose logs --tail=50

# 6. Test external dependencies
./tools/backup-monitor.sh --test-email
```

## 🔒 **Container Security Troubleshooting**

### **Non-Root Container Issues**

#### **Container Permission Denied Errors**
**Symptoms:**
- Containers fail to start with permission errors
- "Permission denied" errors in VaultWarden or Caddy logs
- Files cannot be written to mounted volumes

**Diagnosis:**
```bash
# Check container user IDs
docker compose exec vaultwarden id
docker compose exec caddy id

# Check volume ownership
sudo ls -la /var/lib/vaultwarden/data/
sudo ls -la ./caddy/

# Check Docker Compose user configuration
docker compose config | grep -A2 -B2 "user:"
```

**Resolution:**
```bash
# Fix volume ownership for non-root containers
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/

# Set appropriate permissions
sudo chmod -R 750 /var/lib/vaultwarden/data/
sudo chmod -R 644 ./caddy/*.caddy ./caddy/Caddyfile

# Restart containers
docker compose down
docker compose up -d

# Verify fix
docker compose exec vaultwarden touch /data/test.txt
docker compose exec vaultwarden rm /data/test.txt
```

#### **Container User Mismatch Issues**
**Symptoms:**
- Containers running as root when they should be non-root
- Security warnings about privileged containers
- File ownership conflicts

**Diagnosis:**
```bash
# Verify current container users
for container in vaultwarden caddy fail2ban ddclient watchtower; do
    if docker ps --format "{{.Names}}" | grep -q "${container}"; then
        echo "$container: $(docker exec "${container}" whoami 2>/dev/null || echo 'not running')"
    fi
done

# Check Docker Compose configuration
grep -A5 -B5 "user:" docker-compose.yml
```

**Resolution:**
```bash
# Expected user configuration:
# vaultwarden: user 1000:1000 ✓
# caddy: user 1000:1000 ✓  
# fail2ban: root (required for iptables) ✓
# watchtower: root (required for Docker socket) ✓
# ddclient: PUID=1000 PGID=1000 ✓

# If containers are running as wrong users:
docker compose down
# Edit docker-compose.yml to ensure correct user settings
docker compose up -d

# Verify after restart
./tools/check-health.sh --component security
```

#### **Container Capability and Security Issues**
**Symptoms:**
- Containers cannot bind to privileged ports
- Security options not applied correctly
- Privilege escalation warnings

**Diagnosis:**
```bash
# Check container security settings
docker inspect vaultwarden_vaultwarden | grep -A10 "SecurityOpt"
docker inspect caddy_container | grep -A10 "SecurityOpt"

# Check capabilities
docker inspect caddy_container | grep -A5 "CapAdd"
docker inspect fail2ban_container | grep -A5 "CapAdd"

# Check no-new-privileges setting
docker inspect vaultwarden_vaultwarden | grep "NoNewPrivileges"
```

**Resolution:**
```bash
# Ensure proper security options in docker-compose.yml:
# For vaultwarden and caddy:
security_opt:
  - no-new-privileges:true

# For caddy (needs to bind to ports 80/443):
cap_add:
  - NET_BIND_SERVICE

# For fail2ban (needs iptables access):
cap_add:
  - NET_ADMIN
  - NET_RAW

# Restart with correct configuration
docker compose down
docker compose up -d
```

### **Volume Permission Issues for Non-Root Containers**

#### **Data Volume Permission Problems**
**Symptoms:**
- VaultWarden cannot write to database
- Backup creation fails with permission errors
- Log files not created or accessible

**Diagnosis:**
```bash
# Check data directory permissions
sudo ls -la /var/lib/vaultwarden/
sudo ls -la /var/lib/vaultwarden/data/
sudo ls -la /var/lib/vaultwarden/logs/

# Check if containers can write to volumes
docker compose exec vaultwarden touch /data/permission-test
docker compose exec caddy touch /var/log/caddy/permission-test

# Check volume mount configuration
docker inspect vaultwarden_vaultwarden | grep -A10 "Mounts"
```

**Resolution:**
```bash
# Comprehensive permission fix for non-root containers
PROJECT_STATE_DIR="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"

# Fix ownership
sudo chown -R 1000:1000 "$PROJECT_STATE_DIR"
sudo chown -R 1000:1000 ./caddy

# Fix permissions
sudo find "$PROJECT_STATE_DIR" -type d -exec chmod 750 {} \;
sudo find "$PROJECT_STATE_DIR" -type f -exec chmod 640 {} \;
sudo find ./caddy -type f -exec chmod 644 {} \;

# Special permissions for sensitive files
sudo chmod 600 secrets/keys/age-key.txt
sudo chmod 700 secrets/.docker_secrets/

# Restart containers
docker compose restart

# Test write permissions
docker compose exec vaultwarden touch /data/write-test
docker compose exec vaultwarden rm /data/write-test
echo "✅ Volume permissions fixed"
```

## ✅ **Input Validation Troubleshooting**

### **Domain Validation Issues**

#### **Domain Format Validation Failures**
**Symptoms:**
- `init-setup.sh` rejects valid domain names
- Setup fails with "Invalid domain format" errors
- Domain validation prevents system initialization

**Diagnosis:**
```bash
# Test domain validation manually
source lib/validation.sh
validate_domain_format "vault.example.com"     # Should pass
validate_domain_format "https://vault.example.com"  # Should warn and strip protocol
validate_domain_format "invalid..domain"       # Should fail

# Check current domain in configuration
grep "^DOMAIN=" .env 2>/dev/null || echo "No .env file found"
```

**Resolution:**
```bash
# Common domain validation fixes:

# ❌ Wrong: Including protocol
sudo ./tools/init-setup.sh --domain "https://vault.example.com" --email "admin@example.com"

# ✅ Correct: Clean domain only
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "admin@example.com"

# ❌ Wrong: Trailing slash
sudo ./tools/init-setup.sh --domain "vault.example.com/" --email "admin@example.com"

# ✅ Correct: Clean domain
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "admin@example.com"

# Test domain validation interactively
source lib/validation.sh
validate_domain_format "your-actual-domain.com"
```

#### **Domain Security Validation Issues**
**Symptoms:**
- Valid domains rejected for security reasons
- Warnings about internal/localhost domains
- Domain sanitization removing valid characters

**Diagnosis:**
```bash
# Test domain security validation
source lib/validation.sh

# These should generate warnings but may pass:
validate_domain_format "localhost"             # Internal domain warning
validate_domain_format "192.168.1.100"        # IP address warning
validate_domain_format "10.0.0.5"             # Private IP warning

# These should fail security validation:
validate_domain_format "domain.com<script>"    # Dangerous characters
validate_domain_format "domain.com\$(whoami)" # Command injection attempt
```

**Resolution:**
```bash
# For development/testing with internal domains:
# The system will warn but allow localhost/internal IPs
# Note: Let's Encrypt certificates won't work with internal domains

# For production, use valid public domains:
# ✅ Correct examples:
validate_domain_format "vault.mycompany.com"
validate_domain_format "passwords.example.org"
validate_domain_format "secure.mydomain.co.uk"

# If domain is rejected incorrectly, check for:
# - Hidden characters: cat -A <<< "vault.example.com"
# - Encoding issues: echo "vault.example.com" | hexdump -C
```

### **Email Validation Issues**

#### **Email Format Validation Failures**
**Symptoms:**
- Valid email addresses rejected by setup
- Email validation prevents admin user creation
- SMTP configuration fails validation

**Diagnosis:**
```bash
# Test email validation manually
source lib/validation.sh
validate_email_format "admin@example.com"      # Should pass
validate_email_format "user.name@domain.co.uk" # Should pass
validate_email_format "invalid@"               # Should fail
validate_email_format "@domain.com"            # Should fail

# Check current email in configuration
grep "^ADMIN_EMAIL=" .env 2>/dev/null || echo "No .env file found"
```

**Resolution:**
```bash
# Common email validation fixes:

# ❌ Wrong: Missing domain
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "admin@"

# ✅ Correct: Complete email
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "admin@example.com"

# ❌ Wrong: Missing @ symbol
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "adminexample.com"

# ✅ Correct: Proper email format
sudo ./tools/init-setup.sh --domain "vault.example.com" --email "admin@example.com"

# Test various email formats
source lib/validation.sh
validate_email_format "user.name+label@domain.com"    # Should pass
validate_email_format "user_name@sub.domain.org"      # Should pass
validate_email_format "123@domain.com"                # Should pass
```

#### **Email Security Validation Issues**
**Symptoms:**
- Security warnings about email format
- Emails rejected for containing dangerous characters
- Email validation prevents system setup

**Diagnosis:**
```bash
# Test email security validation
source lib/validation.sh

# These should fail security validation:
validate_email_format "admin@domain.com<script>"      # Dangerous characters
validate_email_format "admin';DROP TABLE--@domain.com" # SQL injection attempt
validate_email_format "$(whoami)@domain.com"           # Command injection

# These should pass:
validate_email_format "admin@domain.com"               # Clean email
validate_email_format "user.name@domain.co.uk"        # Complex but valid
```

**Resolution:**
```bash
# For email security issues:
# Ensure email addresses don't contain:
# - HTML/script tags: < > " ' \
# - SQL injection patterns: ' ; -- DROP
# - Command substitution: $ ( ) ` 

# ✅ Safe email formats:
validate_email_format "admin@company.com"
validate_email_format "vault-admin@domain.org"  
validate_email_format "security.team@example.co.uk"

# If legitimate email is rejected, check for:
# - Copy/paste artifacts: cat -A <<< "your-email@domain.com"
# - Hidden Unicode: echo "your-email@domain.com" | xxd
```

### **Secrets Validation Issues**

#### **Secrets Security Validation Failures**
**Symptoms:**
- Weak passwords rejected during setup
- Secret validation prevents service startup
- SOPS configuration fails validation

**Diagnosis:**
```bash
# Test secrets validation
if [[ -f "secrets/secrets.yaml" ]]; then
    source lib/validation.sh
    # Note: This requires manual inspection as secrets are encrypted
    echo "Secrets file exists, validation occurs during startup"
else
    echo "No secrets file found"
fi

# Check for validation errors in logs
docker compose logs vaultwarden | grep -i "validation"
grep -i "validation" /var/log/syslog 2>/dev/null || echo "No syslog validation errors"
```

**Resolution:**
```bash
# Common secrets validation fixes:

# Edit secrets with stronger passwords
./tools/edit-secrets.sh

# Password requirements:
# - ADMIN_BASIC_AUTH_PASSWORD: min 12 characters, uppercase, lowercase, numbers
# - SMTP_PASSWORD: min 8 characters
# - All secrets: no dangerous characters

# Example strong passwords:
ADMIN_BASIC_AUTH_PASSWORD: "MyVault2025!Admin"     # 12+ chars, mixed case, numbers, symbols
SMTP_PASSWORD: "MySecureAppPassword123"            # App-specific password for Gmail

# Regenerate secrets if needed
sudo ./tools/init-setup.sh --regenerate-secrets
```

## 🐳 **Container and Docker Issues** (Enhanced)

### **Docker Service Problems**

#### **Docker Daemon Not Running**
**Symptoms:**
- `docker info` fails with "Cannot connect to Docker daemon"
- Services fail to start with Docker connection errors

**Diagnosis:**
```bash
# Check Docker service status
sudo systemctl status docker

# Check Docker socket permissions
ls -la /var/run/docker.sock

# Check system resources
df -h                    # Disk space
free -h                  # Memory availability
```

**Resolution:**
```bash
# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# If disk space is full
sudo docker system prune -a --volumes  # WARNING: Removes unused data
sudo ./tools/host-maintenance.sh --cleanup

# Fix Docker socket permissions
sudo chmod 666 /var/run/docker.sock
sudo usermod -aG docker $USER
```

#### **Container Startup Failures with Security Settings**
**Symptoms:**
- Containers fail to start after security updates
- "Operation not permitted" errors
- Resource constraint violations

**Diagnosis:**
```bash
# Check container status and errors
docker compose ps
docker compose logs vaultwarden 2>&1 | grep -i "error"
docker compose logs caddy 2>&1 | grep -i "error"

# Check security options and capabilities
docker inspect vaultwarden_vaultwarden | grep -A10 "SecurityOpt"
docker inspect caddy_container | grep -A10 "CapAdd"

# Check resource constraints
docker stats --no-stream
```

**Resolution:**
```bash
# Reset containers with proper security settings
docker compose down --remove-orphans

# Verify docker-compose.yml has correct security configuration
grep -A15 "vaultwarden:" docker-compose.yml
grep -A15 "caddy:" docker-compose.yml

# Start with proper security settings
docker compose up -d

# Verify security settings are applied
docker inspect vaultwarden_vaultwarden | grep -E "(User|SecurityOpt|NoNewPrivileges)"
```

### **Image and Volume Issues with Non-Root Support**

#### **Image Compatibility with Non-Root Users**
**Symptoms:**
- Containers fail to start as non-root
- Application errors due to user/permission mismatches
- File system permission conflicts

**Diagnosis:**
```bash
# Check if images support non-root execution
docker run --rm --user 1000:1000 vaultwarden/server:1.30.5 whoami
docker run --rm --user 1000:1000 caddy:2.7.6 whoami

# Check image default users
docker inspect vaultwarden/server:1.30.5 | grep -A5 "User"
docker inspect caddy:2.7.6 | grep -A5 "User"
```

**Resolution:**
```bash
# VaultWarden and Caddy images support non-root execution
# If issues persist, verify volume permissions and restart

# For VaultWarden
sudo chown -R 1000:1000 /var/lib/vaultwarden/
docker compose restart vaultwarden

# For Caddy  
sudo chown -R 1000:1000 ./caddy/
docker compose restart caddy

# Test non-root execution
docker compose exec vaultwarden whoami  # Should show user 1000 or vaultwarden
docker compose exec caddy whoami        # Should show user 1000 or caddy
```

## 🔐 **Enhanced Security Troubleshooting**

### **Container Security Monitoring Issues**

#### **Security Validation Failures**
**Symptoms:**
- Health checks report container security issues
- Containers running with incorrect privileges
- Security monitoring alerts

**Diagnosis:**
```bash
# Run comprehensive security validation
source lib/validation.sh
verify_container_security 2>&1

# Check container privilege escalation
docker exec vaultwarden_vaultwarden find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l

# Verify security options
docker inspect vaultwarden_vaultwarden | grep -A5 "SecurityOpt"
docker inspect caddy_container | grep -A5 "SecurityOpt"
```

**Resolution:**
```bash
# Fix container security configuration
docker compose down

# Verify docker-compose.yml has proper security settings:
# security_opt:
#   - no-new-privileges:true

# Restart with security settings
docker compose up -d

# Verify security improvements
./tools/check-health.sh --component security
```

### **Input Validation Security Issues**

#### **Validation Bypass Attempts**
**Symptoms:**
- Suspicious input patterns in logs
- Validation errors with special characters
- Security warnings during configuration

**Diagnosis:**
```bash
# Check for validation bypass attempts in logs
grep -i "validation" /var/log/syslog 2>/dev/null
docker compose logs | grep -i "dangerous\|invalid\|security"

# Test input validation robustness
source lib/validation.sh
validate_domain_format "domain.com<script>alert(1)</script>"
validate_email_format "admin';DROP TABLE users;--@domain.com"
```

**Resolution:**
```bash
# Input validation is designed to catch these attempts
# Monitor logs for repeated validation failures:
grep "validation failed" /var/log/syslog | tail -10

# If seeing repeated attacks, consider:
# 1. Blocking source IPs with fail2ban
sudo ufw deny from ATTACKER_IP

# 2. Reviewing firewall rules
sudo ufw status numbered

# 3. Enabling additional logging
# Edit lib/validation.sh to increase logging for validation failures
```

## 📧 **Email and Notification Issues** (Enhanced)

### **SMTP Configuration with Validation**

#### **Email Validation Preventing SMTP Setup**
**Symptoms:**
- SMTP configuration rejected due to email format
- Email validation errors during secret editing
- Notification system not working due to validation

**Diagnosis:**
```bash
# Test SMTP email validation
source lib/validation.sh
validate_email_format "$(grep SMTP_FROM secrets/secrets.yaml | cut -d':' -f2 | tr -d ' "')"
validate_email_format "$(grep ADMIN_EMAIL .env | cut -d'=' -f2)"

# Check SMTP configuration validation
./tools/backup-monitor.sh --test-email --debug
```

**Resolution:**
```bash
# Fix SMTP email validation issues
./tools/edit-secrets.sh

# Ensure proper email format:
SMTP_FROM: "VaultWarden <vault@yourdomain.com>"  # Include display name
ADMIN_EMAIL: "admin@yourdomain.com"              # Simple format

# Test email validation manually
source lib/validation.sh
validate_email_format "vault@yourdomain.com"     # Should pass
validate_email_format "admin@yourdomain.com"     # Should pass

# Restart services to apply changes
./startup.sh --force-restart
```

## 🗄️ **Database and Backup Issues** (Enhanced)

### **Database Security with Non-Root Containers**

#### **Database Permission Issues with Non-Root**
**Symptoms:**
- Database files inaccessible to VaultWarden container
- SQLite operations fail with permission errors
- Backup creation fails due to database access issues

**Diagnosis:**
```bash
# Check database file permissions
sudo ls -la /var/lib/vaultwarden/data/bwdata/
ls -la data/bwdata/ 2>/dev/null || echo "Local data directory not found"

# Check if VaultWarden can access database
docker compose exec vaultwarden sqlite3 /data/db.sqlite3 ".tables"

# Verify container user can read/write database
docker compose exec vaultwarden id
docker compose exec vaultwarden ls -la /data/
```

**Resolution:**
```bash
# Fix database permissions for non-root container
PROJECT_STATE_DIR="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
sudo chown -R 1000:1000 "$PROJECT_STATE_DIR/data"
sudo chmod -R 750 "$PROJECT_STATE_DIR/data"

# Ensure database files are accessible
sudo find "$PROJECT_STATE_DIR/data" -name "*.sqlite3*" -exec chmod 640 {} \;

# Restart VaultWarden to verify fix
docker compose restart vaultwarden

# Test database access
docker compose exec vaultwarden sqlite3 /data/db.sqlite3 "SELECT COUNT(*) FROM users;"
```

---

## 🆘 **Enhanced Emergency Recovery Procedures**

### **Complete System Recovery with Security Validation**
```bash
# 1. Access emergency kit
age -d -i /path/to/emergency-kit-key.txt emergency-kit.tar.gz.age | tar -xzf -

# 2. Restore critical files with proper permissions
cp emergency-kit/secrets/keys/age-key.txt secrets/keys/
chmod 600 secrets/keys/age-key.txt
cp emergency-kit/secrets.yaml secrets/
cp emergency-kit/.env ./

# 3. Validate restored configuration
source lib/validation.sh
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)"
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)"

# 4. Initialize system with security validation
sudo ./tools/init-setup.sh --restore-mode

# 5. Fix volume permissions for non-root containers
sudo chown -R 1000:1000 /var/lib/vaultwarden/

# 6. Start services
./startup.sh

# 7. Comprehensive verification including security
./tools/check-health.sh --comprehensive
docker compose exec vaultwarden whoami  # Verify non-root execution
docker compose exec caddy whoami         # Verify non-root execution
```

### **Security-Focused Recovery Validation**
```bash
# After any recovery, validate security configuration
echo "=== Container Security Validation ==="
docker compose exec vaultwarden whoami
docker compose exec caddy whoami
echo ""

echo "=== Volume Permission Validation ==="
sudo ls -la /var/lib/vaultwarden/ | head -5
echo ""

echo "=== Input Validation Test ==="
source lib/validation.sh
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)"
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)"
echo ""

echo "=== Overall System Health ==="
./tools/check-health.sh --component security
```

---

## 📞 **Getting Additional Help**

### **Enhanced Log Analysis for Security**
```bash
# Collect comprehensive logs including security events
./tools/check-health.sh --comprehensive > system-health.log
docker compose logs > docker-services.log
journalctl --since "1 hour ago" > system-journal.log

# Collect security-specific information
echo "=== Container Security Status ===" > security-status.log
docker compose exec vaultwarden whoami >> security-status.log 2>&1
docker compose exec caddy whoami >> security-status.log 2>&1
sudo ls -la /var/lib/vaultwarden/ >> security-status.log 2>&1

# Collect validation information
echo "=== Input Validation Status ===" >> validation-status.log
source lib/validation.sh
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)" >> validation-status.log 2>&1
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)" >> validation-status.log 2>&1
```

### **Security-Enhanced System Information Collection**
```bash
# Enhanced system information with security details
echo "=== System Information ===" > enhanced-system-info.txt
uname -a >> enhanced-system-info.txt
docker version >> enhanced-system-info.txt
docker compose version >> enhanced-system-info.txt

echo "=== Container Security Information ===" >> enhanced-system-info.txt
docker inspect vaultwarden_vaultwarden | grep -E "(User|SecurityOpt|NoNewPrivileges)" >> enhanced-system-info.txt
docker inspect caddy_container | grep -E "(User|SecurityOpt|NoNewPrivileges)" >> enhanced-system-info.txt

echo "=== Validation Library Status ===" >> enhanced-system-info.txt
./tools/validate-code.sh >> enhanced-system-info.txt 2>&1
```

---

## 🔧 **Common Issue Quick Fixes**

### **Container Permission Quick Fix**
```bash
# One-command permission fix for non-root containers
sudo chown -R 1000:1000 /var/lib/vaultwarden/ ./caddy/ && docker compose restart
```

### **Input Validation Quick Test**
```bash
# Quick validation test
source lib/validation.sh && validate_domain_format "vault.example.com" && validate_email_format "admin@example.com" && echo "✅ Validation working"
```

### **Security Status Quick Check**
```bash
# Quick security status check
echo "VaultWarden: $(docker compose exec vaultwarden whoami 2>/dev/null || echo 'not running')" && echo "Caddy: $(docker compose exec caddy whoami 2>/dev/null || echo 'not running')"
```

---

**🎯 Enhanced Troubleshooting:** This guide now includes comprehensive troubleshooting for container security hardening and input validation features, ensuring your VaultWarden deployment remains secure and properly configured.

**📚 For security-specific issues, see [Security Configuration](Security.md).**

**🔧 For operational procedures including security checks, consult [Operations Runbook](OperationsRunbook.md).**
