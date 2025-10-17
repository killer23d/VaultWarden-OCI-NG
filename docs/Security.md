# Security Guide

> **🎯 Security Philosophy**: Defense in depth with automated hardening, continuous monitoring, and enterprise-grade protection suitable for small teams without security overhead.

## 🛡️ **Multi-Layer Security Architecture**

VaultWarden-OCI-Minimal implements **defense in depth** with multiple security layers that work together to protect your password manager deployment:

```bash
Security Layers (Outside → Inside):
├── CloudFlare Edge Protection (DDoS, Bot Detection, Geographic Filtering)
├── UFW Host Firewall (Port Control, Connection Limiting)
├── Fail2ban Intrusion Detection (Behavioral Analysis, Automatic Blocking)
├── Container Security (Resource Limits, Non-root Execution)
├── Application Security (Authentication, Authorization, Session Management)
├── Data Security (Encryption, Secure Storage, Backup Protection)
└── Configuration Security (File Permissions, Secret Management)
```

## 🌐 **Network Security**

### **CloudFlare Edge Protection**

#### **Automatic Configuration**
The system automatically configures CloudFlare integration during setup:

```bash
# CloudFlare IP ranges updated daily via cron
./tools/update-cloudflare-ips.sh

# Generated configuration applied to Caddy
cat caddy/cloudflare-ips.caddy

# Trusted proxy configuration ensures real visitor IPs are detected
```

#### **CloudFlare Security Settings** (Manual Configuration Required)
Access your CloudFlare dashboard and configure:

**SSL/TLS Settings**:
```bash
SSL/TLS Mode: "Full (strict)"
Always Use HTTPS: Enabled
Minimum TLS Version: 1.2
HSTS: Enabled (max-age: 31536000)
```

**Security Level**:
```bash
Security Level: "Medium" or "High"
Bot Fight Mode: Enabled
Challenge Passage: 30 minutes
Browser Integrity Check: Enabled
```

**Rate Limiting** (Recommended Rules):
```bash
# Admin Panel Protection
Path: /admin*
Rate: 5 requests per minute per IP

# Login Protection  
Path: /identity/accounts/prelogin
Rate: 10 requests per minute per IP

# API Protection
Path: /api/*
Rate: 100 requests per minute per IP
```

#### **Geographic Access Control**
```bash
# Consider restricting access by country if applicable
# CloudFlare → Security → WAF → Custom Rules
# (country.code ne "US" and country.code ne "CA") → Block

# For international teams, use allowlist instead:
# (country.code in {"US" "CA" "GB" "DE"}) → Allow
```

### **Host Firewall (UFW)**

#### **Automated Configuration**
UFW is automatically configured during `init-setup.sh`:

```bash
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Essential services only
sudo ufw allow ssh      # SSH access (port 22)
sudo ufw allow 80/tcp   # HTTP (redirects to HTTPS)
sudo ufw allow 443/tcp  # HTTPS (VaultWarden access)

# Enable firewall
sudo ufw --force enable
```

#### **Firewall Status Verification**
```bash
# Check firewall status
sudo ufw status verbose

# Expected output:
# Status: active
# Logging: on (low)
# Default: deny (incoming), allow (outgoing)
# New profiles: skip
# 
# To                         Action      From
# --                         ------      ----
# 22/tcp                     ALLOW IN    Anywhere
# 80/tcp                     ALLOW IN    Anywhere
# 443/tcp                    ALLOW IN    Anywhere

# Monitor firewall logs
sudo tail -f /var/log/ufw.log
```

#### **Advanced UFW Configuration**
For enhanced security in sensitive environments:

```bash
# Rate limiting for SSH (prevent brute force)
sudo ufw limit ssh

# Specific IP allowlist for SSH (if feasible)
sudo ufw delete allow ssh
sudo ufw allow from YOUR_TRUSTED_IP to any port 22

# Logging for security analysis
sudo ufw logging medium

# IPv6 support (if needed)
# Edit /etc/default/ufw: IPV6=yes
```

### **Intrusion Detection (Fail2ban)**

#### **Automated Jail Configuration**
The system configures multiple fail2ban jails automatically:

```bash
# Active jails after setup
sudo fail2ban-client status

# Expected jails:
# - sshd (SSH brute force protection)
# - vaultwarden-auth (Login failure detection)
# - vaultwarden-admin (Admin panel protection)
# - caddy-json (HTTP access pattern analysis)
# - caddy-404 (404 abuse detection)
# - caddy-bad-bots (Bot detection)
# - recidive (Repeat offender tracking)
```

#### **CloudFlare Integration**
When CloudFlare credentials are configured, fail2ban automatically blocks IPs at the edge:

```bash
# Check CloudFlare action configuration
cat fail2ban/action.d/cloudflare.conf

# Verify credentials are configured
grep -A 5 "\[Init\]" fail2ban/action.d/cloudflare.conf

# Test CloudFlare API connectivity
curl -X GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \
     -H "X-Auth-Email: $(jq -r '.CLOUDFLARE_EMAIL' settings.json)" \
     -H "X-Auth-Key: $(jq -r '.CLOUDFLARE_API_KEY' settings.json)" \
     -H "Content-Type: application/json"
```

#### **Jail Configuration Details**

**VaultWarden Authentication Protection**:
```ini
[vaultwarden-auth]
enabled = true
filter = vaultwarden
logpath = /var/log/vaultwarden/vaultwarden.log
ports = 80,443
maxretry = 5       # Failed attempts before ban
findtime = 10m     # Time window for attempts
bantime = 2h       # Ban duration
```

**Admin Panel Protection** (More Strict):
```ini
[vaultwarden-admin]
enabled = true
filter = vaultwarden-admin
logpath = /var/log/vaultwarden/vaultwarden.log
ports = 80,443
maxretry = 3       # Lower threshold for admin access
findtime = 10m
bantime = 6h       # Longer ban for admin attacks
```

**Recidivist Tracking** (Repeat Offenders):
```ini
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 168h     # 1 week ban
findtime = 24h
maxretry = 3       # Previously banned IPs
```

#### **Monitoring Fail2ban Activity**
```bash
# Check current banned IPs
sudo fail2ban-client status vaultwarden-auth
sudo fail2ban-client status sshd

# View fail2ban log
sudo tail -f /var/log/fail2ban.log

# Unban IP if needed (emergencies only)
sudo fail2ban-client set vaultwarden-auth unbanip IP_ADDRESS

# Get jail statistics
sudo fail2ban-client get vaultwarden-auth stats
```

## 🔐 **Application Security**

### **SSL/TLS Configuration**

#### **Automatic Certificate Management**
Caddy automatically handles SSL certificate provisioning and renewal:

```bash
# Certificate status
docker compose exec caddy caddy list-certificates

# Expected output shows:
# - Valid Let's Encrypt certificate
# - Automatic renewal configured
# - OCSP stapling enabled

# Force certificate renewal (if needed)
docker compose exec caddy caddy certificates --renew
```

#### **Security Headers**
Caddy is configured with comprehensive security headers:

```caddy
header {
    # Remove server information
    -Server
    
    # HSTS (HTTP Strict Transport Security)
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Prevent MIME type sniffing
    X-Content-Type-Options "nosniff"
    
    # Clickjacking protection
    X-Frame-Options "DENY"
    
    # Referrer policy
    Referrer-Policy "strict-origin-when-cross-origin"
    
    # Content Security Policy (Password Manager Optimized)
    Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'self';"
}
```

#### **SSL Configuration Verification**
```bash
# Test SSL configuration
openssl s_client -connect your-domain.com:443 -servername your-domain.com < /dev/null 2>/dev/null | openssl x509 -noout -text

# Check SSL Labs rating
# Visit: https://www.ssllabs.com/ssltest/
# Enter your domain - should achieve A+ rating

# Verify HSTS header
curl -I https://your-domain.com | grep -i strict-transport-security
```

### **Authentication Security**

#### **Admin Token Security**
```bash
# Admin token is automatically generated with high entropy
# Length: 44 characters (base64 encoded 32 bytes)
# Entropy: ~256 bits (cryptographically secure)

# Verify admin token strength
ADMIN_TOKEN=$(sudo jq -r '.ADMIN_TOKEN' settings.json)
echo "Token length: ${#ADMIN_TOKEN}"

# Regenerate admin token (when needed)
NEW_TOKEN=$(openssl rand -base64 32)
sudo jq --arg token "$NEW_TOKEN" '.ADMIN_TOKEN = $token' settings.json > temp.json
sudo mv temp.json settings.json
sudo chmod 600 settings.json
./startup.sh
```

#### **User Registration Controls**
Configure user registration policy based on your security requirements:

```json
{
  "SIGNUPS_ALLOWED": false,
  "INVITATIONS_ALLOWED": true,
  "INVITATION_EXPIRATION_HOURS": 120,
  "DOMAIN_WHITELIST": "example.com,company.org"
}
```

**Registration Security Options**:
- **Closed**: `SIGNUPS_ALLOWED: false` - Admin creates all accounts
- **Invite-only**: `INVITATIONS_ALLOWED: true` - Users can be invited
- **Domain-restricted**: Use `DOMAIN_WHITELIST` to limit email domains
- **Time-limited**: `INVITATION_EXPIRATION_HOURS` controls invite validity

#### **Password Policy Enforcement**
VaultWarden enforces strong password policies by default:

```bash
# Password requirements (enforced by VaultWarden):
# - Minimum 8 characters (configurable in admin panel)
# - Recommended: 12+ characters with mixed case, numbers, symbols
# - No common passwords (dictionary check)
# - Optional: Breach detection via HaveIBeenPwned API

# Configure in admin panel:
# https://your-domain.com/admin → General Settings → Password Settings
```

## 🗂️ **Data Security**

### **File System Security**

#### **Automated Permission Management**
The system automatically applies secure permissions:

```bash
# Configuration files (sensitive data)
settings.json: 600 (rw-------)
fail2ban/action.d/cloudflare.conf: 600 (rw-------)
/etc/systemd/system/*.env: 600 (rw-------)

# Data directories
/var/lib/*/: 755 (rwxr-xr-x)
/var/lib/*/data/: 700 (rwx------)
/var/lib/*/backups/: 700 (rwx------)

# Executable scripts
*.sh files: 755 (rwxr-xr-x)
```

#### **Permission Verification**
```bash
# Audit file permissions
ls -la settings.json
# Should show: -rw------- 1 root root

ls -ld /var/lib/*/data/
# Should show: drwx------ 2 root root

ls -ld /var/lib/*/backups/
# Should show: drwx------ 2 root root

# Fix permissions if needed
sudo chmod 600 settings.json
sudo chmod -R 700 /var/lib/*/data/
sudo chmod -R 700 /var/lib/*/backups/
```

### **Database Security**

#### **SQLite Security Configuration**
VaultWarden is configured with secure SQLite settings:

```bash
# Database location (protected directory)
DATABASE_URL="sqlite:///data/db.sqlite3"

# SQLite security features enabled:
# - WAL mode for better concurrency and crash safety
# - Foreign key constraints enabled
# - Secure delete to overwrite freed pages
# - Automatic checkpointing for log management

# Verify database security
./tools/sqlite-maintenance.sh --security-check
```

#### **Database Access Control**
```bash
# Database files are only accessible to VaultWarden container
# Host access requires root privileges

# Check database file permissions
sudo ls -la /var/lib/*/data/bwdata/db.sqlite3
# Should show: -rw-r--r-- 1 root root (container manages access)

# Database integrity verification
./tools/sqlite-maintenance.sh --integrity-check

# Enable database encryption at rest (if required)
# Note: VaultWarden handles client-side encryption
# Database encryption adds defense in depth but impacts performance
```

### **Backup Security**

#### **Encrypted Backup System**
All backups are automatically encrypted:

```bash
# Backup encryption details:
# - Algorithm: AES-256-GCM (authenticated encryption)
# - Key derivation: PBKDF2 with random salt
# - Compression: gzip before encryption
# - Integrity: Built-in authentication tag

# Verify backup encryption
./tools/create-full-backup.sh --test-encryption

# Backup passphrase management
BACKUP_PASSPHRASE=$(sudo jq -r '.BACKUP_PASSPHRASE' settings.json)
echo "Passphrase entropy: $(echo -n "$BACKUP_PASSPHRASE" | wc -c) characters"
```

#### **Secure Backup Storage**
```bash
# Backup directory permissions
sudo ls -ld /var/lib/*/backups/
# Should show: drwx------ (only root access)

# Backup file integrity verification
./tools/restore.sh --verify-all

# Off-site backup recommendations:
# 1. Encrypt backups before cloud storage
# 2. Use separate encryption key for cloud storage
# 3. Test restore procedures regularly
# 4. Implement backup rotation policy
```

## 🔧 **Configuration Security**

### **Secret Management**

#### **Local Secret Management**
```bash
# Configuration file security
settings.json:
- Location: Project root directory
- Permissions: 600 (owner read/write only)
- Format: JSON with validation
- Backup: Automatic versioned backups before changes

# Secret rotation procedures
# 1. Generate new secrets
NEW_ADMIN_TOKEN=$(openssl rand -base64 32)
NEW_BACKUP_PASSPHRASE=$(openssl rand -base64 32)

# 2. Update configuration
sudo jq --arg admin "$NEW_ADMIN_TOKEN" --arg backup "$NEW_BACKUP_PASSPHRASE" \
  '.ADMIN_TOKEN = $admin | .BACKUP_PASSPHRASE = $backup' settings.json > temp.json
sudo mv temp.json settings.json
sudo chmod 600 settings.json

# 3. Restart services
./startup.sh
```

#### **OCI Vault Integration** (Enterprise)
For enhanced secret management with OCI Vault:

```bash
# OCI Vault benefits:
# - Centralized secret management
# - Automatic secret rotation
# - Audit logging for secret access
# - Hardware security module (HSM) backing
# - Fine-grained access controls

# Setup OCI Vault integration
./tools/oci-setup.sh

# Verify OCI Vault connectivity
oci vault secret get-secret-bundle --secret-id "$OCI_SECRET_OCID"

# Fallback mechanism ensures high availability
# If OCI Vault is unavailable, system falls back to local settings.json
```

### **Environment Security**

#### **Container Security**
```bash
# Container security features:
# - Non-root user execution where possible
# - Read-only filesystems for system containers
# - Resource limits prevent DoS attacks
# - Minimal attack surface (no unnecessary packages)
# - Regular security updates via Watchtower

# Verify container security
docker compose exec vaultwarden ps aux
# Should show VaultWarden running as non-root user

# Check resource limits
docker stats --no-stream
# Should show memory and CPU limits enforced
```

#### **Network Security**
```bash
# Container network isolation
# - Project-specific bridge network
# - No host network access except fail2ban (required)
# - Internal DNS resolution only
# - No unnecessary port exposure

# Verify network isolation
docker network ls | grep $(basename $(pwd))
docker network inspect $(basename $(pwd))_network
```

## 🔍 **Security Monitoring**

### **Log-Based Security Monitoring**

#### **Security Event Logging**
```bash
# Centralized security logging locations:
/var/lib/*/logs/fail2ban/     # Intrusion detection
/var/lib/*/logs/vaultwarden/  # Authentication events
/var/lib/*/logs/caddy/        # Access logs and security events
/var/log/ufw.log              # Firewall events
/var/log/auth.log             # SSH and system authentication

# Key security events to monitor:
# - Multiple failed login attempts
# - Admin panel access from new IPs
# - Unusual geographic access patterns
# - Failed SSH attempts
# - Large file downloads (potential data exfiltration)
```

#### **Automated Security Monitoring**
```bash
# Security monitoring via cron (every 5 minutes)
./tools/monitor.sh --security-check

# Security checks performed:
# - Failed authentication analysis
# - Suspicious IP address detection
# - Certificate expiration monitoring
# - Unusual resource usage patterns
# - Configuration file integrity verification

# Review security monitoring logs
journalctl -t monitor | grep -i security
```

### **Intrusion Detection Analysis**

#### **Fail2ban Reporting**
```bash
# Generate fail2ban activity report
sudo fail2ban-client get vaultwarden-auth stats

# Check for patterns indicating coordinated attacks
sudo grep "Ban " /var/log/fail2ban.log | tail -20

# Geographic analysis of banned IPs (requires geoip)
# sudo apt install geoip-bin geoip-database
# sudo grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq | xargs -I {} geoiplookup {}
```

#### **Access Pattern Analysis**
```bash
# Analyze access patterns from Caddy logs
sudo tail -1000 /var/lib/*/logs/caddy/access.log | \
  jq -r '.request.remote_addr' | sort | uniq -c | sort -nr | head -20

# Check for unusual user agents
sudo tail -1000 /var/lib/*/logs/caddy/access.log | \
  jq -r '.request.headers["User-Agent"][0]' | sort | uniq -c | sort -nr

# Monitor admin panel access
sudo grep '/admin' /var/lib/*/logs/caddy/access.log | tail -20
```

## 🎯 **Security Best Practices**

### **Operational Security**

#### **Regular Security Tasks**
```bash
# Daily (automated via cron):
# - Review fail2ban activity
# - Check SSL certificate status
# - Monitor resource usage for anomalies
# - Verify backup completion and integrity

# Weekly (manual review recommended):
# - Analyze access logs for patterns
# - Review user account activity
# - Check for VaultWarden security updates
# - Verify CloudFlare security settings

# Monthly (maintenance):
# - Rotate admin tokens
# - Update fail2ban filters if needed
# - Review and test backup/restore procedures
# - Audit user accounts and permissions
```

#### **Incident Response Procedures**
```bash
# Security incident response checklist:

# 1. Immediate containment
docker compose down                    # Stop services if compromised
sudo fail2ban-client set jail banip IP # Block suspicious IPs

# 2. Assessment
./tools/create-full-backup.sh --forensic # Create forensic backup
sudo grep -r "suspicious_pattern" /var/lib/*/logs/ # Analyze logs

# 3. Recovery
./tools/restore.sh /path/to/clean/backup # Restore from clean backup
./startup.sh                            # Restart with monitoring

# 4. Post-incident
# - Update security configurations based on attack vectors
# - Document incident and response for future reference
# - Consider additional security measures if needed
```

### **Compliance and Audit**

#### **Security Audit Checklist**
```bash
# Use this checklist for regular security audits:

# Infrastructure Security:
- [ ] UFW firewall active with minimal ports open
- [ ] Fail2ban active with all jails functioning
- [ ] SSL/TLS A+ rating on SSL Labs test
- [ ] CloudFlare security features enabled
- [ ] All containers running with resource limits

# Access Control:
- [ ] Admin token rotated within last 90 days
- [ ] User registration policy appropriate for organization
- [ ] No unnecessary user accounts exist
- [ ] SSH keys rotated and access reviewed

# Data Protection:
- [ ] Database encrypted in transit and at rest
- [ ] Backups encrypted and tested within last 30 days
- [ ] File permissions secure on all sensitive files
- [ ] Off-site backup tested within last quarter

# Monitoring:
- [ ] Security monitoring cron jobs active
- [ ] Log retention policy implemented
- [ ] Incident response procedures documented
- [ ] Security contact information current
```

#### **Compliance Documentation**
```bash
# Generate compliance report
./tools/monitor.sh --compliance-report

# Security configuration export (for audits)
./tools/security-audit.sh --export-config

# Log retention verification
find /var/lib/*/logs -name "*.log" -mtime +90 -ls
# Should show logs older than 90 days for compliance verification
```

## 🚨 **Emergency Security Procedures**

### **Compromise Response**

#### **Immediate Actions**
```bash
# If you suspect system compromise:

# 1. Isolate the system
sudo ufw deny in
docker compose down

# 2. Preserve evidence
./tools/create-full-backup.sh --forensic --preserve-logs

# 3. Assess damage
sudo grep -r "malicious_pattern" /var/lib/*/logs/
sudo find /var/lib/*/data -name "*.suspicious" -ls

# 4. Clean recovery
./tools/restore.sh --verify /path/to/known-good-backup
./startup.sh
```

#### **Security Hardening Post-Incident**
```bash
# Additional hardening measures post-incident:

# 1. Force password reset for all users
# (Done through admin panel)

# 2. Rotate all secrets
openssl rand -base64 32  # New admin token
openssl rand -base64 32  # New backup passphrase

# 3. Enhanced monitoring
# Enable verbose logging temporarily
export DEBUG=1

# 4. Additional fail2ban protection
# Lower thresholds temporarily
sudo fail2ban-client set vaultwarden-auth maxretry 3
sudo fail2ban-client set vaultwarden-auth bantime 86400  # 24 hours

# 5. Review and update security policies
# Document lessons learned and update procedures
```

## 📚 **Security Resources**

### **Security References**
- **VaultWarden Security**: [Official Security Documentation](https://github.com/dani-garcia/vaultwarden/wiki/Security)
- **Bitwarden Security**: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- **CloudFlare Security**: [CloudFlare Security Center](https://www.cloudflare.com/security/)
- **OWASP Guidelines**: [OWASP Application Security](https://owasp.org/www-project-top-ten/)

### **Security Tools**
```bash
# Built-in security validation tools
./startup.sh --validate          # Configuration security check
./tools/monitor.sh --security    # Security monitoring
./tools/security-audit.sh        # Comprehensive security audit

# External security testing tools
# SSL Labs: https://www.ssllabs.com/ssltest/
# SecurityHeaders: https://securityheaders.com/
# Mozilla Observatory: https://observatory.mozilla.org/
```

### **Staying Updated**
```bash
# Security update monitoring (automated)
# Watchtower handles container security updates

# Manual security monitoring
# Subscribe to:
# - VaultWarden security advisories
# - Docker security bulletins  
# - Ubuntu security updates
# - CloudFlare security blog

# Security mailing lists and notifications
# Configure email notifications for critical security events
```

This security guide provides comprehensive protection suitable for small teams while maintaining the "set and forget" operational model through automation and careful configuration."""
