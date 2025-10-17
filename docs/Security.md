# Security Guide

This document provides comprehensive security information for the VaultWarden-OCI-NG stack, covering threat models, security controls, and hardening recommendations.

## Security Philosophy

### Zero-Trust Architecture
The VaultWarden-OCI-NG stack is built on zero-trust principles:
- **Never Trust, Always Verify**: Every request is authenticated and authorized
- **Principle of Least Privilege**: Minimal necessary access granted
- **Defense in Depth**: Multiple security layers protect against failures
- **Assume Breach**: Systems designed to limit damage from compromises

### Security by Default
- **Encrypted Secrets**: All sensitive data encrypted at rest using SOPS+Age
- **Automatic HTTPS**: Let's Encrypt SSL/TLS certificates with auto-renewal
- **Firewall Hardening**: UFW configured with minimal attack surface
- **Intrusion Prevention**: Fail2ban active protection against attacks

## Threat Model

### Primary Assets Protected
1. **User Vault Data**: Encrypted passwords, notes, and sensitive information
2. **Authentication Credentials**: User passwords, 2FA secrets, session tokens
3. **Administrative Access**: Admin panel tokens and configuration data
4. **System Infrastructure**: Server access, container orchestration, network services

### Threat Actors
- **External Attackers**: Internet-based reconnaissance and exploitation attempts
- **Credential Attacks**: Brute force, credential stuffing, password spraying
- **Insider Threats**: Compromised administrative access or malicious insiders
- **Supply Chain**: Compromised dependencies or container images

### Attack Vectors Addressed
- **Network-based**: DDoS, port scanning, protocol exploitation
- **Application-level**: Authentication bypass, injection attacks, privilege escalation
- **Container Security**: Container escape, image vulnerabilities, runtime attacks
- **Host Security**: OS vulnerabilities, privilege escalation, data exfiltration

## Security Controls

### Network Security

#### Firewall Configuration (UFW)
**Default Policy**: Deny all incoming connections except explicitly allowed

```bash
# View current firewall status
sudo ufw status verbose

# Expected configuration:
# Status: active
# Default: deny (incoming), allow (outgoing)
# Rules:
# 22/tcp    ALLOW IN    # SSH (from anywhere)
# 80/tcp    ALLOW IN    # HTTP (Let's Encrypt)
# 443/tcp   ALLOW IN    # HTTPS (application)
```

**Advanced Firewall Rules** (optional):
```bash
# Restrict SSH to specific networks
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22

# Rate limit SSH connections
sudo ufw limit ssh

# Allow only CloudFlare IPs for HTTPS (if using CF proxy)
# This is handled automatically by the CloudFlare IP update script
```

#### CloudFlare Integration
When using CloudFlare as a CDN/proxy:
- **Real IP Preservation**: Caddy configured to extract real client IPs
- **DDoS Protection**: CloudFlare's network-level DDoS mitigation
- **Bot Protection**: Automated bot detection and challenge system
- **Geographic Blocking**: Country-level access restrictions

**CloudFlare Security Settings**:
```yaml
# Recommended CloudFlare settings:
ssl_mode: "Full (strict)"
always_use_https: true
security_level: "Medium"
browser_integrity_check: true
challenge_passage: 1800
bot_fight_mode: true
```

### Application Security

#### VaultWarden Security Features
**End-to-End Encryption**:
- Client-side encryption of vault data before transmission
- Server never sees plaintext passwords or notes
- AES-256 encryption with user-derived keys

**Password Security**:
- Argon2id password hashing (PHC winner)
- Configurable iteration counts and memory usage
- Protection against rainbow table attacks

**Session Management**:
- JWT tokens with configurable expiration
- Secure cookie attributes (HttpOnly, Secure, SameSite)
- Session invalidation on password change

**Multi-Factor Authentication**:
- TOTP (Time-based One-Time Passwords)
- WebAuthn/FIDO2 hardware security keys
- Email-based 2FA backup method
- Recovery codes for account recovery

#### Admin Panel Security
**Dedicated Authentication**:
- Separate admin token from user authentication
- Token-based access (no password reuse)
- Configurable token complexity and rotation

**Access Controls**:
- Admin-only configuration changes
- User management and organization controls
- System monitoring and health status
- Audit log access and review

### Container Security

#### Image Security
**Base Image Selection**:
- Official images from trusted registries
- Minimal attack surface (Alpine Linux where possible)
- Regular security updates via Watchtower
- Image vulnerability scanning (recommended)

**Container Hardening**:
```yaml
# Security configurations in docker-compose.yml
security_opt:
  - no-new-privileges:true
read_only: true  # Where possible
user: "1000:1000"  # Non-root user
cap_drop:
  - ALL
cap_add:
  - CHOWN  # Only necessary capabilities
```

#### Runtime Security
**Resource Limits**:
- Memory limits prevent DoS attacks
- CPU limits prevent resource exhaustion
- Disk quotas prevent storage exhaustion
- Network policies restrict inter-container communication

**Secret Management**:
- Docker Secrets for sensitive data injection
- No environment variable exposure of secrets
- Temporary secret files with secure permissions
- Automatic cleanup on container stop

### Host Security

#### Operating System Hardening
**System Updates**:
```bash
# Automated security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Manual update verification
sudo apt update && sudo apt list --upgradable
```

**Service Hardening**:
```bash
# Disable unnecessary services
sudo systemctl disable cups bluetooth
sudo systemctl mask cups bluetooth

# SSH hardening in /etc/ssh/sshd_config:
PermitRootLogin no
PasswordAuthentication no  # Use keys only
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

#### File System Security
**Secure Permissions**:
```bash
# Critical file permissions verification
ls -la startup.sh tools/          # Should be 755
ls -la settings.json              # Should be 600
ls -la secrets/                   # Should be 700
ls -la secrets/keys/age-key.txt   # Should be 600
```

**Directory Security**:
- Application data isolated to project directories
- Backup files stored with restricted access
- Log files accessible only to necessary users
- Temporary files cleaned automatically

### Secret Management Security

#### SOPS + Age Encryption
**Encryption Strength**:
- Age uses X25519 (Curve25519) key exchange
- ChaCha20-Poly1305 authenticated encryption
- Scrypt key derivation for password-based keys
- Forward secrecy through ephemeral keys

**Key Management**:
```bash
# Age private key security
chmod 600 secrets/keys/age-key.txt
chown root:root secrets/keys/age-key.txt

# Regular key rotation (recommended annually)
# 1. Generate new Age key
# 2. Re-encrypt secrets with new key
# 3. Update key references
# 4. Secure deletion of old key
```

**Secret Rotation**:
```bash
# Admin token rotation
sudo ./tools/edit-secrets.sh
# Generate new admin_token
# Restart services: ./startup.sh

# SMTP password rotation
# Update password with email provider
# Update secrets file
# Test email functionality
```

### Intrusion Prevention

#### Fail2ban Protection
**Active Jails**:
- **sshd**: SSH brute force protection
- **vaultwarden-auth**: Application authentication failures
- **caddy-limit**: HTTP rate limit violations
- **caddy-scan**: Web application scanning attempts

**Configuration Overview**:
```ini
# /fail2ban/jail.local key settings
[DEFAULT]
bantime = 3600        # 1 hour initial ban
findtime = 600        # 10 minute window
maxretry = 5          # Attempts before ban

[vaultwarden-auth]
enabled = true
logpath = /logs/vaultwarden/vaultwarden.log
maxretry = 3          # Stricter for auth failures
bantime = 86400       # 24 hour ban
```

**CloudFlare Integration**:
When configured, Fail2ban can ban IPs at the CloudFlare level:
```bash
# Check CloudFlare integration status
sudo fail2ban-client status vaultwarden-auth

# View banned IPs
sudo fail2ban-client get vaultwarden-auth banip

# Manual IP ban/unban
sudo fail2ban-client set vaultwarden-auth banip 192.168.1.100
sudo fail2ban-client set vaultwarden-auth unbanip 192.168.1.100
```

#### Real-time Monitoring
**Log Analysis**:
```bash
# Monitor authentication attempts
tail -f /var/lib/*/logs/vaultwarden/vaultwarden.log | grep -i auth

# Monitor fail2ban actions
tail -f /var/log/fail2ban.log

# Monitor access patterns
tail -f /var/lib/*/logs/caddy/access.log
```

## Security Monitoring

### Health Check Security Validation
The `check-health.sh` script includes security-specific checks:

```bash
./tools/check-health.sh --verbose

# Security checks performed:
# ✅ Firewall status and rule compliance
# ✅ Fail2ban jail activity and effectiveness  
# ✅ SSL certificate validity and expiration
# ✅ File permission verification
# ✅ Secret management system health
# ✅ Container security configuration
```

### Audit Logging
**VaultWarden Audit Events**:
- User login/logout activities
- Password and vault item changes
- Administrative actions
- API access patterns
- Failed authentication attempts

**System Audit Events**:
- SSH access and commands
- Container lifecycle events
- Configuration changes
- Backup and restore operations
- Security rule violations

### Security Alerting
**Email Notifications** (when SMTP configured):
- Failed authentication bursts
- SSL certificate expiration warnings
- System resource threshold breaches
- Backup failure alerts
- Container update notifications

## Security Hardening Recommendations

### Immediate Actions (Required)

1. **Change Default Credentials**:
   ```bash
   # Generate new admin token
   sudo ./tools/edit-secrets.sh
   # Update admin_token with strong random value
   ```

2. **Enable 2FA for Admin**:
   - Create admin user account in VaultWarden
   - Enable TOTP/WebAuthn for admin account
   - Store recovery codes securely offline

3. **Configure SMTP for Notifications**:
   ```bash
   sudo ./tools/edit-secrets.sh
   # Add smtp_password
   # Update settings with SMTP configuration
   ```

### Enhanced Security (Recommended)

4. **SSH Key-Only Authentication**:
   ```bash
   # Disable password authentication
   echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

5. **CloudFlare Security Integration**:
   - Enable CloudFlare proxy for domain
   - Configure API token for fail2ban integration
   - Set up geographic access restrictions

6. **Regular Security Updates**:
   ```bash
   # Enable automatic security updates
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```

### Advanced Security (Optional)

7. **Certificate Pinning**:
   - Pin SSL certificate in client applications
   - Monitor for certificate changes
   - Implement certificate transparency monitoring

8. **Network Segmentation**:
   - Isolate VaultWarden in separate VLAN
   - Implement network access control lists
   - Monitor inter-network communications

9. **Host-based Intrusion Detection**:
   ```bash
   # Install AIDE for file integrity monitoring
   sudo apt install aide
   sudo aideinit
   ```

## Compliance Considerations

### Data Protection
**Encryption Standards**:
- Data at rest: AES-256 encryption for backups
- Data in transit: TLS 1.3 for all communications
- Key management: Industry-standard practices

**Privacy Controls**:
- User data isolation between organizations
- Audit logging for compliance tracking
- Data retention policy configuration
- Secure deletion capabilities

### Regulatory Compliance
**GDPR Considerations**:
- User data export capabilities
- Right to erasure implementation
- Data processing transparency
- Consent management features

**SOC 2 Alignment**:
- Access control implementation
- Change management procedures
- Monitoring and logging systems
- Incident response capabilities

## Incident Response

### Security Incident Detection
**Automated Detection**:
- Unusual authentication patterns
- Resource usage anomalies
- Failed security check alerts
- Service availability issues

**Manual Investigation Tools**:
```bash
# Check for compromise indicators
sudo ./tools/check-health.sh --verbose

# Review authentication logs
sudo journalctl -u fail2ban -f

# Analyze access patterns
sudo tail -f /var/lib/*/logs/caddy/access.log

# Container security status
docker compose ps
docker system df
```

### Response Procedures

#### Suspected Compromise
1. **Immediate Isolation**:
   ```bash
   # Block all external access
   sudo ufw deny 80/tcp
   sudo ufw deny 443/tcp

   # Preserve evidence
   sudo tar -czf incident-$(date +%Y%m%d).tar.gz /var/lib/*/logs/
   ```

2. **Investigation**:
   - Review fail2ban logs for attack patterns
   - Analyze VaultWarden authentication logs
   - Check system integrity with file permission audits
   - Verify backup integrity for recovery planning

3. **Recovery**:
   ```bash
   # Restore from clean backup if needed
   ./tools/restore.sh --verify /path/to/backup
   ./tools/restore.sh /path/to/backup

   # Force password reset for all users
   # (Requires database manipulation - contact support)

   # Regenerate all secrets
   sudo ./tools/edit-secrets.sh
   # Update all secret values
   ```

#### Service Disruption
1. **Service Restoration**:
   ```bash
   # Restart failed services
   ./startup.sh

   # Check service health
   ./tools/check-health.sh
   ```

2. **Root Cause Analysis**:
   - Review service logs for error patterns
   - Check system resources for capacity issues
   - Verify configuration integrity
   - Analyze recent changes or updates

## Security Best Practices

### Operational Security
- **Regular Updates**: Automated container updates via Watchtower
- **Backup Verification**: Regular backup integrity testing
- **Access Reviews**: Periodic admin access auditing
- **Configuration Management**: Version control for configuration changes

### User Security Education
- **Strong Password Policy**: Minimum complexity requirements
- **2FA Enforcement**: Multi-factor authentication for all users
- **Phishing Awareness**: Education on social engineering attacks
- **Secure Sharing**: Proper use of secure send features

### Administrative Security
- **Least Privilege**: Minimal necessary administrative access
- **Segregation of Duties**: Multiple administrators for critical operations
- **Change Management**: Documented and approved configuration changes
- **Incident Preparedness**: Regular security incident response drills

This security guide provides comprehensive protection for VaultWarden-OCI-NG deployments. Regular review and updates of security measures ensure continued protection against evolving threats.
