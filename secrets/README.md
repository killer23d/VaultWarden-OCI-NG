# VaultWarden-OCI-NG Secrets Management

**Secure secrets management using SOPS and Age encryption for VaultWarden-OCI-NG**

This directory contains encrypted configuration files and encryption keys for VaultWarden-OCI-NG. The secrets management system provides enterprise-grade security for sensitive configuration data while maintaining operational simplicity.

## 🔐 **Security Architecture**

### **Encryption Technology**
```yaml
Age Encryption:
  Algorithm: ChaCha20-Poly1305 (modern, secure)
  Key Exchange: X25519 elliptic curve Diffie-Hellman
  Authentication: Poly1305 MAC for integrity verification
  Performance: Optimized for modern processors

SOPS Integration:
  Format: Encrypted YAML with metadata preservation
  Editor: Secure in-place editing with automatic encryption
  Validation: Schema validation and integrity checking
  Backup: Automatic backup of previous versions
```

### **Key Management**
```yaml
Age Keys:
  Generation: age-keygen with cryptographically secure randomness
  Storage: File system with 600 permissions (owner read/write only)
  Rotation: Manual process with comprehensive backup validation
  Emergency Access: Included in emergency recovery kits

Security Features:
  - Keys never transmitted over network unencrypted
  - Separate key files for operational security
  - Integration with emergency recovery procedures
  - Comprehensive key integrity validation
```

## 📁 **Directory Structure**

### **Current Directory Layout**
```
secrets/
├── README.md                    # This documentation file
├── .gitkeep                     # Ensures directory exists in git
├── secrets.yaml                 # Main encrypted configuration (SOPS)
├── secrets.yaml.example         # Configuration template for reference
├── keys/                        # Age encryption keys directory
│   ├── README.md                # Key management documentation
│   ├── age-key.txt              # Private key (600 permissions)
│   └── age-public-key.txt       # Public key for encryption
└── .docker_secrets/             # Docker Compose secret files (generated)
    ├── admin_token              # Auto-generated Docker secret
    ├── smtp_password            # SMTP credentials for notifications
    ├── backup_passphrase        # Additional backup encryption
    ├── push_installation_key    # Push notification credentials
    └── cloudflare_api_token     # Cloudflare API access
```

### **File Ownership and Permissions**
```yaml
Security Model:
  secrets/:               755 (directory accessible)
  secrets.yaml:          644 (readable, SOPS encrypted content)
  secrets.yaml.example:  644 (public template)

  keys/:                 700 (directory owner-only access)
  age-key.txt:          600 (private key, owner read/write only)
  age-public-key.txt:   644 (public key, readable for encryption)

  .docker_secrets/:     700 (directory owner-only access) 
  All secret files:     600 (owner read/write only)
```

## ⚙️ **Configuration Management**

### **Editing Encrypted Secrets**

#### **Primary Method - Interactive Editor**
```bash
# Secure editing with SOPS
./tools/edit-secrets.sh

# Editor opens with decrypted content for editing
# File is automatically re-encrypted on save
# Backup created before changes
```

#### **Advanced Usage**
```bash
# Check configuration status
./tools/edit-secrets.sh --status

# Validate configuration without editing
./tools/edit-secrets.sh --validate

# View configuration keys (values remain encrypted)
sops -d secrets/secrets.yaml | yq eval 'keys | .[]' -
```

### **Configuration Schema**

#### **Core System Configuration**
```yaml
# Domain and Identity
domain: "vault.yourdomain.com"           # Your VaultWarden domain
admin_email: "admin@yourdomain.com"      # Administrator email address

# Authentication Secrets (Auto-generated)
admin_token: "[auto-generated-uuid]"     # VaultWarden admin token
admin_basic_auth_hash: "[auto-bcrypt]"   # Admin panel password hash
admin_basic_auth_password: "secure-pw"  # Plain password (hashed automatically)
```

#### **SMTP Configuration (Required)**
```yaml
# Email Service Configuration
smtp_host: "smtp.gmail.com"              # SMTP server hostname
smtp_port: "587"                         # SMTP port (587 for STARTTLS)
smtp_username: "vault@yourdomain.com"    # SMTP authentication username
smtp_password: "app-specific-password"   # SMTP password or app token
smtp_from: "VaultWarden <vault@yourdomain.com>"  # From address
smtp_security: "starttls"                # Security: starttls, ssl, or none
```

#### **Security Integration (Optional)**
```yaml
# Cloudflare Integration (Highly Recommended)
cloudflare_zone_id: "your-zone-id"       # From Cloudflare dashboard
cloudflare_api_token: "your-api-token"   # API token with zone permissions

# Push Notifications (Optional)
push_enabled: "false"                    # Enable mobile push notifications
push_installation_id: "your-install-id" # From Bitwarden cloud if needed
push_installation_key: "your-push-key"  # Push notification credentials

# Dynamic DNS (Optional)
ddclient_enabled: "false"               # Enable dynamic DNS updates
ddclient_protocol: "cloudflare"         # DNS provider protocol
ddclient_login: "your-email"            # Provider login/username
ddclient_password: "your-token"         # Provider password/token
```

#### **Advanced Application Settings (Optional)**
```yaml
# VaultWarden Performance Tuning
websocket_enabled: "true"               # Real-time sync (recommended)
signups_allowed: "false"                # Disable open registration
invitations_allowed: "true"             # Admin-controlled invites only
password_iterations: "350000"           # PBKDF2 iterations (security vs performance)
database_timeout: "30"                  # Database connection timeout
log_level: "warn"                       # Logging level (error, warn, info, debug)
extended_logging: "true"                # Detailed logs for troubleshooting
```

## 🛠️ **Operational Procedures**

### **Initial Setup**

#### **Automated Setup (Recommended)**
```bash
# Complete initialization via init-setup.sh
sudo ./tools/init-setup.sh --domain vault.yourdomain.com --email admin@yourdomain.com

# Process automatically:
# 1. Generates Age encryption keys with secure permissions
# 2. Creates SOPS configuration file
# 3. Generates template secrets.yaml from example
# 4. Prompts for essential configuration via secure editor
```

#### **Manual Setup (Advanced)**
```bash
# 1. Generate Age keys manually
age-keygen -o secrets/keys/age-key.txt
chmod 600 secrets/keys/age-key.txt
age-keygen -y secrets/keys/age-key.txt > secrets/keys/age-public-key.txt

# 2. Create SOPS configuration
cat > .sops.yaml << EOF
creation_rules:
  - path_regex: secrets/secrets\.yaml$
    age: >-
      $(cat secrets/keys/age-public-key.txt)
EOF

# 3. Initialize encrypted configuration
cp secrets/secrets.yaml.example secrets/secrets.yaml
sops -e -i secrets/secrets.yaml

# 4. Edit configuration
./tools/edit-secrets.sh
```

### **Regular Operations**

#### **Configuration Updates**
```bash
# Safe configuration editing
./tools/edit-secrets.sh

# Validate changes before applying
./startup.sh --dry-run

# Apply configuration changes
./startup.sh --force-restart

# Verify configuration
./tools/check-health.sh --comprehensive
```

#### **Key Rotation (Advanced)**
```bash
# WARNING: Key rotation requires careful backup procedures

# 1. Create backup of current configuration
./tools/backup-monitor.sh --full --emergency-kit

# 2. Generate new Age key
age-keygen -o secrets/keys/age-key-new.txt

# 3. Re-encrypt secrets with new key
sops -r -i --age $(age-keygen -y secrets/keys/age-key-new.txt) secrets/secrets.yaml

# 4. Replace keys (keep backup)
mv secrets/keys/age-key.txt secrets/keys/age-key-backup.txt
mv secrets/keys/age-key-new.txt secrets/keys/age-key.txt
age-keygen -y secrets/keys/age-key.txt > secrets/keys/age-public-key.txt

# 5. Update SOPS configuration
# Edit .sops.yaml with new public key

# 6. Verify and restart
./tools/edit-secrets.sh --status
./startup.sh --force-restart
```

### **Troubleshooting**

#### **Common Issues and Solutions**

##### **Age Key Permission Errors**
```yaml
Error: "permission denied: age-key.txt"
Cause: Incorrect file permissions on private key
Solution:
  chmod 600 secrets/keys/age-key.txt
  chown $(id -u):$(id -g) secrets/keys/age-key.txt
```

##### **SOPS Decryption Failures**
```yaml
Error: "failed to decrypt sops file"
Causes:
  - Age key corrupted or wrong key
  - SOPS file corrupted
  - Incorrect .sops.yaml configuration

Solutions:
  # Verify key integrity
  age-keygen -y secrets/keys/age-key.txt

  # Restore from emergency kit if needed
  age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -xzf -
  cp emergency-kit/secrets/keys/age-key.txt secrets/keys/

  # Validate SOPS configuration
  sops -d secrets/secrets.yaml | head -5
```

##### **Docker Secret File Issues**
```yaml
Error: "secret file not found"
Cause: Docker secret files not generated properly
Solution:
  # Regenerate Docker secrets
  ./startup.sh --force-restart

  # Check secret file generation
  ls -la secrets/.docker_secrets/

  # Verify secret values
  ./tools/edit-secrets.sh --status
```

## 🚨 **Emergency Procedures**

### **Configuration Recovery**

#### **From Emergency Kit**
```bash
# Extract configuration from emergency kit
age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -xzf -

# Restore Age keys
cp emergency-kit/secrets/keys/age-key.txt secrets/keys/
chmod 600 secrets/keys/age-key.txt

# Restore encrypted configuration
cp emergency-kit/secrets.yaml secrets/

# Verify restoration
./tools/edit-secrets.sh --status
./startup.sh --dry-run
```

#### **Configuration Reset (Last Resort)**
```bash
# WARNING: This destroys current configuration

# 1. Backup any recoverable data
cp secrets/secrets.yaml secrets/secrets.yaml.corrupted

# 2. Reset to template
cp secrets/secrets.yaml.example secrets/secrets.yaml
sops -e -i secrets/secrets.yaml

# 3. Reconfigure from scratch
./tools/edit-secrets.sh

# 4. Test and deploy
./startup.sh --dry-run
./startup.sh
```

### **Key Recovery**

#### **Age Key Corruption**
```bash
# If Age key is corrupted but emergency kit is available:

# 1. Extract key from emergency kit
age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -xzf -
cp emergency-kit/secrets/keys/age-key.txt secrets/keys/
chmod 600 secrets/keys/age-key.txt

# 2. Verify key works
age-keygen -y secrets/keys/age-key.txt

# 3. Test decryption
./tools/edit-secrets.sh --status
```

## 📊 **Security Monitoring**

### **Key Integrity Validation**
```bash
# Regular key integrity checks (automated in monitoring)
./tools/check-health.sh --component secrets

# Manual validation
age-keygen -y secrets/keys/age-key.txt > /tmp/pubkey-test
diff secrets/keys/age-public-key.txt /tmp/pubkey-test
rm /tmp/pubkey-test
```

### **Configuration Audit**
```bash
# Audit configuration changes
./tools/edit-secrets.sh --audit

# Check configuration drift
./startup.sh --dry-run --verbose

# Validate Docker secret generation
ls -la secrets/.docker_secrets/
```

### **Access Monitoring**
```bash
# Monitor secrets access (from system logs)
grep -E "(sops|age|secrets)" /var/log/vaultwarden/system.log | tail -20

# Check file access timestamps
stat secrets/secrets.yaml
stat secrets/keys/age-key.txt
```

## 🔄 **Integration with Backup System**

### **Secrets in Backups**
```yaml
Database Backups:
  Age Keys: Not included (separate key management)
  Configuration: Not included (encrypted at rest)

Full System Backups:
  Age Keys: Included with secure permissions
  Configuration: Included (remains encrypted)

Emergency Kits:
  Age Keys: Included with separate delivery
  Configuration: Included (decrypted for recovery)
  Documentation: Complete recovery procedures
```

### **Backup Verification**
```bash
# Verify secrets in backup
./tools/backup-recovery.sh --verify /path/to/backup.age

# Test emergency kit extraction
age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -tzf -

# Validate backup contains secrets
./tools/backup-recovery.sh --audit /path/to/backup.age
```

## 📚 **Best Practices**

### **Security Best Practices**
1. **Never store unencrypted secrets** - All sensitive data must use SOPS encryption
2. **Protect Age keys** - Private keys should have 600 permissions and secure storage
3. **Regular key backup** - Include keys in emergency kits and test restoration
4. **Monitor access** - Audit configuration changes and access patterns
5. **Use strong SMTP passwords** - App-specific passwords for email providers

### **Operational Best Practices**
1. **Test configuration changes** - Always use `--dry-run` before applying changes
2. **Backup before changes** - Create emergency kit before major configuration updates
3. **Validate after changes** - Run comprehensive health checks after updates
4. **Document custom settings** - Comment unusual configurations in secrets.yaml
5. **Emergency kit delivery** - Ensure reliable email delivery for emergency kits

### **Troubleshooting Best Practices**
1. **Check permissions first** - Most secrets issues are permission-related
2. **Validate key integrity** - Corrupted Age keys cause widespread failures
3. **Test SOPS access** - Verify decryption works before complex troubleshooting
4. **Review logs** - System logs contain detailed error information
5. **Use emergency kits** - Don't attempt complex recovery without backup validation

---

## 🎯 **Quick Reference**

### **Essential Commands**
```bash
# Edit configuration
./tools/edit-secrets.sh

# Check configuration status
./tools/edit-secrets.sh --status

# Test configuration
./startup.sh --dry-run

# Apply changes
./startup.sh --force-restart

# Health check
./tools/check-health.sh --comprehensive
```

### **Emergency Commands**
```bash
# Create emergency kit
./tools/create-emergency-kit.sh --email

# Restore from kit
age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -xzf -

# Reset configuration
cp secrets/secrets.yaml.example secrets/secrets.yaml
```

---

**🔐 Secrets Philosophy**: VaultWarden-OCI-NG secrets management balances enterprise-grade security with operational simplicity, providing comprehensive protection for sensitive configuration while maintaining ease of administration.

**📚 For operational procedures, see [Operations Runbook](../docs/OperationsRunbook.md)**

**🔒 For security details, review [Security Configuration](../docs/Security.md)**

**🚨 For emergency procedures, consult [Emergency Recovery Guide](../docs/EmergencyRecoveryGuide.md)**
