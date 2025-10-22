# Age Encryption Keys

**Age encryption key management for VaultWarden-OCI-NG secrets**

This directory contains the Age encryption keys used for securing all sensitive configuration data in VaultWarden-OCI-NG. These keys are critical for system operation and disaster recovery.

## 🔐 **Key Files**

### **Current Keys**
```
age-key.txt              # Private key (600 permissions, owner access only)
age-public-key.txt       # Public key (644 permissions, readable for encryption)
```

### **File Purpose**
```yaml
age-key.txt:
  Purpose: Decryption of SOPS-encrypted configuration files
  Format: Age private key (age1...)
  Permissions: 600 (owner read/write only)
  Security: Never share or transmit unencrypted

age-public-key.txt:
  Purpose: Encryption of new secrets and SOPS configuration
  Format: Age public key (age1...)  
  Permissions: 644 (readable for encryption operations)
  Security: Safe to share (public key cryptography)
```

## 🛡️ **Security Model**

### **Access Control**
```yaml
Directory Permissions: 700 (owner access only)
Private Key: 600 (owner read/write only)
Public Key: 644 (readable for encryption)
Owner: Running user (typically ubuntu or vaultwarden)
Group: Running user's primary group
```

### **Key Security Features**
```yaml
Generation: age-keygen with cryptographically secure randomness
Algorithm: X25519 elliptic curve Diffie-Hellman key exchange
Encryption: ChaCha20-Poly1305 authenticated encryption
Integrity: Poly1305 MAC prevents tampering
Performance: Modern, optimized for current processors
```

## 🔑 **Key Management**

### **Key Generation**
```bash
# Generate new Age key pair (done during init-setup)
age-keygen -o secrets/keys/age-key.txt
chmod 600 secrets/keys/age-key.txt

# Extract public key from private key
age-keygen -y secrets/keys/age-key.txt > secrets/keys/age-public-key.txt
chmod 644 secrets/keys/age-public-key.txt

# Verify key integrity
age-keygen -y secrets/keys/age-key.txt | diff - secrets/keys/age-public-key.txt
```

### **Key Validation**
```bash
# Verify private key format and accessibility
if [[ -r secrets/keys/age-key.txt ]] && age-keygen -y secrets/keys/age-key.txt >/dev/null 2>&1; then
    echo "Private key is valid and accessible"
else
    echo "Private key validation failed"
fi

# Verify public key matches private key
if age-keygen -y secrets/keys/age-key.txt | diff - secrets/keys/age-public-key.txt >/dev/null; then
    echo "Public key matches private key"
else
    echo "Key pair mismatch detected"
fi

# Test encryption/decryption cycle
echo "test" | age -e -R secrets/keys/age-public-key.txt | age -d -i secrets/keys/age-key.txt
```

### **Permission Enforcement**
```bash
# Automated permission fixing (done during startup)
chmod 700 secrets/keys                    # Directory: owner access only
chmod 600 secrets/keys/age-key.txt        # Private key: owner read/write
chmod 644 secrets/keys/age-public-key.txt # Public key: readable

# Ownership verification
chown $(id -u):$(id -g) secrets/keys/age-key.txt
chown $(id -u):$(id -g) secrets/keys/age-public-key.txt
```

## 🔄 **Key Rotation**

### **When to Rotate Keys**
```yaml
Routine Rotation: Not typically required for Age keys
Security Incident: Immediately if compromise suspected
Personnel Changes: When administrators leave organization
Compliance Requirements: Based on organizational policy
Key Compromise: Immediately upon detection or suspicion
```

### **Key Rotation Procedure**
```bash
# WARNING: Key rotation is a critical operation requiring careful backup

# Step 1: Create comprehensive backup
./tools/backup-monitor.sh --full --emergency-kit
./tools/create-emergency-kit.sh --email --key-rotation

# Step 2: Generate new key pair
age-keygen -o secrets/keys/age-key-new.txt
chmod 600 secrets/keys/age-key-new.txt
age-keygen -y secrets/keys/age-key-new.txt > secrets/keys/age-public-key-new.txt

# Step 3: Re-encrypt secrets with new key
sops -r -i --age $(cat secrets/keys/age-public-key-new.txt) secrets/secrets.yaml

# Step 4: Update SOPS configuration
sed -i "s/$(cat secrets/keys/age-public-key.txt)/$(cat secrets/keys/age-public-key-new.txt)/" .sops.yaml

# Step 5: Replace keys (keep backups)
mv secrets/keys/age-key.txt secrets/keys/age-key-backup-$(date +%Y%m%d).txt
mv secrets/keys/age-public-key.txt secrets/keys/age-public-key-backup-$(date +%Y%m%d).txt
mv secrets/keys/age-key-new.txt secrets/keys/age-key.txt
mv secrets/keys/age-public-key-new.txt secrets/keys/age-public-key.txt

# Step 6: Test new configuration
./tools/edit-secrets.sh --status
./startup.sh --dry-run

# Step 7: Deploy with new keys
./startup.sh --force-restart
./tools/check-health.sh --comprehensive

# Step 8: Generate new emergency kit
./tools/create-emergency-kit.sh --email
```

### **Post-Rotation Validation**
```bash
# Verify new keys work correctly
./tools/edit-secrets.sh --status
echo "test" | age -e -R secrets/keys/age-public-key.txt | age -d -i secrets/keys/age-key.txt

# Check SOPS integration
sops -d secrets/secrets.yaml | head -5

# Validate service functionality
./tools/check-health.sh --comprehensive

# Clean up old keys (after validation)
shred -vfz -n 3 secrets/keys/age-key-backup-*.txt
rm -f secrets/keys/age-public-key-backup-*.txt
```

## 🚨 **Emergency Procedures**

### **Key Corruption Recovery**
```bash
# If Age keys are corrupted but emergency kit is available:

# Step 1: Extract keys from emergency kit
age -d -i emergency-kit-private-key.txt emergency-kit.tar.gz.age | tar -xzf -

# Step 2: Restore keys from kit
cp emergency-kit-contents/secrets/keys/age-key.txt secrets/keys/
cp emergency-kit-contents/secrets/keys/age-public-key.txt secrets/keys/

# Step 3: Set correct permissions
chmod 700 secrets/keys
chmod 600 secrets/keys/age-key.txt
chmod 644 secrets/keys/age-public-key.txt

# Step 4: Verify restoration
age-keygen -y secrets/keys/age-key.txt | diff - secrets/keys/age-public-key.txt
./tools/edit-secrets.sh --status

# Step 5: Test system functionality
./startup.sh --dry-run
./startup.sh
```

### **Complete Key Loss Recovery**
```bash
# If both keys are lost and no emergency kit is available:
# WARNING: This results in complete loss of encrypted configuration

# Step 1: Generate new keys
age-keygen -o secrets/keys/age-key.txt
chmod 600 secrets/keys/age-key.txt  
age-keygen -y secrets/keys/age-key.txt > secrets/keys/age-public-key.txt

# Step 2: Update SOPS configuration
cat > .sops.yaml << EOF
creation_rules:
  - path_regex: secrets/secrets\.yaml$
    age: >-
      $(cat secrets/keys/age-public-key.txt)
EOF

# Step 3: Reset configuration to template
cp secrets/secrets.yaml.example secrets/secrets.yaml
sops -e -i secrets/secrets.yaml

# Step 4: Reconfigure system
./tools/edit-secrets.sh
# Manually reconfigure all settings

# Step 5: Deploy reconfigured system
./startup.sh
./tools/check-health.sh --comprehensive
```

## 📊 **Monitoring and Maintenance**

### **Automated Key Validation**
```bash
# Performed automatically by check-health.sh --component secrets
validate_age_keys() {
    local errors=0

    # Check private key exists and is readable
    if [[ ! -r "secrets/keys/age-key.txt" ]]; then
        echo "ERROR: Age private key not found or not readable"
        ((errors++))
    fi

    # Check public key exists and is readable  
    if [[ ! -r "secrets/keys/age-public-key.txt" ]]; then
        echo "ERROR: Age public key not found or not readable"
        ((errors++))
    fi

    # Check key permissions
    local private_perms
    private_perms=$(stat -c "%a" secrets/keys/age-key.txt 2>/dev/null)
    if [[ "$private_perms" != "600" ]]; then
        echo "WARN: Age private key has incorrect permissions ($private_perms, should be 600)"
        chmod 600 secrets/keys/age-key.txt
    fi

    # Check key pair consistency
    if ! age-keygen -y secrets/keys/age-key.txt | diff - secrets/keys/age-public-key.txt >/dev/null 2>&1; then
        echo "ERROR: Age key pair mismatch - public key doesn't match private key"
        ((errors++))
    fi

    # Test encryption/decryption
    if ! echo "test" | age -e -R secrets/keys/age-public-key.txt | age -d -i secrets/keys/age-key.txt >/dev/null 2>&1; then
        echo "ERROR: Age encryption/decryption test failed"
        ((errors++))
    fi

    return $errors
}
```

### **Key Integrity Monitoring**
```bash
# Check for key modifications (run via cron)
monitor_key_integrity() {
    local key_file="secrets/keys/age-key.txt"
    local checksum_file="secrets/keys/.age-key.sha256"

    # Create initial checksum if it doesn't exist
    if [[ ! -f "$checksum_file" ]]; then
        sha256sum "$key_file" > "$checksum_file"
        chmod 600 "$checksum_file"
        return 0
    fi

    # Check if key has been modified
    if ! sha256sum -c "$checksum_file" >/dev/null 2>&1; then
        echo "WARNING: Age private key checksum mismatch - key may have been modified"
        # Update checksum after verification
        sha256sum "$key_file" > "$checksum_file"
        # Send notification
        ./tools/backup-monitor.sh --send-notification "Key Modification" "Age private key checksum changed"
    fi
}
```

### **Access Auditing**
```bash
# Monitor key access (requires audit logging)
audit_key_access() {
    local key_file="secrets/keys/age-key.txt"
    local last_access

    # Get last access time
    last_access=$(stat -c "%X" "$key_file")

    # Log access if within last 5 minutes (300 seconds)
    if [[ $(($(date +%s) - last_access)) -lt 300 ]]; then
        echo "INFO: Age private key accessed recently ($(date -d "@$last_access"))"
    fi
}
```

## 📋 **Best Practices**

### **Security Best Practices**
1. **Never transmit private keys** over unencrypted channels
2. **Backup keys regularly** in emergency kits and offline storage
3. **Monitor key integrity** with automated checksum validation
4. **Restrict access** to the absolute minimum required personnel
5. **Document key rotation** procedures and test them regularly

### **Operational Best Practices**
1. **Automate key validation** in health checks and monitoring
2. **Test decryption regularly** to ensure keys are functional
3. **Include keys in backups** with separate delivery mechanisms
4. **Version key rotations** with clear rollback procedures
5. **Monitor for unauthorized access** with audit logging

### **Recovery Best Practices**
1. **Maintain emergency kits** with current keys and documentation
2. **Test recovery procedures** regularly in non-production environments
3. **Document key locations** in emergency access documentation
4. **Train administrators** on key recovery procedures
5. **Verify restored keys** thoroughly before resuming operations

## ⚠️ **Critical Security Notes**

### **Key Protection**
- **Never commit private keys to version control systems**
- **Never send private keys via email or chat**
- **Never store private keys in cloud storage unencrypted**
- **Always use secure transport for key backups**

### **Access Control**
- **Limit key access to essential personnel only**
- **Use separate keys for different environments**
- **Monitor and audit all key access attempts**
- **Revoke access immediately when personnel leave**

### **Emergency Preparedness**
- **Always have current emergency kits available**
- **Test key recovery procedures regularly**
- **Document all key management procedures**
- **Maintain offline key backups for disaster scenarios**

---

**🔑 Key Management Philosophy**: Age encryption keys are the foundation of VaultWarden-OCI-NG's security model. Their protection, backup, and recovery procedures are critical to system reliability and data protection.

**📚 For complete security procedures, see [../docs/Security.md](../docs/Security.md)**

**🚨 For emergency key recovery, consult [../docs/EmergencyRecoveryGuide.md](../docs/EmergencyRecoveryGuide.md)**

**🔧 For operational procedures, review [../docs/OperationsRunbook.md](../docs/OperationsRunbook.md)**
