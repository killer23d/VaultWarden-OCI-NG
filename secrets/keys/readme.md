# Age Key Management

This directory contains your Age encryption keys for SOPS secret management.

## 🔑 Files in this directory:

### `age-key.txt` (PRIVATE KEY)
- **CRITICAL**: This is your Age private key
- **PERMISSIONS**: Must be 600 (readable only by owner)
- **BACKUP REQUIRED**: Without this key, encrypted secrets cannot be decrypted
- **NEVER COMMIT**: Automatically ignored by Git

### `backup-info.txt` (Backup Metadata)
- Contains information about your key backup status
- Tracks when backups were created and verified
- Safe to commit (contains no sensitive data)

## ⚠️ CRITICAL BACKUP INSTRUCTIONS

### 1. Immediate Actions Required:

```bash
# Verify your key exists and has correct permissions
ls -la secrets/keys/age-key.txt

# Should show: -rw------- (600 permissions)
```

### 2. Backup Your Private Key:

**Option A: Manual Backup**
```bash
# Copy to secure external storage
cp secrets/keys/age-key.txt /path/to/secure/backup/location/
```

**Option B: Automated Backup (with init-setup.sh)**
```bash
# The init-setup.sh script will prompt you to backup your key
./tools/init-setup.sh
```

### 3. Verify Your Backup:
```bash
# Test that your backup can decrypt secrets
age -d -i /path/to/backup/age-key.txt < <(echo "test" | age -e -R <(age-keygen -y secrets/keys/age-key.txt))
```

## 🔧 Key Generation Process:

Keys are generated automatically by `init-setup.sh`:

1. **Check Existing**: Verify no key already exists (idempotent)
2. **Generate**: Create new Age key pair using `age-keygen`
3. **Set Permissions**: Secure private key with 600 permissions
4. **Update SOPS Config**: Configure `.sops.yaml` with public key
5. **Prompt Backup**: Force user acknowledgment of backup responsibility

## 🛠️ Key Operations:

### View Public Key (safe to share):
```bash
age-keygen -y secrets/keys/age-key.txt
```

### Regenerate Keys (DESTRUCTIVE):
```bash
# WARNING: This will make existing encrypted secrets unreadable!
rm secrets/keys/age-key.txt
rm secrets/keys/backup-info.txt
./tools/init-setup.sh
```

## 🆘 Emergency Recovery:

### Key Lost but Backup Exists:
1. Copy backup to `secrets/keys/age-key.txt`
2. Set permissions: `chmod 600 secrets/keys/age-key.txt`
3. Verify: `./tools/check-health.sh`

### Key Lost and No Backup:
1. **All encrypted secrets are permanently lost**
2. Generate new key: `rm secrets/keys/* && ./tools/init-setup.sh`
3. Re-enter all secrets: `./tools/edit-secrets.sh`

## 🔍 Key Validation:

### Health Check:
```bash
./tools/check-health.sh
```

### Manual Validation:
```bash
# Check key file exists and has correct permissions
[[ -f "secrets/keys/age-key.txt" ]] && [[ "$(stat -c %a secrets/keys/age-key.txt)" == "600" ]]

# Test encryption/decryption
echo "test" | age -e -R <(age-keygen -y secrets/keys/age-key.txt) | age -d -i secrets/keys/age-key.txt
```

## 📋 Key Rotation (Advanced):

To rotate Age keys (creates new key, re-encrypts secrets):

1. **Backup current encrypted secrets**: `cp secrets/secrets.yaml secrets/secrets.yaml.backup`
2. **Decrypt to temporary file**: `sops -d secrets/secrets.yaml > /tmp/secrets.plain.yaml`
3. **Generate new key**: `rm secrets/keys/age-key.txt && ./tools/init-setup.sh`
4. **Re-encrypt with new key**: `sops -e /tmp/secrets.plain.yaml > secrets/secrets.yaml`
5. **Cleanup**: `shred -vfz /tmp/secrets.plain.yaml`
6. **Verify**: `./tools/check-health.sh`

---

🔐 **Your Age private key is the ONLY way to decrypt your secrets. Backup immediately!**
