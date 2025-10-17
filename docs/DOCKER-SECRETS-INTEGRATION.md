# Docker Secrets Integration Guide

This guide explains how VaultWarden integrates Docker Compose Secrets with SOPS+Age encryption for secure credential management.

## Overview

The VaultWarden SOPS+Age integration provides:
- **Encrypted Storage**: Secrets stored encrypted at rest with Age encryption
- **Runtime Decryption**: Secrets decrypted only when needed by Docker containers
- **Zero Plaintext**: No sensitive data stored in plaintext configuration files
- **Container Security**: Secrets mounted securely into containers via Docker secrets

## Architecture

### Secret Flow
```
SOPS Encrypted File → Age Decryption → Docker Secrets Directory → Container Mounts
secrets/secrets.yaml   (SOPS+Age)      secrets/.docker_secrets/     /run/secrets/
```

### Components

#### 1. SOPS Configuration (.sops.yaml)
```yaml
creation_rules:
  - path_regex: secrets/secrets\.yaml$
    age: age1ql3z7hjy54pw9hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
    encrypted_regex: '^(admin_token|smtp_password|backup_passphrase|push_installation_key|cloudflare_api_token)$'
```

#### 2. Encrypted Secrets File (secrets/secrets.yaml)
```yaml
# Encrypted with SOPS+Age - example structure when decrypted:
admin_token: "your-encrypted-admin-token"
smtp_password: "your-encrypted-smtp-password"  
backup_passphrase: "your-encrypted-backup-passphrase"
push_installation_key: "your-encrypted-push-key"
cloudflare_api_token: "your-encrypted-cf-token"
```

#### 3. Docker Compose Secrets Integration
```yaml
# docker-compose.yml
secrets:
  admin_token:
    file: ${DOCKER_SECRETS_DIR}/admin_token
  smtp_password:
    file: ${DOCKER_SECRETS_DIR}/smtp_password
  # ... other secrets

services:
  vaultwarden:
    secrets:
      - admin_token
      - smtp_password
    environment:
      ADMIN_TOKEN_FILE: /run/secrets/admin_token
      SMTP_PASSWORD_FILE: /run/secrets/smtp_password
```

## Implementation Details

### Secret Preparation Process

#### 1. Startup Sequence
```bash
# 1. Load SOPS library
source lib/sops.sh

# 2. Initialize SOPS environment
init_sops_environment

# 3. Load encrypted secrets
load_secrets

# 4. Prepare Docker secrets directory
prepare_docker_secrets

# 5. Start services
docker compose up -d
```

#### 2. Docker Secrets Directory Structure
```
secrets/.docker_secrets/
├── admin_token              # Plaintext file, 644 permissions
├── smtp_password            # Plaintext file, 644 permissions
├── backup_passphrase        # Plaintext file, 644 permissions
├── push_installation_key    # Plaintext file, 644 permissions
└── cloudflare_api_token     # Plaintext file, 644 permissions
```

### Security Model

#### File Permissions
```bash
secrets/keys/age-key.txt     # 600 (root:root) - Private key
secrets/secrets.yaml         # 644 (root:root) - Encrypted secrets
secrets/.docker_secrets/     # 755 (root:root) - Docker access
secrets/.docker_secrets/*    # 644 (root:root) - Container readable
```

#### Container Access
- Secrets mounted at `/run/secrets/` in containers
- Read-only access for containers
- Automatically cleaned up when containers stop
- No secrets in environment variables or logs

## Service Integration

### VaultWarden Service
```yaml
services:
  vaultwarden:
    environment:
      # File-based secret access
      ADMIN_TOKEN_FILE: /run/secrets/admin_token
      SMTP_PASSWORD_FILE: /run/secrets/smtp_password
      BACKUP_PASSPHRASE_FILE: /run/secrets/backup_passphrase
      PUSH_INSTALLATION_KEY_FILE: /run/secrets/push_installation_key
    secrets:
      - admin_token
      - smtp_password
      - backup_passphrase
      - push_installation_key
```

### Watchtower Service
```yaml
services:
  watchtower:
    command:
      - --notification-email-server-password-file=/run/secrets/smtp_password
    secrets:
      - smtp_password
```

### Fail2ban Service
```yaml
services:
  fail2ban:
    environment:
      CLOUDFLARE_API_TOKEN_FILE: /run/secrets/cloudflare_api_token
    secrets:
      - cloudflare_api_token
```

## Management Operations

### Edit Secrets
```bash
# Interactive editing with validation
./tools/edit-secrets.sh

# View decrypted secrets (read-only)
./tools/edit-secrets.sh --view

# Validate secrets format
./tools/edit-secrets.sh --validate
```

### Rotate Individual Secrets
```bash
# Rotate admin token with random value
./tools/rotate-secrets.sh --key admin_token --random --restart

# Rotate SMTP password with specific value
./tools/rotate-secrets.sh --key smtp_password --value "new-password"
```

### Batch Operations
```bash
# Rotate all secrets at once
./tools/rotate-all-secrets.sh

# Rotate specific secrets only
./tools/rotate-all-secrets.sh --include admin_token,backup_passphrase
```

## Health Monitoring

### SOPS-Specific Checks
```bash
# Check SOPS integration health
./tools/check-health.sh --sops-only

# Validate Docker secrets preparation
./startup.sh --secrets-info

# Show SOPS status
./startup.sh --sops-status
```

### Integration Validation
```bash
# Test secret decryption
sops -d secrets/secrets.yaml

# Test Docker secrets mounting
docker compose exec vaultwarden ls -la /run/secrets/

# Verify container can read secrets  
docker compose exec vaultwarden cat /run/secrets/admin_token | wc -c
```

## Backup and Recovery

### Age Key Backup
```bash
# Create secure Age key backup
./tools/backup-recovery.sh create-age-backup /secure/location/

# Validate existing backups
./tools/backup-recovery.sh validate-backups

# Test recovery workflow
./tools/backup-recovery.sh test-recovery
```

### Secret Export/Import
```bash
# Export encrypted secrets for backup
./tools/backup-recovery.sh export-secrets /secure/location/

# Import secrets from backup
./tools/backup-recovery.sh import-secrets /path/to/backup/secrets.yaml
```

## Migration from Legacy Systems

### From OCI Vault
```bash
# Automated migration from OCI Vault to SOPS+Age
sudo ./tools/migrate-from-oci.sh

# Dry run to preview changes
sudo ./tools/migrate-from-oci.sh --dry-run

# Rollback if needed
sudo ./tools/migrate-from-oci.sh --rollback
```

### From Environment Variables
```bash
# Manual migration process:
# 1. Create secrets template
./tools/edit-secrets.sh

# 2. Copy values from environment/config files
# 3. Remove sensitive values from settings.json
jq 'del(.ADMIN_TOKEN, .SMTP_PASSWORD, .BACKUP_PASSPHRASE)' settings.json

# 4. Test new setup
./startup.sh --validate
```

## Advanced Configuration

### Custom Secret Names
```bash
# Add custom secrets to secrets/secrets.yaml
# Then update docker-compose.yml:

secrets:
  custom_api_key:
    file: ${DOCKER_SECRETS_DIR}/custom_api_key

services:
  your_service:
    secrets:
      - custom_api_key
    environment:
      CUSTOM_API_KEY_FILE: /run/secrets/custom_api_key
```

### Multiple Environments
```bash
# Different secrets per environment
# Development
cp secrets/secrets.yaml secrets/secrets.dev.yaml
export SOPS_FILE=secrets/secrets.dev.yaml

# Production  
cp secrets/secrets.yaml secrets/secrets.prod.yaml
export SOPS_FILE=secrets/secrets.prod.yaml
```

### CI/CD Integration
```bash
# Validate secrets in CI
./tools/ci-validate.sh

# Seal secrets for consistent formatting
./tools/seal-secrets.sh

# Test decryption without starting services
SOPS_AGE_KEY_FILE=/path/to/key sops -d secrets/secrets.yaml > /dev/null
```

## Security Best Practices

### File System Security
1. **Restricted Access**: Only root can read Age private key
2. **Temporary Files**: Docker secrets cleaned up automatically
3. **No Plaintext Storage**: Secrets never stored unencrypted on disk
4. **Secure Permissions**: All files have minimal required permissions

### Runtime Security
1. **Container Isolation**: Secrets only accessible to authorized containers
2. **Read-Only Mounts**: Secrets mounted read-only in containers
3. **Memory Only**: Decrypted secrets exist only in container memory
4. **No Logging**: Secret values never appear in logs

### Operational Security
1. **Regular Rotation**: Rotate secrets on schedule
2. **Access Auditing**: Monitor secret file access
3. **Backup Validation**: Regularly test backup recovery
4. **Update Management**: Keep SOPS and Age updated

## Troubleshooting Quick Reference

### Common Issues
```bash
# SOPS decryption fails
chmod 600 secrets/keys/age-key.txt
age-keygen -y secrets/keys/age-key.txt

# Docker secrets not accessible
ls -la secrets/.docker_secrets/
chmod 755 secrets/.docker_secrets/
find secrets/.docker_secrets/ -exec chmod 644 {} \;

# Container can't read secrets
docker compose exec vaultwarden ls -la /run/secrets/
docker compose down && ./startup.sh
```

### Debug Commands
```bash
# Enable debug mode
DEBUG=1 ./startup.sh

# Test secret mounting manually
docker run --rm -v $(pwd)/secrets/.docker_secrets:/run/secrets:ro     alpine:latest ls -la /run/secrets/

# Check container environment
docker compose exec vaultwarden env | grep FILE
```

## Performance Considerations

### Startup Time
- SOPS decryption adds ~1-2 seconds to startup
- Docker secrets preparation adds ~1 second
- Total overhead: ~3-4 seconds for typical deployment

### Resource Usage
- Minimal memory overhead (secrets kept in memory only during preparation)
- No significant CPU impact after startup
- Disk usage: ~1-2KB per secret for Docker files

### Scaling
- Secrets prepared once per deployment
- Multiple container replicas share same secret files
- No performance impact on container scaling

## Integration Examples

### Custom Application Integration
```yaml
# Add your own service with secret access
services:
  custom_app:
    image: your-app:latest
    secrets:
      - custom_secret
    environment:
      CUSTOM_SECRET_FILE: /run/secrets/custom_secret
    depends_on:
      - vaultwarden

secrets:
  custom_secret:
    file: ${DOCKER_SECRETS_DIR}/custom_secret
```

### External Service Integration
```bash
# Use SOPS secrets in external scripts
SECRET_VALUE=$(sops -d --extract '["custom_secret"]' secrets/secrets.yaml)
export CUSTOM_SECRET="$SECRET_VALUE"

# Or use Docker secrets files directly
SECRET_VALUE=$(cat secrets/.docker_secrets/custom_secret)
```

This integration provides a robust, secure foundation for managing sensitive configuration data while maintaining operational simplicity and security best practices.
