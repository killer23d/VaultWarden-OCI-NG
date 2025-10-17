# Migration Guide

This guide provides comprehensive procedures for migrating to VaultWarden-OCI-NG from various sources, including legacy VaultWarden installations, official Bitwarden servers, and other password management solutions.

## Migration Overview

### Migration Scenarios Supported
The VaultWarden-OCI-NG stack supports migration from:
- **Legacy VaultWarden installations** (any version)
- **Official Bitwarden server** (self-hosted or cloud)
- **Other VaultWarden distributions**
- **Password managers with export capabilities**
- **Fresh installations** (new deployments)

### Migration Principles
- **Zero Data Loss**: All user data, vault items, and configurations preserved
- **Minimal Downtime**: Migration designed for production environments
- **Security First**: Encrypted data remains encrypted during migration
- **Rollback Capability**: Ability to revert if migration issues occur
- **Validation Required**: Comprehensive data verification post-migration

## Pre-Migration Planning

### Assessment and Planning

#### Current System Assessment
```bash
# Assess your current VaultWarden installation
# Document the following information:

# 1. Current version and configuration
docker --version
docker compose version

# If using older docker-compose:
docker-compose --version

# 2. Database information
ls -la /path/to/current/data/
du -sh /path/to/current/data/db.sqlite3

# 3. User and data statistics
sqlite3 /path/to/current/data/db.sqlite3 "
SELECT 
  'Users' as type, COUNT(*) as count FROM users
UNION ALL
SELECT 
  'Organizations', COUNT(*) FROM organizations
UNION ALL
SELECT 
  'Vault Items', COUNT(*) FROM cipher
UNION ALL
SELECT 
  'Attachments', COUNT(*) FROM attachments;
"

# 4. Current configuration review
cat /path/to/current/.env
cat /path/to/current/docker-compose.yml
```

#### Migration Checklist
```markdown
## Pre-Migration Checklist
- [ ] Current system fully documented
- [ ] Complete backup of existing system created
- [ ] User notification plan prepared
- [ ] Maintenance window scheduled
- [ ] Rollback procedure documented
- [ ] New system tested in staging environment
- [ ] DNS change procedure planned
- [ ] Team member roles assigned

## Migration Day Checklist  
- [ ] All team members available
- [ ] Communication channels established
- [ ] Backup procedures verified
- [ ] Migration scripts tested
- [ ] Monitoring systems ready
- [ ] User communication sent

## Post-Migration Checklist
- [ ] All services operational
- [ ] User authentication verified
- [ ] Data integrity confirmed
- [ ] Performance benchmarks met
- [ ] Security systems active
- [ ] Backup systems configured
- [ ] User communication completed
```

### Resource Requirements

#### System Requirements for Migration
- **Temporary Storage**: 2x current database size for migration workspace
- **Memory**: 4GB+ recommended during migration
- **Network**: Stable connection for data transfer
- **Time Window**: 2-6 hours depending on data volume

## Migration from Legacy VaultWarden

### Standard VaultWarden Migration

#### Step 1: Backup Current Installation
```bash
# Create comprehensive backup of current system
CURRENT_DIR="/path/to/current/vaultwarden"
BACKUP_DIR="/tmp/vw-migration-backup-$(date +%Y%m%d)"

mkdir -p $BACKUP_DIR

# Stop current services
cd $CURRENT_DIR
docker compose down

# Backup all data
cp -r data/ $BACKUP_DIR/
cp docker-compose.yml $BACKUP_DIR/
cp .env $BACKUP_DIR/ 2>/dev/null || true
cp -r ssl/ $BACKUP_DIR/ 2>/dev/null || true

# Create database dump for verification
sqlite3 data/db.sqlite3 .dump > $BACKUP_DIR/database-dump.sql

echo "Backup created in $BACKUP_DIR"
ls -la $BACKUP_DIR/
```

#### Step 2: Setup VaultWarden-OCI-NG
```bash
# 1. Clone new repository
cd /opt/
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG

# 2. Make scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh

# 3. Run initial setup
sudo ./tools/init-setup.sh

# During setup, use the same domain and admin email as current installation
```

#### Step 3: Data Migration
```bash
# 1. Stop the new installation services
docker compose down

# 2. Migrate database
cp $BACKUP_DIR/data/db.sqlite3 $PROJECT_STATE_DIR/data/bwdata/

# 3. Migrate attachments (if they exist)
if [ -d "$BACKUP_DIR/data/attachments" ]; then
    cp -r $BACKUP_DIR/data/attachments/ $PROJECT_STATE_DIR/data/bwdata/
fi

# 4. Migrate sends (if they exist)  
if [ -d "$BACKUP_DIR/data/sends" ]; then
    cp -r $BACKUP_DIR/data/sends/ $PROJECT_STATE_DIR/data/bwdata/
fi

# 5. Set proper permissions
chown -R 1000:1000 $PROJECT_STATE_DIR/data/bwdata/
chmod 755 $PROJECT_STATE_DIR/data/bwdata/
```

#### Step 4: Configuration Migration
```bash
# Extract configuration from old installation
OLD_ENV="$BACKUP_DIR/.env"
OLD_COMPOSE="$BACKUP_DIR/docker-compose.yml"

# Create migration script for configuration
cat > tools/migrate-config.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

OLD_ENV="$1"
OLD_COMPOSE="$2"

_log_header "Configuration Migration"

# Extract important settings from old .env file
if [ -f "$OLD_ENV" ]; then
    ADMIN_TOKEN=$(grep ADMIN_TOKEN $OLD_ENV | cut -d= -f2)
    SMTP_HOST=$(grep SMTP_HOST $OLD_ENV | cut -d= -f2)
    SMTP_USERNAME=$(grep SMTP_USERNAME $OLD_ENV | cut -d= -f2)

    _log_info "Migrating configuration values..."

    # Update secrets with old admin token (if desired)
    if [ -n "$ADMIN_TOKEN" ]; then
        _log_info "Found existing admin token - consider updating secrets"
    fi
fi

# Extract settings from docker-compose.yml
if [ -f "$OLD_COMPOSE" ]; then
    _log_info "Analyzing old docker-compose configuration..."
    # Document any custom ports, volumes, or settings
    grep -E "(ports|volumes|environment)" $OLD_COMPOSE
fi
EOF

chmod +x tools/migrate-config.sh
./tools/migrate-config.sh $OLD_ENV $OLD_COMPOSE
```

#### Step 5: Start and Verify Migration
```bash
# 1. Start the new installation
./startup.sh

# 2. Verify database migration
./tools/sqlite-maintenance.sh --check

# 3. Compare user counts
NEW_USERS=$(echo "SELECT COUNT(*) FROM users;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3)
OLD_USERS=$(echo "SELECT COUNT(*) FROM users;" | sqlite3 $BACKUP_DIR/data/db.sqlite3)

echo "Migration verification:"
echo "Old system users: $OLD_USERS"
echo "New system users: $NEW_USERS"

if [ "$NEW_USERS" -eq "$OLD_USERS" ]; then
    echo "✅ User count matches - migration successful"
else
    echo "❌ User count mismatch - investigate migration"
fi

# 4. Test user authentication
curl -X POST https://your-domain.com/identity/accounts/prelogin   -H "Content-Type: application/json"   -d '{"email":"test@example.com"}'
```

### Docker Compose v1 to v2 Migration

#### Legacy Docker Compose Migration
```bash
# For systems using older docker-compose (v1)
# 1. Verify current docker-compose version
docker-compose --version

# 2. Update to Docker Compose v2
sudo apt update
sudo apt install docker-compose-plugin

# 3. Update compose file format if needed
# Change version from "3.x" to current format in docker-compose.yml

# 4. Test new compose command
docker compose version

# 5. Migrate using new command structure
docker compose down  # instead of docker-compose down
./startup.sh         # handles new compose format automatically
```

### Environment Variable Migration
```bash
# Create environment variable migration script
cat > tools/migrate-env-vars.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

OLD_ENV_FILE="$1"
NEW_SETTINGS_FILE="settings.json"

if [ ! -f "$OLD_ENV_FILE" ]; then
    _log_error "Old environment file not found: $OLD_ENV_FILE"
    exit 1
fi

_log_header "Environment Variable Migration"

# Map old environment variables to new configuration
while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue

    # Remove quotes from value
    value=$(echo "$value" | sed 's/^["'"'"']//;s/["'"'"']$//')

    case $key in
        DOMAIN)
            _log_info "Migrating DOMAIN: $value"
            # Update settings.json or environment
            ;;
        ADMIN_TOKEN)
            _log_info "Found ADMIN_TOKEN - update secrets file"
            # Store in encrypted secrets
            ;;
        SMTP_*)
            _log_info "Migrating SMTP setting: $key"
            # Update SMTP configuration
            ;;
        SIGNUPS_ALLOWED|INVITATIONS_ALLOWED)
            _log_info "Migrating policy: $key=$value"
            ;;
        *)
            _log_debug "Unknown variable: $key"
            ;;
    esac
done < "$OLD_ENV_FILE"

_log_success "Environment variable migration analysis complete"
EOF

chmod +x tools/migrate-env-vars.sh
```

## Migration from Official Bitwarden

### Bitwarden Server Migration

#### Export Data from Bitwarden
```bash
# 1. Create organization export from Bitwarden admin panel
# Navigate to: Admin Panel > Tools > Export Vault
# Download: organization_export.json

# 2. Individual user exports
# Each user should export their vault:
# Bitwarden Web Vault > Tools > Export Vault
# Format: .json (encrypted or unencrypted)

# 3. Server configuration documentation
# Document current Bitwarden server settings:
# - User registration policies
# - Organization settings  
# - Admin configurations
# - SSL certificate setup
```

#### Convert Bitwarden Export to VaultWarden
```bash
# Create Bitwarden import script
cat > tools/import-bitwarden.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

EXPORT_FILE="$1"
IMPORT_USER="$2"

if [ ! -f "$EXPORT_FILE" ]; then
    _log_error "Export file not found: $EXPORT_FILE"
    exit 1
fi

_log_header "Bitwarden Data Import"

# 1. Verify export file format
if jq empty "$EXPORT_FILE" 2>/dev/null; then
    _log_success "Export file is valid JSON"
else
    _log_error "Export file is not valid JSON"
    exit 1
fi

# 2. Analyze export contents
ITEM_COUNT=$(jq '.items | length' "$EXPORT_FILE")
FOLDER_COUNT=$(jq '.folders | length' "$EXPORT_FILE")
ORG_COUNT=$(jq '.collections | length' "$EXPORT_FILE" 2>/dev/null || echo "0")

_log_info "Export contains:"
_log_info "  Items: $ITEM_COUNT"
_log_info "  Folders: $FOLDER_COUNT"
_log_info "  Collections: $ORG_COUNT"

# 3. Import process
# Note: VaultWarden supports Bitwarden export format natively
# Users can import directly through the web interface
# Or use the Bitwarden CLI

_log_info "Import methods available:"
_log_info "1. Web Interface: Tools > Import Data"
_log_info "2. Bitwarden CLI: bw import bitwarden <export_file>"
_log_info "3. API endpoint: /api/ciphers/import"

_log_success "Import preparation complete"
EOF

chmod +x tools/import-bitwarden.sh
```

### Bitwarden CLI Migration
```bash
# Install Bitwarden CLI for migration
curl -L https://github.com/bitwarden/clients/releases/latest/download/bw-linux.zip -o bw.zip
unzip bw.zip
chmod +x bw
sudo mv bw /usr/local/bin/

# Configure CLI for new VaultWarden server
bw config server https://your-domain.com

# Login as user
bw login user@example.com

# Import organization data
bw import bitwarden organization_export.json

# Verify import
bw list items --organizationid <org_id>
```

## Large-Scale Migration Procedures

### Enterprise Migration Strategy

#### Multi-Organization Migration
```bash
# Create organization migration script
cat > tools/migrate-organizations.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

MIGRATION_DIR="/tmp/org-migration"
mkdir -p $MIGRATION_DIR

_log_header "Multi-Organization Migration"

# 1. Export all organizations from source system
organizations=$(sqlite3 /path/to/old/db.sqlite3 "SELECT uuid, name FROM organizations;")

while IFS='|' read -r uuid name; do
    _log_info "Migrating organization: $name ($uuid)"

    # Export organization data
    sqlite3 /path/to/old/db.sqlite3 ".mode json"       "SELECT * FROM cipher WHERE organization_uuid='$uuid';" > $MIGRATION_DIR/org_$uuid.json

    # Export organization users
    sqlite3 /path/to/old/db.sqlite3 ".mode json"       "SELECT u.* FROM users u 
       JOIN users_organizations uo ON u.uuid = uo.user_uuid 
       WHERE uo.org_uuid='$uuid';" > $MIGRATION_DIR/org_users_$uuid.json

done <<< "$organizations"

_log_success "Organization data exported to $MIGRATION_DIR"

# 2. Import organizations into new system
# This requires the new system to be running
for org_file in $MIGRATION_DIR/org_*.json; do
    org_uuid=$(basename $org_file .json | cut -d_ -f2)
    _log_info "Importing organization data: $org_uuid"

    # Import via API or database insertion
    # Implementation depends on specific requirements
done
EOF

chmod +x tools/migrate-organizations.sh
```

#### User Batch Migration
```bash
# Create batch user migration script  
cat > tools/migrate-users-batch.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

USER_LIST="$1"
BATCH_SIZE=10

if [ ! -f "$USER_LIST" ]; then
    _log_error "User list file not found: $USER_LIST"
    exit 1
fi

_log_header "Batch User Migration"

# Process users in batches to avoid overwhelming the system
split -l $BATCH_SIZE "$USER_LIST" /tmp/user_batch_

for batch_file in /tmp/user_batch_*; do
    _log_info "Processing batch: $(basename $batch_file)"

    while read -r user_email; do
        _log_info "Migrating user: $user_email"

        # Export user data from old system
        sqlite3 /path/to/old/db.sqlite3 ".mode json"           "SELECT * FROM users WHERE email='$user_email';" > /tmp/user_$user_email.json

        # Export user's vault items
        user_uuid=$(sqlite3 /path/to/old/db.sqlite3 "SELECT uuid FROM users WHERE email='$user_email';")
        sqlite3 /path/to/old/db.sqlite3 ".mode json"           "SELECT * FROM cipher WHERE user_uuid='$user_uuid';" > /tmp/vault_$user_email.json

        # Import into new system (implementation specific)
        # ./tools/import-user.sh /tmp/user_$user_email.json /tmp/vault_$user_email.json

    done < "$batch_file"

    # Pause between batches
    sleep 30
    rm "$batch_file"
done

_log_success "Batch migration completed"
EOF

chmod +x tools/migrate-users-batch.sh
```

## Migration Validation and Testing

### Data Integrity Verification

#### Post-Migration Validation Script
```bash
# Create comprehensive migration validation
cat > tools/validate-migration.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

OLD_DB="$1"
NEW_DB="$PROJECT_STATE_DIR/data/bwdata/db.sqlite3"

if [ ! -f "$OLD_DB" ] || [ ! -f "$NEW_DB" ]; then
    _log_error "Database files not found"
    exit 1
fi

_log_header "Migration Validation"

# 1. User count verification
old_users=$(sqlite3 "$OLD_DB" "SELECT COUNT(*) FROM users;")
new_users=$(sqlite3 "$NEW_DB" "SELECT COUNT(*) FROM users;")

_log_info "User count comparison:"
_log_info "  Old system: $old_users"
_log_info "  New system: $new_users"

if [ "$old_users" -eq "$new_users" ]; then
    _log_success "✅ User count matches"
else
    _log_error "❌ User count mismatch"
fi

# 2. Organization count verification
old_orgs=$(sqlite3 "$OLD_DB" "SELECT COUNT(*) FROM organizations;" 2>/dev/null || echo "0")
new_orgs=$(sqlite3 "$NEW_DB" "SELECT COUNT(*) FROM organizations;" 2>/dev/null || echo "0")

_log_info "Organization count comparison:"
_log_info "  Old system: $old_orgs"
_log_info "  New system: $new_orgs"

# 3. Vault item count verification
old_items=$(sqlite3 "$OLD_DB" "SELECT COUNT(*) FROM cipher;")
new_items=$(sqlite3 "$NEW_DB" "SELECT COUNT(*) FROM cipher;")

_log_info "Vault item count comparison:"
_log_info "  Old system: $old_items"
_log_info "  New system: $new_items"

if [ "$old_items" -eq "$new_items" ]; then
    _log_success "✅ Vault item count matches"
else
    _log_error "❌ Vault item count mismatch"
fi

# 4. Database integrity check
if ./tools/sqlite-maintenance.sh --check; then
    _log_success "✅ Database integrity verified"
else
    _log_error "❌ Database integrity issues found"
fi

# 5. Sample user verification
sample_user=$(sqlite3 "$OLD_DB" "SELECT email FROM users LIMIT 1;")
if [ -n "$sample_user" ]; then
    _log_info "Testing sample user authentication: $sample_user"

    # Test API endpoint
    response=$(curl -s -X POST https://your-domain.com/identity/accounts/prelogin       -H "Content-Type: application/json"       -d "{"email":"$sample_user"}")

    if echo "$response" | grep -q "Kdf"; then
        _log_success "✅ User authentication endpoint responsive"
    else
        _log_error "❌ User authentication issues detected"
    fi
fi

_log_success "Migration validation completed"
EOF

chmod +x tools/validate-migration.sh
```

### Performance Benchmark Comparison
```bash
# Create performance comparison script
cat > tools/benchmark-migration.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

_log_header "Migration Performance Benchmarking"

# 1. Database query performance
_log_info "Testing database query performance..."

start_time=$(date +%s.%N)
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "SELECT COUNT(*) FROM users;"
end_time=$(date +%s.%N)
query_time=$(echo "$end_time - $start_time" | bc)

_log_info "User count query time: ${query_time}s"

# 2. Web interface response time
_log_info "Testing web interface response time..."

response_time=$(curl -w "%{time_total}" -s -o /dev/null https://your-domain.com)
_log_info "Web interface response time: ${response_time}s"

# 3. API endpoint performance
_log_info "Testing API endpoint performance..."

api_time=$(curl -w "%{time_total}" -s -o /dev/null   -X POST https://your-domain.com/identity/accounts/prelogin   -H "Content-Type: application/json"   -d '{"email":"test@example.com"}')

_log_info "API endpoint response time: ${api_time}s"

# 4. Database size comparison
db_size=$(du -sh $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 | cut -f1)
_log_info "Database size after migration: $db_size"

_log_success "Performance benchmarking completed"
EOF

chmod +x tools/benchmark-migration.sh
```

## Rollback Procedures

### Migration Rollback Plan

#### Emergency Rollback Script
```bash
# Create rollback script for migration emergencies
cat > tools/rollback-migration.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

BACKUP_DIR="$1"
ROLLBACK_REASON="$2"

if [ ! -d "$BACKUP_DIR" ]; then
    _log_error "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

_log_header "EMERGENCY MIGRATION ROLLBACK"
_log_info "Reason: $ROLLBACK_REASON"
_log_info "Backup source: $BACKUP_DIR"

# 1. Stop new system
docker compose down

# 2. Document rollback
echo "$(date): ROLLBACK INITIATED - $ROLLBACK_REASON" >> /var/log/migration.log

# 3. Restore old configuration
if [ -f "$BACKUP_DIR/docker-compose.yml" ]; then
    cp "$BACKUP_DIR/docker-compose.yml" ./
fi

if [ -f "$BACKUP_DIR/.env" ]; then
    cp "$BACKUP_DIR/.env" ./
fi

# 4. Restore data
if [ -d "$BACKUP_DIR/data" ]; then
    rm -rf $PROJECT_STATE_DIR/data/bwdata/
    cp -r "$BACKUP_DIR/data" $PROJECT_STATE_DIR/data/bwdata/
    chown -R 1000:1000 $PROJECT_STATE_DIR/data/bwdata/
fi

# 5. Start system with old configuration
docker compose up -d

# 6. Verify rollback
sleep 30
./tools/check-health.sh

_log_success "Rollback completed - verify system functionality"
EOF

chmod +x tools/rollback-migration.sh
```

## Migration Documentation

### Migration Report Template
```bash
# Create migration report template
cat > templates/migration-report.md << 'EOF'
# VaultWarden Migration Report

## Migration Summary
- **Migration Date**: {{DATE}}
- **Migration Type**: {{TYPE}}
- **Source System**: {{SOURCE}}
- **Target System**: VaultWarden-OCI-NG
- **Migration Duration**: {{DURATION}}
- **Downtime**: {{DOWNTIME}}

## Data Migration Results
- **Users Migrated**: {{USER_COUNT}}
- **Organizations**: {{ORG_COUNT}}
- **Vault Items**: {{ITEM_COUNT}}
- **Attachments**: {{ATTACHMENT_COUNT}}
- **Database Size**: {{DB_SIZE}}

## Validation Results
- [ ] User count verification: {{USER_VALIDATION}}
- [ ] Database integrity: {{DB_INTEGRITY}}
- [ ] Authentication testing: {{AUTH_TEST}}
- [ ] Performance benchmarks: {{PERFORMANCE}}
- [ ] SSL certificate: {{SSL_STATUS}}

## Issues Encountered
{{ISSUES_LIST}}

## Resolution Actions
{{RESOLUTIONS_LIST}}

## Performance Comparison
| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Response Time | {{OLD_RESPONSE}} | {{NEW_RESPONSE}} | {{RESPONSE_CHANGE}} |
| Database Size | {{OLD_DB_SIZE}} | {{NEW_DB_SIZE}} | {{SIZE_CHANGE}} |
| Memory Usage | {{OLD_MEMORY}} | {{NEW_MEMORY}} | {{MEMORY_CHANGE}} |

## Recommendations
{{RECOMMENDATIONS}}

## Sign-off
- **Technical Lead**: {{TECH_LEAD}} - {{DATE}}
- **Project Manager**: {{PM}} - {{DATE}}
- **System Administrator**: {{SYSADMIN}} - {{DATE}}
EOF
```

This migration guide provides comprehensive procedures for safely migrating to VaultWarden-OCI-NG while ensuring data integrity and minimal service disruption.
