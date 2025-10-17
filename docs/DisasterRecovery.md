# Disaster Recovery Guide

This comprehensive guide covers disaster recovery planning, emergency procedures, and business continuity strategies for the VaultWarden-OCI-NG deployment.

## Disaster Recovery Overview

### Business Continuity Objectives
The VaultWarden-OCI-NG disaster recovery plan is designed to meet these critical objectives:

- **Recovery Time Objective (RTO)**: Maximum acceptable downtime
  - Database corruption: 15 minutes
  - Service failure: 5 minutes  
  - Complete server failure: 45 minutes
  - Infrastructure disaster: 4 hours

- **Recovery Point Objective (RPO)**: Maximum acceptable data loss
  - Normal operations: 24 hours (daily backups)
  - Critical periods: 1 hour (with manual backups)
  - Real-time protection: 0 seconds (WAL mode)

### Disaster Categories

#### Category 1: Service-Level Failures
- Container crashes or failures
- Database corruption
- SSL certificate issues
- Configuration corruption
- **Recovery Time**: 5-15 minutes
- **Data Loss Risk**: Minimal to none

#### Category 2: System-Level Failures  
- Operating system corruption
- Disk failures
- Network connectivity issues
- Security breaches requiring rebuilds
- **Recovery Time**: 30-60 minutes
- **Data Loss Risk**: Up to 24 hours

#### Category 3: Infrastructure Disasters
- Complete server hardware failure
- Data center outages
- Natural disasters
- Cloud provider service disruptions
- **Recovery Time**: 2-8 hours
- **Data Loss Risk**: Up to 24 hours

## Disaster Response Procedures

### Immediate Response Protocol

#### Step 1: Incident Assessment (< 2 minutes)
```bash
# Quick system health assessment
./tools/check-health.sh --summary

# Service status check
docker compose ps

# Resource availability check
df -h && free -h

# Network connectivity test
curl -I https://your-domain.com
```

#### Step 2: Impact Classification
**Critical Impact**: Complete service unavailability
```bash
# Immediate actions for critical impact:
echo "$(date): CRITICAL INCIDENT - VaultWarden service unavailable" |   tee -a /var/log/disaster-recovery.log

# Notify administrators (if email configured)
echo "VaultWarden CRITICAL service failure at $(date)" |   mail -s "CRITICAL: VaultWarden Down" admin@your-domain.com
```

**High Impact**: Degraded performance or partial functionality
```bash
# High impact response:
echo "$(date): HIGH IMPACT - VaultWarden degraded service" |   tee -a /var/log/disaster-recovery.log

# Begin diagnostic procedures
docker compose logs --tail=50 > /tmp/incident-logs-$(date +%Y%m%d-%H%M).txt
```

**Medium Impact**: Minor issues not affecting core functionality
```bash
# Medium impact monitoring:
echo "$(date): MEDIUM IMPACT - Performance degradation detected" |   tee -a /var/log/disaster-recovery.log
```

### Category 1: Service-Level Recovery

#### Container Service Recovery
```bash
# Automated recovery (preferred method)
./startup.sh

# Manual service recovery if automated fails
docker compose down
docker compose up -d

# Verify recovery
./tools/check-health.sh

# Document recovery action
echo "$(date): Service recovery completed via container restart" |   tee -a /var/log/disaster-recovery.log
```

#### Database Corruption Recovery
```bash
# 1. Immediate database assessment
./tools/sqlite-maintenance.sh --check

# 2. If corruption detected, stop services
docker compose stop vaultwarden

# 3. Create backup of corrupted database
cp $PROJECT_STATE_DIR/data/bwdata/db.sqlite3    /tmp/corrupted-db-$(date +%Y%m%d-%H%M).sqlite3

# 4. Restore from most recent backup
./tools/restore.sh --database-only    $PROJECT_STATE_DIR/backups/daily/db-backup-latest.sqlite3.enc

# 5. Verify database integrity
./tools/sqlite-maintenance.sh --check

# 6. Restart services
./startup.sh

# 7. Verify full functionality
./tools/check-health.sh
curl -I https://your-domain.com
```

#### SSL Certificate Recovery
```bash
# 1. Check certificate status
echo | openssl s_client -connect your-domain.com:443 2>/dev/null |   openssl x509 -noout -dates

# 2. Force certificate renewal
docker compose exec caddy caddy reload

# 3. If renewal fails, check Let's Encrypt logs
docker compose logs caddy | grep -i acme

# 4. Manual certificate troubleshooting
# Verify domain accessibility for ACME challenge
curl -I http://your-domain.com/.well-known/acme-challenge/

# 5. If necessary, restore certificates from backup
./tools/restore.sh --certificates-only    $PROJECT_STATE_DIR/backups/weekly/backup-full-latest.tar.gz.enc
```

### Category 2: System-Level Recovery

#### Operating System Recovery
```bash
# 1. Assessment of system integrity
sudo apt update && sudo apt list --upgradable
sudo systemctl status docker
sudo systemctl status fail2ban

# 2. If system is recoverable, update and repair
sudo apt upgrade -y
sudo systemctl restart docker
./startup.sh

# 3. If system requires rebuild
# Stop services gracefully
docker compose down

# Create emergency backup
./tools/create-full-backup.sh --output-dir /tmp/emergency-backup/

# Proceed with system rebuild
sudo ./tools/init-setup.sh
./tools/restore.sh /tmp/emergency-backup/backup-full-*.tar.gz.enc
```

#### Disk Failure Recovery
```bash
# 1. Immediate data assessment
df -h
sudo dmesg | grep -i "disk\|error\|fail"

# 2. If disk is failing but accessible
# Emergency backup creation
./tools/create-full-backup.sh --output-dir /external/storage/

# Copy backup to safe location
rsync -av $PROJECT_STATE_DIR/backups/ /external/storage/backups/

# 3. After disk replacement/repair
# Restore system from backup
./tools/restore.sh /external/storage/backup-full-latest.tar.gz.enc

# 4. Verify system integrity
./tools/check-health.sh --verbose
```

### Category 3: Infrastructure Disaster Recovery

#### Complete Server Rebuild Process
```bash
# Prerequisites:
# - New Ubuntu 24.04 LTS server
# - Access to backup files
# - Age private key from secure storage
# - DNS pointing to new server IP

# 1. Initial server setup (10 minutes)
ssh ubuntu@NEW_SERVER_IP
sudo apt update && sudo apt upgrade -y

# 2. Clone and prepare repository (3 minutes)
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
cd VaultWarden-OCI-NG
chmod +x startup.sh tools/*.sh lib/*.sh

# 3. Restore Age encryption key (2 minutes)
sudo mkdir -p secrets/keys/
# Copy age-key.txt from secure offline storage
sudo cp /secure/location/age-key.txt secrets/keys/
sudo chmod 600 secrets/keys/age-key.txt
sudo chown root:root secrets/keys/age-key.txt

# 4. Automated system setup (15 minutes)
sudo ./tools/init-setup.sh --auto

# 5. Restore from backup (10 minutes)
# Copy backup files to server first
scp backup-full-YYYYMMDD-HHMMSS.tar.gz.enc ubuntu@NEW_SERVER_IP:/tmp/
./tools/restore.sh /tmp/backup-full-YYYYMMDD-HHMMSS.tar.gz.enc

# 6. Start services and verify (5 minutes)
./startup.sh
./tools/check-health.sh --verbose

# 7. Update DNS if necessary
# Point domain to new server IP address
```

#### Multi-Region Disaster Recovery
```bash
# For organizations requiring high availability
# Set up secondary VaultWarden instance in different region

# 1. Create automated backup replication
cat > tools/dr-replication.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

DR_SERVER="dr-vault.company.com"
DR_USER="ubuntu"
BACKUP_DIR="$PROJECT_STATE_DIR/backups"

# Sync backups to disaster recovery server
rsync -av --delete -e "ssh -i /path/to/dr-key"   $BACKUP_DIR/ $DR_USER@$DR_SERVER:/opt/vaultwarden-backups/

if [ $? -eq 0 ]; then
    _log_success "DR backup replication completed"
else
    _log_error "DR backup replication failed"
    # Send alert
    echo "DR replication failed at $(date)" |       mail -s "DR Replication Alert" admin@company.com
fi
EOF

chmod +x tools/dr-replication.sh

# 2. Schedule regular replication
echo "0 4 * * * /path/to/tools/dr-replication.sh" | crontab -

# 3. DR server activation procedure
# On disaster recovery server:
./tools/restore.sh /opt/vaultwarden-backups/backup-full-latest.tar.gz.enc
./startup.sh

# Update DNS to point to DR server
# Notify users of temporary DR activation
```

## Emergency Communication Plan

### Incident Communication Templates

#### Internal Team Notification
```bash
# Create incident notification script
cat > tools/incident-notify.sh << 'EOF'
#!/bin/bash

INCIDENT_LEVEL=$1
INCIDENT_DESCRIPTION=$2
ADMIN_EMAIL="admin@company.com"
TEAM_EMAIL="team@company.com"

case $INCIDENT_LEVEL in
    CRITICAL)
        SUBJECT="🚨 CRITICAL: VaultWarden Service Down"
        PRIORITY="High"
        ;;
    HIGH)
        SUBJECT="⚠️ HIGH: VaultWarden Service Degraded"
        PRIORITY="Medium"
        ;;
    MEDIUM)
        SUBJECT="📊 MEDIUM: VaultWarden Performance Issue"
        PRIORITY="Low"
        ;;
esac

cat > /tmp/incident-email.txt << EOL
Incident Level: $INCIDENT_LEVEL
Time: $(date)
Description: $INCIDENT_DESCRIPTION
Server: $(hostname)
Status URL: https://your-domain.com/health

Automatic recovery in progress...
Updates will be provided every 15 minutes during CRITICAL incidents.

VaultWarden Monitoring System
EOL

mail -s "$SUBJECT" $ADMIN_EMAIL < /tmp/incident-email.txt
if [ "$INCIDENT_LEVEL" = "CRITICAL" ]; then
    mail -s "$SUBJECT" $TEAM_EMAIL < /tmp/incident-email.txt
fi

rm /tmp/incident-email.txt
EOF

chmod +x tools/incident-notify.sh
```

#### User Communication Templates
```bash
# Status page update template
cat > templates/user-notification.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VaultWarden Service Status</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status-critical { color: #d32f2f; background: #ffebee; }
        .status-degraded { color: #f57c00; background: #fff3e0; }
        .status-operational { color: #388e3c; background: #e8f5e8; }
        .status-box { padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>VaultWarden Service Status</h1>
    <div class="status-box status-critical">
        <h2>Service Disruption</h2>
        <p><strong>Status:</strong> Service Temporarily Unavailable</p>
        <p><strong>Started:</strong> {{INCIDENT_TIME}}</p>
        <p><strong>Expected Resolution:</strong> {{ESTIMATED_RESOLUTION}}</p>
        <p><strong>Impact:</strong> Users may experience login difficulties</p>
        <p><strong>Updates:</strong> This page will be updated every 15 minutes</p>
    </div>

    <h3>What We're Doing</h3>
    <ul>
        <li>Automatic recovery systems are active</li>
        <li>Technical team has been notified</li>
        <li>All user data remains secure and encrypted</li>
    </ul>

    <p>Last updated: {{LAST_UPDATE_TIME}}</p>
</body>
</html>
EOF
```

### Escalation Procedures

#### Tier 1: Automated Response (0-5 minutes)
- Automated monitoring detects issue
- Self-healing systems attempt resolution
- Initial incident logging
- Health checks continue monitoring

#### Tier 2: Administrative Response (5-15 minutes)
- Email notifications sent to admin team
- Manual diagnostics begin
- Recovery procedures initiated
- Incident severity assessment

#### Tier 3: Emergency Response (15+ minutes)
- Senior technical staff notified
- External vendor contact (if applicable)
- User communication initiated
- Disaster recovery procedures activated

## Data Protection During Disasters

### Data Integrity Verification

#### Pre-Disaster Data Validation
```bash
# Create pre-disaster validation script
cat > tools/pre-disaster-validation.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

VALIDATION_LOG="/var/log/pre-disaster-validation.log"

echo "=== Pre-Disaster Validation $(date) ===" >> $VALIDATION_LOG

# 1. Database integrity check
if ./tools/sqlite-maintenance.sh --check >> $VALIDATION_LOG 2>&1; then
    _log_success "Database integrity verified"
else
    _log_error "Database integrity check failed"
fi

# 2. Backup system verification
if ./tools/restore.sh --verify $(ls -t $PROJECT_STATE_DIR/backups/daily/*.enc | head -1) >> $VALIDATION_LOG 2>&1; then
    _log_success "Latest backup verified"
else
    _log_error "Backup verification failed"
fi

# 3. Configuration validation
if ./startup.sh --validate >> $VALIDATION_LOG 2>&1; then
    _log_success "Configuration validated"
else
    _log_error "Configuration validation failed"
fi

# 4. Security status check
if ./tools/check-health.sh --security-only >> $VALIDATION_LOG 2>&1; then
    _log_success "Security systems operational"
else
    _log_error "Security system issues detected"
fi

echo "=== Validation Complete ===" >> $VALIDATION_LOG
EOF

chmod +x tools/pre-disaster-validation.sh

# Schedule daily validation
echo "0 6 * * * /path/to/tools/pre-disaster-validation.sh" | crontab -
```

#### Post-Recovery Data Validation
```bash
# Create post-recovery validation script
cat > tools/post-recovery-validation.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

_log_header "Post-Recovery Validation"

# 1. System health comprehensive check
if ./tools/check-health.sh --verbose; then
    _log_success "System health check passed"
else
    _log_error "System health check failed"
    exit 1
fi

# 2. Database functionality test
DB_PATH="$PROJECT_STATE_DIR/data/bwdata/db.sqlite3"
if sqlite3 $DB_PATH "SELECT COUNT(*) FROM users;" >/dev/null 2>&1; then
    USER_COUNT=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM users;")
    _log_success "Database functional - $USER_COUNT users found"
else
    _log_error "Database functionality test failed"
    exit 1
fi

# 3. Service connectivity test
if curl -I https://your-domain.com >/dev/null 2>&1; then
    _log_success "Web service connectivity verified"
else
    _log_error "Web service connectivity failed"
    exit 1
fi

# 4. SSL certificate validation
if echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates >/dev/null 2>&1; then
    _log_success "SSL certificate validated"
else
    _log_error "SSL certificate validation failed"
    exit 1
fi

# 5. Authentication system test
AUTH_TEST=$(curl -s -X POST https://your-domain.com/identity/accounts/prelogin -H "Content-Type: application/json" -d '{"email":"test@invalid.com"}')
if echo $AUTH_TEST | grep -q "Kdf"; then
    _log_success "Authentication system responsive"
else
    _log_error "Authentication system test failed"
    exit 1
fi

_log_success "All post-recovery validations passed"
EOF

chmod +x tools/post-recovery-validation.sh
```

## Disaster Recovery Testing

### Regular DR Testing Schedule

#### Monthly DR Tests
```bash
# Create monthly DR test script
cat > tools/monthly-dr-test.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

TEST_ENV="/tmp/dr-test-$(date +%Y%m%d)"
BACKUP_FILE=$(ls -t $PROJECT_STATE_DIR/backups/weekly/*.enc | head -1)

_log_header "Monthly Disaster Recovery Test"

# 1. Create isolated test environment
mkdir -p $TEST_ENV
cd $TEST_ENV

# 2. Clone repository
git clone https://github.com/killer23d/VaultWarden-OCI-NG.git .
chmod +x startup.sh tools/*.sh lib/*.sh

# 3. Copy encryption keys
sudo cp -r $PROJECT_STATE_DIR/../secrets/keys secrets/

# 4. Test backup restore
if ./tools/restore.sh --dry-run $BACKUP_FILE; then
    _log_success "DR Test: Backup restore simulation successful"
else
    _log_error "DR Test: Backup restore simulation failed"
fi

# 5. Test configuration validation
if ./startup.sh --validate; then
    _log_success "DR Test: Configuration validation successful"
else
    _log_error "DR Test: Configuration validation failed"
fi

# 6. Clean up test environment
cd /
rm -rf $TEST_ENV

_log_success "Monthly DR test completed"

# 7. Generate test report
cat > /tmp/dr-test-report.txt << EOL
Disaster Recovery Test Report
Date: $(date)
Test Type: Monthly Simulation
Backup Tested: $(basename $BACKUP_FILE)
Results: All tests passed
Next Test: $(date -d "+1 month" +%Y-%m-%d)
EOL

mail -s "DR Test Report - $(date +%Y-%m-%d)" admin@company.com < /tmp/dr-test-report.txt
rm /tmp/dr-test-report.txt
EOF

chmod +x tools/monthly-dr-test.sh

# Schedule monthly DR testing
echo "0 5 15 * * /path/to/tools/monthly-dr-test.sh >> /var/log/dr-tests.log 2>&1" | crontab -
```

#### Quarterly Full DR Simulation
```bash
# Create quarterly full DR simulation
cat > tools/quarterly-dr-simulation.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

# This script should be run in a completely separate test environment
# that mirrors the production environment

_log_header "Quarterly Disaster Recovery Simulation"

# 1. Simulate complete infrastructure failure
_log_info "Simulating infrastructure disaster..."

# 2. Measure recovery time
start_time=$(date +%s)

# 3. Execute complete rebuild process
sudo ./tools/init-setup.sh --auto

# 4. Restore from backup
LATEST_BACKUP="/path/to/copied/backup-full-latest.tar.gz.enc"
./tools/restore.sh $LATEST_BACKUP

# 5. Start services
./startup.sh

# 6. Validate recovery
./tools/post-recovery-validation.sh

# 7. Calculate recovery time
end_time=$(date +%s)
recovery_time=$((end_time - start_time))

_log_success "Quarterly DR simulation completed in ${recovery_time} seconds"

# 8. Generate comprehensive report
cat > /tmp/quarterly-dr-report.txt << EOL
Quarterly Disaster Recovery Simulation Report
=============================================
Date: $(date)
Test Duration: ${recovery_time} seconds ($(echo "scale=2; $recovery_time/60" | bc) minutes)
Target RTO: 45 minutes
Target RPO: 24 hours

Test Results:
- Infrastructure rebuild: PASS
- Backup restoration: PASS
- Service startup: PASS
- Data validation: PASS
- SSL certificate: PASS
- User authentication: PASS

Recommendations:
- Consider automation improvements if recovery time > 30 minutes
- Review backup retention if data loss > RPO target
- Update documentation based on lessons learned

Next quarterly test: $(date -d "+3 months" +%Y-%m-%d)
EOL

mail -s "Quarterly DR Simulation Report - $(date +%Y-%m-%d)" admin@company.com < /tmp/quarterly-dr-report.txt
EOF

chmod +x tools/quarterly-dr-simulation.sh
```

## Business Continuity Planning

### Service Level Agreements (SLA)

#### Availability Targets
- **Monthly Uptime**: 99.5% (3.6 hours downtime allowed)
- **Scheduled Maintenance**: Maximum 2 hours per month
- **Unplanned Downtime**: Maximum 1.6 hours per month
- **Response Time**: 95th percentile under 2 seconds

#### Performance Standards
- **Authentication Response**: < 1 second
- **Vault Sync**: < 5 seconds for typical vault
- **Password Generation**: < 100ms
- **Search Operations**: < 500ms

### Incident Response Team Structure

#### Primary Response Team
- **Incident Commander**: Overall incident management
- **Technical Lead**: System diagnostics and recovery
- **Communications Lead**: User and stakeholder communication
- **Security Lead**: Security assessment and response

#### Escalation Contacts
```bash
# Create emergency contact list
cat > docs/emergency-contacts.md << 'EOF'
# Emergency Contacts

## Primary Response Team
- **Incident Commander**: +1-555-XXXX (24/7)
- **Technical Lead**: +1-555-YYYY (24/7)
- **Communications Lead**: +1-555-ZZZZ (business hours)

## Secondary Contacts
- **Backup Technical**: +1-555-AAAA
- **Management**: +1-555-BBBB
- **Legal/Compliance**: +1-555-CCCC

## External Vendors
- **Cloud Provider**: support.cloud-provider.com
- **DNS Provider**: support.dns-provider.com
- **SSL Certificate**: support.ssl-provider.com

## Emergency Procedures
1. Call Incident Commander first
2. If no response within 15 minutes, call Technical Lead
3. For security incidents, call Security Lead immediately
4. Document all actions in incident log
EOF
```

This disaster recovery guide provides comprehensive procedures for handling various disaster scenarios while maintaining business continuity and data protection for your VaultWarden-OCI-NG deployment.
