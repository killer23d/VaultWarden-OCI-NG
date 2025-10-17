# Operations Runbook

> **🎯 Operations Philosophy**: Comprehensive operational procedures for day-to-day management, incident response, and troubleshooting of VaultWarden-OCI-Minimal deployments.

## 📋 **Operations Overview**

This runbook provides **step-by-step procedures** for all operational scenarios encountered in managing VaultWarden-OCI-Minimal:

```bash
Operations Categories:
├── Daily Operations (Monitoring, Health Checks)
├── User Management (Account Creation, Access Control)
├── Incident Response (Outages, Security Events)
├── Performance Management (Optimization, Scaling)
├── Change Management (Updates, Configuration Changes)
├── Backup and Recovery (Data Protection, Restoration)
├── Security Operations (Threat Response, Access Review)
└── Compliance and Auditing (Reporting, Documentation)
```

### **Operations Team Roles**
```bash
Operational Responsibilities:

Primary Administrator:
├── System health monitoring
├── Security event response
├── Backup verification
├── User account management
├── Configuration changes
└── Incident coordination

Secondary Administrator (Backup):
├── Emergency access capability
├── Incident response support
├── Knowledge transfer maintenance
├── Documentation updates
└── Compliance reporting

Emergency Contact:
├── After-hours incident escalation
├── Critical security event notification
├── Service outage communication
└── Disaster recovery coordination
```

## 🔄 **Daily Operations**

### **Morning Health Check (5 minutes)**

#### **System Status Verification**
```bash
# Daily morning checklist (recommended: 9:00 AM)
# Execute as root or with appropriate sudo privileges

# Step 1: Overall system health
./tools/monitor.sh --morning-report

# Expected morning report output:
🌅 VaultWarden Morning Health Report - $(date +%Y-%m-%d %H:%M)

Overnight Summary:
✅ Service Uptime: 100% (last 12 hours)
✅ Automated Backups: Completed at 1:00 AM (892KB)
✅ Security Events: 0 incidents
✅ Performance: Within normal parameters

Current Status:
✅ All containers healthy (4/4)
✅ Database responsive (12ms avg)
✅ SSL certificate valid (87 days remaining)
✅ Memory usage: 892MB/4GB (22% - normal)
✅ Disk usage: 15% (plenty of space)

Overnight Automation:
✅ Database backup: Successful (1:00 AM)
✅ Log rotation: Completed (freed 23MB)
✅ Health monitoring: 144/144 checks passed
✅ Security monitoring: No threats detected

Attention Required:
   None - all systems operating normally

Quick Actions Available:
[1] View detailed logs: docker compose logs --tail=50
[2] Check user activity: ./tools/monitor.sh --user-activity  
[3] Security review: ./tools/monitor.sh --security-summary
[4] Performance metrics: ./tools/monitor.sh --performance

Status: 🟢 All systems operational
```

#### **User Activity Review**
```bash
# Step 2: Review user activity and system usage
./tools/monitor.sh --user-activity-summary

# User activity summary:
👥 User Activity Summary (Last 24 Hours)

Login Activity:
📊 Total Logins: 23 sessions
📊 Unique Users: 6/8 users active
📊 Failed Attempts: 1 (4.3% - normal)
📊 Geographic Distribution: Expected locations

Recent Activity:
✅ user1@company.com - 2h ago (mobile app)
✅ user2@company.com - 4h ago (web browser)  
✅ admin@company.com - 8h ago (admin panel)

Inactive Users (>24h):
⚠️  user7@company.com - Last login: 3 days ago
⚠️  user8@company.com - Last login: 5 days ago

Security Observations:
✅ All login attempts from expected IP ranges
✅ Two-factor authentication: 6/8 users (75%)
✅ No suspicious access patterns detected
✅ Session management: Normal duration patterns

Action Items:
   None required - normal usage patterns
```

#### **Alert and Notification Review**
```bash
# Step 3: Check for any alerts or notifications
./tools/monitor.sh --check-alerts

# Alert review:
🔔 Alert and Notification Review

System Alerts (Last 24h):
✅ No critical alerts
✅ No warning conditions
✅ All automated systems functioning normally

Email Notifications Sent:
📧 Daily backup confirmation: Sent to admin@company.com
📧 Weekly security summary: Scheduled for tomorrow

Monitoring Status:
✅ Automated monitoring: Active (every 5 minutes)
✅ Email notifications: Configured and functional
✅ Fail2ban notifications: Active
✅ SSL expiration warnings: Active (30-day threshold)

Notification Settings Review:
✅ Admin email: admin@company.com (verified)
✅ SMTP configuration: Functional
✅ Alert thresholds: Appropriately configured
✅ Escalation procedures: Documented

Status: ✅ All notification systems operational
```

### **Evening Status Check (3 minutes)**

#### **End-of-Day Summary**
```bash
# Evening status check (recommended: 5:00 PM)
./tools/monitor.sh --evening-summary

# Evening summary output:
🌆 End-of-Day Status Summary - $(date +%Y-%m-%d %H:%M)

Daily Performance Summary:
📊 Uptime: 100% (24 hours)
📊 Average Response Time: 89ms
📊 Peak Response Time: 156ms (during backup)
📊 Total Requests: 1,247
📊 Error Rate: 0.08% (1 timeout - normal)

User Activity Today:
👥 Total Active Users: 7/8 (87.5%)
👥 New Vault Items: 12 entries created
👥 Vault Synchronizations: 156 sync operations
👥 Admin Panel Access: 2 sessions

Security Events:
🛡️  Failed Login Attempts: 3 (normal level)
🛡️  Blocked IPs: 0 (no active threats)
🛡️  Fail2ban Activity: 1 SSH attempt blocked
🛡️  Security Scans Detected: 2 (blocked by CloudFlare)

System Health:
✅ All services healthy throughout the day
✅ Database performance: Excellent (11ms avg)
✅ Memory usage peak: 1.1GB (stable)
✅ Storage growth: +34KB (normal)

Tomorrow's Scheduled Tasks:
⏰ 1:00 AM - Automated database backup
⏰ 3:00 AM - CloudFlare IP range update
⏰ 4:00 AM - Log rotation and cleanup

Status: 🟢 Day completed successfully - all systems stable
```

## 👥 **User Management Operations**

### **New User Onboarding**

#### **Create New User Account**
```bash
# Method 1: Via Admin Panel (Recommended)
# 1. Access admin panel: https://vault.yourdomain.com/admin
# 2. Navigate to Users → Create User
# 3. Fill in user details
# 4. Send invitation email

# Method 2: Enable Self-Registration (Temporary)
# Edit configuration to allow signups temporarily
sudo jq '.SIGNUPS_ALLOWED = true' settings.json > temp.json
sudo mv temp.json settings.json
./startup.sh

# User registers at: https://vault.yourdomain.com/register

# Disable self-registration after user creation
sudo jq '.SIGNUPS_ALLOWED = false' settings.json > temp.json  
sudo mv temp.json settings.json
./startup.sh

# Method 3: Invitation System (Preferred for Teams)
# Admin panel → Users → Invite User
# User receives email with registration link
```

#### **User Onboarding Checklist**
```bash
New User Onboarding Process:

Pre-Setup:
- [ ] Verify user email address is valid
- [ ] Confirm user should have access to VaultWarden
- [ ] Determine appropriate organization membership (if applicable)
- [ ] Prepare welcome documentation/training materials

Account Creation:
- [ ] Create user account via admin panel
- [ ] Send invitation email (or provide registration instructions)
- [ ] Verify user receives and can access invitation
- [ ] Confirm successful account creation

Security Setup:
- [ ] Ensure user sets strong master password
- [ ] Verify user enables two-factor authentication
- [ ] Confirm user understands password recovery limitations
- [ ] Provide security best practices documentation

Client Setup:
- [ ] Help user install Bitwarden mobile app
- [ ] Configure mobile app with server URL: https://vault.yourdomain.com
- [ ] Test mobile app login and synchronization
- [ ] Install browser extension (if needed)
- [ ] Test browser extension functionality

Training and Documentation:
- [ ] Provide VaultWarden user guide
- [ ] Explain organization policies (password sharing, etc.)
- [ ] Share emergency contact information
- [ ] Document user account in admin records

# Example user creation log entry:
echo "$(date): Created user account for john.doe@company.com - Organization: Engineering" >> /var/log/user-management.log
```

### **User Account Management**

#### **Disable User Account (Emergency)**
```bash
# Emergency user account disabling procedure
# Use when immediate access revocation is required

# Step 1: Access admin panel
# Navigate to: https://vault.yourdomain.com/admin

# Step 2: Locate user account
# Users → Search for username/email

# Step 3: Disable account
# Click user → Disable User Account

# Step 4: Verify deactivation
# User should receive "Account disabled" error on next login attempt

# Step 5: Document action
echo "$(date): EMERGENCY - Disabled user account: $USERNAME - Reason: $REASON - Admin: $ADMIN_USER" >> /var/log/user-management.log

# Step 6: Follow-up actions (as appropriate)
# - Change shared organization passwords if user had access
# - Review audit logs for user activity
# - Notify relevant stakeholders
# - Plan account reactivation or permanent deletion
```

#### **Reset User Master Password**
```bash
# Master password reset procedure
# Note: Admin cannot reset master passwords directly (security feature)

# Step 1: Inform user that admin cannot reset master password
# This is a security feature of VaultWarden - only user knows master password

# Step 2: Guide user through password reset process
# User must delete account and recreate (data loss) OR
# User must remember password with hints

# Step 3: If user cannot remember password
# Option A: Account deletion and recreation (loses all data)
# Admin panel → Users → Select user → Delete Account

# Option B: Provide password hint system
# Help user think through possible password variations
# Check if user has password written down securely

# Step 4: Document incident
echo "$(date): Password reset requested for $USERNAME - Resolution: $RESOLUTION" >> /var/log/user-management.log

# Step 5: Prevention measures
# Remind all users to:
# - Use password manager for master password recovery
# - Set up password hints that only they understand
# - Consider using passphrases instead of complex passwords
```

## 🚨 **Incident Response Procedures**

### **Service Outage Response**

#### **Complete Service Outage**
```bash
# Incident Response: Complete VaultWarden Outage
# Use this procedure when VaultWarden is completely inaccessible

# Step 1: Immediate Assessment (2 minutes)
START_TIME=$(date)
echo "INCIDENT START: $START_TIME - Complete service outage detected" >> /var/log/incidents.log

# Check basic connectivity
curl -I https://vault.yourdomain.com || echo "Service unreachable"
docker compose ps
systemctl status docker

# Step 2: Quick Recovery Attempt (3 minutes)
# Attempt standard restart
./startup.sh

# If startup fails, check for obvious issues
df -h                    # Disk space
free -h                  # Memory availability  
docker system df         # Docker storage

# Step 3: Detailed Diagnostics (5 minutes)
# Capture system state for analysis
docker compose logs --tail=100 > /tmp/incident-logs-$(date +%Y%m%d_%H%M%S).log
./tools/monitor.sh --emergency > /tmp/incident-diagnostics-$(date +%Y%m%d_%H%M%S).log

# Check system resources
echo "=== SYSTEM STATE ===" >> /tmp/incident-diagnostics-$(date +%Y%m%d_%H%M%S).log
df -h >> /tmp/incident-diagnostics-$(date +%Y%m%d_%H%M%S).log
free -h >> /tmp/incident-diagnostics-$(date +%Y%m%d_%H%M%S).log
ps aux --sort=-%mem | head -10 >> /tmp/incident-diagnostics-$(date +%Y%m%d_%H%M%S).log

# Step 4: Emergency Backup (2 minutes)
# Preserve current state before making changes
./tools/create-full-backup.sh --emergency --incident-backup

# Step 5: Recovery Escalation (10 minutes)
# Attempt progressive recovery steps

# Level 1: Container restart
docker compose restart

# Level 2: Clean container rebuild  
if ! curl -I https://vault.yourdomain.com; then
    docker compose down
    docker system prune -f
    ./startup.sh
fi

# Level 3: Restore from recent backup
if ! curl -I https://vault.yourdomain.com; then
    echo "Escalating to backup restoration" >> /var/log/incidents.log
    ./tools/restore.sh --list-recent
    ./tools/restore.sh /var/lib/*/backups/full/latest.tar.gz
fi

# Step 6: Communication (During recovery)
# Prepare status update for users
SERVICE_STATUS="investigating"  # investigating/identified/monitoring/resolved
ESTIMATED_RESOLUTION="15 minutes"
USER_IMPACT="Complete service unavailability"

# Step 7: Resolution Verification (3 minutes)
if curl -I https://vault.yourdomain.com; then
    RESOLUTION_TIME=$(date)
    echo "INCIDENT RESOLVED: $RESOLUTION_TIME" >> /var/log/incidents.log
    
    # Verify full functionality
    ./tools/monitor.sh --post-incident-check
    
    # Test user login (use test account)
    echo "Service restoration verified at $RESOLUTION_TIME"
else
    echo "ESCALATION REQUIRED: Service still unavailable after standard recovery procedures" >> /var/log/incidents.log
    # Escalate to secondary admin or vendor support
fi
```

#### **Partial Service Degradation**
```bash
# Incident Response: Service Performance Issues
# Use when service is accessible but performing poorly

# Step 1: Performance Assessment
./tools/monitor.sh --performance-incident

# Performance incident analysis:
⚠️  Performance Incident Analysis

Current Performance Metrics:
📊 Average Response Time: 2,456ms (baseline: 89ms)
📊 Database Query Time: 89ms (baseline: 11ms)  
📊 Error Rate: 5.2% (baseline: <0.1%)
📊 Memory Usage: 3.7GB/4GB (93% - high)

Identified Issues:
🔴 High response times (27x baseline)
🔴 Database performance degraded (8x baseline)
🔴 Memory pressure detected
🟡 CPU usage elevated but manageable

# Step 2: Immediate Mitigation
# Clear memory pressure
sync && echo 1 > /proc/sys/vm/drop_caches

# Check for resource-intensive processes
ps aux --sort=-%mem | head -5
ps aux --sort=-%cpu | head -5

# Step 3: Database Performance Check
./tools/sqlite-maintenance.sh --emergency-check

# Step 4: Log Analysis for Root Cause
tail -1000 /var/lib/*/logs/vaultwarden/vaultwarden.log | grep -E "(ERROR|timeout|slow)"
tail -1000 /var/lib/*/logs/caddy/access.log | jq 'select(.duration > 1000)'

# Step 5: Progressive Optimization
# Optimize database if safe to do so
./tools/sqlite-maintenance.sh --quick-optimize

# Restart services if degradation continues
if [[ $(./tools/monitor.sh --response-time-check) -gt 1000 ]]; then
    docker compose restart vaultwarden
fi

# Step 6: Monitor Recovery
./tools/monitor.sh --recovery-monitoring --interval 30 --duration 300
```

### **Security Incident Response**

#### **Suspected Breach or Unauthorized Access**
```bash
# Security Incident Response: Suspected Unauthorized Access
# Use when suspicious activity is detected

# Step 1: Immediate Assessment and Containment
INCIDENT_ID="SEC-$(date +%Y%m%d_%H%M%S)"
echo "SECURITY INCIDENT $INCIDENT_ID: Suspected unauthorized access detected" >> /var/log/security-incidents.log

# Check current active sessions and recent activity
./tools/monitor.sh --security-incident-analysis

# Step 2: Preserve Evidence
# Create forensic backup before making changes
./tools/create-full-backup.sh --forensic --incident-id "$INCIDENT_ID"

# Preserve current logs
cp -r /var/lib/*/logs /tmp/forensic-logs-$INCIDENT_ID
chmod -R 600 /tmp/forensic-logs-$INCIDENT_ID

# Step 3: Immediate Containment (if breach confirmed)
# Block suspicious IPs immediately
SUSPICIOUS_IPS=("1.2.3.4" "5.6.7.8")  # Replace with actual IPs
for ip in "${SUSPICIOUS_IPS[@]}"; do
    sudo fail2ban-client set vaultwarden banip "$ip"
    echo "$INCIDENT_ID: Blocked suspicious IP: $ip" >> /var/log/security-incidents.log
done

# Step 4: Enhanced Monitoring
# Increase monitoring frequency temporarily
./tools/monitor.sh --security-enhanced-monitoring --duration 3600 &

# Step 5: User Account Review
# Check for compromised accounts
./tools/security-audit.sh --incident-mode --check-compromised-accounts

# Step 6: System Integrity Check
# Verify system files haven't been modified
./tools/monitor.sh --integrity-check
find /opt/VaultWarden-OCI-Minimal -name "*.sh" -exec ls -la {} \; | tee /tmp/file-integrity-$INCIDENT_ID.log

# Step 7: Communication Preparation
# Prepare incident communication
INCIDENT_SUMMARY="Suspicious access patterns detected. Investigation in progress."
IMPACT_ASSESSMENT="Precautionary measures activated. User access may be monitored."
ACTIONS_TAKEN="Enhanced monitoring, suspicious IPs blocked, forensic evidence preserved."

# Step 8: Resolution and Follow-up
# After investigation:
# - Force password reset for affected users (if any)
# - Review and strengthen security measures
# - Update incident response procedures
# - Conduct post-incident review
```

## 🔧 **Change Management Operations**

### **Configuration Changes**

#### **Safe Configuration Update Procedure**
```bash
# Configuration Change Procedure
# Use for any changes to settings.json or system configuration

# Step 1: Change Request Documentation
CHANGE_ID="CHG-$(date +%Y%m%d_%H%M%S)"
CHANGE_REQUESTOR="admin@company.com"
CHANGE_DESCRIPTION="Update SMTP configuration for new mail server"
CHANGE_IMPACT="Low - affects email notifications only"
CHANGE_ROLLBACK="Revert to previous SMTP settings"

echo "CHANGE REQUEST $CHANGE_ID: $CHANGE_DESCRIPTION" >> /var/log/changes.log

# Step 2: Pre-Change Backup
./tools/backup-current-config.sh --change-id "$CHANGE_ID"

# Step 3: Configuration Testing (Staging)
# Test configuration syntax
cp settings.json settings.json.new
# Edit settings.json.new with proposed changes
nano settings.json.new

# Validate JSON syntax
jq . settings.json.new

# Step 4: Change Implementation Window
# Implement during maintenance window (if applicable)
MAINTENANCE_START=$(date)
echo "$CHANGE_ID: Maintenance window started at $MAINTENANCE_START" >> /var/log/changes.log

# Apply configuration changes
sudo cp settings.json.new settings.json
sudo chmod 600 settings.json

# Step 5: Configuration Validation
./startup.sh --validate

# Step 6: Service Restart and Testing
./startup.sh

# Verify services are healthy
./tools/monitor.sh --post-change-validation

# Step 7: Functional Testing
# Test affected functionality (e.g., email notifications)
./tools/monitor.sh --test-email

# Step 8: Change Documentation
MAINTENANCE_END=$(date)
echo "$CHANGE_ID: Change completed successfully at $MAINTENANCE_END" >> /var/log/changes.log

# Clean up temporary files
rm settings.json.new
```

#### **Emergency Configuration Rollback**
```bash
# Emergency rollback procedure
# Use when configuration change causes service issues

# Step 1: Immediate Assessment
ROLLBACK_ID="RBK-$(date +%Y%m%d_%H%M%S)"
echo "EMERGENCY ROLLBACK $ROLLBACK_ID: Configuration rollback initiated" >> /var/log/changes.log

# Step 2: Stop Services (if still running)
docker compose down

# Step 3: Restore Previous Configuration
# Find most recent configuration backup
BACKUP_FILE=$(ls -t /var/lib/*/config-backups/settings_*.json | head -1)
echo "Restoring configuration from: $BACKUP_FILE" >> /var/log/changes.log

sudo cp "$BACKUP_FILE" settings.json
sudo chmod 600 settings.json

# Step 4: Validate Restored Configuration
jq . settings.json
./startup.sh --validate

# Step 5: Restart Services
./startup.sh

# Step 6: Verify Rollback Success
./tools/monitor.sh --post-rollback-check

ROLLBACK_END=$(date)
echo "ROLLBACK $ROLLBACK_ID: Completed at $ROLLBACK_END" >> /var/log/changes.log
```

### **System Updates**

#### **Container Update Procedure**
```bash
# Container Update Procedure
# Use for updating VaultWarden and related containers

# Step 1: Update Preparation
UPDATE_ID="UPD-$(date +%Y%m%d_%H%M%S)"
echo "UPDATE $UPDATE_ID: Container update procedure started" >> /var/log/updates.log

# Check current versions
docker compose images > /tmp/versions-before-$UPDATE_ID.txt

# Step 2: Pre-Update Backup
./tools/create-full-backup.sh --pre-update --update-id "$UPDATE_ID"

# Step 3: Download New Images
docker compose pull

# Check what will be updated
docker compose images > /tmp/versions-after-pull-$UPDATE_ID.txt
diff /tmp/versions-before-$UPDATE_ID.txt /tmp/versions-after-pull-$UPDATE_ID.txt

# Step 4: Maintenance Window Communication
# Notify users of upcoming brief maintenance (if applicable)
MAINTENANCE_START=$(date)

# Step 5: Service Update
docker compose down
docker compose up -d

# Step 6: Post-Update Validation
./tools/monitor.sh --post-update-validation

# Verify all services are healthy
docker compose ps
./startup.sh --validate

# Step 7: Functional Testing
# Test critical functions
curl -I https://vault.yourdomain.com
./tools/monitor.sh --functionality-test

# Step 8: Update Documentation
MAINTENANCE_END=$(date)  
echo "UPDATE $UPDATE_ID: Completed successfully at $MAINTENANCE_END" >> /var/log/updates.log

# Record new versions
docker compose images > /var/log/versions-current.txt
```

## 📊 **Performance Management Operations**

### **Performance Monitoring and Optimization**

#### **Performance Baseline Establishment**
```bash
# Establish performance baselines for monitoring
# Run during normal operating conditions

# Step 1: Comprehensive Performance Analysis
./tools/monitor.sh --establish-baseline

# Baseline establishment process:
📊 Performance Baseline Establishment

Current System State:
✅ System load: Normal operating conditions
✅ User activity: Typical usage patterns
✅ No maintenance operations running
✅ All services healthy and stable

Performance Measurements (30-minute sampling):
📈 Response Time:
   - Average: 89ms
   - 95th percentile: 156ms
   - 99th percentile: 245ms
   - Max observed: 312ms

📈 Database Performance:
   - Query time average: 11ms
   - Query time 95th percentile: 23ms
   - Database size: 2.3MB
   - Index efficiency: 99.1%

📈 Resource Utilization:
   - Memory usage: 892MB (22% of 4GB)
   - CPU usage: 2.3% average, 8.7% peak
   - Disk I/O: <5% utilization
   - Network I/O: 15MB in, 890KB out

📈 Throughput:
   - Requests per minute: 24 avg
   - Concurrent users: 3-8 range
   - Data sync operations: 12 per hour

# Baseline saved to: /var/lib/*/monitoring/baseline-YYYYMMDD.json
```

#### **Performance Issue Investigation**
```bash
# Performance issue troubleshooting workflow
# Use when performance degradation is reported

# Step 1: Current Performance Assessment
./tools/monitor.sh --performance-investigation

# Performance investigation results:
🔍 Performance Investigation Analysis

Performance Comparison (Current vs Baseline):
📊 Response Time: 234ms (baseline: 89ms) - 2.6x slower
📊 Database Queries: 45ms (baseline: 11ms) - 4.1x slower  
📊 Memory Usage: 2.1GB (baseline: 892MB) - 2.4x higher
📊 CPU Usage: 12.3% (baseline: 2.3%) - 5.3x higher

# Step 2: Resource Analysis
top -bn1 | head -20
iostat -x 1 5
netstat -tuln | wc -l

# Step 3: Database Performance Analysis
./tools/sqlite-maintenance.sh --performance-analysis

# Step 4: Log Analysis for Bottlenecks
# Look for slow queries, errors, or unusual patterns
grep -E "(slow|timeout|error)" /var/lib/*/logs/vaultwarden/vaultwarden.log | tail -20

# Step 5: Container Resource Check
docker stats --no-stream
docker system df

# Step 6: Optimization Recommendations
./tools/monitor.sh --optimization-recommendations

# Recommended optimizations based on analysis:
💡 Performance Optimization Recommendations

Immediate Actions:
1. Database optimization needed (fragmentation detected)
2. Memory pressure - consider container restart
3. Old log files consuming disk I/O - rotate logs

Medium-term Actions:
1. Monitor if user growth requires resource scaling
2. Consider database indexing optimization
3. Review backup timing to avoid peak usage

Long-term Considerations:
1. Plan for storage expansion (growth trend analysis)
2. Evaluate server specifications for user growth
3. Consider load balancing if usage continues growing
```

## 📋 **Compliance and Audit Operations**

### **Audit Log Management**

#### **Generate Compliance Report**
```bash
# Generate comprehensive compliance report
# Use for regular compliance reviews or audits

# Step 1: Comprehensive Audit Data Collection
AUDIT_ID="AUD-$(date +%Y%m%d_%H%M%S)"
AUDIT_PERIOD_START="2024-09-01"  # Adjust as needed
AUDIT_PERIOD_END="2024-10-01"

./tools/compliance-report.sh --period "$AUDIT_PERIOD_START" "$AUDIT_PERIOD_END" --audit-id "$AUDIT_ID"

# Compliance report generation:
📋 Compliance Report Generation

Report Parameters:
- Report ID: AUD-20241014_173025
- Period: 2024-09-01 to 2024-10-01
- System: VaultWarden-OCI-Minimal
- Administrator: admin@company.com

Access Control Compliance:
✅ User account management: All changes logged
✅ Administrative access: Proper authentication required
✅ Session management: Secure timeouts enforced
✅ Password policies: Enforced (12 char minimum, complexity)

Data Protection Compliance:
✅ Encryption at rest: Client-side by VaultWarden
✅ Encryption in transit: TLS 1.3 enforced
✅ Backup encryption: AES-256-GCM for all backups
✅ Data retention: Policies documented and enforced

System Security Compliance:
✅ Security patching: Up to date (last update: 7 days ago)
✅ Vulnerability management: Regular container updates
✅ Intrusion detection: fail2ban active with logging
✅ Firewall configuration: Minimal attack surface

Audit Logging Compliance:
✅ Authentication events: All logins/failures logged
✅ Administrative actions: All changes documented
✅ System events: Comprehensive logging active
✅ Log retention: 30+ days (configurable)

# Report saved to: /var/lib/*/compliance/audit-report-AUD-20241014_173025.pdf
```

#### **Access Review Procedures**
```bash
# Quarterly access review procedure
# Verify all user access is appropriate and authorized

# Step 1: Generate User Access Report
./tools/access-review.sh --quarterly

# Access review report:
👥 Quarterly Access Review Report

User Account Status (as of $(date +%Y-%m-%d)):
📊 Total Active Accounts: 8
📊 Disabled Accounts: 0  
📊 Admin Accounts: 1 (appropriate)

User Activity Analysis (Last 90 days):
✅ user1@company.com - Active (last login: 2d ago) - Engineering Team
✅ user2@company.com - Active (last login: 1d ago) - Engineering Team  
✅ user3@company.com - Active (last login: 5d ago) - Marketing Team
⚠️  user4@company.com - Inactive (last login: 45d ago) - Former Employee?
✅ user5@company.com - Active (last login: 1d ago) - Sales Team
✅ user6@company.com - Active (last login: 3d ago) - Management
✅ user7@company.com - Active (last login: 7d ago) - IT Team
✅ admin@company.com - Active (last login: 1d ago) - Administrator

Organization Membership Review:
✅ Engineering Org: 2 members (appropriate)
✅ Company-wide Org: 8 members (all employees)

Access Recommendations:
1. Review user4@company.com - possible termination needed
2. All other access appears appropriate
3. Two-factor authentication: 6/8 users (75% - good)

# Step 2: Access Review Actions
# Remove or disable inappropriate access
# Document all access changes
# Update user records as needed
```

This comprehensive operations runbook provides detailed procedures for managing VaultWarden-OCI-Minimal in production environments, ensuring consistent operations and effective incident response."""
