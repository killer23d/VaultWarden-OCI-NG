# Maintenance Guide

> **🎯 Maintenance Philosophy**: Minimal maintenance overhead through automation while providing comprehensive tools for when manual intervention is required.

## 🤖 **Automated Maintenance Overview**

VaultWarden-OCI-Minimal is designed around the **"set and forget"** philosophy with comprehensive automation that handles routine maintenance tasks:

```bash
Automated Maintenance Systems:
├── Health Monitoring (Every 5 minutes)
│   ├── Container health validation
│   ├── Database connectivity checks
│   ├── SSL certificate monitoring
│   ├── Resource usage tracking
│   └── Automatic service recovery
│
├── Data Management (Daily/Weekly)
│   ├── Database backups (Daily 1:00 AM)
│   ├── Full system backups (Sunday 12:00 AM)
│   ├── Database optimization (Weekly)
│   ├── Log rotation and cleanup
│   └── Backup integrity verification
│
├── Security Maintenance (Daily/Continuous)
│   ├── CloudFlare IP updates (Daily 3:00 AM)
│   ├── Security log analysis (Continuous)
│   ├── Intrusion detection (Real-time)
│   ├── SSL certificate renewal (Automatic)
│   └── Failed access pattern monitoring
│
└── System Maintenance (Weekly/Monthly)
    ├── Container image updates (Configurable)
    ├── System package updates (Security only)
    ├── Disk space cleanup (Weekly)
    ├── Performance optimization (Monthly)
    └── Configuration validation (Daily)
```

### **Maintenance Schedule Overview**
```bash
# View current maintenance schedule
crontab -l | grep -E "(backup|monitor|maintenance|cleanup)"

# Expected automated schedule:
# Every 5 minutes: Health monitoring and recovery
*/5 * * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/monitor.sh

# Daily 1:00 AM: Database backup
0 1 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/db-backup.sh

# Daily 3:00 AM: CloudFlare IP updates
0 3 * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/update-cloudflare-ips.sh --quiet

# Daily 4:00 AM: Log cleanup and rotation
0 4 * * * root find /var/lib/*/logs -name "*.log" -size +50M -exec truncate -s 10M {} \\;

# Weekly Sunday 12:00 AM: Full system backup
0 0 * * 0 root cd /opt/VaultWarden-OCI-Minimal && ./tools/create-full-backup.sh

# Weekly Monday 2:00 AM: Database optimization
0 2 * * 1 root cd /opt/VaultWarden-OCI-Minimal && ./tools/sqlite-maintenance.sh -t full
```

## 📅 **Routine Maintenance Tasks**

### **Daily Maintenance (Automated)**

#### **Health Check Verification**
```bash
# Monitor daily health status
./tools/monitor.sh --daily-report

# Expected daily health output:
📊 VaultWarden Daily Health Report - $(date +%Y-%m-%d)

System Health Summary:
✅ Uptime: 99.8% (24h monitoring period)
✅ Average Response Time: 89ms
✅ Container Health: All services healthy (4/4)
✅ Database Performance: Excellent (avg 12ms query time)
✅ Memory Usage: 892MB/4GB (22% - normal)
✅ Disk Usage: 15% (/var/lib/vaultwarden-oci-minimal)

Backup Status:
✅ Last Database Backup: 6 hours ago (success)
✅ Backup Size: 892KB (normal growth)
✅ Backup Integrity: Verified successfully
✅ Storage Available: 47GB (98% free)

Security Events:
✅ Failed Login Attempts: 2 (normal level)
✅ Blocked IPs: 0 (no active threats)
✅ SSL Certificate: Valid (87 days remaining)
✅ Firewall Status: Active (3 rules applied)

Performance Metrics:
✅ CPU Usage: 2.3% average (low)
✅ Network I/O: 15MB/890KB (normal web traffic)
✅ Database Size: 2.3MB (expected growth)
✅ Log Growth: 234KB/day (normal)

Automated Actions Taken:
• Log rotation completed (freed 45MB)
• Database integrity check passed
• CloudFlare IP ranges updated
• Security monitoring: No issues detected

Status: 🟢 System operating optimally
Next Scheduled Maintenance: Full backup (Sunday 12:00 AM)
```

#### **Backup Verification**
```bash
# Daily backup verification (automated via cron)
./tools/restore.sh --verify-recent

# Backup verification process:
🔍 Daily Backup Verification

Recent Backups Analysis:
✅ Database backup (6h ago): 892KB, integrity verified
✅ Database backup (30h ago): 891KB, integrity verified  
✅ Database backup (54h ago): 889KB, integrity verified

Backup Quality Metrics:
✅ Average backup time: 18 seconds
✅ Compression ratio: 71% (excellent)
✅ Encryption verification: All backups secure
✅ Storage growth rate: +28KB/day (sustainable)

Full System Backups:
✅ Weekly backup (3d ago): 1.2MB, verified
✅ Previous backup (10d ago): 1.1MB, verified

Backup System Health:
✅ Backup directory accessible (700 permissions)
✅ Encryption keys secure and accessible
✅ Retention policy active (30 days database, 8 weeks full)
✅ Available storage: 47GB (sufficient for 2+ years)

Issues Found: None
Recommendations: Backup system operating optimally
```

### **Weekly Maintenance (Mostly Automated)**

#### **Database Optimization**
```bash
# Weekly database optimization (automated Monday 2:00 AM)
./tools/sqlite-maintenance.sh --full

# Database maintenance process:
🔧 Weekly Database Optimization

Pre-Optimization Analysis:
📊 Database size: 2.3MB
📊 Table count: 12 tables
📊 Index efficiency: 98.2%
📊 Query performance: 12ms average
📊 Fragmentation level: 2.1%

Optimization Operations:
✅ VACUUM operation: Completed (freed 45KB)
✅ ANALYZE statistics: Updated for all tables
✅ Index optimization: All indexes optimal
✅ Integrity check: No corruption detected
✅ WAL checkpoint: Completed successfully

Post-Optimization Results:
📊 Database size: 2.25MB (2.2% reduction)
📊 Query performance: 11ms average (8% improvement)
📊 Index efficiency: 99.1% (improved)
📊 Fragmentation: 0.8% (significantly reduced)

Performance Impact:
• Service downtime: 0 seconds (online operation)
• Query performance improved by 8%
• Storage optimization: 45KB reclaimed
• Index access speed improved

Status: ✅ Database optimization completed successfully
Next optimization: Scheduled for next Monday 2:00 AM
```

#### **Security Review and Updates**
```bash
# Weekly security maintenance check
./tools/monitor.sh --security-weekly

# Security review output:
🛡️ Weekly Security Review

Authentication Security:
✅ Failed login attempts (7 days): 14 total
✅ Geographic distribution: Normal patterns
✅ No brute force attacks detected
✅ Admin panel access: 3 legitimate sessions

Network Security:
✅ Firewall status: Active with proper rules
✅ Fail2ban activity: 2 IPs blocked (spam/bots)
✅ SSL certificate: Valid, auto-renewal working
✅ CloudFlare protection: 127 threats blocked at edge

System Security:
✅ Container security: No vulnerabilities detected
✅ File permissions: All sensitive files secure (600/700)
✅ Log analysis: No security anomalies found
✅ Update status: All security updates applied

Compliance Status:
✅ Audit logs: 7 days retention maintained
✅ Access controls: Properly configured
✅ Data encryption: At rest and in transit
✅ Backup security: All backups encrypted

Recommendations:
• Continue current security posture (excellent)
• Consider rotating admin token (last changed 45d ago)
• Review user access patterns monthly

Security Score: 96/100 (Excellent)
```

### **Monthly Maintenance (Manual Review Recommended)**

#### **Capacity Planning and Performance Review**
```bash
# Monthly capacity and performance analysis
./tools/monitor.sh --monthly-analysis

# Monthly performance report:
📈 Monthly Performance and Capacity Analysis

Growth Analysis (30 days):
📊 User Growth: +2 users (now 8 total)
📊 Vault Items: +89 entries (now 1,336 total)
📊 Database Growth: +156KB (2.4MB total)
📊 Storage Growth: +234MB (now 2.1GB used)
📊 Attachment Growth: +3 files, 890KB

Performance Trends:
📊 Average Response Time: 89ms (stable, <5ms variation)
📊 Peak Response Time: 245ms (during backup operations)
📊 Database Query Time: 11ms average (improved from 12ms)
📊 Memory Usage Peak: 1.2GB (well within 4GB limit)
📊 CPU Usage Average: 2.3% (very low, stable)

Capacity Projections (12 months):
📊 Projected Users: ~15 users (75% of recommended 20-user limit)
📊 Projected Database Size: ~15MB (excellent)
📊 Projected Storage Need: ~8GB (within current allocation)
📊 Resource Requirements: Current config sufficient

Performance Recommendations:
✅ Current configuration optimal for projected growth
✅ No immediate scaling required
⚠️  Consider monitoring if user count exceeds 12
⚠️  Plan storage expansion if growth rate doubles

Capacity Status: 🟢 Excellent headroom for growth
Infrastructure Changes Needed: None for next 12 months
```

#### **Security Audit and Access Review**
```bash
# Monthly security audit
./tools/security-audit.sh --comprehensive

# Security audit report:
🔒 Monthly Comprehensive Security Audit

Access Control Review:
👤 Active Users: 8 accounts
   - Last login activity: All within 14 days (active users)
   - Inactive accounts: None (all users active)
   - Admin access: 1 account (appropriate)
   - Organization memberships: Properly configured

Authentication Security:
🔐 Password Policies: Enforced (min 12 chars, complexity required)
🔐 Two-Factor Auth: 6/8 users enabled (75% adoption - good)
🔐 Admin Token: Last rotated 45 days ago (consider rotation)
🔐 Session Management: Secure timeouts configured

Infrastructure Security:
🛡️  Firewall Configuration: Optimal (minimal attack surface)
🛡️  Intrusion Detection: Active, 2 IPs blocked this month
🛡️  SSL Configuration: A+ rating maintained
🛡️  Container Security: No vulnerabilities in current images

Data Protection:
💾 Backup Encryption: All backups encrypted (AES-256)
💾 Database Encryption: VaultWarden handles client-side encryption
💾 Transport Security: TLS 1.3 enforced
💾 At-Rest Security: File permissions secure

Compliance Status:
📋 Audit Logs: 30-day retention maintained
📋 Access Logging: All authentication events logged
📋 Change Management: All configuration changes documented
📋 Incident Response: Procedures documented and tested

Security Recommendations:
1. Rotate admin token (45 days since last rotation)
2. Encourage remaining 2 users to enable 2FA
3. Consider implementing IP restrictions if feasible
4. Review and update emergency contact information

Overall Security Posture: 94/100 (Excellent)
```

## 🔧 **Manual Maintenance Procedures**

### **System Updates and Upgrades**

#### **Container Image Updates**
```bash
# Manual container updates (or configure Watchtower for automation)
# Check for available updates
docker compose pull

# View current and available versions
docker compose images

# Update containers (with backup first)
./tools/create-full-backup.sh --pre-update

# Stop services, update, and restart
docker compose down
docker compose pull
./startup.sh

# Verify update success
docker compose ps
./tools/monitor.sh --post-update-check

# Expected update verification:
🔄 Post-Update Verification

Container Updates:
✅ VaultWarden: Updated from 1.30.1 to 1.30.3
✅ Caddy: Updated from 2.7.4 to 2.7.6
✅ Fail2ban: No update available (current)
✅ Watchtower: Updated from 1.5.0 to 1.5.1

Service Health:
✅ All containers healthy after update
✅ Database connectivity confirmed
✅ SSL certificates still valid
✅ Admin panel accessible

Functionality Testing:
✅ User login successful
✅ Vault sync working properly
✅ Admin functions operational
✅ Backup system functional

Update Summary:
- Total update time: 3 minutes 45 seconds
- Service downtime: 45 seconds
- Issues encountered: None
- Rollback capability: Available (pre-update backup)

Status: ✅ Update completed successfully
```

#### **System Package Updates**
```bash
# System package maintenance (security updates only for stability)
# Check for available updates
sudo apt list --upgradable

# Security updates only (recommended)
sudo apt update
sudo apt upgrade -y --with-new-pkgs -o Dpkg::Options::="--force-confdef"

# Full system update (use with caution, test first)
# sudo apt full-upgrade -y

# Clean package cache
sudo apt autoremove -y
sudo apt autoclean

# Verify system stability after updates
./startup.sh --validate
./tools/monitor.sh --system-check
```

### **Configuration Management**

#### **Configuration Updates and Changes**
```bash
# Safe configuration change procedure

# 1. Create configuration backup
./tools/backup-current-config.sh

# 2. Edit configuration
sudo nano settings.json

# Example configuration changes:
{
  "SIGNUPS_ALLOWED": false,           # Disable new registrations
  "INVITATION_EXPIRATION_HOURS": 72,  # 3-day invite expiration
  "WEBSOCKET_ENABLED": true,          # Enable real-time sync
  "LOG_LEVEL": "info"                 # Increase logging detail
}

# 3. Validate configuration syntax
jq . settings.json

# 4. Test configuration loading
./startup.sh --validate

# 5. Apply configuration (restart services)
./startup.sh

# 6. Verify changes applied correctly
./tools/monitor.sh --config-check

# 7. Test functionality
curl -I https://vault.yourdomain.com
# Test user login and admin panel access
```

#### **SSL Certificate Management**
```bash
# SSL certificate maintenance (usually automatic)

# Check certificate status
./tools/monitor.sh --certificate-status

# Certificate status report:
🔐 SSL Certificate Status

Current Certificates:
✅ Primary: vault.yourdomain.com
   - Issuer: Let's Encrypt Authority X3
   - Valid from: 2024-10-01 14:23:45 UTC
   - Valid until: 2024-12-30 14:23:45 UTC (87 days remaining)
   - Auto-renewal: Enabled (Caddy automatic)

Certificate Chain:
✅ Root CA: DST Root CA X3 (trusted)
✅ Intermediate: Let's Encrypt Authority X3
✅ End Entity: vault.yourdomain.com

Security Analysis:
✅ SSL Labs Rating: A+
✅ Perfect Forward Secrecy: Enabled
✅ HSTS Header: Enabled (max-age: 31536000)
✅ Certificate Transparency: Logged

Auto-Renewal Status:
✅ Caddy auto-renewal: Active
✅ Next renewal check: ~60 days before expiration
✅ Renewal history: 3 successful renewals

Manual renewal (if needed):
docker compose exec caddy caddy reload
```

#### **User and Access Management**
```bash
# User management procedures

# Add new user (via admin panel or command line)
# Via admin panel: https://vault.yourdomain.com/admin → Users

# Disable user account (emergency)
# Access admin panel → Users → Select user → Disable

# Reset user's master password (user must do this themselves)
# Admin panel → Users → Select user → Send password reset email

# Review user activity
./tools/monitor.sh --user-activity

# User activity report:
👥 User Activity Summary (Last 30 days)

Active Users (8 total):
✅ user1@example.com - Last login: 2 hours ago (active)
✅ user2@example.com - Last login: 1 day ago (active)
✅ user3@example.com - Last login: 3 days ago (active)
✅ admin@example.com - Last login: 5 days ago (normal)

Inactive Users (0):
   None (all users active within 14 days)

Login Statistics:
📊 Total logins: 247 (average: 8.2/day)
📊 Failed attempts: 12 (4.9% failure rate - normal)
📊 Geographic distribution: Normal patterns
📊 Device variety: Mobile (60%), Desktop (40%)

Security Events:
✅ No suspicious activity detected
✅ All login attempts from expected locations
✅ Two-factor authentication: 6/8 users (75%)

Recommendations:
• Encourage 2FA adoption for remaining 2 users
• All users actively using the system (good adoption)
```

### **Storage and Performance Maintenance**

#### **Storage Cleanup and Optimization**
```bash
# Storage maintenance and cleanup

# Analyze storage usage
./tools/monitor.sh --storage-analysis

# Storage analysis report:
💾 Storage Analysis and Cleanup

Current Usage:
📊 Total Allocated: 50GB
📊 Used Space: 2.1GB (4.2%)
📊 Available Space: 47.9GB (95.8%)

Usage Breakdown:
📁 VaultWarden Data: 2.3MB
   ├── Database: 2.3MB
   ├── Attachments: 890KB
   └── Sends: 124KB

📁 Logs: 234MB
   ├── Caddy Access: 89MB
   ├── VaultWarden: 67MB
   ├── Fail2ban: 23MB
   └── System: 55MB

📁 Backups: 45MB
   ├── Database Backups: 25MB (30 files)
   └── Full Backups: 20MB (8 files)

📁 Docker Images: 1.2GB
   ├── VaultWarden: 456MB
   ├── Caddy: 89MB
   ├── Fail2ban: 234MB
   └── System: 421MB

Cleanup Opportunities:
✅ Old log files: Can clean 89MB (>30 days old)
✅ Docker cache: Can clean 234MB (unused layers)
✅ Temp files: Can clean 12MB

# Perform cleanup
./tools/storage-cleanup.sh --safe

# Safe cleanup process:
🧹 Safe Storage Cleanup

Cleanup Operations:
✅ Rotated oversized log files (freed 45MB)
✅ Cleaned Docker system cache (freed 234MB)
✅ Removed temporary files (freed 12MB)
✅ Optimized database storage (freed 2MB)

Preservation:
✅ All backups preserved (within retention policy)
✅ Recent logs preserved (last 7 days)
✅ Active Docker images preserved
✅ Configuration files unchanged

Results:
📊 Storage freed: 293MB
📊 Current usage: 1.8GB (3.6%)
📊 Available space: 48.2GB (96.4%)

Status: ✅ Cleanup completed successfully
```

#### **Performance Optimization**
```bash
# Performance tuning and optimization

# Analyze current performance
./tools/monitor.sh --performance-analysis

# Performance optimization report:
⚡ Performance Analysis and Optimization

Current Performance Metrics:
📊 Average Response Time: 89ms
📊 Database Query Time: 11ms
📊 Memory Usage: 892MB/4GB (22%)
📊 CPU Usage: 2.3% average
📊 Disk I/O: Low (< 5% utilization)

Performance Bottlenecks:
✅ No bottlenecks identified
✅ All metrics within optimal ranges
✅ Resource utilization healthy

Optimization Opportunities:
💡 Database indexing: All indexes optimal
💡 Memory allocation: Well-balanced
💡 CPU scheduling: Efficient
💡 Network optimization: Properly configured

Recommendations:
✅ Current configuration optimal for workload
✅ No immediate optimization needed
⚠️  Monitor if user count grows beyond 12
⚠️  Consider SSD upgrade if database >50MB

Performance Trend (30 days):
📈 Response time: Stable (±5ms variation)
📈 Memory usage: Steady growth (+12MB/month)
📈 CPU usage: Stable (no performance degradation)

Status: 🟢 Performance excellent, no optimization needed
```

## 📋 **Maintenance Schedules and Checklists**

### **Weekly Maintenance Checklist**
```bash
Weekly Maintenance Tasks (15-20 minutes):

System Health Review:
- [ ] Review weekly health reports (./tools/monitor.sh --weekly)
- [ ] Check backup status and verify recent backups
- [ ] Review security events and fail2ban activity
- [ ] Monitor resource usage trends

Configuration Review:
- [ ] Verify all services healthy (docker compose ps)
- [ ] Check SSL certificate expiration (>30 days remaining)
- [ ] Review log files for any anomalies
- [ ] Verify automated maintenance is running

User Management:
- [ ] Review user activity and inactive accounts
- [ ] Check for new user registration requests
- [ ] Verify admin access is working properly
- [ ] Review two-factor authentication adoption

Security Tasks:
- [ ] Review fail2ban reports and blocked IPs
- [ ] Check for any unusual access patterns
- [ ] Verify firewall rules are appropriate
- [ ] Review CloudFlare security events (if used)

Documentation:
- [ ] Update maintenance log with any issues found
- [ ] Document any configuration changes made
- [ ] Review and update emergency contact info if needed
```

### **Monthly Maintenance Checklist**
```bash
Monthly Maintenance Tasks (30-45 minutes):

Performance Review:
- [ ] Run comprehensive performance analysis
- [ ] Review capacity planning projections
- [ ] Analyze response time trends
- [ ] Check resource utilization growth

Security Audit:
- [ ] Conduct comprehensive security audit
- [ ] Review user access and permissions
- [ ] Consider admin token rotation (if >60 days old)
- [ ] Update security contact information

System Updates:
- [ ] Check for VaultWarden updates
- [ ] Review Docker image updates
- [ ] Apply system security updates
- [ ] Test update procedures in staging (if available)

Backup and Recovery:
- [ ] Test backup restoration procedure
- [ ] Verify off-site backup synchronization (if configured)
- [ ] Review backup retention policies
- [ ] Test disaster recovery procedures

Documentation and Compliance:
- [ ] Update system documentation
- [ ] Review incident response procedures
- [ ] Audit configuration changes
- [ ] Update capacity planning documentation
```

### **Quarterly Maintenance Checklist**
```bash
Quarterly Maintenance Tasks (60-90 minutes):

Strategic Review:
- [ ] Review overall system performance and growth
- [ ] Assess user adoption and feedback
- [ ] Plan for capacity upgrades if needed
- [ ] Review security posture and improvements

Major Updates:
- [ ] Plan and execute major system updates
- [ ] Review and update emergency procedures
- [ ] Test disaster recovery scenarios
- [ ] Update monitoring and alerting thresholds

Security Enhancement:
- [ ] Conduct penetration testing (or security scan)
- [ ] Review and rotate all secrets and tokens
- [ ] Update security policies and procedures
- [ ] Review compliance requirements

Infrastructure Planning:
- [ ] Assess infrastructure needs for next quarter
- [ ] Plan for scaling if user growth requires it
- [ ] Review backup and storage requirements
- [ ] Update business continuity plans
```

## 🚨 **Emergency Maintenance Procedures**

### **Critical Issue Response**

#### **Service Outage Response**
```bash
# Immediate response for complete service outage

# Step 1: Assess the situation
docker compose ps                    # Check container status
./tools/monitor.sh --emergency      # Emergency diagnostic
systemctl status docker             # Check Docker daemon

# Step 2: Immediate recovery attempts
./startup.sh                        # Attempt normal startup
docker compose restart              # Force container restart
systemctl restart docker            # Restart Docker if needed

# Step 3: Emergency backup (preserve current state)
./tools/create-full-backup.sh --emergency

# Step 4: Detailed diagnostics
docker compose logs --tail=100      # Recent logs
./tools/monitor.sh --verbose        # Comprehensive check
df -h && free -h                    # Resource check

# Step 5: Recovery escalation
./tools/restore.sh --list-recent    # Available backups
./tools/restore.sh /path/to/recent/backup  # Restore if needed

# Step 6: Communication
# Notify users of service status
# Document incident details
# Plan post-incident review
```

#### **Security Incident Response**
```bash
# Response to suspected security breach

# Step 1: Immediate containment
docker compose down                  # Stop services immediately
sudo ufw deny in                    # Block all incoming traffic

# Step 2: Preserve evidence
./tools/create-full-backup.sh --forensic  # Forensic backup
sudo cp -r /var/lib/*/logs /tmp/incident-logs-$(date +%Y%m%d)

# Step 3: Assess damage
./tools/security-audit.sh --incident-mode
grep -r "suspicious_pattern" /var/lib/*/logs/
sudo fail2ban-client status          # Check blocked IPs

# Step 4: Clean recovery
./tools/restore.sh --verify /path/to/clean/backup  # Restore known-good state
./startup.sh --security-hardened     # Restart with enhanced security

# Step 5: Post-incident hardening
# Change all passwords and tokens
# Review and strengthen security measures
# Update incident response procedures
# Document lessons learned
```

### **Data Recovery Procedures**

#### **Database Corruption Recovery**
```bash
# Response to database corruption

# Step 1: Stop VaultWarden to prevent further damage
docker compose stop vaultwarden

# Step 2: Assess database integrity
./tools/sqlite-maintenance.sh --integrity-check
sqlite3 /var/lib/*/data/bwdata/db.sqlite3 "PRAGMA integrity_check;"

# Step 3: Attempt repair (if corruption is minor)
./tools/sqlite-maintenance.sh --repair

# Step 4: Restore from backup (if repair fails)
./tools/restore.sh --database-only /path/to/recent/database/backup

# Step 5: Verify recovery
./tools/sqlite-maintenance.sh --verify-repair
./startup.sh --validate

# Step 6: Restart services and monitor
./startup.sh
./tools/monitor.sh --post-recovery-monitoring
```

This comprehensive maintenance guide ensures your VaultWarden-OCI-Minimal deployment continues operating smoothly with minimal administrative overhead while providing detailed procedures for when manual intervention is required."""
