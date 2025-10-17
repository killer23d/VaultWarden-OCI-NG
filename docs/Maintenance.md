# Maintenance Guide

This guide provides comprehensive information for ongoing maintenance of the VaultWarden-OCI-NG stack, including routine tasks, monitoring procedures, and system optimization.

## Maintenance Philosophy

### Proactive Maintenance
The VaultWarden-OCI-NG stack is designed with "set and forget" principles, but proactive maintenance ensures optimal performance, security, and reliability:
- **Automated Tasks**: Most maintenance is handled automatically
- **Scheduled Reviews**: Regular system health assessments
- **Preventive Actions**: Address issues before they impact users
- **Documentation**: Track changes and maintenance activities

## Automated Maintenance Tasks

### Cron Job Schedule
The `init-setup.sh` script automatically configures these maintenance tasks:

```bash
# View current maintenance schedule
crontab -l | grep -E "(backup|monitor|maintenance)"

# Expected schedule:
# 0 2 * * * /path/to/tools/db-backup.sh >/dev/null 2>&1
# 0 3 * * 0 /path/to/tools/create-full-backup.sh >/dev/null 2>&1
# */5 * * * * /path/to/tools/monitor.sh --quiet >/dev/null 2>&1
# 0 1 * * 6 /path/to/tools/sqlite-maintenance.sh --full >/dev/null 2>&1
```

#### Daily Tasks (2:00 AM)
- **Database Backup**: Encrypted SQLite database backup
- **Log Rotation**: Cleanup of old log files
- **Security Monitoring**: Failed authentication analysis

#### Weekly Tasks
- **Full System Backup** (Sunday 3:00 AM): Complete system backup including configuration
- **Database Optimization** (Saturday 1:00 AM): SQLite VACUUM and integrity checks
- **SSL Certificate Check**: Certificate expiration monitoring

#### Every 5 Minutes
- **Health Monitoring**: Service status and automatic recovery
- **Resource Monitoring**: Disk space, memory, and CPU usage
- **Security Monitoring**: Fail2ban status and intrusion attempts

### Watchtower Automated Updates
Container updates are handled automatically:

```bash
# Check Watchtower configuration
docker compose logs watchtower

# View update schedule
# Default: First Monday of each month at 4:00 AM
```

## Manual Maintenance Tasks

### Daily Maintenance Checks

#### System Health Verification
```bash
# Comprehensive health check
./tools/check-health.sh

# Expected output indicators:
# ✅ All services healthy
# ✅ SSL certificate valid
# ✅ Database integrity confirmed
# ✅ Backup system operational
# ✅ Security systems active
```

#### Service Status Review
```bash
# Quick service status
docker compose ps

# Resource utilization
docker stats --no-stream

# Recent log review
docker compose logs --tail=50 vaultwarden | grep -E "(error|warn)"
```

### Weekly Maintenance Tasks

#### Backup Verification
```bash
# List recent backups
ls -la $PROJECT_STATE_DIR/backups/ | tail -10

# Verify backup integrity
./tools/restore.sh --verify $PROJECT_STATE_DIR/backups/db-backup-latest.sqlite3.enc

# Test restore process (dry run)
./tools/restore.sh --dry-run $PROJECT_STATE_DIR/backups/backup-full-latest.tar.gz.enc
```

#### Security Review
```bash
# Review fail2ban activity
sudo fail2ban-client status
sudo fail2ban-client get vaultwarden-auth banip

# Check authentication logs
tail -100 $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log | grep -i auth

# SSL security verification
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates

# External SSL test (quarterly)
# Visit: https://www.ssllabs.com/ssltest/
# Target: A+ rating
```

#### Performance Review
```bash
# Database performance metrics
./tools/sqlite-maintenance.sh --stats

# System resource trends
df -h  # Disk usage should be stable
free -h  # Memory usage patterns
uptime  # System load averages
```

### Monthly Maintenance Tasks

#### Configuration Review
```bash
# Review current configuration
./startup.sh --validate

# Check for configuration drift
git status
git diff HEAD

# Review user growth and resource needs
echo "SELECT COUNT(*) as user_count FROM users;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3
```

#### Security Updates
```bash
# Check system packages for updates
apt list --upgradable

# Apply security updates
sudo apt update && sudo apt upgrade -y

# Verify service stability after updates
./tools/check-health.sh
```

#### Log Analysis
```bash
# Analyze authentication patterns
awk '/login_attempt/ {print $1, $2, $3}' $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log | sort | uniq -c | sort -nr

# Review access patterns
awk '{print $1}' $PROJECT_STATE_DIR/logs/caddy/access.log | sort | uniq -c | sort -nr | head -20

# Check for unusual activity
grep -E "(404|500|fail)" $PROJECT_STATE_DIR/logs/caddy/access.log | tail -20
```

### Quarterly Maintenance Tasks

#### Comprehensive Security Audit
```bash
# Review all security settings
./tools/check-health.sh --verbose

# Update security configurations
sudo ufw --force reset
# Re-run security hardening
sudo ./tools/init-setup.sh --security-only

# Review and rotate secrets
sudo ./tools/edit-secrets.sh --view
# Consider rotating admin_token and other sensitive values
```

#### Capacity Planning Review
```bash
# Database growth analysis
du -sh $PROJECT_STATE_DIR/data/bwdata/
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "SELECT 
  COUNT(*) as total_items,
  COUNT(DISTINCT user_uuid) as active_users,
  (COUNT(*) * 1.0 / COUNT(DISTINCT user_uuid)) as avg_items_per_user
FROM cipher;"

# Resource utilization trends
docker stats --no-stream --format "table {{.Name}}	{{.CPUPerc}}	{{.MemUsage}}	{{.NetIO}}	{{.BlockIO}}"

# Storage growth projection
find $PROJECT_STATE_DIR -type f -name "*.log" -exec ls -la {} \; | awk '{sum += $5} END {print "Log files total:", sum/1024/1024 "MB"}'
```

#### Backup Strategy Review
```bash
# Backup retention analysis
find $PROJECT_STATE_DIR/backups -name "*.enc" -type f -printf '%T@ %p
' | sort -n | tail -20

# Storage usage by backups
du -sh $PROJECT_STATE_DIR/backups/

# Test restoration procedure
# (Use test environment or carefully planned maintenance window)
./tools/restore.sh --verify /path/to/older/backup
```

## Database Maintenance

### SQLite Optimization

#### Regular Optimization Tasks
```bash
# Full database maintenance (automated weekly)
./tools/sqlite-maintenance.sh --full

# Check database integrity
./tools/sqlite-maintenance.sh --check

# View database statistics
./tools/sqlite-maintenance.sh --stats
```

#### Manual Database Optimization
```bash
# Access database directly (read-only)
sqlite3 -readonly $PROJECT_STATE_DIR/data/bwdata/db.sqlite3

# Useful queries:
.tables                    # List all tables
.schema users             # View table structure
SELECT COUNT(*) FROM users;  # Count users
SELECT COUNT(*) FROM cipher; # Count vault items

# Performance analysis queries:
PRAGMA integrity_check;
PRAGMA foreign_key_check;
PRAGMA table_info(users);
```

#### Database Migration Considerations
For growth beyond 50 users, consider PostgreSQL migration:

```bash
# Current database size assessment
du -sh $PROJECT_STATE_DIR/data/bwdata/db.sqlite3

# User and item counts
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "
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
  'Collections', COUNT(*) FROM collections;"
```

## System Performance Tuning

### Container Resource Optimization

#### Memory Tuning
```bash
# Current memory usage analysis
docker stats --no-stream --format "table {{.Name}}	{{.MemUsage}}	{{.MemPerc}}"

# Adjust memory limits based on usage patterns
# Edit environment variables or docker-compose.yml
export VAULTWARDEN_MEMORY_LIMIT=3G  # Increase for >25 users
export CADDY_MEMORY_LIMIT=512M      # Increase for high traffic
export FAIL2BAN_MEMORY_LIMIT=256M   # Usually sufficient

# Apply new limits
./startup.sh
```

#### Storage Performance
```bash
# I/O performance monitoring
iostat -x 1 5

# Database file access patterns
sudo lsof $PROJECT_STATE_DIR/data/bwdata/db.sqlite3

# Consider SSD upgrade if:
# - High I/O wait times (>20%)
# - Frequent disk access patterns
# - Slow query response times
```

### Network Performance Optimization

#### CloudFlare Configuration Review
```bash
# Update CloudFlare IP ranges
./tools/update-cloudflare-ips.sh

# Verify real IP detection
tail -10 $PROJECT_STATE_DIR/logs/caddy/access.log
# Should show real client IPs, not CloudFlare IPs
```

#### SSL Performance
```bash
# Check current SSL configuration
echo | openssl s_client -connect your-domain.com:443 -cipher 'ALL' 2>/dev/null | grep -E "(Protocol|Cipher)"

# Verify HTTP/2 support
curl -I --http2 https://your-domain.com

# Monitor SSL handshake performance
time openssl s_client -connect your-domain.com:443 </dev/null
```

## Log Management

### Log Rotation Configuration
```bash
# Check current log sizes
du -sh $PROJECT_STATE_DIR/logs/*/

# Configure log rotation for large deployments
cat > /tmp/vaultwarden-logs << EOF
$PROJECT_STATE_DIR/logs/*/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

sudo cp /tmp/vaultwarden-logs /etc/logrotate.d/vaultwarden
sudo logrotate -d /etc/logrotate.d/vaultwarden  # Test configuration
```

### Log Analysis Automation
```bash
# Create log analysis script
cat > tools/log-analysis.sh << 'EOF'
#!/bin/bash
LOGS_DIR="$PROJECT_STATE_DIR/logs"

echo "=== VaultWarden Log Analysis $(date) ==="
echo "Authentication attempts (last 24h):"
find $LOGS_DIR -name "*.log" -mtime -1 -exec grep -h "login_attempt" {} \; | wc -l

echo "Failed authentications (last 24h):"
find $LOGS_DIR -name "*.log" -mtime -1 -exec grep -h "Invalid password" {} \; | wc -l

echo "Top accessing IPs:"
awk '{print $1}' $LOGS_DIR/caddy/access.log | sort | uniq -c | sort -nr | head -10

echo "HTTP status code distribution:"
awk '{print $9}' $LOGS_DIR/caddy/access.log | sort | uniq -c | sort -nr
EOF

chmod +x tools/log-analysis.sh

# Run weekly log analysis
# Add to cron: 0 6 * * 1 /path/to/tools/log-analysis.sh | mail -s "VaultWarden Weekly Log Report" admin@domain.com
```

## Disaster Recovery Testing

### Regular Recovery Testing
```bash
# Monthly recovery test (use test environment)
# 1. Create test backup
./tools/create-full-backup.sh --output-dir /tmp/test-backup/

# 2. Simulate disaster (in test environment only)
docker compose down
rm -rf $PROJECT_STATE_DIR/data/bwdata/*  # TEST ENVIRONMENT ONLY!

# 3. Test recovery procedure
./tools/restore.sh /tmp/test-backup/backup-full-*.tar.gz.enc

# 4. Verify recovery
./startup.sh
./tools/check-health.sh

# 5. Document recovery time and any issues
```

### Recovery Time Objectives (RTO) Testing
```bash
# Time complete recovery process
start_time=$(date +%s)

# Perform recovery steps...
./tools/restore.sh /path/to/backup
./startup.sh
./tools/check-health.sh

end_time=$(date +%s)
recovery_time=$((end_time - start_time))
echo "Total recovery time: ${recovery_time} seconds"

# Target RTO: < 30 minutes for database recovery
#            < 60 minutes for full system recovery
```

## Security Maintenance

### Regular Security Tasks

#### Certificate Management
```bash
# Check certificate expiration
./tools/check-health.sh | grep -i certificate

# Manual certificate renewal (if needed)
docker compose exec caddy caddy reload

# Verify certificate chain
echo | openssl s_client -connect your-domain.com:443 -showcerts 2>/dev/null | openssl x509 -noout -text | grep -A 2 "Validity"
```

#### Fail2ban Monitoring
```bash
# Review fail2ban effectiveness
sudo fail2ban-client status vaultwarden-auth
sudo fail2ban-client get vaultwarden-auth stats

# Check ban statistics
sudo awk '/Ban/ {print $1, $2, $3, $6}' /var/log/fail2ban.log | tail -20

# Optimize fail2ban rules based on attack patterns
# Edit /fail2ban/jail.local as needed
```

#### Secret Rotation Schedule
- **Admin Token**: Rotate annually or after suspected compromise
- **SMTP Password**: Rotate when email provider requires
- **Backup Passphrase**: Rotate annually, ensure old backups remain accessible
- **API Tokens**: Rotate based on provider recommendations

### Security Monitoring Enhancement
```bash
# Install additional security monitoring (optional)
sudo apt install aide rkhunter chkrootkit

# Configure AIDE for file integrity monitoring
sudo aideinit
sudo aide --check

# Add to weekly cron
echo "0 3 * * 0 /usr/bin/aide --check | mail -s 'AIDE Report' admin@domain.com" | sudo crontab -
```

## Maintenance Documentation

### Change Management
Maintain a maintenance log:

```bash
# Create maintenance log entry
cat >> maintenance.log << EOF
Date: $(date)
Task: [Description of maintenance performed]
Duration: [Time taken]
Issues: [Any problems encountered]
Resolution: [How issues were resolved]
Next Action: [Any follow-up required]
---
EOF
```

### Maintenance Checklist Template
```markdown
## Weekly Maintenance Checklist
- [ ] Run health check: `./tools/check-health.sh`
- [ ] Review service status: `docker compose ps`
- [ ] Check disk usage: `df -h`
- [ ] Verify recent backups: `ls -la $PROJECT_STATE_DIR/backups/ | tail -5`
- [ ] Review fail2ban activity: `sudo fail2ban-client status`
- [ ] Check SSL certificate status
- [ ] Review authentication logs for anomalies
- [ ] Update maintenance log

## Monthly Maintenance Checklist  
- [ ] System package updates: `sudo apt update && sudo apt upgrade`
- [ ] Configuration validation: `./startup.sh --validate`
- [ ] Database optimization: `./tools/sqlite-maintenance.sh --full`
- [ ] Backup integrity test: `./tools/restore.sh --verify [recent-backup]`
- [ ] Performance review: analyze resource usage trends
- [ ] Security configuration review
- [ ] Log analysis and cleanup

## Quarterly Maintenance Checklist
- [ ] Comprehensive security audit
- [ ] Capacity planning review  
- [ ] Disaster recovery test
- [ ] Secret rotation assessment
- [ ] Documentation updates
- [ ] Backup strategy review
- [ ] Performance optimization review
```

This maintenance guide ensures the long-term reliability, security, and performance of your VaultWarden-OCI-NG deployment. Regular adherence to these maintenance practices will prevent issues before they impact users and maintain optimal system operation.
