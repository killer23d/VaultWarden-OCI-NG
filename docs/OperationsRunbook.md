# Operations Runbook

This comprehensive operations runbook provides step-by-step procedures for managing, maintaining, and troubleshooting the VaultWarden-OCI-NG stack in production environments.

## Runbook Overview

### Purpose and Scope
This runbook serves as the definitive guide for:
- **Daily Operations**: Routine tasks and health monitoring
- **Incident Response**: Structured problem resolution procedures
- **Maintenance Activities**: Scheduled and unscheduled maintenance
- **Emergency Procedures**: Critical incident handling and recovery

### Operations Team Structure
- **Primary Operator**: Daily monitoring and routine maintenance
- **Secondary Operator**: Backup support and specialized procedures
- **Escalation Contact**: Senior technical support for critical issues
- **Management**: Business impact assessment and communication

## Daily Operations Procedures

### Morning Health Check (Daily - 08:00)

#### Standard Health Assessment
```bash
# Execute comprehensive morning health check
./tools/check-health.sh

# Expected output confirmation:
# ✅ All containers healthy
# ✅ SSL certificate valid  
# ✅ Database integrity confirmed
# ✅ Backup system operational
# ✅ Security systems active
```

#### Resource Utilization Review
```bash
# Check system resources
df -h $PROJECT_STATE_DIR
free -h
uptime

# Container resource usage
docker stats --no-stream --format "table {{.Name}}	{{.CPUPerc}}	{{.MemUsage}}"

# Log disk space review
du -sh $PROJECT_STATE_DIR/logs/*/

# Expected thresholds:
# Disk usage: < 80% for data, < 70% for logs
# Memory usage: < 85% per container
# CPU load average: < 2.0 for single core systems
```

#### Service Status Verification
```bash
# Verify all services are running
docker compose ps

# Check service health endpoints
curl -I https://your-domain.com  # Should return 200
curl -I https://your-domain.com/alive  # VaultWarden health

# Verify SSL certificate status
echo | openssl s_client -connect your-domain.com:443 2>/dev/null |   openssl x509 -noout -dates | grep "notAfter"
```

### Evening Operations Review (Daily - 18:00)

#### Backup Verification
```bash
# Verify daily backup completion
ls -la $PROJECT_STATE_DIR/backups/daily/ | tail -5

# Check backup integrity (weekly rotation)
./tools/restore.sh --verify   $(ls -t $PROJECT_STATE_DIR/backups/daily/*.enc | head -1)

# Review backup log for any issues
grep -E "(ERROR|WARN)" /var/log/cron.log | grep backup | tail -10
```

#### Security Review
```bash
# Check fail2ban activity
sudo fail2ban-client status
sudo fail2ban-client get vaultwarden-auth stats

# Review authentication failures
tail -50 $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log |   grep -E "(Invalid|failed|denied)" | tail -10

# Check for unusual access patterns
awk '{print $1}' $PROJECT_STATE_DIR/logs/caddy/access.log |   sort | uniq -c | sort -nr | head -10
```

## Weekly Operations Procedures

### Weekly System Review (Monday - 09:00)

#### Performance Analysis
```bash
# Database performance review
./tools/sqlite-maintenance.sh --stats

# System performance trends
# Generate weekly performance report
cat > /tmp/weekly-performance.txt << EOF
Weekly Performance Report - $(date)
================================

System Resources:
$(df -h $PROJECT_STATE_DIR | tail -n +2)
$(free -h | grep Mem)
Load Average: $(uptime | awk -F'load average:' '{print $2}')

Container Resource Usage:
$(docker stats --no-stream --format "{{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}}")

Database Statistics:
Database Size: $(du -sh $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 | cut -f1)
User Count: $(echo "SELECT COUNT(*) FROM users;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3)
Vault Items: $(echo "SELECT COUNT(*) FROM cipher;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3)

Backup Status:
Latest Backup: $(ls -t $PROJECT_STATE_DIR/backups/daily/*.enc | head -1 | xargs basename)
Backup Size: $(ls -lh $PROJECT_STATE_DIR/backups/daily/*.enc | head -1 | awk '{print $5}')

Security Events (7 days):
Failed Logins: $(grep -c "Invalid password" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log)
Blocked IPs: $(sudo fail2ban-client status vaultwarden-auth | grep "Currently banned" | awk '{print $NF}')
EOF

# Email performance report if SMTP configured
if command -v mail >/dev/null 2>&1; then
    mail -s "Weekly VaultWarden Performance Report" admin@your-domain.com < /tmp/weekly-performance.txt
fi

rm /tmp/weekly-performance.txt
```

#### Configuration Drift Detection
```bash
# Check for configuration changes
cd $PROJECT_STATE_DIR/..
git status

# Review any uncommitted changes
git diff HEAD

# Check for security updates
sudo apt list --upgradable | grep -E "(security|docker)"

# Verify cron jobs are still configured
crontab -l | grep -E "(backup|monitor|maintenance)"
```

### Weekly Maintenance Tasks (Saturday - 02:00)

#### Database Optimization
```bash
# Run comprehensive database maintenance
./tools/sqlite-maintenance.sh --full

# Check database growth trends
DB_SIZE_MB=$(du -m $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 | cut -f1)
echo "$(date): Database size: ${DB_SIZE_MB}MB" >> /var/log/database-growth.log

# Analyze growth rate (if log exists)
if [ -f /var/log/database-growth.log ]; then
    tail -4 /var/log/database-growth.log |       awk '{print "Date:", $1, $2, "Size:", $5}' |       column -t
fi
```

#### Log Cleanup and Rotation
```bash
# Manual log cleanup for large deployments
find $PROJECT_STATE_DIR/logs/ -name "*.log" -size +50M -exec ls -lh {} \;

# Compress old logs if needed
find $PROJECT_STATE_DIR/logs/ -name "*.log" -mtime +7 -exec gzip {} \;

# Clean up compressed logs older than 30 days
find $PROJECT_STATE_DIR/logs/ -name "*.gz" -mtime +30 -delete

# Verify log rotation is working
ls -la $PROJECT_STATE_DIR/logs/*/
```

## Incident Response Procedures

### Severity Classification

#### Severity 1 (Critical) - Complete Service Outage
**Response Time**: Immediate (< 5 minutes)
**Escalation**: Automatic to all team members

**Indicators**:
- VaultWarden web interface completely inaccessible
- All user authentication failing
- Database corruption preventing service start
- Security breach confirmed

#### Severity 2 (High) - Degraded Service
**Response Time**: 15 minutes
**Escalation**: Primary and secondary operators

**Indicators**:
- Slow response times (> 5 seconds)
- Intermittent authentication failures
- Some features unavailable
- SSL certificate warnings

#### Severity 3 (Medium) - Minor Issues  
**Response Time**: 2 hours
**Escalation**: Primary operator

**Indicators**:
- Performance degradation
- Non-critical feature failures
- Backup warnings
- Monitoring alerts

### Incident Response Workflow

#### Initial Response (0-5 minutes)
```bash
# Step 1: Immediate assessment
echo "$(date): INCIDENT RESPONSE INITIATED" >> /var/log/incidents.log

# Step 2: Quick health check
./tools/check-health.sh --summary

# Step 3: Service status verification
docker compose ps

# Step 4: Log snapshot capture
mkdir -p /tmp/incident-$(date +%Y%m%d-%H%M)
INCIDENT_DIR="/tmp/incident-$(date +%Y%m%d-%H%M)"
docker compose logs --tail=100 > $INCIDENT_DIR/service-logs.txt
cp $PROJECT_STATE_DIR/logs/vaultwarden/*.log $INCIDENT_DIR/ 2>/dev/null || true

# Step 5: Resource check
df -h > $INCIDENT_DIR/disk-usage.txt
free -h > $INCIDENT_DIR/memory-usage.txt
ps aux > $INCIDENT_DIR/processes.txt
```

#### Detailed Investigation (5-15 minutes)
```bash
# Container-specific diagnostics
for service in vaultwarden caddy fail2ban; do
    echo "=== $service Service Analysis ===" >> $INCIDENT_DIR/diagnostics.txt
    docker compose logs --tail=50 $service >> $INCIDENT_DIR/diagnostics.txt

    # Service-specific health checks
    case $service in
        vaultwarden)
            curl -I http://localhost:8080/alive >> $INCIDENT_DIR/diagnostics.txt 2>&1
            ;;
        caddy)
            curl -I http://localhost:2019/metrics >> $INCIDENT_DIR/diagnostics.txt 2>&1
            ;;
    esac
done

# Database diagnostics
if [ -f $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 ]; then
    sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "PRAGMA integrity_check;" > $INCIDENT_DIR/db-integrity.txt
    sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "PRAGMA table_info(users);" > $INCIDENT_DIR/db-schema.txt
fi
```

#### Resolution Actions (15+ minutes)
```bash
# Standard resolution procedures based on incident type

# Service restart procedure
attempt_service_restart() {
    echo "$(date): Attempting service restart" >> /var/log/incidents.log
    ./startup.sh
    sleep 30
    ./tools/check-health.sh
}

# Database recovery procedure
attempt_database_recovery() {
    echo "$(date): Attempting database recovery" >> /var/log/incidents.log
    ./tools/sqlite-maintenance.sh --check
    if [ $? -ne 0 ]; then
        latest_backup=$(ls -t $PROJECT_STATE_DIR/backups/daily/*.enc | head -1)
        ./tools/restore.sh --database-only "$latest_backup"
    fi
}

# Configuration recovery procedure
attempt_config_recovery() {
    echo "$(date): Attempting configuration recovery" >> /var/log/incidents.log
    git checkout HEAD -- docker-compose.yml
    ./startup.sh --validate
}
```

## Maintenance Procedures

### Scheduled Maintenance Windows

#### Monthly Maintenance (First Sunday, 02:00-06:00)
```bash
# Monthly maintenance checklist
cat > /tmp/monthly-maintenance-$(date +%Y%m).txt << EOF
Monthly Maintenance Checklist - $(date)
======================================

Pre-maintenance:
[ ] Maintenance window notification sent to users
[ ] Full system backup created
[ ] Backup integrity verified
[ ] Rollback plan documented

System Updates:
[ ] Operating system security updates applied
[ ] Docker and Docker Compose updated
[ ] Container images updated (via Watchtower or manual)

Database Maintenance:
[ ] Database optimization completed
[ ] Integrity check performed
[ ] Growth analysis completed
[ ] Index optimization reviewed

Security Review:
[ ] SSL certificate status verified
[ ] Security patches applied
[ ] Firewall rules reviewed
[ ] Access logs analyzed

Configuration Review:
[ ] Configuration drift checked
[ ] Backup retention policies verified
[ ] Monitoring thresholds reviewed
[ ] Documentation updated

Performance Review:
[ ] Resource utilization analyzed
[ ] Performance benchmarks recorded
[ ] Capacity planning updated

Post-maintenance:
[ ] All services verified operational
[ ] User acceptance testing completed
[ ] Maintenance completion notification sent
[ ] Incident log updated

EOF

# Execute maintenance tasks
echo "Starting monthly maintenance..." >> /var/log/maintenance.log
```

#### Emergency Maintenance Procedures
```bash
# Emergency maintenance workflow
emergency_maintenance() {
    local reason="$1"
    local estimated_duration="$2"

    echo "$(date): EMERGENCY MAINTENANCE - $reason" >> /var/log/incidents.log

    # 1. Immediate notification
    cat > /tmp/emergency-notice.txt << EOF
EMERGENCY MAINTENANCE NOTIFICATION

Service: VaultWarden Password Manager
Start Time: $(date)
Estimated Duration: $estimated_duration
Reason: $reason

Impact: Service will be temporarily unavailable during maintenance.
All data remains secure and will be restored upon completion.

Status updates will be provided every 30 minutes.
EOF

    # Send notification if email configured
    if command -v mail >/dev/null 2>&1; then
        mail -s "EMERGENCY MAINTENANCE - VaultWarden" admin@your-domain.com < /tmp/emergency-notice.txt
    fi

    # 2. Create maintenance backup
    ./tools/create-full-backup.sh --output-dir /tmp/emergency-maintenance-backup/

    # 3. Execute maintenance procedures
    # (Specific procedures depend on maintenance type)

    # 4. Verification and restoration
    ./tools/check-health.sh --verbose

    # 5. Completion notification
    echo "Emergency maintenance completed at $(date)" |       mail -s "MAINTENANCE COMPLETE - VaultWarden" admin@your-domain.com
}
```

### Container Update Procedures

#### Manual Container Updates
```bash
# Controlled container update procedure
update_containers() {
    echo "$(date): Starting container update procedure" >> /var/log/updates.log

    # 1. Create pre-update backup
    ./tools/create-full-backup.sh --output-dir /tmp/pre-update-backup/

    # 2. Stop services gracefully
    docker compose down

    # 3. Pull latest images
    docker compose pull

    # 4. Start services
    ./startup.sh

    # 5. Verify update success
    if ./tools/check-health.sh; then
        echo "$(date): Container update successful" >> /var/log/updates.log
    else
        echo "$(date): Container update failed - initiating rollback" >> /var/log/updates.log
        # Rollback procedure
        docker compose down
        docker tag $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(vaultwarden|caddy)" | head -1) backup
        ./startup.sh
    fi
}
```

## Monitoring and Alerting Operations

### Alert Response Procedures

#### High CPU Usage Alert
```bash
# CPU usage investigation and resolution
investigate_high_cpu() {
    echo "$(date): High CPU usage alert triggered" >> /var/log/performance.log

    # 1. Identify resource-heavy processes
    docker stats --no-stream --format "table {{.Name}}	{{.CPUPerc}}" |       sort -k2 -nr > /tmp/cpu-usage.txt

    # 2. Check for specific issues
    # Database performance
    ./tools/sqlite-maintenance.sh --stats

    # Container resource limits
    docker compose config | grep -A2 -B2 "cpus\|memory"

    # 3. Mitigation actions
    if [ "$(docker stats --no-stream vaultwarden --format '{{.CPUPerc}}' | sed 's/%//')" -gt 80 ]; then
        echo "VaultWarden CPU usage > 80% - investigating database load"
        # Restart VaultWarden to clear any resource leaks
        docker compose restart vaultwarden
    fi
}
```

#### Disk Space Alert
```bash
# Disk space management procedure
handle_disk_space_alert() {
    local usage_percent=$(df $PROJECT_STATE_DIR | tail -1 | awk '{print $5}' | sed 's/%//')

    echo "$(date): Disk space alert - ${usage_percent}% usage" >> /var/log/disk-space.log

    if [ "$usage_percent" -gt 90 ]; then
        # Critical disk space - immediate action required
        echo "CRITICAL: Disk space > 90%" >> /var/log/disk-space.log

        # 1. Emergency log cleanup
        find $PROJECT_STATE_DIR/logs/ -name "*.log" -mtime +7 -exec gzip {} \;
        find $PROJECT_STATE_DIR/logs/ -name "*.gz" -mtime +14 -delete

        # 2. Old backup cleanup (keep 14 days minimum)
        find $PROJECT_STATE_DIR/backups/daily/ -name "*.enc" -mtime +21 -delete

        # 3. Docker system cleanup
        docker system prune -f

        # 4. Report space recovered
        new_usage=$(df $PROJECT_STATE_DIR | tail -1 | awk '{print $5}')
        echo "Space cleanup completed - usage now: $new_usage" >> /var/log/disk-space.log
    fi
}
```

#### SSL Certificate Expiration Alert
```bash
# SSL certificate renewal procedure
handle_ssl_expiration() {
    local days_until_expiry=$1

    echo "$(date): SSL certificate expires in $days_until_expiry days" >> /var/log/ssl.log

    if [ "$days_until_expiry" -le 7 ]; then
        # Force certificate renewal
        echo "Forcing SSL certificate renewal" >> /var/log/ssl.log
        docker compose exec caddy caddy reload

        # Wait and verify renewal
        sleep 60
        new_expiry=$(echo | openssl s_client -connect your-domain.com:443 2>/dev/null |           openssl x509 -noout -enddate | cut -d= -f2)

        echo "SSL certificate renewed - new expiry: $new_expiry" >> /var/log/ssl.log

        # Send confirmation
        echo "SSL certificate successfully renewed. New expiry: $new_expiry" |           mail -s "SSL Certificate Renewed" admin@your-domain.com
    fi
}
```

## Backup and Recovery Operations

### Backup Validation Procedures

#### Weekly Backup Testing
```bash
# Weekly backup integrity testing
test_backup_integrity() {
    echo "$(date): Starting weekly backup integrity test" >> /var/log/backup-tests.log

    # Select random backup from last 7 days
    random_backup=$(find $PROJECT_STATE_DIR/backups/daily/ -name "*.enc" -mtime -7 | shuf -n 1)

    if [ -n "$random_backup" ]; then
        echo "Testing backup: $(basename $random_backup)" >> /var/log/backup-tests.log

        if ./tools/restore.sh --verify "$random_backup"; then
            echo "✅ Backup integrity test PASSED" >> /var/log/backup-tests.log
        else
            echo "❌ Backup integrity test FAILED" >> /var/log/backup-tests.log
            # Send alert
            echo "Backup integrity test failed for: $(basename $random_backup)" |               mail -s "BACKUP INTEGRITY ALERT" admin@your-domain.com
        fi
    else
        echo "❌ No recent backups found for testing" >> /var/log/backup-tests.log
    fi
}
```

### Emergency Recovery Operations

#### Point-in-Time Recovery
```bash
# Point-in-time recovery procedure
perform_point_in_time_recovery() {
    local target_date="$1"  # Format: YYYY-MM-DD
    local reason="$2"

    echo "$(date): POINT-IN-TIME RECOVERY - Target: $target_date, Reason: $reason" >> /var/log/recovery.log

    # 1. Stop current services
    docker compose down

    # 2. Backup current state
    ./tools/create-full-backup.sh --output-dir /tmp/pre-recovery-backup/

    # 3. Find appropriate backup
    backup_file=$(find $PROJECT_STATE_DIR/backups/ -name "*${target_date}*.enc" | head -1)

    if [ -z "$backup_file" ]; then
        echo "ERROR: No backup found for date $target_date" >> /var/log/recovery.log
        # Try closest backup
        backup_file=$(find $PROJECT_STATE_DIR/backups/ -name "*.enc" -newermt "$target_date" | head -1)
    fi

    # 4. Perform recovery
    if [ -n "$backup_file" ]; then
        echo "Recovering from backup: $(basename $backup_file)" >> /var/log/recovery.log
        ./tools/restore.sh "$backup_file"

        # 5. Verify recovery
        if ./startup.sh && ./tools/check-health.sh; then
            echo "✅ Point-in-time recovery successful" >> /var/log/recovery.log
        else
            echo "❌ Point-in-time recovery failed" >> /var/log/recovery.log
        fi
    else
        echo "❌ No suitable backup found for recovery" >> /var/log/recovery.log
    fi
}
```

## Performance Optimization Operations

### Performance Tuning Procedures

#### Database Performance Optimization
```bash
# Database performance tuning
optimize_database_performance() {
    echo "$(date): Starting database performance optimization" >> /var/log/performance.log

    # 1. Analyze current performance
    ./tools/sqlite-maintenance.sh --stats > /tmp/db-stats-before.txt

    # 2. Run optimization
    ./tools/sqlite-maintenance.sh --full

    # 3. Compare results
    ./tools/sqlite-maintenance.sh --stats > /tmp/db-stats-after.txt

    # 4. Generate optimization report
    cat > /tmp/optimization-report.txt << EOF
Database Optimization Report - $(date)
=====================================

Performance Metrics Before:
$(cat /tmp/db-stats-before.txt)

Performance Metrics After:
$(cat /tmp/db-stats-after.txt)

Optimization Actions Completed:
- Database VACUUM operation
- Index rebuilding
- Statistics update
- WAL checkpoint

EOF

    # 5. Email report if configured
    if command -v mail >/dev/null 2>&1; then
        mail -s "Database Optimization Report" admin@your-domain.com < /tmp/optimization-report.txt
    fi

    # 6. Cleanup
    rm /tmp/db-stats-*.txt /tmp/optimization-report.txt
}
```

#### Resource Optimization
```bash
# System resource optimization
optimize_system_resources() {
    echo "$(date): Starting system resource optimization" >> /var/log/performance.log

    # 1. Container resource analysis
    docker stats --no-stream --format "table {{.Name}}	{{.CPUPerc}}	{{.MemUsage}}" > /tmp/resource-usage.txt

    # 2. Identify resource optimization opportunities
    # Check for memory leaks
    container_memory=$(docker stats --no-stream vaultwarden --format '{{.MemUsage}}' | cut -d'/' -f1)

    # 3. Optimize Docker resources
    docker system prune -f

    # 4. Adjust container limits if needed
    # This requires editing docker-compose.yml and restarting services

    echo "Resource optimization completed" >> /var/log/performance.log
}
```

This operations runbook provides comprehensive procedures for managing VaultWarden-OCI-NG in production environments, ensuring reliable operation and effective incident response.
