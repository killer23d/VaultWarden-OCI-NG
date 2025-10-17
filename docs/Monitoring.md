# Monitoring and Health Management

> **🎯 Monitoring Philosophy**: Proactive health monitoring with automated recovery, comprehensive alerting, and minimal administrative overhead for small teams.

## 🔍 **Monitoring Architecture Overview**

The VaultWarden-OCI-Minimal stack implements **multi-tier monitoring** with automated self-healing capabilities:

```bash
Monitoring Tiers:
├── Container Health (Docker native health checks)
├── Application Health (HTTP endpoints, database connectivity)
├── System Health (resources, connectivity, certificates)
├── Security Health (intrusion detection, access patterns)
├── Data Health (backup integrity, database optimization)
└── Performance Health (response times, resource utilization)
```

### **Automated Self-Healing**
```bash
Detection → Analysis → Recovery → Notification → Documentation

Recovery Actions:
├── Container restart with exponential backoff
├── Log rotation to free disk space
├── Database integrity repair
├── Service dependency resolution
├── Configuration validation and repair
└── Safe mode activation for critical failures
```

## 📊 **Health Check System**

### **Container-Level Health Checks**

#### **VaultWarden Health Check**
```yaml
# Configured in docker-compose.yml
healthcheck:
  test: ["CMD", "curl", "-fsSL", "http://localhost:8080/alive"]
  interval: 30s      # Check every 30 seconds
  timeout: 10s       # 10 second timeout
  retries: 5         # 5 failures = unhealthy
  start_period: 45s  # Allow 45s for startup
```

**Health Check Verification**:
```bash
# Check container health status
docker compose ps
# Look for "healthy" status next to vaultwarden

# Manual health check test
docker compose exec vaultwarden curl -f http://localhost:8080/alive
# Should return: {"status":"ok"}

# View health check logs
docker inspect $(docker compose ps -q vaultwarden) | jq '.[0].State.Health'
```

#### **Caddy Health Check**
```yaml
healthcheck:
  test: ["CMD", "curl", "-fsSL", "http://localhost:2019/metrics"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 20s
```

**Caddy Monitoring**:
```bash
# Check Caddy metrics endpoint
docker compose exec caddy curl -s http://localhost:2019/metrics

# Verify reverse proxy functionality
curl -I https://your-domain.com
# Should return HTTP 200 response

# Monitor Caddy configuration
docker compose exec caddy caddy list-certificates
```

#### **Fail2ban Health Check**
```bash
# Fail2ban runs in host network mode (no Docker health check)
# Monitored via systemd and custom monitoring script

# Check fail2ban service status
sudo systemctl is-active fail2ban

# Verify jails are active
sudo fail2ban-client status

# Check fail2ban process health
ps aux | grep fail2ban-server
```

### **Application-Level Monitoring**

#### **Database Health Monitoring**
```bash
# Database connectivity test
./tools/monitor.sh --database-check

# Database integrity verification
./tools/sqlite-maintenance.sh --quick-check

# Database performance monitoring
./tools/sqlite-maintenance.sh --analyze --stats

# Database size monitoring
du -sh /var/lib/*/data/bwdata/db.sqlite3
```

**Database Health Indicators**:
```bash
# Key metrics monitored automatically:
# - Database file accessibility
# - SQLite integrity (PRAGMA integrity_check)
# - Connection response time
# - Database file size growth
# - WAL file size (write-ahead log)
# - Backup completion status

# Database health check output example:
# ✅ Database accessible
# ✅ Integrity check passed
# ✅ Response time: 15ms
# ✅ Size: 2.3MB (normal growth)
# ⚠️  WAL file size: 1.2MB (will checkpoint soon)
```

#### **SSL Certificate Monitoring**
```bash
# Certificate expiration monitoring
./tools/monitor.sh --certificate-check

# Manual certificate verification
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | \
  openssl x509 -noout -dates

# Certificate auto-renewal verification
docker compose logs caddy | grep -i "certificate.*success"
```

**Certificate Health Alerts**:
```bash
# Automatic alerts for:
# - Certificates expiring within 30 days
# - Certificate renewal failures
# - Invalid certificate chains
# - OCSP stapling issues

# Certificate monitoring output:
# ✅ Certificate valid: your-domain.com
# ✅ Expires: 2024-04-15 (87 days)
# ✅ Chain valid: 3 certificates
# ✅ OCSP stapling: active
```

## 🤖 **Automated Monitoring System**

### **Cron-Based Monitoring**

#### **Primary Monitor Script**
```bash
# Executed every 5 minutes via cron
*/5 * * * * root cd /opt/VaultWarden-OCI-Minimal && ./tools/monitor.sh 2>&1 | logger -t monitor

# Monitor script functions:
# 1. Container health validation
# 2. Resource usage monitoring  
# 3. Network connectivity tests
# 4. Database integrity checks
# 5. SSL certificate validation
# 6. Backup system verification
# 7. Security event analysis
# 8. Automatic recovery actions
```

#### **Monitoring Script Details**
```bash
# View the monitoring script capabilities
./tools/monitor.sh --help

# Available monitoring modes:
--summary        # Quick overview of system health
--verbose        # Detailed health information
--silent         # No output (for cron usage)
--database-only  # Focus on database health
--security-only  # Focus on security monitoring
--test-all      # Comprehensive test mode
```

#### **Monitoring Output Examples**
```bash
# Normal operation (./tools/monitor.sh --summary)
🟢 VaultWarden-OCI-Minimal Health Summary
✅ All containers healthy (4/4)
✅ Database responsive (12ms)
✅ SSL certificate valid (89 days remaining)
✅ Disk usage: 15% (/var/lib/vaultwarden-oci-minimal)
✅ Memory usage: 1.2GB/4GB (30%)
✅ Last backup: 2 hours ago (✅ verified)
✅ Fail2ban: 3 jails active, 0 current bans
✅ Network: All endpoints reachable

# Warning condition example
🟡 VaultWarden-OCI-Minimal Health Summary  
✅ All containers healthy (4/4)
⚠️  Database responsive but slow (245ms - investigating)
✅ SSL certificate valid (89 days remaining)
⚠️  Disk usage: 87% (/var/lib/vaultwarden-oci-minimal)
✅ Memory usage: 1.8GB/4GB (45%)
✅ Last backup: 2 hours ago (✅ verified)
✅ Fail2ban: 3 jails active, 2 current bans
✅ Network: All endpoints reachable

🔧 Automatic actions taken:
- Log rotation initiated to free disk space
- Database VACUUM scheduled for next maintenance window
```

### **Self-Healing Mechanisms**

#### **Container Recovery**
```bash
# Automatic container restart logic
# 1. Detect unhealthy container
# 2. Attempt graceful restart
# 3. Wait for health check recovery
# 4. Escalate if recovery fails

# Container recovery workflow:
if ! docker compose ps | grep -q "healthy.*vaultwarden"; then
    echo "$(date): VaultWarden unhealthy, attempting restart" | logger -t monitor
    docker compose restart vaultwarden
    
    # Wait for recovery with timeout
    timeout 300 bash -c 'while ! docker compose ps | grep -q "healthy.*vaultwarden"; do sleep 10; done'
    
    if docker compose ps | grep -q "healthy.*vaultwarden"; then
        echo "$(date): VaultWarden recovery successful" | logger -t monitor
    else
        echo "$(date): VaultWarden recovery failed - manual intervention required" | logger -t monitor
        # Send alert email if configured
    fi
fi
```

#### **Resource Recovery**
```bash
# Disk space recovery
if [[ $(df /var/lib/*/data | tail -1 | awk '{print $5}' | sed 's/%//') -gt 85 ]]; then
    # Rotate logs
    find /var/lib/*/logs -name "*.log" -size +50M -exec truncate -s 10M {} \\;
    
    # Clean old backups (keep last 10)
    cd /var/lib/*/backups/db/
    ls -t *.backup | tail -n +11 | xargs -r rm -f
    
    # Clean Docker system
    docker system prune -f
fi

# Memory pressure recovery
if [[ $(free | grep ^Mem | awk '{print ($3/$2)*100.0}') > 90 ]]; then
    # Clear page cache (safe)
    sync && echo 1 > /proc/sys/vm/drop_caches
    
    # Restart containers if memory usage remains high
    sleep 60
    if [[ $(free | grep ^Mem | awk '{print ($3/$2)*100.0}') > 90 ]]; then
        docker compose restart
    fi
fi
```

#### **Database Recovery**
```bash
# Database integrity recovery
if ! sqlite3 /var/lib/*/data/bwdata/db.sqlite3 "PRAGMA integrity_check;" | grep -q "ok"; then
    echo "$(date): Database integrity issue detected" | logger -t monitor
    
    # Stop VaultWarden to prevent further corruption
    docker compose stop vaultwarden
    
    # Create emergency backup
    ./tools/create-full-backup.sh --emergency
    
    # Attempt database recovery
    ./tools/sqlite-maintenance.sh --repair
    
    # Restart if repair successful
    if sqlite3 /var/lib/*/data/bwdata/db.sqlite3 "PRAGMA integrity_check;" | grep -q "ok"; then
        docker compose start vaultwarden
        echo "$(date): Database recovery successful" | logger -t monitor
    else
        echo "$(date): Database recovery failed - restore required" | logger -t monitor
        # Alert for manual intervention
    fi
fi
```

## 📧 **Alerting and Notifications**

### **Email Notification System**

#### **SMTP Configuration for Alerts**
```json
{
  "SMTP_HOST": "smtp.gmail.com",
  "SMTP_PORT": 587,
  "SMTP_SECURITY": "starttls",
  "SMTP_USERNAME": "alerts@yourdomain.com",
  "SMTP_PASSWORD": "your-app-password",
  "SMTP_FROM": "vaultwarden-alerts@yourdomain.com",
  "ADMIN_EMAIL": "admin@yourdomain.com"
}
```

#### **Alert Categories and Triggers**

**Critical Alerts** (Immediate notification):
```bash
# Service completely down
# Database corruption detected
# SSL certificate expired
# Disk usage >95%
# Security breach indicators
# Backup system failure >24 hours

# Example critical alert email:
Subject: 🚨 CRITICAL: VaultWarden Service Down - your-domain.com

VaultWarden-OCI-Minimal Critical Alert

Time: 2024-10-14 17:30:25 UTC
Severity: CRITICAL
Service: VaultWarden Core Application

Issue: VaultWarden container failed to start after 3 restart attempts

Details:
- Container Status: Exited (1)
- Last Error: Database connection failed
- Automatic Recovery: Failed
- Manual Intervention: Required

Actions Taken:
- Emergency backup created: /var/lib/vaultwarden/backups/emergency-20241014-173025.tar.gz
- Container restart attempted (3x)
- Database integrity check initiated

Next Steps:
1. SSH to server: ssh ubuntu@your-server-ip
2. Check logs: docker compose logs vaultwarden
3. Run diagnostics: ./tools/monitor.sh --verbose
4. Contact support if needed with diagnostic output

Server: your-domain.com (10.0.0.15)
Monitoring: VaultWarden-OCI-Minimal v1.0
```

**Warning Alerts** (Daily digest):
```bash
# High resource usage (>80%)
# SSL certificate expires <30 days
# Failed login attempts detected
# Backup warnings
# Performance degradation

# Example warning digest:
Subject: ⚠️  VaultWarden Daily Health Report - your-domain.com

VaultWarden-OCI-Minimal Health Summary
Period: 2024-10-14 00:00 - 23:59 UTC

🟢 System Health: Good
✅ Uptime: 99.8% (4 minutes downtime for updates)
✅ Response Time: Avg 89ms, Max 245ms
✅ Database: Healthy, 2.3MB size
✅ SSL: Valid, expires in 87 days

⚠️  Items Requiring Attention:
- Disk usage: 87% (increased 5% this week)
- Memory usage peaked at 89% during backup
- 3 failed login attempts from new IP ranges
- CloudFlare blocked 45 requests (normal)

🔧 Actions Taken:
- Log rotation completed (freed 120MB)
- Database optimized (VACUUM completed)
- Old backups cleaned (removed 8 files)

📊 Statistics:
- Successful logins: 147
- Failed login attempts: 3
- Fail2ban blocks: 2 IPs
- Data backed up: 2.8MB
- Monitoring checks: 288/288 successful

Next Scheduled Maintenance: Weekly full backup (Sunday 00:00 UTC)
```

#### **Notification Configuration**
```bash
# Test email notifications
./tools/monitor.sh --test-email

# Configure alert thresholds (optional customization)
cat > /etc/vaultwarden-monitoring.conf <<EOF
# Monitoring thresholds
DISK_WARNING_THRESHOLD=80
DISK_CRITICAL_THRESHOLD=95
MEMORY_WARNING_THRESHOLD=85
MEMORY_CRITICAL_THRESHOLD=95
RESPONSE_TIME_WARNING=500
RESPONSE_TIME_CRITICAL=2000
CERTIFICATE_WARNING_DAYS=30
CERTIFICATE_CRITICAL_DAYS=7
EOF
```

### **Log-Based Monitoring**

#### **Centralized Logging**
```bash
# Log locations and purposes
/var/lib/*/logs/vaultwarden/    # Application logs
/var/lib/*/logs/caddy/          # Access and error logs
/var/lib/*/logs/fail2ban/       # Security event logs
/var/log/syslog                 # System events
/var/log/auth.log               # Authentication events

# Automated log analysis
journalctl -t monitor           # Monitoring script logs
journalctl -t backup            # Backup operation logs
journalctl -t sqlite-maintenance # Database maintenance logs
```

#### **Log Rotation and Management**
```bash
# Automatic log rotation (configured via cron)
0 4 * * * root find /var/lib/*/logs -name "*.log" -size +50M -exec truncate -s 10M {} \\;

# Log retention policy
# - Keep logs for 30 days
# - Rotate when >50MB
# - Compress logs >7 days old

# Manual log analysis
# Recent errors across all services
grep -r "ERROR" /var/lib/*/logs/ | tail -20

# Authentication failures
grep "auth failure" /var/lib/*/logs/vaultwarden/ | tail -10

# High response times
jq 'select(.duration > 1000)' /var/lib/*/logs/caddy/access.log | tail -5
```

## 📈 **Performance Monitoring**

### **Resource Usage Tracking**

#### **System Resource Monitoring**
```bash
# Container resource usage
docker stats --no-stream --format "table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\\t{{.BlockIO}}"

# System resource monitoring
./tools/monitor.sh --resources

# Expected output:
NAME               CPU %     MEM USAGE / LIMIT     NET I/O           BLOCK I/O
bw_vaultwarden     2.34%     456.2MiB / 2GiB      1.2MB / 890kB     12MB / 2.1MB
bw_caddy           0.12%     89.1MiB / 512MiB      15MB / 12MB       890kB / 123kB
bw_fail2ban        0.05%     23.4MiB / 256MiB      45kB / 67kB       12kB / 8kB
bw_watchtower      0.01%     12.1MiB / 256MiB      234kB / 123kB     0B / 0B
```

#### **Application Performance Metrics**
```bash
# Response time monitoring (from Caddy access logs)
tail -1000 /var/lib/*/logs/caddy/access.log | \
  jq -r '.duration' | \
  awk '{sum+=$1; count++} END {print "Avg response time: " sum/count "ms"}'

# Database performance analysis
./tools/sqlite-maintenance.sh --performance-report

# Example performance report:
Database Performance Report:
- Query average response time: 12ms
- Database size: 2.3MB
- Index efficiency: 98.7%
- WAL file size: 234KB (normal)
- Last VACUUM: 2 days ago (scheduled: weekly)
- Fragmentation: 2.1% (good)
```

### **Capacity Planning**

#### **Growth Trend Analysis**
```bash
# Database growth tracking
./tools/monitor.sh --growth-analysis

# Disk usage trends
df -h /var/lib/*/ | awk '{print $(NF-1), $NF}' | \
  grep -v "Use%" | \
  awk '{print "Disk usage: " $1 " on " $2}'

# Memory usage trends over time
free -h | grep ^Mem | awk '{print "Memory: " $3 "/" $2 " (" int($3/$2*100) "%)"}'

# Backup size trends
ls -lah /var/lib/*/backups/db/*.backup | \
  awk '{print $5, $9}' | \
  tail -10 | \
  awk '{print "Backup size: " $1}'
```

#### **Scaling Recommendations**
```bash
# Automated scaling recommendations
./tools/monitor.sh --scaling-recommendations

# Example output:
Scaling Analysis for VaultWarden-OCI-Minimal:

Current Capacity:
- Users: ~8 active users
- Database size: 2.3MB
- Daily growth: ~50KB
- Peak memory: 1.2GB
- Peak CPU: 15%

Projected Capacity (6 months):
- Database size: ~11MB
- Memory needed: ~1.5GB
- Storage needed: ~500MB

Recommendations:
✅ Current configuration sufficient for 6+ months
✅ No immediate scaling required
⚠️  Consider monitoring if user count >12
⚠️  Plan storage expansion if growth >200KB/day

Scale-up triggers:
- Memory usage consistently >85%
- Database size >100MB
- Response times consistently >500ms
- User count >15
```

## 🔧 **Monitoring Tools and Commands**

### **Built-in Monitoring Commands**

#### **Quick Status Checks**
```bash
# Overall system health
./tools/monitor.sh --summary

# Detailed health information
./tools/monitor.sh --verbose

# Test all monitoring functions
./tools/monitor.sh --test-all

# Check specific components
./tools/monitor.sh --database-only
./tools/monitor.sh --security-only
./tools/monitor.sh --network-only
```

#### **Service-Specific Monitoring**
```bash
# VaultWarden application monitoring
curl -s http://localhost:8080/alive | jq .

# Caddy reverse proxy monitoring
docker compose exec caddy caddy list-certificates
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile

# Database monitoring
./tools/sqlite-maintenance.sh --status
./tools/sqlite-maintenance.sh --quick-check

# Backup system monitoring
./tools/create-full-backup.sh --verify-last
./tools/restore.sh --list-recent
```

### **External Monitoring Integration**

#### **Uptime Monitoring Services**
```bash
# Configure external uptime monitoring (recommended)
# Services like UptimeRobot, Pingdom, or StatusCake

# Endpoints to monitor:
# - https://your-domain.com (main application)
# - https://your-domain.com/alive (health endpoint)
# - https://your-domain.com/admin (admin panel - with auth)

# Expected responses:
# Main app: HTTP 200 with HTML content
# Health endpoint: HTTP 200 with {"status":"ok"}
# Admin panel: HTTP 401 or 200 (depending on authentication)
```

#### **Log Aggregation Services**
```bash
# For larger deployments, consider log aggregation
# Examples: ELK Stack, Splunk, DataDog, New Relic

# Log formats are structured for easy parsing:
# - JSON format for Caddy access logs
# - Structured format for application logs
# - Standard syslog format for system logs

# Example log shipping configuration (optional):
# Install log shipper like Filebeat or Fluentd
# Configure to ship logs to your SIEM/monitoring service
```

## 📊 **Monitoring Dashboard**

### **Command-Line Dashboard**
```bash
# Real-time monitoring dashboard
watch -n 30 './tools/monitor.sh --summary'

# Comprehensive system overview
./tools/monitor.sh --dashboard

# Example dashboard output:
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VaultWarden-OCI-Minimal Dashboard                        ║
║                        Last Updated: 2024-10-14 17:30 UTC                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ System Status: 🟢 HEALTHY                    Uptime: 15d 4h 23m             ║
║                                                                              ║
║ ┌─ Services ──────────────────────────────────────────────────────────────┐ ║
║ │ VaultWarden:    🟢 Healthy    │ Memory: 456MB/2GB    │ CPU: 2.3%        │ ║  
║ │ Caddy:          🟢 Healthy    │ Memory: 89MB/512MB   │ CPU: 0.1%        │ ║
║ │ Fail2ban:       🟢 Active     │ Jails: 3 active     │ Bans: 0          │ ║
║ │ Watchtower:     🟢 Running    │ Memory: 12MB/256MB   │ CPU: 0.0%        │ ║
║ └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║ ┌─ Resources ─────────────────────────────────────────────────────────────┐ ║
║ │ Disk Usage:     15% (2.3GB/16GB)    │ Free: 13.7GB                      │ ║
║ │ Memory Usage:   30% (1.2GB/4GB)     │ Available: 2.8GB                  │ ║
║ │ CPU Load:       0.15, 0.12, 0.08    │ Load Average (1/5/15 min)         │ ║
║ └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║ ┌─ Security ─────────────────────────────────────────────────────────────┐ ║
║ │ SSL Certificate: ✅ Valid (89 days)  │ Firewall: ✅ Active               │ ║
║ │ Last Failed Login: 2h ago           │ Failed Attempts (24h): 3          │ ║
║ │ Banned IPs: 0                       │ Active Jails: 3                   │ ║
║ └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║ ┌─ Data & Backups ───────────────────────────────────────────────────────┐ ║
║ │ Database Size: 2.3MB                │ Last Backup: 2h ago ✅            │ ║
║ │ Database Health: ✅ Good             │ Backup Size: 892KB                │ ║
║ │ Response Time: 12ms avg             │ Next Backup: 22h                  │ ║
║ └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║ Recent Events:                                                               ║
║ • 17:25 - Database maintenance completed successfully                        ║
║ • 17:20 - CloudFlare IP ranges updated                                      ║
║ • 15:30 - Container health check: All services healthy                      ║
║ • 14:15 - Weekly backup completed (892KB)                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Commands: [R]efresh [L]ogs [S]tatus [H]elp [Q]uit
```

This comprehensive monitoring system ensures your VaultWarden deployment maintains high availability and performance with minimal administrative overhead."""
