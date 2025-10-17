# Monitoring Guide

This comprehensive guide covers monitoring strategies, health checks, alerting systems, and performance tracking for the VaultWarden-OCI-NG stack.

## Monitoring Philosophy

### Proactive Monitoring Approach
The VaultWarden-OCI-NG monitoring system is designed around these principles:
- **Early Detection**: Identify issues before they impact users
- **Automated Response**: Self-healing systems reduce manual intervention
- **Comprehensive Coverage**: Monitor all stack layers from infrastructure to application
- **Actionable Alerts**: Notifications include context and resolution guidance

### Monitoring Layers
```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│     • User authentication success/failure rates            │
│     • API response times and error rates                   │
│     • Vault operations (create, read, update, delete)      │
│     • Push notification delivery                           │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Service Layer                            │
│     • Container health and restart events                  │
│     • Service availability and response times              │
│     • SSL certificate validity and expiration              │
│     • Database connectivity and performance                │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Security Layer                           │
│     • Failed authentication attempts                       │
│     • Banned IP addresses and attack patterns             │
│     • Firewall rule violations                            │
│     • Certificate validation and renewal                   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                       │
│     • System resource utilization (CPU, memory, disk)      │
│     • Network connectivity and bandwidth                   │
│     • Storage performance and capacity                     │
│     • Backup system health and success rates              │
└─────────────────────────────────────────────────────────────┘
```

## Built-in Monitoring Systems

### Automated Health Checks
The monitoring system runs automatically via cron every 5 minutes:

```bash
# View current monitoring schedule
crontab -l | grep monitor

# Expected entry:
# */5 * * * * /path/to/tools/monitor.sh --quiet >/dev/null 2>&1
```

#### Health Check Components
```bash
# Run comprehensive health check
./tools/check-health.sh

# Health check categories:
# ✅ Container Health: All services running and responding
# ✅ Database Health: Connectivity and integrity verification
# ✅ SSL Certificate: Validity and expiration monitoring
# ✅ Security Status: Firewall and fail2ban verification
# ✅ System Resources: Disk, memory, and CPU monitoring
# ✅ Backup System: Recent backup verification
```

### Container Health Monitoring
Docker Compose includes native health checks for all services:

```yaml
# Example health check configuration
healthcheck:
  test: ["CMD", "curl", "-fsSL", "http://localhost:8080/alive"]
  interval: 30s
  timeout: 10s
  retries: 5
  start_period: 45s
```

#### Monitoring Container Status
```bash
# Check all container health status
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"

# Expected output:
# NAME                     STATUS        HEALTH
# project_vaultwarden     Up (healthy)  healthy
# project_caddy           Up (healthy)  healthy
# project_fail2ban        Up            N/A
```

### Self-Healing Mechanisms
The monitoring system includes automated recovery:

#### Service Recovery Actions
- **Unhealthy Containers**: Automatic restart after failed health checks
- **Resource Exhaustion**: Memory cleanup and container restart
- **Database Issues**: Integrity checks and optimization
- **SSL Certificate Problems**: Automatic renewal and reload
- **Network Connectivity**: DNS cache flush and connection retry

#### Monitoring Script Capabilities
```bash
# Monitor script options
./tools/monitor.sh --help

# Key monitoring features:
--summary        # Brief health status overview
--test-email     # Send test notification email  
--no-restart     # Check health but don't restart failed services
--verbose        # Detailed diagnostic output
```

## Performance Monitoring

### Resource Utilization Tracking

#### System Resource Monitoring
```bash
# Current resource usage
./tools/check-health.sh --verbose

# Real-time resource monitoring
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Storage monitoring
df -h $PROJECT_STATE_DIR
du -sh $PROJECT_STATE_DIR/data/bwdata/
```

#### Performance Baselines
Establish performance baselines for monitoring:

**CPU Usage Baselines:**
- Normal operation: 5-15% average CPU
- Peak usage: <50% during high activity
- Alert threshold: >80% sustained for 15+ minutes

**Memory Usage Baselines:**
- VaultWarden: 200-800MB (depending on user count)
- Caddy: 50-200MB
- Fail2ban: 20-100MB
- Alert threshold: >90% of allocated memory

**Disk Usage Baselines:**
- Database growth: ~1-5MB per user per month
- Log growth: ~100-500MB per month
- Alert thresholds: >80% disk usage, >90% critical

### Database Performance Monitoring

#### SQLite Performance Metrics
```bash
# Database statistics
./tools/sqlite-maintenance.sh --stats

# Key metrics monitored:
# - Database size and growth rate
# - Index usage and effectiveness
# - Query performance and slow queries
# - WAL file size and checkpoint frequency
# - Page cache hit ratio
```

#### Database Health Indicators
```bash
# Database integrity check
./tools/sqlite-maintenance.sh --check

# Performance optimization assessment
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "
  PRAGMA optimize;
  PRAGMA analysis_limit=1000;
  ANALYZE main;
"

# Query performance analysis
sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 "
  .timer on
  .explain on
  SELECT COUNT(*) FROM users;
"
```

### Application Performance Monitoring

#### Response Time Monitoring
```bash
# Test application response times
time curl -s -o /dev/null -w "%{http_code} %{time_total}s" https://your-domain.com

# API endpoint performance testing
curl -w "Total: %{time_total}s, Connect: %{time_connect}s, SSL: %{time_appconnect}s\n"      -o /dev/null -s https://your-domain.com/api/config

# Expected response times:
# - Static content: <200ms
# - API endpoints: <500ms
# - Authentication: <1000ms
```

#### User Experience Monitoring
```bash
# Monitor authentication success rates
grep -c "login_attempt" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log
grep -c "Invalid password" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log

# API error rate monitoring
awk '{if($9 >= 400) error++; total++} END {print "Error rate:", (error/total)*100"%"}'     $PROJECT_STATE_DIR/logs/caddy/access.log
```

## Security Monitoring

### Authentication Monitoring

#### Failed Authentication Tracking
```bash
# Recent failed authentication attempts
tail -100 $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log |   grep -E "(Invalid password|login_attempt)" |   awk '{print $1, $2, $3}' | sort | uniq -c

# Geographic analysis of failed attempts (requires IP geolocation)
awk '/Invalid password/ {print $NF}' $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log |   sort | uniq -c | sort -nr
```

#### Fail2ban Monitoring
```bash
# Current fail2ban status
sudo fail2ban-client status

# Detailed jail information
sudo fail2ban-client status vaultwarden-auth

# Ban statistics
sudo fail2ban-client get vaultwarden-auth stats

# Recent ban activity
sudo tail -50 /var/log/fail2ban.log | grep -E "(Ban|Unban)"
```

### Network Security Monitoring

#### Access Pattern Analysis
```bash
# Top accessing IP addresses
awk '{print $1}' $PROJECT_STATE_DIR/logs/caddy/access.log |   sort | uniq -c | sort -nr | head -20

# Suspicious request patterns
grep -E "(admin|api/accounts|\.php|wp-|/etc/)"   $PROJECT_STATE_DIR/logs/caddy/access.log | tail -20

# HTTP status code analysis
awk '{print $9}' $PROJECT_STATE_DIR/logs/caddy/access.log |   sort | uniq -c | sort -nr
```

#### SSL Security Monitoring
```bash
# Certificate expiration monitoring
echo | openssl s_client -connect your-domain.com:443 2>/dev/null |   openssl x509 -noout -dates |   grep "notAfter" |   awk -F= '{print $2}'

# SSL configuration verification
echo | openssl s_client -connect your-domain.com:443 2>/dev/null |   grep -E "(Protocol|Cipher)"

# Check for weak ciphers or protocols
nmap --script ssl-enum-ciphers -p 443 your-domain.com
```

## Alerting and Notifications

### Email Notification Configuration

#### SMTP Setup for Alerts
```bash
# Configure SMTP for notifications
sudo ./tools/edit-secrets.sh
# Add: smtp_password: "your-email-password"

# Update email configuration
# Edit settings with SMTP details:
# SMTP_HOST=smtp.gmail.com
# SMTP_FROM=alerts@your-domain.com
# ADMIN_EMAIL=admin@your-domain.com
```

#### Test Email Notifications
```bash
# Test email functionality
./tools/monitor.sh --test-email

# Manual email test
echo "Test alert from VaultWarden monitoring" |   mail -s "VaultWarden Test Alert" admin@your-domain.com
```

### Alert Categories and Thresholds

#### Critical Alerts (Immediate Attention)
- **Service Down**: Any core service (VaultWarden, Caddy) unavailable
- **Database Corruption**: SQLite integrity check failures
- **SSL Certificate Issues**: Expired or invalid certificates
- **Disk Space Critical**: >95% disk usage
- **Security Breach**: Multiple authentication failures from single IP

#### Warning Alerts (Monitor Closely)
- **High Resource Usage**: >80% CPU/memory for >15 minutes
- **Database Performance**: Query response times >2 seconds
- **Backup Failures**: Failed backup creation or verification
- **Certificate Expiration**: SSL certificate expires within 7 days
- **Unusual Access Patterns**: Unexpected geographic or volume patterns

#### Informational Alerts (Awareness)
- **Container Updates**: Watchtower automatic updates
- **Scheduled Maintenance**: Automated optimization tasks
- **User Activity**: New user registrations or unusual activity
- **System Events**: Planned restarts or configuration changes

### Custom Alerting Scripts

#### Create Custom Alert Script
```bash
# Create custom alerting script
cat > tools/custom-alerts.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90

# Check CPU usage
cpu_usage=$(docker stats --no-stream --format "{{.CPUPerc}}" | sed 's/%//' | awk '{sum+=$1} END {print sum/NR}')
if (( $(echo "$cpu_usage > $ALERT_THRESHOLD_CPU" | bc -l) )); then
    echo "HIGH CPU ALERT: ${cpu_usage}% usage detected" |       mail -s "VaultWarden CPU Alert" admin@your-domain.com
fi

# Check memory usage
memory_usage=$(free | grep Mem | awk '{printf "%.0f", ($3/$2)*100}')
if [ "$memory_usage" -gt "$ALERT_THRESHOLD_MEMORY" ]; then
    echo "HIGH MEMORY ALERT: ${memory_usage}% usage detected" |       mail -s "VaultWarden Memory Alert" admin@your-domain.com
fi

# Check disk usage
disk_usage=$(df $PROJECT_STATE_DIR | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$disk_usage" -gt "$ALERT_THRESHOLD_DISK" ]; then
    echo "HIGH DISK USAGE ALERT: ${disk_usage}% usage detected" |       mail -s "VaultWarden Disk Alert" admin@your-domain.com
fi
EOF

chmod +x tools/custom-alerts.sh

# Add to cron for regular checks
echo "*/15 * * * * /path/to/tools/custom-alerts.sh >/dev/null 2>&1" | crontab -
```

## Log Monitoring and Analysis

### Centralized Log Management

#### Log File Locations
```bash
# Application logs
$PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log
$PROJECT_STATE_DIR/logs/caddy/access.log
$PROJECT_STATE_DIR/logs/caddy/error.log
$PROJECT_STATE_DIR/logs/fail2ban/fail2ban.log

# System logs
/var/log/syslog
/var/log/auth.log
/var/log/docker.log
```

#### Log Analysis Tools
```bash
# Real-time log monitoring
tail -f $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log

# Log pattern analysis
grep -E "(ERROR|WARN)" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log |   tail -20

# Access log analysis
awk '{print $1, $7, $9}' $PROJECT_STATE_DIR/logs/caddy/access.log |   grep -E " (404|500) " | tail -10
```

### Automated Log Analysis

#### Log Rotation and Retention
```bash
# Configure log rotation
cat > /etc/logrotate.d/vaultwarden << EOF
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

# Test log rotation
sudo logrotate -d /etc/logrotate.d/vaultwarden
```

#### Log Monitoring Script
```bash
# Create log monitoring script
cat > tools/log-monitor.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

LOG_DIR="$PROJECT_STATE_DIR/logs"
ALERT_EMAIL="admin@your-domain.com"

# Monitor for critical errors
error_count=$(find $LOG_DIR -name "*.log" -mmin -5 -exec grep -l "ERROR\|CRITICAL\|FATAL" {} \; | wc -l)
if [ "$error_count" -gt 0 ]; then
    echo "CRITICAL ERRORS detected in logs (last 5 minutes)" |       mail -s "VaultWarden Log Alert" $ALERT_EMAIL
fi

# Monitor authentication failures
auth_failures=$(find $LOG_DIR -name "vaultwarden.log" -mmin -15 -exec grep -c "Invalid password" {} \;)
if [ "$auth_failures" -gt 10 ]; then
    echo "HIGH AUTH FAILURE RATE: $auth_failures failures in last 15 minutes" |       mail -s "VaultWarden Security Alert" $ALERT_EMAIL
fi

# Monitor HTTP errors
http_errors=$(find $LOG_DIR -name "access.log" -mmin -10 -exec awk '$9 >= 400 {count++} END {print count+0}' {} \;)
if [ "$http_errors" -gt 50 ]; then
    echo "HIGH HTTP ERROR RATE: $http_errors errors in last 10 minutes" |       mail -s "VaultWarden HTTP Alert" $ALERT_EMAIL
fi
EOF

chmod +x tools/log-monitor.sh

# Add to cron for regular monitoring
echo "*/5 * * * * /path/to/tools/log-monitor.sh >/dev/null 2>&1" | crontab -
```

## Dashboard and Reporting

### System Health Dashboard

#### Create Health Dashboard Script
```bash
# Create comprehensive health dashboard
cat > tools/dashboard.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

echo "=== VaultWarden System Health Dashboard ==="
echo "Generated: $(date)"
echo

# Service Status
echo "=== Service Status ==="
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"
echo

# Resource Usage
echo "=== Resource Usage ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
echo

# System Resources
echo "=== System Resources ==="
df -h $PROJECT_STATE_DIR | grep -v "Filesystem"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
echo

# Database Status
echo "=== Database Status ==="
db_size=$(du -sh $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 | awk '{print $1}')
user_count=$(echo "SELECT COUNT(*) FROM users;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 2>/dev/null || echo "N/A")
item_count=$(echo "SELECT COUNT(*) FROM cipher;" | sqlite3 $PROJECT_STATE_DIR/data/bwdata/db.sqlite3 2>/dev/null || echo "N/A")
echo "Database Size: $db_size"
echo "Users: $user_count"
echo "Vault Items: $item_count"
echo

# Security Status
echo "=== Security Status ==="
echo "Firewall: $(sudo ufw status | head -1 | awk '{print $2}')"
echo "Fail2ban: $(sudo fail2ban-client status 2>/dev/null | grep "Number of jail" || echo "Not available")"
banned_ips=$(sudo fail2ban-client status vaultwarden-auth 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
echo "Banned IPs: $banned_ips"
echo

# Certificate Status
echo "=== SSL Certificate ==="
cert_expiry=$(echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
echo "Certificate Expires: $cert_expiry"
echo

# Backup Status
echo "=== Backup Status ==="
last_backup=$(ls -t $PROJECT_STATE_DIR/backups/ 2>/dev/null | head -1)
if [ -n "$last_backup" ]; then
    echo "Last Backup: $last_backup"
    echo "Backup Age: $(find $PROJECT_STATE_DIR/backups/$last_backup -mtime +1 && echo ">24h" || echo "<24h")"
else
    echo "No backups found"
fi
EOF

chmod +x tools/dashboard.sh
```

#### Automated Reporting
```bash
# Create daily status report
cat > tools/daily-report.sh << 'EOF'
#!/bin/bash
source "$(dirname "$0")/../lib/logging.sh"

REPORT_EMAIL="admin@your-domain.com"
REPORT_FILE="/tmp/vaultwarden-daily-report.txt"

# Generate comprehensive daily report
{
    echo "VaultWarden Daily Status Report"
    echo "Date: $(date)"
    echo "================================"
    echo

    # System health summary
    ./tools/check-health.sh --summary
    echo

    # Resource usage trends
    echo "Resource Usage (24h average):"
    docker stats --no-stream --format "{{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}}"
    echo

    # Security summary
    echo "Security Events (last 24h):"
    auth_attempts=$(grep -c "login_attempt" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log 2>/dev/null || echo "0")
    failed_attempts=$(grep -c "Invalid password" $PROJECT_STATE_DIR/logs/vaultwarden/vaultwarden.log 2>/dev/null || echo "0")
    banned_ips=$(sudo fail2ban-client status vaultwarden-auth 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")

    echo "Authentication attempts: $auth_attempts"
    echo "Failed authentications: $failed_attempts"
    echo "Currently banned IPs: $banned_ips"
    echo

    # Backup status
    echo "Backup Status:"
    last_backup=$(ls -t $PROJECT_STATE_DIR/backups/ 2>/dev/null | head -1)
    echo "Last backup: ${last_backup:-'None found'}"
    echo

} > $REPORT_FILE

# Email the report
mail -s "VaultWarden Daily Report - $(date +%Y-%m-%d)" $REPORT_EMAIL < $REPORT_FILE
rm -f $REPORT_FILE
EOF

chmod +x tools/daily-report.sh

# Schedule daily reports
echo "0 8 * * * /path/to/tools/daily-report.sh >/dev/null 2>&1" | crontab -
```

## Advanced Monitoring Integration

### External Monitoring Services

#### Uptime Monitoring Services
For external monitoring, configure these popular services:
- **UptimeRobot**: Free tier monitors 50 endpoints
- **Pingdom**: Comprehensive uptime and performance monitoring
- **StatusCake**: Global monitoring network
- **Site24x7**: Full-stack monitoring solution

#### Monitoring Endpoint Setup
```bash
# Create health endpoint for external monitoring
cat > caddy/health-check.caddy << EOF
/health {
    respond "OK" 200
}

/api/config {
    # Allow monitoring of API endpoint
    header Access-Control-Allow-Origin *
}
EOF

# Include in main Caddyfile
echo "import /etc/caddy-extra/health-check.caddy" >> caddy/Caddyfile
```

### Metrics Collection and Visualization

#### Prometheus Integration (Advanced)
```bash
# Add Prometheus metrics collection
cat >> docker-compose.yml << EOF
  prometheus:
    image: prom/prometheus:latest
    container_name: \${CONTAINER_NAME_PROMETHEUS:-\${COMPOSE_PROJECT_NAME}_prometheus}
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    profiles:
      - monitoring

volumes:
  prometheus_data:
    driver: local

EOF

# Create Prometheus configuration
mkdir -p monitoring
cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'caddy'
    static_configs:
      - targets: ['caddy:2019']

  - job_name: 'vaultwarden'
    static_configs:
      - targets: ['vaultwarden:8080']
    metrics_path: '/metrics'
EOF
```

This comprehensive monitoring guide provides the foundation for maintaining visibility into your VaultWarden-OCI-NG deployment's health, performance, and security posture. Regular monitoring ensures optimal performance and early detection of potential issues.
