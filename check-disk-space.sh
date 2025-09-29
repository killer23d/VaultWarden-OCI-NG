#!/bin/bash
# check-disk-space.sh - Monitor disk usage and send alerts

set -euo pipefail

# Source settings
if [ -f ./settings.env ]; then
    source ./settings.env
else
    echo "ERROR: settings.env not found"
    exit 1
fi

# Configuration
THRESHOLD=${DISK_ALERT_THRESHOLD:-85}  # Alert when disk usage exceeds this percentage
DATA_DIR="./data"

# Function to get container ID dynamically
get_container_id() {
    local service_name=$1
    docker compose ps -q "$service_name" 2>/dev/null || echo ""
}

# Function to send alert
send_alert() {
    local message=$1
    local subject="Vaultwarden Disk Space Alert"
    
    echo "$(date): $message"
    
    # Send email notification if configured
    if [ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_FROM:-}" ] && [ -n "${ALERT_EMAIL:-}" ]; then
        backup_id=$(get_container_id "backup")
        if [ -n "$backup_id" ]; then
            echo "$message" | docker exec -i "$backup_id" msmtp "$ALERT_EMAIL" --subject="$subject" || echo "Failed to send email alert"
        fi
    fi
}

# Check data directory disk usage
if [ -d "$DATA_DIR" ]; then
    usage=$(df "$DATA_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
    
    echo "Current disk usage: ${usage}%"
    
    if [ "$usage" -gt "$THRESHOLD" ]; then
        send_alert "WARNING: Disk usage is ${usage}% (threshold: ${THRESHOLD}%). Please free up space or expand storage."
        
        # Show largest directories
        echo "Largest directories in data folder:"
        du -sh "$DATA_DIR"/* 2>/dev/null | sort -hr | head -10
        
        # Suggest cleanup actions
        echo ""
        echo "Cleanup suggestions:"
        echo "1. Check backup retention: old backups in $DATA_DIR/backups/"
        echo "2. Rotate logs: check $DATA_DIR/caddy_logs/ and $DATA_DIR/backup_logs/"
        echo "3. Database maintenance: consider optimizing MariaDB"
        
        exit 1
    else
        echo "Disk usage OK (${usage}% < ${THRESHOLD}%)"
    fi
else
    send_alert "ERROR: Data directory $DATA_DIR not found"
    exit 1
fi

# Check container disk usage
echo ""
echo "Container disk usage:"
containers=("vaultwarden" "mariadb" "redis" "caddy" "fail2ban" "backup")
for service in "${containers[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        size=$(docker exec "$container_id" du -sh / 2>/dev/null | cut -f1 || echo "unknown")
        echo "  $service: $size"
    fi
done

echo "Disk space check completed successfully"
