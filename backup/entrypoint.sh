# Mark successful backup
date > /backup/last_success

# Prune old backups (older than 14 days)
find /backup -type f -name "*.tar.gz.enc" -mtime +14 -delete
