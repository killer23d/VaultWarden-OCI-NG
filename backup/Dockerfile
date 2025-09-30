FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    bash \
    mysql-client \
    tar \
    gzip \
    gnupg \
    rclone \
    msmtp \
    mailx \
    curl \
    netcat-openbsd \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create backup user with consistent UID/GID
RUN addgroup -g 1000 backup && adduser -u 1000 -S backup -G backup

# Set up directories with proper permissions
RUN mkdir -p /backups /var/log/backup /etc/crontabs /home/backup/.config/rclone \
    && chown -R backup:backup /backups /var/log/backup /home/backup \
    && chmod 700 /home/backup/.config/rclone

# Copy scripts and entrypoint
COPY db-backup.sh /backup/db-backup.sh
COPY db-restore.sh /backup/db-restore.sh
COPY verify-backup.sh /backup/verify-backup.sh
COPY entrypoint.sh /backup/entrypoint.sh

# Make scripts executable
RUN chmod +x /backup/*.sh

# Set up cron jobs
RUN echo "0 2 * * * /backup/db-backup.sh" > /etc/crontabs/backup && \
    echo "0 6 * * 0 /backup/db-backup.sh --force" >> /etc/crontabs/backup && \
    chmod 600 /etc/crontabs/backup

# Health check with enhanced validation
HEALTHCHECK --interval=30m --timeout=15s --retries=3 --start-period=120s \
    CMD /backup/entrypoint.sh --health-check

# Switch to backup user
USER backup
WORKDIR /backup

# Use entrypoint for proper initialization
ENTRYPOINT ["/backup/entrypoint.sh"]
CMD ["crond", "-f", "-l", "8"]
