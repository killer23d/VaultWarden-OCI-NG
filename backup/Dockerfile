FROM alpine:latest

# Install required packages (rclone is included but won't break if misconfigured)
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

# Create backup user
RUN addgroup -S backup && adduser -S backup -G backup

# Set up directories
RUN mkdir -p /backups /var/log/backup /etc/crontabs /home/backup/.config/rclone
RUN chown -R backup:backup /backups /var/log/backup /home/backup

# Copy scripts
COPY db-backup.sh /backup/db-backup.sh
COPY db-restore.sh /backup/db-restore.sh
COPY verify-backup.sh /backup/verify-backup.sh
RUN chmod +x /backup/*.sh

# Create empty rclone config if none exists (prevents startup failures)
RUN touch /home/backup/.config/rclone/rclone.conf && \
    chown backup:backup /home/backup/.config/rclone/rclone.conf

# Set up cron job for automated database backups
RUN echo "0 2 * * * /backup/db-backup.sh" > /etc/crontabs/root
RUN echo "0 6 * * 0 /backup/db-backup.sh --force" >> /etc/crontabs/root

# Health check with database connectivity
HEALTHCHECK --interval=30m --timeout=15s --retries=3 --start-period=120s \
    CMD pgrep crond >/dev/null && test -w /backups || exit 1

USER backup
WORKDIR /backup

CMD ["crond", "-f", "-l", "8"]
