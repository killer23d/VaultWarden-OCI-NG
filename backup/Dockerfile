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

# Create backup user
RUN addgroup -S backup && adduser -S backup -G backup

# Set up directories
RUN mkdir -p /backups /var/log/backup /etc/crontabs
RUN chown -R backup:backup /backups /var/log/backup

# Copy scripts
COPY db-backup.sh /backup/db-backup.sh
COPY restore.sh /backup/restore.sh
RUN chmod +x /backup/*.sh

# Set up cron job for automated database backups
RUN echo "0 2 * * * /backup/db-backup.sh" > /etc/crontabs/root
RUN echo "0 6 * * 0 /backup/db-backup.sh --force" >> /etc/crontabs/root

# Health check with database connectivity
HEALTHCHECK --interval=30m --timeout=15s --retries=3 --start-period=120s \
    CMD pgrep crond >/dev/null && test -w /backups || exit 1

USER backup
WORKDIR /backup

CMD ["crond", "-f", "-l", "8"]
