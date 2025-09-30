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
    tzdata \
    && rm -rf /var/cache/apk/*

# Create backup user
RUN addgroup -S backup && adduser -S backup -G backup

# Set up directories
RUN mkdir -p /backups /var/log/backup /etc/crontabs
RUN chown -R backup:backup /backups /var/log/backup

# Copy scripts
COPY backup.sh /backup/backup.sh
COPY restore.sh /backup/restore.sh
RUN chmod +x /backup/*.sh

# Set up cron job for automated backups
RUN echo "0 2 * * * /backup/backup.sh" > /etc/crontabs/root
RUN echo "0 6 * * 0 /backup/backup.sh --force" >> /etc/crontabs/root  # Weekly forced backup

# Health check
HEALTHCHECK --interval=30m --timeout=10s --retries=3 --start-period=60s \
    CMD pgrep crond >/dev/null && test -w /backups || exit 1

USER backup
WORKDIR /backup

CMD ["crond", "-f", "-l", "8"]
