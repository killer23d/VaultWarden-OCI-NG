FROM ubuntu:22.04

# Install only essential packages for backup operations
RUN apt-get update && apt-get install -y \
    gpg \
    msmtp \
    ca-certificates \
    curl \
    tar \
    gzip \
    cron \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install rclone
RUN curl https://rclone.org/install.sh | bash

# Create backup directory
RUN mkdir -p /backup

# Copy backup scripts
COPY backup.sh /backup/backup.sh
COPY restore.sh /backup/restore.sh

# Make scripts executable
RUN chmod +x /backup/backup.sh /backup/restore.sh

# Setup cron
COPY crontab /etc/cron.d/backup-crontab
RUN chmod 0644 /etc/cron.d/backup-crontab
RUN crontab /etc/cron.d/backup-crontab

# Create log directory
RUN mkdir -p /var/log/backup

# Set up proper timezone handling
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Start cron in foreground
CMD ["cron", "-f"]
