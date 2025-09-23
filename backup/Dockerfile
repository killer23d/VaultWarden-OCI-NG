FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    mariadb-client \
    gnupg \
    tar \
    gzip \
    msmtp \
    bsd-mailx \
    cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /home/ubuntu/backup

COPY backup.sh /home/ubuntu/backup/backup.sh
COPY restore.sh /home/ubuntu/backup/restore.sh
COPY crontab /etc/cron.d/backup-cron

RUN chmod +x /home/ubuntu/backup/backup.sh /home/ubuntu/backup/restore.sh && \
    chmod 0644 /etc/cron.d/backup-cron && \
    crontab /etc/cron.d/backup-cron

CMD ["cron", "-f"]
