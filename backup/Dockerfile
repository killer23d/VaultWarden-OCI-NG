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

WORKDIR /opt/backup

COPY backup.sh /opt/backup/backup.sh
RUN chmod +x /opt/backup/backup.sh

# Run cron by default
CMD ["cron", "-f"]
