FROM alpine:latest
RUN apk add --no-cache mariadb-client gnupg tar gzip msmtp bsd-mailx awscli cronie
WORKDIR /backup
COPY backup.sh /backup/backup.sh
COPY restore.sh /backup/restore.sh
COPY crontab /etc/cron.d/backup-cron
COPY msmtprc /etc/msmtprc
RUN chmod +x /backup/backup.sh /backup/restore.sh && \
    chmod 0644 /etc/cron.d/backup-cron && \
    crontab /etc/cron.d/backup-cron
CMD ["crond", "-f"]
