# backup/Dockerfile
# Multi-arch (arm64/amd64) friendly. Creates non-root 'backup' user.
FROM debian:bookworm-slim

LABEL maintainer="you@example.com"
ENV DEBIAN_FRONTEND=noninteractive

# Create backup user
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    gpg \
    gnupg \
    msmtp \
    ca-certificates \
    curl \
    jq \
    tar \
    gzip \
    coreutils \
    procps \
    cron \
    dirmngr \
    gnupg2 \
    less \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r backup && useradd -r -g backup -d /backup -s /sbin/nologin backup \
  && mkdir -p /backup /var/log/backup /etc/msmtp.d \
  && chown -R backup:backup /backup /var/log/backup /etc/msmtp.d

COPY backup.sh /backup/backup.sh
COPY restore.sh /backup/restore.sh
COPY crontab /etc/cron.d/bw_backup
COPY msmtprc /etc/msmtp.d/msmtprc.template

RUN chmod 700 /backup/backup.sh /backup/restore.sh \
  && chmod 644 /etc/cron.d/bw_backup \
  && crontab /etc/cron.d/bw_backup \
  && chmod -R 700 /etc/msmtp.d

USER backup
WORKDIR /backup

ENTRYPOINT ["/backup/backup.sh"]
