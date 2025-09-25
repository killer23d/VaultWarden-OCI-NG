# Vaultwarden on OCI A1 Flex Free Tier

Self-hosted Vaultwarden deployment for 3-5 users on OCI A1 Flex Free Tier (1 OCPU, 6GB RAM, Ubuntu 24.04 Minimal, 50GB boot volume) with Cloudflare DDNS and MailerSend SMTP. Backups are stored in `./data/backups` and emailed to `backup@mydomain.com`. Data is grouped in `./data/`, with configurations in the root.

## Folder Structure
```
bitwardenUnified-OCI/
├── data/
│   ├── mariadb/
│   ├── bwdata/
│   ├── backups/
│   ├── caddy_data/
│   ├── caddy_config/
│   ├── caddy_logs/
│   ├── backup_logs/
│   ├── fail2ban/
│   └── redis/
├── caddy/
│   └── Caddyfile
├── ddclient/
│   └── ddclient.conf
├── fail2ban/
│   ├── jail.local
│   └── filter.d/
│       ├── bitwarden.conf
│       └── bitwarden-admin.conf
├── backup/
│   ├── Dockerfile
│   ├── backup.sh
│   ├── restore.sh
│   ├── crontab
│   └── msmtprc
└── settings.env
```

## Prerequisites
- OCI A1 Flex Free Tier instance (1 OCPU, 6GB RAM, Ubuntu 24.04 Minimal, 50GB boot volume).
- Reserved Public IP.
- Cloudflare account with API token and DNS configured.
- MailerSend account for SMTP relay.
- Domain (set as `APP_DOMAIN` in `settings.env`, e.g., `vault.mydomain.com`).
- (Optional) OCI Vault for storing `settings.env` (Free Tier: 5 secrets, 5MB total).

## Setup
1. **Install Docker and Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y docker.io docker-compose jq
   sudo usermod -aG docker $USER
   newgrp docker
   ```
2. **(For OCI Vault) Install OCI CLI**:
   ```bash
   curl -L -o /tmp/oci_install.sh https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh
   bash /tmp/oci_install.sh --accept-all-defaults
   oci setup config  # Configure with OCI user credentials
   ```
3. **Configure Storage**:
   ```bash
   mkdir -p data/{mariadb,bwdata,backups,caddy_data,caddy_config,caddy_logs,backup_logs,fail2ban,redis} caddy ddclient fail2ban/filter.d backup
   chmod -R 777 data
   ```
4. **Configure Secrets**:
   - **Option 1: Local Storage**:
     - Create/edit `settings.env`:
       ```bash
       nano settings.env
       ```
     - Set `APP_DOMAIN` (e.g., `vault.mydomain.com`), passwords (`openssl rand -base64 32`), MailerSend SMTP (`SMTP_USER`, `SMTP_PASSWORD`), Cloudflare token (`DDCLIENT_PASSWORD`).
   - **Option 2: OCI Vault**:
     - Create `settings.env` locally, then store in OCI Vault:
       ```bash
       echo -n "$(cat settings.env | base64)" > secrets.b64
       oci vault secret create --compartment-id <compartment-id> --secret-name bitwarden-secrets --secret-content '{"content": "'$(cat secrets.b64)'"}'
       ```
     - Fetch during deployment:
       ```bash
       oci vault secret get --secret-id <secret-ocid> --raw-output | jq -r '.data."secret-content".content' | base64 -d > settings.env
       ```
5. **Deploy**:
   ```bash
   sudo docker-compose up -d
   ```
6. **Verify**:
   - HTTPS: `https://<APP_DOMAIN>`
   - Logs: `sudo docker logs vaultwarden caddy vaultwarden_backup`
   - `fail2ban`: `sudo fail2ban-client status bitwarden`
   - Backups: Check `./data/backups`, verify emails at `backup@mydomain.com`
   - Restore: `docker exec vaultwarden_backup /backup/restore.sh /backups/bitwarden_backup_YYYYMMDD-HHMMSS.tar.gz.gpg`
   - DDNS: `dig <APP_DOMAIN>`
   - Storage: `df -h` (50GB boot volume)

## Troubleshooting
- Check logs: `sudo docker logs <container>`.
- Verify DNS: `dig <APP_DOMAIN>`.
- Test `fail2ban`: `sudo fail2ban-client status`.
- Ensure OCI Security List allows TCP 80/443.
- Verify Cloudflare proxy, MailerSend SMTP, `api.myip.com` access.
- Monitor CPU/RAM: `top` (1 OCPU, 6GB RAM).

## Maintenance
- Update: `docker-compose pull && docker-compose up -d`
- Monitor storage: `df -h`
- Check logs: `./data/backup_logs/backup.log`, `./data/bwdata/logs`