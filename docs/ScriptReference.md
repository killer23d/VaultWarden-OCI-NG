# Script Reference

**Operational scripts with notes for security validation and non-root containers**

## Core

- `startup.sh`
  - Orchestrates Docker Compose lifecycle with health checks
  - Notes: After upgrade to non-root containers, may require volume ownership fix once

- `tools/check-health.sh`
  - Comprehensive health and optional auto-fix
  - New: Includes container user checks and certificate validation helpers

- `tools/init-setup.sh`
  - One-time initialization, generates keys, configures firewall and fail2ban
  - New: Validates `--domain` and `--email` inputs; creates `.sops.yaml`

## Security

- `tools/update-firewall-rules.sh`
  - Manages UFW with Cloudflare IP ranges

- `tools/update-cloudflare-ips.sh`
  - Fetches Cloudflare IP ranges for trusted proxies and firewall allowlist

- `tools/host-maintenance.sh`
  - Security updates, cleanup, optional `--security-audit`

- `lib/validation.sh`
  - System checks and NEW input validation functions:
    - `validate_domain_format DOMAIN`
    - `validate_email_format EMAIL`

## Backups

- `tools/backup-monitor.sh`
  - Orchestrates DB/full backups and email notifications

- `tools/backup-recovery.sh`
  - Verifies and restores backups, supports integrity checks

- `tools/create-emergency-kit.sh`
  - Generates encrypted recovery kit and delivers via email

## Maintenance

- `tools/sqlite-maintenance.sh`
  - Integrity check, optimize, reindex, vacuum

- `tools/install-deps.sh`
  - Installs Docker, SOPS, Age and dependencies

## Networking

- `tools/render-ddclient-conf.sh`
  - Renders ddclient config if dynamic DNS is enabled

## Notes on Non-Root Containers

- VaultWarden and Caddy run as UID/GID 1000
- ddclient runs as PUID/PGID 1000 via LinuxServer standards
- fail2ban requires root with NET_ADMIN/NET_RAW for iptables
- If permission errors occur post-upgrade, run:
```bash
sudo chown -R 1000:1000 /var/lib/vaultwarden/ ./caddy/
```
