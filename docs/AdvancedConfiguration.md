# Advanced Configuration

**Optional tunables; security-hardening options for non-root containers and validation**

## Docker Security Options (Optional)

```yaml
services:
  vaultwarden:
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:noexec,nosuid,nodev

  caddy:
    security_opt:
      - no-new-privileges:true
    cap_add:
      - NET_BIND_SERVICE
    cap_drop:
      - ALL
```

## Resource Limits

```yaml
  vaultwarden:
    deploy:
      resources:
        limits:
          memory: 1.5G
          cpus: '0.75'
        reservations:
          memory: 256M
```

## Admin Panel Security

- Increase admin rate limits in Caddy
- Restrict admin by IP via Cloudflare firewall rules

## Input Validation Hooks

- `lib/validation.sh` functions can be used in your custom scripts
- Call before writing `.env` or secrets to prevent mistakes

```bash
source lib/validation.sh
validate_domain_format "$DOMAIN"
validate_email_format "$ADMIN_EMAIL"
```

## Backup Tuning

- Adjust retention in `lib/constants.sh`
- Change backup windows to avoid peak hours

## Cloudflare Modes

- “Under Attack” mode during incidents
- Country-based challenges for admin paths
