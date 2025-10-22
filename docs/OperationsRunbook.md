# Operations Runbook

**Day-2 operations with security validation and non-root container awareness**

This runbook describes daily/weekly/monthly operational tasks, now including security checks for container users and input validation for configuration changes.

## 🗓 Daily

- Check overall health
```bash
./tools/check-health.sh
```
- Scan logs for anomalies
```bash
docker compose logs --tail=200 | grep -Ei "error|warning|rate|ban"
```
- Verify certificates and DNS
```bash
./tools/check-health.sh --component certificates
dig +short $DOMAIN
```

## 📅 Weekly

- Apply security updates
```bash
sudo ./tools/host-maintenance.sh --auto
```
- Validate backups
```bash
./tools/backup-monitor.sh --db-only
./tools/backup-recovery.sh --verify $(ls -t backups/db/*.age | head -1)
```
- Validate container security
```bash
docker compose exec vaultwarden whoami
docker compose exec caddy whoami
sudo ls -la /var/lib/vaultwarden/ | head -10
```

## 🗓 Monthly

- Optimize database
```bash
./tools/sqlite-maintenance.sh --optimize --vacuum
```
- Review firewall and Cloudflare
```bash
./tools/update-cloudflare-ips.sh --validate
sudo ufw status verbose
```
- Review secrets health
```bash
source lib/validation.sh
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)"
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)"
```

## 🔧 Common Ops Procedures

### Restart Stack
```bash
./startup.sh --force-restart
```

### Change Admin Email/Domain (Validated)
```bash
# Update .env
sed -i "s/^ADMIN_EMAIL=.*/ADMIN_EMAIL=new-admin@example.com/" .env
sed -i "s/^DOMAIN=.*/DOMAIN=vault.newdomain.com/" .env

# Validate
source lib/validation.sh
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)"
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)"

# Restart
./startup.sh --force-restart
```

### Permission Repair (Non-Root)
```bash
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/
```

### Security Audit
```bash
sudo ./tools/host-maintenance.sh --security-audit
```

## 📈 SLIs/SLOs (Lightweight)

- Availability: UI reachable, `/alive` returns 200 < 2s
- Latency: API P50 < 1s, Admin P50 < 1.5s
- Backups: DB daily, full weekly, verify monthly
- Security: Containers non-root (vw, caddy), fail2ban active, certificates > 30 days
