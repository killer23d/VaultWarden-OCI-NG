# FAQ & Reference Guide

**Quick answers and references for VaultWarden-OCI-NG with security enhancements**

## 🚀 Quick Start Questions

**Q: Why does init-setup reject my domain?**  
A: Use clean domain format like `vault.example.com` without `https://` or trailing slashes. The validation prevents common setup mistakes.

**Q: Why does init-setup reject my email?**  
A: Email must be properly formatted like `admin@example.com`. The validation catches missing @ symbols, incomplete domains, and security risks.

**Q: Which containers run as non-root?**  
A: VaultWarden and Caddy run as user 1000:1000. fail2ban runs as root (needs iptables), watchtower runs as default (needs Docker socket).

**Q: How do I fix permission errors after upgrading?**  
A: Run `sudo chown -R 1000:1000 /var/lib/vaultwarden/ ./caddy/` once after upgrading to non-root containers.

## 🔧 Operations Questions

**Q: How do I restart everything?**  
A: `./startup.sh --force-restart`

**Q: How do I check system health?**  
A: `./tools/check-health.sh --comprehensive`

**Q: How do I create a manual backup?**  
A: `./tools/backup-monitor.sh --db-only` or `./tools/create-emergency-kit.sh --email`

**Q: How do I change my domain/admin email safely?**  
A: Edit `.env`, then validate with `source lib/validation.sh && validate_domain_format "new.domain.com"` before restarting.

## 🔒 Security Questions

**Q: Is this secure out of the box?**  
A: Yes. Non-root containers, input validation, Cloudflare integration, fail2ban, UFW firewall, and Age encryption are enabled by default.

**Q: Can I run this on a public VPS?**  
A: Yes, that's the primary use case. Enable Cloudflare proxy and configure UFW properly.

**Q: How do I verify container security?**  
A: Run `docker compose exec vaultwarden whoami` and `docker compose exec caddy whoami` - both should show user 1000 or container username.

## 📧 Email/SMTP Questions

**Q: Gmail SMTP not working?**  
A: Use App Password, not regular password. Set `SMTP_HOST: "smtp.gmail.com"`, `SMTP_PORT: "587"`, `SMTP_SECURITY: "starttls"`.

**Q: How do I test email delivery?**  
A: `./tools/backup-monitor.sh --test-email`

## 🔄 Backup Questions

**Q: Where are backups stored?**  
A: Local: `backups/db/` and `backups/full/`. Emergency kits emailed and stored in `backups/emergency-kits/`.

**Q: How do I restore from backup?**  
A: `./tools/backup-recovery.sh --restore /path/to/backup.age --confirm`

## 🌐 Network Questions

**Q: Can I use this without Cloudflare?**  
A: Yes, but you'll need to configure UFW to allow HTTP/HTTPS from all IPs instead of just Cloudflare ranges.

**Q: How do I troubleshoot certificate issues?**  
A: Check DNS with `dig yourdomain.com`, verify Caddy logs with `docker compose logs caddy`, and ensure ports 80/443 are accessible.

## 🎛️ Configuration Questions

**Q: How do I edit encrypted secrets?**  
A: `./tools/edit-secrets.sh` - uses your Age key to decrypt, edit, and re-encrypt.

**Q: Can I customize the Docker Compose file?**  
A: Yes, but preserve the security settings (user: "1000:1000" for vaultwarden/caddy, capabilities for fail2ban).

## 📊 Performance Questions

**Q: What are the minimum requirements?**  
A: 1 vCPU, 2GB RAM, 20GB disk. Recommended: 1 vCPU, 6GB RAM, 50GB disk.

**Q: How many users can this support?**  
A: 10-50 users comfortably on recommended specs. SQLite scales surprisingly well for VaultWarden workloads.

## 🛠️ Troubleshooting Quick Reference

**Service won't start:**
```bash
docker compose down
./startup.sh --force-restart
docker compose logs
```

**Permission denied errors:**
```bash
sudo chown -R 1000:1000 /var/lib/vaultwarden/ ./caddy/
docker compose restart
```

**Can't access web interface:**
```bash
sudo ufw status
dig yourdomain.com
curl -I https://yourdomain.com
```

**Input validation failing:**
```bash
source lib/validation.sh
validate_domain_format "yourdomain.com"
validate_email_format "you@yourdomain.com"
```

## 📚 Key File Locations

- **Configuration**: `.env`, `secrets/secrets.yaml`
- **Keys**: `secrets/keys/age-key.txt`
- **Data**: `/var/lib/vaultwarden/data/bwdata/`
- **Logs**: `/var/lib/vaultwarden/logs/`, `docker compose logs`
- **Backups**: `backups/db/`, `backups/full/`

## 🎯 Common Workflows

**Initial Setup:**
```bash
git clone && cd VaultWarden-OCI-NG
sudo ./tools/install-deps.sh --auto
sudo ./tools/init-setup.sh --domain vault.example.com --email admin@example.com
./tools/edit-secrets.sh
./startup.sh
```

**Daily Check:**
```bash
./tools/check-health.sh
docker compose logs --tail=50
```

**Security Audit:**
```bash
sudo ./tools/host-maintenance.sh --security-audit
docker compose exec vaultwarden whoami
docker compose exec caddy whoami
```
