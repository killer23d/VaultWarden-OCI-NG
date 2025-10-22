# Emergency Recovery Guide

**15–30 minute recovery from Emergency Kit; updated with validation and non-root fixes**

## 📦 What’s in the Emergency Kit

- Encrypted config and documentation
- Age keys (public and optional rotated key material)
- Minimal scripts and guides to recover

## 🧯 When to Use

- Host loss or corruption
- Database irreparable issues
- Certificate or secrets compromise

## 🚑 Recovery Steps

```bash
# 1) Provision fresh Ubuntu 24.04 VM
# 2) Install git and clone repo
sudo apt update -y && sudo apt install -y git
cd /opt && sudo git clone https://github.com/killer23d/VaultWarden-OCI-NG
cd VaultWarden-OCI-NG && chmod +x startup.sh tools/*.sh lib/*.sh

# 3) Install dependencies
sudo ./tools/install-deps.sh --auto

# 4) Decrypt and extract kit
age -d -i emergency-key.txt emergency-kit.tar.gz.age | tar -xzf -

# 5) Restore critical files
cp emergency-kit/.env ./.env
cp -r emergency-kit/secrets ./secrets
chmod 600 secrets/keys/age-key.txt

# 6) Validate restored config
source lib/validation.sh
validate_domain_format "$(grep '^DOMAIN=' .env | cut -d'=' -f2)"
validate_email_format "$(grep '^ADMIN_EMAIL=' .env | cut -d'=' -f2)"

# 7) Initialize (restore mode may be no-op if files present)
sudo ./tools/init-setup.sh --restore-mode || true

# 8) Fix ownership for non-root containers (one-time)
sudo chown -R 1000:1000 /var/lib/vaultwarden/

# 9) Start services
./startup.sh

# 10) Verify
./tools/check-health.sh --comprehensive
docker compose exec vaultwarden whoami
docker compose exec caddy whoami
```

## 🔐 Post-Recovery Actions

- Rotate admin basic auth password
- Verify SMTP and Cloudflare integration
- Generate new emergency kit and store offsite

## 🧭 Tips

- Keep emergency key offline (USB, password manager)
- Test recovery quarterly
- Use Cloudflare DNS for fastest cutover
