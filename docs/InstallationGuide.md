# Installation Guide

**Comprehensive, secure installation of VaultWarden-OCI-NG with input validation and non-root containers**

This guide walks through a production-grade installation with enhanced security defaults: input validation for setup and non-root container execution for VaultWarden and Caddy.

## 📦 Prerequisites

- Ubuntu 24.04 LTS (fresh install recommended)
- Sudo privileges on the host
- Domain name and DNS control
- SMTP credentials (App Password recommended)
- Optional: Cloudflare account and API token

## 🧰 Install Steps

### 1) Clone and Prepare
```bash
sudo apt update -y && sudo apt install -y git

# Clone repository
cd /opt && sudo git clone https://github.com/killer23d/VaultWarden-OCI-NG
sudo chown -R $USER:$USER VaultWarden-OCI-NG
cd VaultWarden-OCI-NG

# Make scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh
```

### 2) Install Dependencies
```bash
sudo ./tools/install-deps.sh --auto

# Verify core tools
docker --version
age --version
sops --version
```

### 3) Initialize with Validation
```bash
# Provide a clean domain (no protocol) and valid admin email
sudo ./tools/init-setup.sh --domain vault.example.com --email admin@example.com
```

What this does:
- Generates Age keys and SOPS config
- Creates .env and state directories
- Configures UFW + fail2ban
- Validates domain and email formats (new)
- Creates initial emergency kit

### 4) Configure Secrets (Encrypted)
```bash
./tools/edit-secrets.sh
```
Set at minimum:
```yaml
DOMAIN: "vault.example.com"
ADMIN_EMAIL: "admin@example.com"
SMTP_HOST: "smtp.gmail.com"
SMTP_PORT: "587"
SMTP_USERNAME: "your@gmail.com"
SMTP_PASSWORD: "app-specific-password"
SMTP_FROM: "vault@yourdomain.com"
SMTP_SECURITY: "starttls"
```

### 5) First Startup (Non-Root Containers)
```bash
./startup.sh

# Verify services
./tools/check-health.sh --comprehensive
```

By default:
- VaultWarden runs as user 1000:1000
- Caddy runs as user 1000:1000
- fail2ban runs as root (required for iptables)
- ddclient runs as non-root via PUID/PGID
- watchtower runs with Docker socket access (short-lived)

### 6) Fix Permissions if Needed (One-Time)
```bash
# If you upgraded from a prior version or see permission errors
sudo chown -R 1000:1000 /var/lib/vaultwarden/
sudo chown -R 1000:1000 ./caddy/
```

## 🔒 Security Defaults

- Non-root container execution for VaultWarden and Caddy
- Input validation for domain and email during setup
- UFW configured with Cloudflare IP allowlisting helper
- fail2ban enabled and configured
- Strong defaults for logging and rate limits

## 🧪 Validation and Tests

```bash
# Validate container users
docker compose exec vaultwarden whoami
docker compose exec caddy whoami

# Validate input functions
source lib/validation.sh
validate_domain_format "vault.example.com"
validate_email_format "admin@example.com"
```

## 🔄 Updates

```bash
# Pull latest changes
cd /opt/VaultWarden-OCI-NG
git pull

# Recreate containers
./startup.sh --force-restart
```

## ❓ FAQ (Install)

- Q: Why do some services still run as root?
  - A: fail2ban needs iptables; watchtower needs Docker socket access. Other services run as non-root.

- Q: Why does init-setup reject my domain?
  - A: Use a clean domain like `vault.example.com` without protocol or slashes.

- Q: Can I run on rootless Docker?
  - A: Supported by Docker, but this project already minimizes privileges with non-root containers where possible.
