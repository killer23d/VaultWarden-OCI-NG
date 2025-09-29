# Vaultwarden on OCI Ampere A1 Flex (Optimized for Small Deployment)

A secure, lightweight Vaultwarden deployment optimized for OCI Ampere A1 Flex (1 CPU, 6GB RAM) serving up to 5 users. This configuration balances security with resource efficiency and includes comprehensive validation tools.

## Features

- **Vaultwarden**: Lightweight Bitwarden-compatible password manager
- **MariaDB**: Resource-optimized database configuration
- **Redis**: Lightweight caching for session management
- **Caddy**: Automatic HTTPS with minimal memory footprint
- **Fail2ban**: Intelligent brute-force protection
- **DDClient**: Dynamic DNS updates
- **Automated Backups**: Encrypted nightly backups with cloud storage
- **Configuration Validation**: Pre-deployment validation scripts


## Prerequisites

- OCI Ampere A1 Flex VM (1 CPU, 6GB RAM) with Ubuntu 22.04 LTS
- Domain name pointing to your server's public IP
- SSH access to the VM
- Basic understanding of Docker and environment variables


## Step 1: Prepare the VM

### Configure Network Security

In OCI Console > Networking > Virtual Cloud Networks:

- Add ingress rule for port 80 (HTTP) from 0.0.0.0/0
- Add ingress rule for port 443 (HTTPS) from 0.0.0.0/0


### Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install additional tools
sudo apt install -y git python3-pip unattended-upgrades
pip3 install oci-cli

# Logout and login again for Docker group changes
```


## Step 2: Project Setup

### Clone and Configure

```bash
git clone https://github.com/killer23d/VaultWarden-OCI.git
cd VaultWarden-OCI
chmod +x *.sh caddy/*.sh backup/*.sh validate-config.sh
```


### Create Directory Structure

```bash
# Create required data directories
mkdir -p data/{bwdata,mariadb,redis,caddy_data,caddy_config,caddy_logs,backups,backup_logs,fail2ban}

# Set proper permissions
sudo chown -R $USER:$USER data/
```


### Configure Environment Variables

Edit `settings.env` and replace all placeholder values:

**Required Changes:**

- `DOMAIN_NAME`: Your actual domain (e.g., example.com)
- `MARIADB_ROOT_PASSWORD`: Generate with `openssl rand -base64 32`
- `MARIADB_PASSWORD`: Generate with `openssl rand -base64 32`
- `ADMIN_TOKEN`: Generate with `openssl rand -base64 32`
- `REDIS_PASSWORD`: Generate with `openssl rand -base64 32`
- `BACKUP_PASSPHRASE`: Strong passphrase for backup encryption
- `CF_API_TOKEN`: Cloudflare API token (if using Cloudflare DNS)
- `FAIL2BAN_DEST`: Email for security notifications
- `SMTP_USER`: MailerSend API token
- `SMTP_PASSWORD`: Same as SMTP_USER for API authentication

**Optional for Push Notifications:**

- `PUSH_INSTALLATION_ID`: From Bitwarden hosting portal
- `PUSH_INSTALLATION_KEY`: From Bitwarden hosting portal


### Validate Configuration

**Always run validation before deployment:**

```bash
./validate-config.sh
```

This script will:

- Check for placeholder values that need replacement
- Verify required files and directories exist
- Validate password strength
- Confirm environment variable consistency
- Report deployment readiness status


## Step 3: OCI Vault Integration (Recommended)

### On Your Local Machine

```bash
# Configure OCI CLI
oci setup config

# Run setup script to create vault and upload secrets
./oci_setup.sh
```


### Create IAM Resources

1. **Dynamic Group**: Create with rule `resource.id = 'your-vm-ocid'`
2. **Policy**: Allow dynamic group to read secrets
```
Allow dynamic-group <group-name> to read secret-bundles where target.secret.id = '<secret-ocid>'
```


## Step 4: Deploy Stack

### Pre-Deployment Validation

```bash
# Validate configuration
./validate-config.sh

# Check Docker Compose syntax
docker-compose config

# Verify all files are present
ls -la caddy/ fail2ban/ backup/
```


### Automatic Deployment (with OCI Vault)

```bash
# Create systemd service
sudo tee /etc/systemd/system/vaultwarden.service > /dev/null <<EOF
[Unit]
Description=Vaultwarden Stack
After=network-online.target docker.service
Requires=docker.service

[Service]
User=$USER
Group=$USER
WorkingDirectory=$HOME/VaultWarden-OCI
Environment="OCI_SECRET_OCID=<your-secret-ocid>"
ExecStart=$HOME/VaultWarden-OCI/startup.sh
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable --now vaultwarden.service
```


### Manual Deployment (without OCI Vault)

```bash
# Validate configuration first
./validate-config.sh

# Start the stack
docker-compose up -d

# Verify all services are healthy
docker-compose ps
docker-compose logs
```


## Step 5: Configure Maintenance

### Automated Updates

```bash
sudo dpkg-reconfigure -plow unattended-upgrades
```


### System Maintenance Cron Jobs

```bash
sudo crontab -e
```

Add these lines (replace `<USER>` with your username):

```cron
# Docker cleanup - Sunday 2 AM
0 2 * * 0 /usr/bin/docker system prune -af

# Update Cloudflare IPs - Sunday 3 AM
0 3 * * 0 /home/<USER>/VaultWarden-OCI/caddy/update_cloudflare_ips.sh >> /home/<USER>/VaultWarden-OCI/data/caddy_logs/cloudflare_update.log 2>&1

# Weekly configuration validation - Sunday 4 AM
0 4 * * 0 cd /home/<USER>/VaultWarden-OCI && ./validate-config.sh >> /home/<USER>/VaultWarden-OCI/data/validation.log 2>&1
```


## Resource Optimization for Small Deployments

### Memory Configuration

The stack is optimized for 6GB RAM with these limits:

- MariaDB: ~512MB working memory
- Redis: 128MB maximum memory
- Vaultwarden: ~256MB typical usage
- Caddy: ~64MB typical usage
- Fail2ban: ~32MB typical usage


### Database Optimization

MariaDB is configured with conservative settings:

- `innodb_buffer_pool_size=256M`
- `max_connections=20`
- `query_cache_size=32M`


### Security Adjustments

Fail2ban policies are tuned for small user bases:

- Longer find times (10 minutes) to reduce false positives
- Progressive banning with reasonable escalation
- Whitelist for Cloudflare IPs


## Required File Structure

Your project should contain these critical files:

```
VaultWarden-OCI/
├── docker-compose.yml
├── settings.env
├── validate-config.sh
├── caddy/
│   ├── Caddyfile
│   ├── cloudflare_ips.caddy
│   └── update_cloudflare_ips.sh
├── fail2ban/
│   ├── jail.local
│   └── filter.d/
├── backup/
│   ├── Dockerfile
│   ├── rclone.conf
│   └── restore.sh
├── ddclient/
└── data/
    ├── bwdata/
    ├── mariadb/
    ├── redis/
    ├── caddy_data/
    ├── caddy_config/
    ├── caddy_logs/
    ├── backups/
    ├── backup_logs/
    └── fail2ban/
```


## Monitoring and Maintenance

### Health Checks

```bash
# Check service status
sudo systemctl status vaultwarden.service

# Validate current configuration
./validate-config.sh

# Check container health
./diagnose.sh

# View logs
docker-compose logs -f [service-name]
```


### Backup Management

- Automated nightly backups to `./data/backups/`
- Backups emailed via MailerSend using SMTP configuration
- Manual restore: `GPG_PASSPHRASE='your-passphrase' ./backup/restore.sh`


### Troubleshooting

**Configuration Validation Failed:**

- Run `./validate-config.sh` to identify specific issues
- Check for unreplaced placeholder values in `settings.env`
- Verify all required files exist in their expected locations

**High Memory Usage:**

- Check `docker stats` for resource consumption
- Restart services: `docker-compose restart`

**Failed Services:**

- Check logs: `docker-compose logs [service]`
- Verify configuration: `docker-compose config`
- Ensure all directories exist with proper permissions

**Connection Issues:**

- Verify DNS resolution
- Check OCI security rules
- Confirm Caddy configuration and port accessibility


## Security Notes

- **Always run validation** before deployment: `./validate-config.sh`
- Change all default passwords before deployment
- Enable OCI Vault for production secrets management
- Monitor fail2ban logs regularly
- Keep system and containers updated
- Use strong backup encryption passphrase
- Regular security audits using included validation tools


## Performance Expectations

For 5 users on 1 CPU/6GB RAM:

- Concurrent users: 5+
- Response time: <500ms typical
- Database: Handles 1000+ vault items efficiently
- Memory usage: 60-70% under normal load
- Storage: <1GB for vault data, ~500MB for logs/backups


## Configuration Validation

The included `validate-config.sh` script provides comprehensive pre-deployment validation:

### What it checks:

- Placeholder value replacement
- Required file existence
- Password strength validation
- Directory structure verification
- Environment variable consistency
- Service configuration syntax


### Usage:

```bash
# Basic validation
./validate-config.sh

# Validation with detailed output
./validate-config.sh --verbose

# Check specific components only
./validate-config.sh --check-config
```

**Never deploy without running validation first!**

This configuration provides enterprise security with resource efficiency optimized for small teams, now with comprehensive validation and error prevention tools.
