# **Vaultwarden on OCI**

This project provides a comprehensive, secure, and automated setup for self-hosting Vaultwarden, a Bitwarden-compatible server, using Docker Compose. It is optimized for deployment on an Oracle Cloud Infrastructure (OCI) A1 Flex VM but is portable to other environments.

The stack is designed with a security-first approach and includes the following components:

* **Vaultwarden**: The core password manager application.
* **MariaDB**: A robust database for data persistence.
* **Redis**: High-performance caching to speed up the application.
* **Caddy**: A modern, automated reverse proxy with automatic HTTPS.
* **Fail2ban**: Proactive security against brute-force attacks with custom rules for Vaultwarden.
* **Automated Backups**: Daily encrypted backups to cloud storage using rclone.
* **Automated Updates**: Watchtower keeps your application containers up-to-date.
* **Management Scripts**: A suite of scripts for easy setup, monitoring, and troubleshooting.


## **System Requirements**

### **Hardware Requirements**

* **Minimum**: 1 vCPUs, 4GB RAM, 20GB disk space
* **Recommended**: 4 vCPUs, 6GB RAM, 50GB disk space
* **Oracle A1 Flex**: 1 OCPUs, 6GB RAM (free tier) - excellent choice


### **Software Prerequisites**

* **Operating System**: Ubuntu 22.04 LTS (recommended) or similar Linux distribution
* **Docker**: Version 20.10+
* **Docker Compose**: Version 2.0+
* **Domain name** you own with DNS management access
* **Cloudflare account** for DNS management (recommended for DDoS protection)


### **Service Requirements**

* **SMTP provider** (MailerSend, SendGrid, etc.) for transactional emails
* **Cloud storage** compatible with rclone (Backblaze B2, Google Drive, AWS S3, etc.)
* **SSL certificate** (automatically managed by Caddy)


## **Setup Instructions**

### **1. Clone the Repository**

git clone https://github.com/killer23d/VaultWarden-OCI.git
cd VaultWarden-OCI

### **2. Configure Your Environment**

Copy the example configuration and customize it:

cp settings.env.example settings.env
nano settings.env

**Critical Configuration Items:**

* **DOMAIN_NAME**: Your root domain (e.g., example.com)
* **Strong Passwords**: Generate secure passwords for all database and application secrets
* **SMTP Settings**: Configure your email provider credentials
* **Cloud Storage**: Set up rclone remote name and backup path
* **Timezone**: Set your local timezone (e.g., America/Los_Angeles)

**Generate Secure Passwords:**

# Generate strong passwords

openssl rand -base64 32  \# For MARIADB_ROOT_PASSWORD
openssl rand -base64 32  \# For MARIADB_PASSWORD
openssl rand -base64 32  \# For ADMIN_TOKEN
openssl rand -base64 32  \# For REDIS_PASSWORD

### **3. Configure rclone for Backups**

Set up cloud storage for automated backups:

1. **Install rclone locally** (temporary):
curl https://rclone.org/install.sh | sudo bash
2. **Configure your cloud provider**:
rclone config
Follow the prompts for your cloud storage provider (Backblaze B2, Google Drive, etc.)
3. **Copy configuration to project**:
cp ~/.config/rclone/rclone.conf ./backup/rclone.conf
4. **Test the configuration**:
rclone lsd your-remote-name:

### **4. Bitwarden Push Notifications (Optional)**

For mobile app push notifications:

1. Visit the Bitwarden Hosting Portal at https://bitwarden.com/host/
2. Create an installation
3. Copy the Installation ID and Key to your settings.env:
PUSH_INSTALLATION_ID=your-installation-id
PUSH_INSTALLATION_KEY=your-installation-key

### **5. (Optional) Configure OCI Vault for Secrets**

For enhanced security, store your settings in OCI's Vault:

# Ensure OCI CLI is installed and configured

./oci_setup.sh

The script will guide you through creating vault resources and uploading your settings.env file.

To use OCI Vault:
export OCI_SECRET_OCID=your-secret-ocid
./startup.sh

### **6. Validate and Launch**

# Make scripts executable

chmod +x *.sh caddy/*.sh backup/*.sh

# Validate configuration

./validate-config.sh

# Set correct permissions for data directories

sudo chown -R 1000:1000 ./data

# Launch the stack

./startup.sh

Your Vaultwarden instance will be accessible at https://vault.your-domain.com

## **Usage and Management Scripts**

| Script | Purpose |
| :-- | :-- |
| startup.sh | Securely starts the Docker stack with RAM-based env loading |
| monitor.sh | Shows container status, resource usage, and recent logs |
| diagnose.sh | Comprehensive troubleshooting and connectivity tests |
| validate-config.sh | Validates configuration files and checks for common issues |
| check-disk-space.sh | Monitors disk usage and sends alerts |
| update-settings.sh | Safely updates environment variables |

## **Post-Setup and Maintenance**

### **Automatic Operations**

* **Updates**: Watchtower checks for new container versions every Sunday at 3 AM
* **Backups**: Encrypted backups created daily at 3 AM UTC and uploaded to cloud storage
* **IP Updates**: Cloudflare IP ranges updated automatically before startup
* **Security**: Fail2ban monitors and blocks suspicious activities


### **Manual Operations**

# View container status and logs

./monitor.sh

# Run comprehensive diagnostics

./diagnose.sh

# Manual backup (with confirmation)

docker compose exec bw_backup /backup/backup.sh

# Update Cloudflare IP ranges

./caddy/update_cloudflare_ips.sh

## **Backup and Restore**

### **Backup System**

* **Schedule**: Daily at 3 AM UTC via cron
* **Encryption**: GPG with AES256 cipher
* **Storage**: Local and cloud via rclone
* **Retention**: Configurable (default 30 days)
* **Notifications**: Email alerts on success/failure


### **Restore Process**

**WARNING: Critical**: Your backups are encrypted with BACKUP_PASSPHRASE. **Store this securely** - lost passphrases mean unrecoverable backups.

# Stop services

docker compose down

# Set your backup passphrase

export GPG_PASSPHRASE='your-strong-backup-passphrase'

# Run interactive restore

./backup/restore.sh

# Restart services and verify

./startup.sh
./diagnose.sh

## **Troubleshooting**

### **Common Issues**

| Issue | Solution |
| :-- | :-- |
| Container won't start | Check ./diagnose.sh for detailed analysis |
| Can't access web interface | Verify DNS pointing to server IP |
| Email not working | Check SMTP credentials in settings.env |
| Backup failures | Verify rclone configuration and cloud credentials |
| Permission errors | Run sudo chown -R 1000:1000 ./data |

### **Getting Help**

1. **Run diagnostics**: ./diagnose.sh
2. **Check logs**: ./monitor.sh
3. **Validate config**: ./validate-config.sh
4. **Review documentation**: All scripts have built-in help

### **Log Locations**

# Container logs

docker compose logs service-name

# Application logs

./data/caddy_logs/       \# Caddy access logs
./data/backup_logs/      \# Backup operation logs
./data/fail2ban/         \# Security logs

## **Security Features**

* **Automatic HTTPS** with Let's Encrypt certificates
* **Security headers** (HSTS, CSP, X-Frame-Options)
* **Fail2ban protection** against brute force attacks
* **Cloudflare integration** for DDoS protection
* **Encrypted backups** with strong cipher suites
* **Network isolation** via Docker bridge networks
* **Non-root containers** where possible
* **Secret management** via OCI Vault integration


## **Performance Optimization**

The configuration is optimized for 6GB RAM systems:

* **Database connection pooling**: 15 connections
* **Redis caching**: 25 max connections
* **Vaultwarden workers**: 3 processes
* **Automatic cleanup**: Old logs and backups

For different hardware, adjust these values in settings.env:
VAULTWARDEN_WORKERS=3          \# Adjust based on CPU cores
DATABASE_POOL_SIZE=15          \# Adjust based on RAM
REDIS_MAX_CONNECTIONS=25       \# Adjust based on usage

## **Advanced Configuration**

### **Custom Domain Setup**

1. Point your domain's A record to your server's IP
2. Configure Cloudflare DNS (recommended)
3. Update DOMAIN_NAME in settings.env
4. Restart with ./startup.sh

### **Email Provider Setup**

**MailerSend Example:**
SMTP_HOST=smtp.mailersend.net
SMTP_PORT=587
SMTP_USER=MS_your_token_here
SMTP_PASSWORD=MS_your_token_here

**SendGrid Example:**
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your_sendgrid_api_key

### **Cloud Storage Setup**

**Backblaze B2 Example:**

- Remote name: b2remote
- Remote path: vaultwarden-backups

**Google Drive Example:**

- Remote name: gdrive
- Remote path: Backups/VaultWarden


### **Firewall Configuration**

# UFW example

sudo ufw allow 22/tcp     \# SSH
sudo ufw allow 80/tcp     \# HTTP (redirects to HTTPS)
sudo ufw allow 443/tcp    \# HTTPS
sudo ufw enable

## **Monitoring and Alerts**

### **Built-in Monitoring**

* Container health checks
* Disk space monitoring
* Backup success/failure notifications
* Failed login attempt alerts


### **Log Rotation Setup**

Create /etc/logrotate.d/vaultwarden-oci:

/path/to/VaultWarden-OCI/data/caddy_logs/*.log {
daily
missingok
rotate 30
compress
delaycompress
notifempty
sharedscripts
postrotate
docker exec bw_caddy caddy reload 2>/dev/null || true
endscript
}

/path/to/VaultWarden-OCI/data/backup_logs/*.log {
weekly
missingok
rotate 12
compress
delaycompress
notifempty
}

## **Updating the Stack**

### **Automatic Updates**

Watchtower handles container updates automatically. To customize:
WATCHTOWER_SCHEDULE=0 0 3 * * 0  \# 3 AM every Sunday

### **Manual Updates**

# Update containers

docker compose pull
docker compose up -d

# Update scripts (backup your settings first)

git pull origin main

## **Disaster Recovery**

### **Complete System Recovery**

1. **Fresh server setup**: Install Docker and Docker Compose
2. **Clone repository**: git clone and cd into directory
3. **Restore settings**: Copy settings.env or configure OCI Vault access
4. **Restore rclone config**: Copy ./backup/rclone.conf
5. **Run restore**: ./backup/restore.sh
6. **Start services**: ./startup.sh

### **Backup Verification**

# Test backup integrity

export GPG_PASSPHRASE='your-backup-passphrase'
gpg --decrypt backup_file.tar.gz.gpg | tar -tzf - > /dev/null

### **Emergency Access**

If Vaultwarden is inaccessible:

1. Check container logs: docker compose logs vaultwarden
2. Verify network: ./diagnose.sh
3. Check DNS resolution
4. Verify SSL certificate status

## **License and Support**

This project is provided as-is for educational and production use. Please review all security configurations for your specific requirements.

For issues and contributions, please use the GitHub repository issue tracker.

**Security Note**: This setup includes multiple layers of security, but you are responsible for:

- Keeping your server updated
- Managing secure passwords
- Monitoring backup integrity
- Following security best practices

