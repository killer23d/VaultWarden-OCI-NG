# **Vaultwarden on OCI**

This project provides a comprehensive, secure, and automated setup for self-hosting Vaultwarden, a Bitwarden-compatible server, using Docker Compose. It is optimized for deployment on an Oracle Cloud Infrastructure (OCI) A1 Flex VM but is portable to other environments.

The stack is designed with a security-first approach and includes the following components:

* **Vaultwarden**: The core password manager application.
* **MariaDB**: A robust database for data persistence.
* **Redis**: High-performance caching to speed up the application.
* **Caddy**: A modern, automated reverse proxy with automatic HTTPS.
* **Fail2ban**: Proactive security against brute-force attacks with custom rules for Vaultwarden.
* **Automated Backups**: Daily encrypted backups to cloud storage using rclone, with email notifications.
* **Automated Updates**: Watchtower keeps your application containers up-to-date.
* **Advanced Management Scripts**: A suite of scripts for easy setup, validation, monitoring, and troubleshooting.
* **OCI Vault Integration**: Enterprise-grade secret management for production deployments.


## **⚠️ Important Configuration Notice**

This project requires manual configuration before its first use. It will not work by simply cloning the repository and running it. You must create and modify several key files which contain your specific domain information and secrets.

The most critical files that you **must** create or configure are:

* **settings.env**: This is the main configuration file where you will set your domain, passwords, and API keys. You must create it by copying settings.env.example and filling in all the required values.
* **backup/rclone.conf**: This file is required for cloud backups to function. You must generate it by running the rclone config command and copying the resulting configuration file to this location.
* **fail2ban/jail.d/jail.local**: This file is **generated automatically** by the startup.sh script from the jail.local.template. You do not need to create it, but its contents depend on the variables you set in settings.env.

Please follow the **Setup Instructions** below carefully to ensure all necessary files are configured correctly.

## **System Requirements**

### **Hardware Requirements**

* **Minimum**: 1 vCPUs, 4GB RAM, 20GB disk space
* **Recommended**: 4 vCPUs, 6GB RAM, 50GB disk space
* **Oracle A1 Flex**: 1 OCPU ARM64, 6GB RAM (free tier) - excellent choice


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

```
git clone https://github.com/killer23d/VaultWarden-OCI.git
cd VaultWarden-OCI
```


### **2. Configure Your Environment**

Copy the example configuration and customize it. This file contains all your secrets, so ensure it is protected.

```
cp settings.env.example settings.env
nano settings.env
```

**Critical Configuration Items:**

* **DOMAIN_NAME**: Your root domain (e.g., example.com)
* **APP_DOMAIN**: Your vault subdomain (e.g., vault.example.com) - **REQUIRED** for Caddy to work properly
* **Strong Passwords**: Generate secure passwords for all database and application secrets
* **SMTP Configuration**: Configure your email provider credentials with consistent variable names
* **BACKUP_REMOTE**: Set up rclone remote name for cloud storage
* **TZ**: Set your local timezone (e.g., America/Los_Angeles)
* **ALERT_EMAIL**: Set the email address for critical alerts like disk space warnings

**Important Variable Consistency**: Ensure these variables match exactly:

- Use **SMTP_USERNAME** and **SMTP_PASSWORD** (not SMTP_USER)
- Database configuration must use consistent container name **bw_mariadb**
- **APP_DOMAIN** must be defined for Caddyfile to work properly

**Generate Secure Passwords:**

```
# Generate strong, unique passwords for each secret  
openssl rand -base64 32  # For MARIADB_ROOT_PASSWORD  
openssl rand -base64 32  # For MARIADB_PASSWORD  
openssl rand -base64 32  # For ADMIN_TOKEN  
openssl rand -base64 32  # For REDIS_PASSWORD
openssl rand -base64 32  # For BACKUP_PASSPHRASE
```


### **3. Configure rclone for Backups**

Set up cloud storage for automated backups:

1. **Install rclone locally** (this is temporary for setup):

```
curl https://rclone.org/install.sh | sudo bash
```

2. **Configure your cloud provider**:

```
rclone config
```

Follow the prompts for your cloud storage provider (e.g., Backblaze B2, Google Drive). Give your remote a name (e.g., b2-backups).
3. **Copy configuration to project**:

```
cp ~/.config/rclone/rclone.conf ./backup/rclone.conf
```

**Alternative**: Copy the provided example and customize:

```
cp backup/rclone.conf.example backup/rclone.conf
nano backup/rclone.conf
```

4. **Test the configuration** (replace your-remote-name with the name you chose):

```
rclone lsd your-remote-name:
```


### **4. Bitwarden Push Notifications (Optional)**

For mobile app push notifications:

1. Visit the Bitwarden Hosting Portal at https://bitwarden.com/host/
2. Create an installation and copy the **Installation ID** and **Key** to your settings.env file.

### **5. Configure OCI Vault for Secrets (Recommended for Production)**

For enhanced security, store your entire settings.env file in OCI's Vault as a single encrypted secret:

```
# The oci_setup.sh script handles everything automatically:
# - Installs OCI CLI if not present
# - Guides through OCI CLI configuration  
# - Creates vault, keys, and secrets
# - Returns SECRET_OCID for use with startup.sh

./oci_setup.sh
```

**What the oci_setup.sh script does:**

- **Checks for OCI CLI** and installs it automatically if missing
- **Validates or sets up** OCI CLI configuration interactively
- **Creates or selects** existing vault and encryption key
- **Uploads your complete settings.env** file as a single encrypted secret
- **Returns the SECRET_OCID** needed for vault integration

**To use the secret from OCI Vault:**

```
export OCI_SECRET_OCID=your-secret-ocid  
./startup.sh
```

**Benefits of OCI Vault Integration:**

- Settings never stored in plain text on disk
- Encrypted with OCI KMS keys
- Centralized secret management
- Settings loaded into memory only during startup
- Automatic cleanup after container launch


### **6. Set Up Weekly Cloudflare IP Updates**

**Important**: Cloudflare IP ranges are currently updated **only at startup**. For production deployments, set up automatic weekly updates to ensure security rules stay current:

```
# Make the update script executable
chmod +x ./caddy/update_cloudflare_ips.sh

# Add weekly cron job (Sundays at 2 AM, before backups at 3 AM)
(crontab -l 2>/dev/null; echo "0 2 * * 0 /full/path/to/VaultWarden-OCI/caddy/update_cloudflare_ips.sh") | crontab -
```

**Why weekly updates matter:**

- Cloudflare IP ranges change periodically (1-2 times per year)
- Outdated IP lists can cause legitimate traffic to be blocked
- Automatic updates prevent security gaps between service restarts
- Minimal resource impact on OCI A1 Flex (just curl requests + file comparison)


### **7. Validate and Launch**

1. **Make scripts executable**:

```
chmod +x *.sh caddy/*.sh backup/*.sh
```

2. **Validate configuration**:
This script checks for common errors in your setup before you launch.

```
./validate-config.sh
```

3. **Set correct permissions for data directories**:

```
sudo chown -R 1000:1000 ./data
```

4. **Launch the stack**:

```
# For local settings.env file:
./startup.sh

# For OCI Vault integration:
export OCI_SECRET_OCID=your-secret-ocid
./startup.sh
```


Your Vaultwarden instance will be accessible at https://vault.your-domain.com.

## **Usage and Management Scripts**

This project includes a powerful suite of scripts for easy management and troubleshooting.


| Script | Purpose |
| :-- | :-- |
| **startup.sh** | Securely starts the Docker stack. Loads settings.env into RAM for enhanced security, updates Cloudflare IPs, and generates fail2ban config from template. |
| **oci_setup.sh** | **Complete OCI integration setup**. Installs OCI CLI if needed, creates vault/keys/secrets, and returns SECRET_OCID for production deployment. |
| **monitor.sh** | Provides a real-time, color-coded dashboard of container status, health, resource usage (CPU, RAM, Network), and recent logs for all running services. |
| **diagnose.sh** | A comprehensive troubleshooting tool. Checks system requirements, file permissions, container health, network connectivity, and configuration, providing detailed error logs. |
| **validate-config.sh** | A pre-flight check for your configuration. Validates file existence, settings.env variables, docker-compose.yml syntax, password strength, and variable consistency. |
| **check-disk-space.sh** | Monitors disk usage of the data directory. If threshold exceeded, sends email alert, identifies largest folders, and suggests cleanup actions. |
| **update-settings.sh** | Safely updates your environment variables if you are using OCI Vault for secret management. |

## **OCI A1 Flex Optimization**

This stack is specifically optimized for OCI A1 Flex Free Tier (1 OCPU ARM64, 6GB RAM):

### **Resource Allocation**

```
# Optimized settings for OCI A1 Flex in settings.env:
VAULTWARDEN_WORKERS=2          # Efficient for ARM64 single CPU
DATABASE_MAX_CONNECTIONS=15    # Balanced for 6GB RAM
REDIS_MAX_CONNECTIONS=25       # Redis is lightweight
```


### **Memory Limits (Applied via Docker Compose)**

- **MariaDB**: 2.5GB (primary database)
- **Vaultwarden**: 512MB (Rust is memory efficient)
- **Redis**: 256MB (caching layer)
- **Caddy**: 128MB (reverse proxy)
- **Fail2ban**: 128MB (security monitoring)
- **Total**: ~3.5GB used, ~2.5GB free for system and buffers


### **Performance Features**

- **ARM64 optimized** container images
- **Efficient health checks** with reasonable intervals
- **Resource reservations** to prevent memory starvation
- **Proper startup dependencies** to avoid race conditions


## **Post-Setup and Maintenance**

### **Automatic Operations**

* **Updates**: Watchtower checks for new container versions every Sunday at 3 AM.
* **Backups**: Encrypted backups are created daily at 3 AM UTC and uploaded to your cloud storage.
* **IP Updates**: Cloudflare IP ranges are updated automatically by startup.sh and optionally weekly via cron.
* **Security**: Fail2ban actively monitors logs and blocks suspicious IP addresses.


### **Manual Operations**

```
# View the real-time status dashboard  
./monitor.sh

# Run a deep diagnostic check if you suspect issues  
./diagnose.sh

# Run a manual backup (with confirmation prompt)  
docker compose exec backup /backup/backup.sh

# Manually update Cloudflare IP lists  
./caddy/update_cloudflare_ips.sh

# Update OCI Vault secrets
./oci_setup.sh  # Updates existing secret with current settings.env
```


### **Cloudflare IP Management**

Your setup includes comprehensive Cloudflare IP range management:

1. **Startup Updates**: IPs refreshed every time `./startup.sh` runs
2. **Weekly Schedule**: Automated updates every Sunday at 2 AM (if cron configured)
3. **Manual Updates**: Run `./caddy/update_cloudflare_ips.sh` anytime
4. **Smart Reloading**: Only reloads services when IP ranges actually change
5. **Container-Safe**: Gracefully handles stopped containers during updates

**Current Limitation**: Without the cron job, Cloudflare IPs are only updated at startup. This could create security gaps if IP ranges change between restarts.

## **Backup and Restore**

### **Restore Process**

**WARNING: Critical**: Your backups are encrypted with BACKUP_PASSPHRASE. **Store this passphrase securely**. Without it, your backups are unrecoverable.

1. **Stop services**:

```
docker compose down
```

2. **Set your backup passphrase**:

```
export GPG_PASSPHRASE='your-very-strong-backup-passphrase'
```

3. **Run interactive restore**:
The script will find available backups and let you choose which one to restore.

```
./backup/restore.sh
```

4. **Restart services and verify**:

```
./startup.sh  
./diagnose.sh
```


## **Security Features and Best Practices**

### **Production Security Hardening**

* **OCI Vault Integration**: Settings stored encrypted, never on disk
* **Memory-Only Secrets**: Settings loaded to RAM during startup, wiped after use
* **Hardcoded User IDs**: MariaDB and Redis run as UID 999:999 (system user) for security
* **Automatic HTTPS**: Let's Encrypt certificates with automatic renewal
* **Security Headers**: HSTS, CSP, X-Frame-Options, referrer policy
* **Fail2ban Protection**: Active monitoring and IP blocking for suspicious activity
* **Cloudflare Integration**: DDoS protection with auto-updating IP trust lists
* **Network Isolation**: Docker bridge networks prevent container cross-talk
* **Encrypted Backups**: GPG AES256 cipher with configurable retention


### **OCI-Specific Security**

* **Instance Principal Authentication**: Secure vault access without API keys on disk
* **IAM Policy Integration**: Granular permissions for vault and secret access
* **KMS Integration**: Hardware-backed encryption key management
* **Audit Trail**: Complete logging of vault setup and secret access


## **Troubleshooting**

### **Common Configuration Issues**

| Issue | Cause | Solution |
| :-- | :-- | :-- |
| **Caddyfile fails to start** | Missing APP_DOMAIN variable | Add `APP_DOMAIN=vault.yourdomain.com` to settings.env |
| **SMTP errors** | Wrong variable names | Use `SMTP_USERNAME` not `SMTP_USER` in settings.env |
| **Database connection fails** | Container name mismatch | Ensure DATABASE_URL uses `bw_mariadb` as hostname |
| **Backup container won't start** | Missing rclone.conf | Copy rclone.conf.example and configure for your provider |
| **Out of memory on OCI A1** | No resource limits | Resource limits are included in corrected docker-compose.yml |
| **Cloudflare IPs outdated** | No weekly updates | Set up cron job: `0 2 * * 0 /path/to/caddy/update_cloudflare_ips.sh` |

### **OCI Vault Issues**

| Issue | Cause | Solution |
| :-- | :-- | :-- |
| **OCI CLI not found** | Not installed | Run `./oci_setup.sh` - it will install automatically |
| **Authentication failed** | No OCI config | Run `oci setup config` or let oci_setup.sh guide you |
| **Secret not found** | Wrong OCID | Check SECRET_OCID format: `ocid1.vaultsecret.oc1...` |
| **Permission denied** | IAM policies | Ensure user/instance has vault and secret permissions |

### **Getting Help**

1. **Run diagnostics**: `./diagnose.sh` - comprehensive system analysis
2. **Check logs**: `./monitor.sh` - real-time container status and logs
3. **Validate config**: `./validate-config.sh` - pre-flight configuration check
4. **Test OCI integration**: `oci os ns get` - verify OCI CLI connectivity

## **Critical Fixes Applied**

Based on analysis of the original project, the following critical issues have been identified and corrected:

### **Configuration Inconsistencies Fixed**

- **APP_DOMAIN variable**: Added to settings.env.example (required for Caddyfile)
- **SMTP variables**: Standardized to use SMTP_USERNAME/SMTP_PASSWORD consistently
- **Database configuration**: Unified database names and container references
- **Resource optimization**: Added memory limits for OCI A1 Flex (1 CPU, 6GB RAM)


### **Missing Dependencies Resolved**

- **OCI CLI installation**: oci_setup.sh now installs automatically if missing
- **rclone.conf template**: Added backup/rclone.conf.example to prevent build failures
- **Cloudflare IP scheduling**: Added cron job setup for weekly updates


### **Security Enhancements**

- **OCI Vault integration**: Complete automated setup with oci_setup.sh
- **Memory-based secrets**: Settings loaded to RAM only, never persist on disk
- **Resource limits**: Prevent OOM kills on constrained OCI A1 Flex instances
- **Backup service profiles**: Made optional to prevent startup failures

These corrections ensure the stack will launch successfully on OCI A1 Flex Free tier without manual intervention or configuration errors.

## **Monitoring and Alerts**

This stack is designed for proactive monitoring with minimal resource impact on OCI A1 Flex:

* **Container Health Checks**: Every service has intelligent health monitoring
* **Disk Space Monitoring**: Automated alerts when storage exceeds thresholds
* **Backup Notifications**: Email alerts on success/failure of daily backups
* **Fail2ban Alerts**: Real-time notifications when IPs are banned
* **Weekly IP Updates**: Automated Cloudflare IP range maintenance
* **Resource Monitoring**: Built-in tracking via monitor.sh script

The monitoring system is lightweight and optimized for single-CPU ARM64 systems, ensuring security without impacting application performance.

