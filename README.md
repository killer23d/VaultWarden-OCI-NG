
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

## **⚠️ Important Configuration Notice**

This project requires manual configuration before its first use. It will not work by simply cloning the repository and running it. You must create and modify several key files which contain your specific domain information and secrets.

The most critical files that you **must** create or configure are:

* settings.env: This is the main configuration file where you will set your domain, passwords, and API keys. You must create it by copying settings.env.example and filling in all the required values.  
* backup/rclone.conf: This file is required for cloud backups to function. You must generate it by running the rclone config command and copying the resulting configuration file to this location.  
* fail2ban/jail.d/jail.local: This file is **generated automatically** by the startup.sh script from the jail.local.template. You do not need to create it, but its contents depend on the variables you set in settings.env.

Please follow the **Setup Instructions** below carefully to ensure all necessary files are configured correctly.

## **System Requirements**

### **Hardware Requirements**
 
* **Oracle A1 Flex**: 1 OCPUs, 6GB RAM (free tier)

### **Software Prerequisites**

* **Operating System**: Ubuntu 22.04 Minimal LTS (recommended) or similar Linux distribution  
* **Docker**: Version 20.10+  
* **Docker Compose**: Version 2.0+  
* **Domain name** you own with DNS management access  
* **Cloudflare account** for DNS management (recommended for DDoS protection)

### **Service Requirements**

* **SMTP provider** (MailerSend, SendGrid, etc.) for transactional emails  
* **Cloud storage** compatible with rclone (Backblaze B2, Google Drive, AWS S3, etc.)  
* **SSL certificate** (automatically managed by Caddy)

## **Setup Instructions**

### **1\. Clone the Repository**

Bash

git clone https://github.com/killer23d/VaultWarden-OCI.git  
cd VaultWarden-OCI

### **2\. Configure Your Environment**

Copy the example configuration and customize it. This file contains all your secrets, so ensure it is protected.

Bash

cp settings.env.example settings.env  
nano settings.env

**Critical Configuration Items:**

* DOMAIN\_NAME: Your root domain (e.g., example.com)  
* **Strong Passwords**: Generate secure passwords for all database and application secrets  
* SMTP\_HOST, SMTP\_USERNAME, SMTP\_PASSWORD: Configure your email provider credentials  
* BACKUP\_REMOTE: Set up rclone remote name for cloud storage  
* TZ: Set your local timezone (e.g., America/Los\_Angeles)  
* ALERT\_EMAIL: Set the email address for critical alerts like disk space warnings

**Generate Secure Passwords:**

Bash

\# Generate strong, unique passwords for each secret  
openssl rand \-base64 32 

### **3\. Configure rclone for Backups**

Set up cloud storage for automated backups:

1. **Install rclone locally** (this is temporary for setup):  
   Bash  
   curl https://rclone.org/install.sh | sudo bash

2. **Configure your cloud provider**:  
   Bash  
   rclone config

   Follow the prompts for your cloud storage provider (e.g., Backblaze B2, Google Drive). Give your remote a name (e.g., b2-backups).  
3. **Copy configuration to project**:  
   Bash  
   cp \~/.config/rclone/rclone.conf ./backup/rclone.conf

4. **Test the configuration** (replace your-remote-name with the name you chose):  
   Bash  
   rclone lsd your-remote-name:

### **4\. Bitwarden Push Notifications (Optional)**

For mobile app push notifications:

1. Visit the Bitwarden Hosting Portal at https://bitwarden.com/host/  
2. Create an installation and copy the **Installation ID** and **Key** to your settings.env file.

### **5\. (Optional) Configure OCI Vault for Secrets**

For enhanced security, you can store your settings.env file in OCI's Vault:

Bash

\# Ensure OCI CLI is installed and configured, then run the setup script.  
./oci\_setup.sh

The script will guide you through creating vault resources and uploading your settings file. To use the secret from OCI Vault instead of a local file, export the secret's OCID before running startup.sh:

Bash

export OCI\_SECRET\_OCID=your-secret-ocid  
./startup.sh

### **6\. Validate and Launch**

1. **Make scripts executable**:  
   Bash  
   chmod \+x \*.sh caddy/\*.sh backup/\*.sh

2. Validate configuration:  
   This script checks for common errors in your setup before you launch.  
   Bash  
   ./validate-config.sh

3. **Set correct permissions for data directories**:  
   Bash  
   sudo chown \-R 1000:1000 ./data

4. **Launch the stack**:  
   Bash  
   ./startup.sh

Your Vaultwarden instance will be accessible at https://vault.your-domain.com.

## **Usage and Management Scripts**

This project includes a powerful suite of scripts for easy management and troubleshooting.

| Script | Purpose |
| :---- | :---- |
| startup.sh | Securely starts the Docker stack. It loads the settings.env file into RAM for enhanced security and generates the fail2ban config from a template. |
| monitor.sh | Provides a real-time, color-coded dashboard of container status, health, resource usage (CPU, RAM, Network), and recent logs for all running services. |
| diagnose.sh | A comprehensive troubleshooting tool. It checks system requirements, file permissions, container health, network connectivity, and configuration, providing detailed error logs. |
| validate-config.sh | A pre-flight check for your configuration. It validates file existence, settings.env variables, docker-compose.yml syntax, and password strength. |
| check-disk-space.sh | Monitors disk usage of the data directory. If the threshold is exceeded, it **sends an email alert**, identifies the largest folders, and suggests cleanup actions. |
| update-settings.sh | Safely updates your environment variables if you are using OCI Vault for secret management. |

## **Post-Setup and Maintenance**

### **Automatic Operations**

* **Updates**: Watchtower checks for new container versions every Sunday at 3 AM.  
* **Backups**: Encrypted backups are created daily at 3 AM UTC and uploaded to your cloud storage.  
* **IP Updates**: Cloudflare IP ranges are updated automatically by startup.sh to ensure the firewall is always current.  
* **Security**: Fail2ban actively monitors logs and blocks suspicious IP addresses.

### **Manual Operations**

Bash

\# View the real-time status dashboard  
./monitor.sh

\# Run a deep diagnostic check if you suspect issues  
./diagnose.sh

\# Run a manual backup (with confirmation prompt)  
docker compose exec backup /backup/backup.sh

\# Manually update Cloudflare IP lists  
./caddy/update\_cloudflare\_ips.sh

## **Backup and Restore**

### **Restore Process**

**WARNING: Critical**: Your backups are encrypted with BACKUP\_PASSPHRASE. **Store this passphrase securely**. Without it, your backups are unrecoverable.

1. **Stop services**:  
   Bash  
   docker compose down

2. **Set your backup passphrase**:  
   Bash  
   export GPG\_PASSPHRASE='your-very-strong-backup-passphrase'

3. Run interactive restore:  
   The script will find available backups and let you choose which one to restore.  
   Bash  
   ./backup/restore.sh

4. **Restart services and verify**:  
   Bash  
   ./startup.sh  
   ./diagnose.sh

## **Monitoring and Alerts**

This stack is designed for proactive monitoring.

* **Container Health Checks**: Every service in the docker-compose.yml has a health check to ensure it's running correctly.  
* **Disk Space Monitoring**: The check-disk-space.sh script can be run via a cron job to automate disk usage monitoring and receive email alerts.  
* **Backup Notifications**: You will receive an email on the success or failure of every daily backup.  
* **Fail2ban Alerts**: Fail2ban is configured to send email alerts when an IP is banned.
