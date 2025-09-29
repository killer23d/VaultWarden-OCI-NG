
# **Vaultwarden on OCI**

This project provides a comprehensive, secure, and automated setup for self-hosting [Vaultwarden](https://github.com/dani-garcia/vaultwarden), a Bitwarden-compatible server, using Docker Compose. It is optimized for deployment on an Oracle Cloud Infrastructure (OCI) A1 Flex VM but is portable to other environments.

The stack is designed with a security-first approach and includes the following components:

* **Vaultwarden**: The core password manager application.  
* **MariaDB**: A robust database for data persistence.  
* **Redis**: High-performance caching to speed up the application.  
* **Caddy**: A modern, automated reverse proxy with automatic HTTPS.  
* **Fail2ban**: Proactive security against brute-force attacks with custom rules for Vaultwarden.  
* **Automated Backups**: Daily encrypted backups to cloud storage using rclone.  
* **Automated Updates**: Watchtower keeps your application containers up-to-date.  
* **Management Scripts**: A suite of scripts for easy setup, monitoring, and troubleshooting.

## **Prerequisites**

Before you begin, ensure you have the following:

* An Oracle Cloud Infrastructure (OCI) A1 Flex VM (or any other Linux server) running Ubuntu 22.04 LTS or a similar distribution.  
* **Docker** and **Docker Compose** installed on the VM.  
* A **domain name** you own.  
* A **Cloudflare account** to manage your domain's DNS.  
* An **SMTP provider** (e.g., MailerSend, SendGrid) for sending transactional emails (invitations, notifications).  
* An **rclone-compatible cloud storage** provider (e.g., Backblaze B2, Google Drive, Dropbox) for off-site backups.

## **Setup Instructions**

These steps assume you have already created your OCI VM and are connected to it via SSH.

### **1\. Clone the Repository**

Clone this repository to a location of your choice on your VM.

Bash

git clone \<your-repository-url\>  
cd \<repository-directory\>

### **2\. Configure settings.env**

This is the most critical step. Copy the example settings file and edit it with your specific details.

Bash

cp settings.env.example settings.env  
nano settings.env

You **must** replace all placeholder values. Pay close attention to the following:

* **DOMAIN\_NAME**: Your root domain (e.g., example.com).  
* **MARIADB\_ROOT\_PASSWORD**, **MARIADB\_PASSWORD**, **ADMIN\_TOKEN**, **REDIS\_PASSWORD**: Generate strong, unique passwords for these fields.  
* **SMTP\_USER**, **SMTP\_PASSWORD**: Your email provider's credentials.  
* **RCLONE\_REMOTE\_NAME**, **RCLONE\_REMOTE\_PATH**: The name of your rclone remote and the backup folder path.  
* **BACKUP\_PASSPHRASE**: A strong passphrase to encrypt your backups. **Do not lose this\!**  
* **CF\_API\_TOKEN**: Your Cloudflare API token for ddclient.  
* **TZ**: Your timezone (e.g., America/Los\_Angeles).  
* **SCRIPT CONFIGURATION**: Ensure the container names match those in docker-compose.yml.

### **3\. Configure rclone for Backups**

The backup service requires a valid rclone.conf file.

1. Run rclone config on your local machine to generate the configuration file for your chosen cloud provider.  
2. Once configured, copy the contents of your rclone.conf file and paste them into a new file at backup/rclone.conf in this project.

### **4\. (Optional) Configure OCI Vault for Secrets**

For enhanced security, you can store your settings.env file in OCI's Vault.

1. Ensure the OCI CLI is installed and configured on your VM.  
2. Run the interactive setup script: ./oci\_setup.sh  
3. The script will guide you through creating or selecting a vault, key, and secret, then upload your local settings.env file. It will output a Secret OCID.  
4. To use the secret from OCI Vault, set the environment variable before running startup.sh: export OCI\_SECRET\_OCID=\<your-secret-ocid\>

### **5\. Validate and Launch**

Before launching, run the validation script to check for common configuration errors.

Bash

\# Make scripts executable  
chmod \+x \*.sh caddy/\*.sh backup/\*.sh

\# Run the validator  
./validate-config.sh

If all checks pass, set the correct permissions for the data directories and launch the stack.

Bash

\# Replace 1000:1000 with your PUID:PGID from settings.env if different  
sudo chown \-R 1000:1000 ./data

\# Launch the stack  
./startup.sh

Your Vaultwarden instance should now be running and accessible at https://vault.your.domain.com.

## **Usage and Management Scripts**

This project includes several scripts to simplify management:

* startup.sh: Securely starts the entire Docker stack. It automatically updates Cloudflare IPs before starting.  
* monitor.sh: Displays a color-coded status of all containers, resource usage, and recent logs.  
* diagnose.sh: A comprehensive troubleshooting tool that checks container health, internal and external network connectivity, and volume permissions.  
* validate-config.sh: Checks your settings.env and project structure for missing files or placeholder values.

## **Post-Setup and Maintenance**

* **Automatic Updates**: The watchtower service automatically checks for and downloads new versions of your containers every Sunday at 3 AM, based on the WATCHTOWER\_SCHEDULE in settings.env.  
* **Automatic Backups**: The backup container runs a cron job daily at 3 AM UTC to create a GPG-encrypted backup of your database and data, which is then uploaded to your rclone remote.  
* **Log Management**: Container logs are written to the data directory. You may want to implement a log rotation strategy (e.g., using logrotate) on the host to manage the size of these logs over time.

## **Backup and Restore**

**Your backups are encrypted with the BACKUP\_PASSPHRASE. If you lose this passphrase, your backups will be unrecoverable.**

### **Restoring from a Backup**

1. Download the desired backup file (e.g., vaultwarden\_backup\_...tar.gz.gpg) from your rclone cloud storage into the ./data/backups directory.  
2. Stop the running containers: docker compose down.  
3. Run the interactive restore script. You will need your BACKUP\_PASSPHRASE.  
   Bash  
   \# Set the passphrase in your environment  
   export GPG\_PASSPHRASE='your-strong-backup-passphrase'

   \# Run the script  
   ./backup/restore.sh

4. The script will prompt you to select a backup and confirm the restore operation.  
5. After completion, restart the stack with ./startup.sh and run ./diagnose.sh to verify everything is working.
