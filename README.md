# **Vaultwarden on OCI (Oracle Cloud Infrastructure)**

This project provides a comprehensive, secure, and automated setup for self-hosting Vaultwarden, a Bitwarden-compatible server, using Docker Compose. It is optimized for deployment on an Oracle Cloud Infrastructure (OCI) A1 Flex VM but is portable to other environments.

The stack is designed with a security-first approach and includes the following components:

* **Vaultwarden**: The core password manager application
* **MariaDB**: A robust database for data persistence
* **Redis**: High-performance caching to speed up the application
* **Caddy**: A modern, automated reverse proxy with automatic HTTPS
* **Fail2ban**: Proactive security against brute-force attacks with custom rules for Vaultwarden
* **Automated Backups**: Daily encrypted backups to cloud storage using rclone, with email notifications
* **Automated Updates**: Watchtower keeps your application containers up-to-date
* **Advanced Management Scripts**: A suite of scripts for easy setup, validation, monitoring, and troubleshooting
* **OCI Vault Integration**: Enterprise-grade secret management for production deployments

## **System Requirements**

### **Hardware Requirements**
* **Oracle A1 Flex**: 1 OCPU ARM64, 6GB RAM (free tier)

### **Software Prerequisites**
* **Operating System**: Ubuntu 22.04 LTS (recommended) or similar Linux distribution
* **Docker & Docker Compose**: Docker 20.10+ and Docker Compose 2.0+
* **Domain Name**: A domain you own with DNS management access
* **Cloudflare Account**: Recommended for DNS management and DDoS protection
* **SMTP Provider**: For transactional emails (e.g., MailerSend, SendGrid)
* **Cloud Storage**: An rclone-compatible provider (e.g., Backblaze B2, Google Drive, AWS S3) for backups

## **VM Setup and System Preparation**

Before deploying the application, you must prepare your server. The `init-setup.sh` script automates most of this process.

### **Step 1: Initial System Setup**

For a fresh VM, the `init-setup.sh` script will:

1. Check system requirements (architecture, memory, disk space)
2. Install necessary packages like curl, git, and docker
3. Set up the project directory structure
4. Create initial configuration files from templates

To run the script, clone the repository and execute it:

```bash
git clone https://github.com/killer23d/vaultwarden-oci-ng.git
cd vaultwarden-oci-ng
./init-setup.sh
```

### **Step 2: Configure Memory Swap (OCI A1 Flex)**

To prevent out-of-memory issues, especially during database operations, add a swap file:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### **Step 3: Configure Firewall and OCI Security Lists**

You must allow HTTP and HTTPS traffic to your instance.

1. **In the OCI Console**:
   * Navigate to your instance's subnet and edit the Security List
   * Add Ingress Rules for ports 80 (HTTP) and 443 (HTTPS) from source `0.0.0.0/0`

2. **On the Server (if using ufw)**:
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw reload
   ```

## **Application Deployment**

### **Step 1: Configure Your Environment**

This is the most critical step. All your secrets and instance-specific settings are in the `settings.env` file.

1. **Create the configuration file**:
   ```bash
   cp settings.env.example settings.env
   ```

2. **Edit `settings.env`**:
   * **DOMAIN_NAME**: Set to your root domain (e.g., `example.com`)
   * **Passwords & Tokens**: Replace all placeholders like `generate-with-openssl-rand-base64-32`. Use `openssl rand -base64 32` to generate secure values for `ADMIN_TOKEN`, `MARIADB_ROOT_PASSWORD`, `MARIADB_PASSWORD`, `REDIS_PASSWORD`, and `BACKUP_PASSPHRASE`
   * **DATABASE_URL**: Ensure the password in this URL matches `MARIADB_PASSWORD`
   * **SMTP Configuration**: Fill in your email provider's details
   * **ADMIN_EMAIL**: Your email for SSL certificate registration

### **Step 2: Configure Backups with rclone**

For encrypted, off-site backups to work, configure rclone:

1. **Copy the template**:
   ```bash
   cp backup/templates/rclone.conf.example backup/config/rclone.conf
   ```

2. **Run the interactive setup**: This command runs inside the backup container and helps you configure your cloud storage provider:
   ```bash
   docker compose run --rm bw_backup rclone config
   ```

   Ensure the remote name you create matches the `BACKUP_REMOTE` variable in `settings.env`.

### **Step 3 (Optional): Secure Secrets with OCI Vault**

For production, avoid storing secrets in plaintext. The `oci_setup.sh` script automates storing your `settings.env` file in OCI's secure Vault.

1. **Run the setup script**:
   ```bash
   ./oci_setup.sh
   ```

2. **Save the Secret OCID**: The script will output a `SECRET_OCID`. You will use this to launch the application.

### **Step 4: Launch the Stack**

The `startup.sh` script handles the entire deployment process, including configuration validation and service initialization.

* **To launch using the local settings.env file**:
  ```bash
  ./startup.sh
  ```

* **To launch using OCI Vault**:
  ```bash
  export OCI_SECRET_OCID="your-secret-ocid-from-step-3"
  ./startup.sh
  ```

Your Vaultwarden instance will now be available at `https://vault.your-domain.com`.
