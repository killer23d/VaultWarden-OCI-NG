# **Vaultwarden on OCI Ampere A1 Flex**

This guide details the deployment of a secure, resilient Vaultwarden stack on an Oracle Cloud Infrastructure (OCI) Ampere A1 Flex VM running Ubuntu. The stack is fully containerized using Docker Compose and includes Vaultwarden, MariaDB, Redis, Caddy, Fail2ban, DDClient, and an automated backup solution.

This document assumes you have already provisioned an OCI Ubuntu A1 Flex VM and have SSH access to it.

## **Table of Contents**

1. [Host Setup & Configuration](https://www.google.com/search?q=%231-host-setup--configuration)  
   * [Network Security Rules](https://www.google.com/search?q=%23network-security-rules)  
   * [Install Essential Tools](https://www.google.com/search?q=%23install-essential-tools)  
   * [Automated Security Updates & Reboots](https://www.google.com/search?q=%23automated-security-updates--reboots)  
   * [Configure OCI CLI](https://www.google.com/search?q=%23configure-oci-cli)  
   * [Clone This Repository](https://www.google.com/search?q=%23clone-this-repository)  
   * [Setup Host Cron Jobs](https://www.google.com/search?q=%23setup-host-cron-jobs)  
2. [Application Configuration](https://www.google.com/search?q=%232-application-configuration)  
   * [Customize settings.env](https://www.google.com/search?q=%23customize-settingsenv)  
   * [Review and Set Script Permissions](https://www.google.com/search?q=%23review-and-set-script-permissions)  
3. [Secrets Management with OCI Vault](https://www.google.com/search?q=%233-secrets-management-with-oci-vault)  
   * [Initial Secret Upload](https://www.google.com/search?q=%23initial-secret-upload)  
4. [Deployment](https://www.google.com/search?q=%234-deployment)  
   * [Starting the Stack](https://www.google.com/search?q=%23starting-the-stack)  
5. [Maintenance & Troubleshooting](https://www.google.com/search?q=%235-maintenance--troubleshooting)  
   * [Troubleshooting with diagnose.sh](https://www.google.com/search?q=%23troubleshooting-with-diagnosesh)  
   * [Backups and Restore](https://www.google.com/search?q=%23backups-and-restore)

## **1\. Host Setup & Configuration**

This section covers the necessary steps to prepare your Ubuntu VM for deployment.

### **Network Security Rules**

Before anything else, you must allow public internet traffic to reach your instance on the standard web ports.

In your OCI Console:

1. Navigate to **Networking** \-\> **Virtual Cloud Networks**.  
2. Select the VCN your VM is in.  
3. Go to **Security Lists** or **Network Security Groups** (whichever you are using).  
4. Add **Ingress Rules** to allow TCP traffic on ports **80** and **443** from source 0.0.0.0/0. This allows Caddy to receive traffic and handle TLS certificates.

| Type | Source | IP Protocol | Source Port | Destination Port | Description |
| :---- | :---- | :---- | :---- | :---- | :---- |
| Ingress | 0.0.0.0/0 | TCP | All | 80 | Allow HTTP traffic |
| Ingress | 0.0.0.0/0 | TCP | All | 443 | Allow HTTPS traffic |

### **Install Essential Tools**

SSH into your VM and run the following commands to install Git, the OCI CLI, and the latest versions of Docker Engine and the Docker Compose Plugin from Docker's official repository.

\# Update package lists and install prerequisites  
sudo apt-get update  
sudo apt-get upgrade \-y  
sudo apt-get install \-y ca-certificates curl gnupg git python3-pip

\# Add Docker’s official GPG key  
sudo install \-m 0755 \-d /etc/apt/keyrings  
curl \-fsSL \[https://download.docker.com/linux/ubuntu/gpg\](https://download.docker.com/linux/ubuntu/gpg) | sudo gpg \--dearmor \-o /etc/apt/keyrings/docker.gpg  
sudo chmod a+r /etc/apt/keyrings/docker.gpg

\# Set up the Docker repository  
echo \\  
  "deb \[arch=$(dpkg \--print-architecture) signed-by=/etc/apt/keyrings/docker.gpg\] \[https://download.docker.com/linux/ubuntu\](https://download.docker.com/linux/ubuntu) \\  
  $(. /etc/os-release && echo "$VERSION\_CODENAME") stable" | \\  
  sudo tee /etc/apt/sources.list.d/docker.list \> /dev/null

\# Install Docker Engine and Compose Plugin  
sudo apt-get update  
sudo apt-get install \-y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

\# Add your user to the docker group to run docker commands without sudo  
sudo usermod \-aG docker ${USER}  
echo "Please log out and log back in for docker group changes to take effect."

\# Install OCI CLI  
pip3 install oci-cli

**Important:** You must log out and log back in for the docker group membership to apply. After logging back in, verify the installation with docker \--version and docker compose version.

### **Automated Security Updates & Reboots**

To keep the host OS secure, we will configure automatic security updates and scheduled reboots.

1. **Set the Host Timezone:** Ensure the VM's timezone is set correctly. This is critical for the reboot schedule. Use the same timezone as in your settings.env file.  
   \# Example for PST/PDT  
   sudo timedatectl set-timezone America/Los\_Angeles

2. **Install the unattended-upgrades package:**  
   sudo apt-get install \-y unattended-upgrades

3. **Enable Automatic Updates:** Run the following command and select **"Yes"** when prompted to enable automatic updates. This will create the necessary configuration file.  
   sudo dpkg-reconfigure \--priority=low unattended-upgrades

4. **Configure Automatic Reboot:** Edit the configuration file to enable reboots at your desired time.  
   sudo nano /etc/apt/apt.conf.d/50unattended-upgrades

   Find the following lines. You will need to uncomment them (remove the //) and set the values as shown:  
   // Automatically reboot \*WITHOUT\* confirmation if  
   //  the file /var/run/reboot-required is found after the upgrade.  
   Unattended-Upgrade::Automatic-Reboot "true";

   // If automatic reboot is enabled and needed, reboot at the specific  
   // time instead of immediately after running the upgrade.  
   // Has to be in format "HH:MM" in 24h format and in system time.  
   Unattended-Upgrade::Automatic-Reboot-Time "02:30";

   Save the file and exit the editor (press CTRL+X, then Y, then Enter). Your VM will now automatically install security updates and reboot at 2:30 AM local time if an update requires it.

### **Configure OCI CLI**

The oci-cli needs to be configured to interact with your OCI account to manage Vault secrets. Run the interactive setup tool and follow the prompts. You will need your User, Tenancy, and Region OCIDs from the OCI console.

oci setup config

### **Clone This Repository**

Clone the project files onto your VM.

git clone \<URL\_OF\_YOUR\_REPOSITORY\>  
cd \<REPOSITORY\_DIRECTORY\>

### **Setup Host Cron Jobs**

The cron job below handles routine system maintenance that is not covered by automatic security updates.

Run sudo crontab \-e to edit the root user's cron jobs, and add the following line:

\# Prune unused docker images, containers, and volumes weekly at 2 AM on Sunday.  
\# Note: System updates are handled by the unattended-upgrades package.  
0 2 \* \* 0 /usr/bin/docker system prune \-af

## **2\. Application Configuration**

All application configuration is managed through the settings.env file.

### **Customize settings.env**

Open the settings.env file in a text editor (nano settings.env). This is the most critical step. You must replace all placeholder values.

* **APP\_DOMAIN**: Set this to the public domain name for your Vaultwarden instance (e.g., vault.yourdomain.com).  
* **MariaDB Passwords**: Use openssl rand \-base64 32 to generate strong, unique passwords for MARIADB\_ROOT\_PASSWORD and MARIADB\_PASSWORD.  
* **Vaultwarden ADMIN\_TOKEN**: Generate another unique string with openssl rand \-base64 32\. This token gives you access to the Vaultwarden admin panel at https://\<YOUR\_DOMAIN\>/admin.  
* **Push Notifications**: To enable push notifications to mobile apps, you must obtain an ID and key from [bitwarden.com/host](https://bitwarden.com/host) and set PUSH\_INSTALLATION\_ID and PUSH\_INSTALLATION\_KEY.  
* **Redis Password**: Generate a password for REDIS\_PASSWORD.  
* **SMTP Settings**: Configure these to allow Vaultwarden to send emails for invitations and notifications. The example uses MailerSend, but any SMTP provider will work.  
* **BACKUP\_PASSPHRASE**: A critical password used to encrypt your backups. **Do not lose this passphrase.**  
* **Caddy CADDY\_EMAIL**: The email address Caddy will use for Let's Encrypt SSL certificate registration.  
* **DDClient**: Configure your root domain (DDCLIENT\_DOMAIN), the subdomain for Vaultwarden (DDCLIENT\_HOST, e.g., 'vault'), and your Cloudflare API token (CF\_API\_TOKEN).  
* **Fail2ban FAIL2BAN\_DEST**: The email address where Fail2ban will send notification emails when an IP is banned.  
* **Timezone TZ**: Set to your local timezone (e.g., America/Los\_Angeles).

### **Review and Set Script Permissions**

The provided shell scripts need to be executable. Run this command from the root of the project directory to ensure they are set correctly.

chmod \+x \*.sh caddy/\*.sh backup/\*.sh

## **3\. Secrets Management with OCI Vault**

For better security, the settings.env file should not be stored on the disk of the VM permanently. This project uses OCI Vault to store the settings securely. The startup.sh script will fetch it into memory when the application starts.

### **Initial Secret Upload**

The oci\_setup.sh script is an interactive wizard that will:

1. Verify your OCI CLI is working.  
2. Ask for your Compartment OCID.  
3. Help you select or create a Vault.  
4. Help you select or create an encryption Key.  
5. Upload your populated settings.env file as a secret.

Run the script from the project root:

./oci\_setup.sh

At the end of the process, it will output the **Secret OCID**. **Copy this OCID and save it somewhere safe.**

## **4\. Deployment**

### **Starting the Stack**

To start the entire application stack, you will run the startup.sh script. You must provide the Secret OCID you saved from the previous step as an environment variable.

OCI\_SECRET\_OCID=\<YOUR\_SECRET\_OCID\_HERE\> ./startup.sh

This command will:

1. Fetch the Cloudflare IPs for Caddy.  
2. Connect to OCI Vault using the provided OCID.  
3. Download your settings.env file into a secure in-memory location (/dev/shm).  
4. Start all containers defined in docker-compose.yml using that environment file.  
5. The script then cleans up the in-memory file upon exit.

Your Vaultwarden instance should now be live and accessible at your domain.

## **5\. Maintenance & Troubleshooting**

### **Troubleshooting with diagnose.sh**

If you encounter issues, the diagnose.sh script is your first tool for troubleshooting. It checks container health, shows recent logs, and tests internal network connectivity.

./diagnose.sh

### **Backups and Restore**

* **Automated Backups**: The backup container runs a cron job every night at 03:00 UTC. It creates an encrypted tarball of your Vaultwarden data and MariaDB database, stores it locally in ./data/backups, and emails it to you.  
* **Manual Restore**: If you need to restore from a backup, use the interactive restore.sh script. You must provide the GPG\_PASSPHRASE from your settings.env file to decrypt the backup.  
  GPG\_PASSPHRASE='\<your\_backup\_passphrase\>' ./backup/restore.sh  
