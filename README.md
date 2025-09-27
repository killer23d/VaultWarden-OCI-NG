

# **Vaultwarden on OCI Ampere A1 Flex (Enhanced for Resilience)**

This guide provides a comprehensive, step-by-step process for deploying a secure, resilient, and fully containerized Vaultwarden stack on an Oracle Cloud Infrastructure (OCI) Ampere A1 Flex virtual machine running Ubuntu.

This project is designed for security and ease of maintenance, featuring a complete Docker Compose setup that includes:

* **Vaultwarden**: The core password manager service.  
* **MariaDB**: A robust database for storing Vaultwarden data.  
* **Redis**: Used for caching to improve performance.  
* **Caddy**: A modern, powerful web server that automatically handles HTTPS.  
* **Fail2ban**: Protects against brute-force attacks by monitoring logs and banning suspicious IPs.  
* **DDClient**: Automatically updates your DNS records, essential for dynamic IP addresses.  
* **Automated Backups**: Nightly encrypted backups of your data, sent to you via email.

---

## **Step 1: Prerequisites**

Before you begin, ensure you have the following:

* An active **Oracle Cloud Infrastructure (OCI)** account.  
* An **Ampere A1 Flex VM** already provisioned with **Ubuntu**.  
* **SSH access** to the virtual machine.  
* A **domain name** that you will point to this server's IP address.

---

## **Step 2: Prepare the Host VM**

First, you need to configure the OCI network and prepare the Ubuntu operating system for the Vaultwarden stack.

### **A. Configure Network Security Rules**

You must allow public internet traffic to reach your VM on the standard web ports (80 for HTTP and 443 for HTTPS).

1. In your OCI Console, navigate to **Networking** \> **Virtual Cloud Networks**.  
2. Select the VCN your VM is in and go to **Security Lists** or **Network Security Groups**.  
3. Add the following **Ingress Rules** to allow TCP traffic from source 0.0.0.0/0:  
   * **Destination Port 80** (for HTTP)  
   * **Destination Port 443** (for HTTPS)

### **B. Install Essential Tools**

SSH into your VM and run the following commands to install Docker, Git, and the OCI CLI.

Bash

\# Update package lists and install prerequisites  
sudo apt-get update  
sudo apt-get upgrade \-y  
sudo apt-get install \-y ca-certificates curl gnupg git python3-pip

\# Add Docker’s official GPG key  
sudo install \-m 0755 \-d /etc/apt/keyrings  
curl \-fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg \--dearmor \-o /etc/apt/keyrings/docker.gpg  
sudo chmod a+r /etc/apt/keyrings/docker.gpg

\# Set up the Docker repository  
echo \\  
  "deb \[arch=$(dpkg \--print-architecture) signed-by=/etc/apt/keyrings/docker.gpg\] https://download.docker.com/linux/ubuntu \\  
  $(. /etc/os-release && echo "$VERSION\_CODENAME") stable" | \\  
  sudo tee /etc/apt/sources.list.d/docker.list \> /dev/null

\# Install Docker Engine and Compose Plugin  
sudo apt-get update  
sudo apt-get install \-y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

\# Add your user to the docker group to run docker commands without sudo  
sudo usermod \-aG docker ${USER}

\# Install OCI CLI  
pip3 install oci-cli

**Important:** You must **log out and log back in** for the Docker group changes to take effect.

### **C. Configure the OCI CLI**

The OCI CLI needs to be configured to interact with your OCI account. This is a critical step, as it provides the authentication needed to fetch your secrets from OCI Vault.

1. Run the interactive setup tool:  
   Bash  
   oci setup config

2. Follow the prompts. You will need your **User, Tenancy, and Region OCIDs** from the OCI console. This process creates a configuration and key file (usually in \~/.oci/) that the startup.sh script relies on to authenticate with OCI.

### **D. Set Up Automated Security Updates & Maintenance**

To keep the host OS secure and clean, configure automatic updates and maintenance jobs.

1. **Set the Host Timezone** (e.g., America/Los\_Angeles).  
   Bash  
   sudo timedatectl set-timezone America/Los\_Angeles

2. **Install the unattended-upgrades package**.  
   Bash  
   sudo apt-get install \-y unattended-upgrades

3. **Enable Automatic Updates** by running the following command and selecting "Yes" when prompted.  
   Bash  
   sudo dpkg-reconfigure \--priority=low unattended-upgrades

4. **Enable Automatic Reboots** if required by an update. Edit the configuration file:  
   Bash  
   sudo nano /etc/apt/apt.conf.d/50unattended-upgrades

   Uncomment and set the following lines to enable a reboot at a specific time (e.g., 02:30):  
   Unattended-Upgrade::Automatic-Reboot "true";  
   Unattended-Upgrade::Automatic-Reboot-Time "02:30";

5. **Set up Maintenance Cron Jobs**.  
   Bash  
   sudo crontab \-e

   Add the following lines to the file. **Note:** You must replace /path/to/project with the actual path to your project directory.  
   \# Prune unused Docker resources every Sunday at 2 AM  
   0 2 \* \* 0 /usr/bin/docker system prune \-af

   \# Update Cloudflare IPs for Caddy every Sunday at 3 AM  
   0 3 \* \* 0 /path/to/project/caddy/update\_cloudflare\_ips.sh \>\> /path/to/project/data/caddy\_logs/cloudflare\_update.log 2\>&1

---

## **Step 3: Project Setup**

Now, clone the project repository and configure the application settings.

1. **Clone the Repository**.  
   Bash  
   git clone \<URL\_OF\_YOUR\_REPOSITORY\>  
   cd \<REPOSITORY\_DIRECTORY\>

2. Customize settings.env.  
   Open the settings.env file in a text editor (nano settings.env) and replace all placeholder values. This is the most critical step. You will need to set your domain, generate strong passwords, and provide API keys for push notifications and your DNS provider.  
3. Set Script Permissions.  
   Run this command from the root of the project to make the scripts executable:  
   Bash  
   chmod \+x \*.sh caddy/\*.sh backup/\*.sh

---

## **Step 4: Secrets Management with OCI Vault**

To improve security, this project stores the settings.env file in OCI Vault instead of leaving it on the disk.

1. Run the Interactive Setup Script.  
   This script will guide you through creating a vault, creating an encryption key, and uploading your settings.env file as a secret.  
   Bash  
   ./oci\_setup.sh

2. **Save the Secret OCID**. At the end of the process, the script will output a **Secret OCID**. Copy this value and save it somewhere safe; you will need it for the next steps.

---

## **Step 5: Deployment**

You can now start the entire application stack.

1. Run the startup.sh Script Manually (for the first time).  
   Provide the Secret OCID you saved from the previous step as an environment variable:  
   Bash  
   OCI\_SECRET\_OCID=\<YOUR\_SECRET\_OCID\_HERE\> ./startup.sh

2. **How it Works**. This command uses two key components:  
   * The **OCI CLI configuration** (from Step 2C) to authenticate with your account.  
   * The **Secret OCID** to identify which secret to fetch.

It then pulls your settings into a secure in-memory location and starts all the Docker containers. The in-memory file is deleted when the script exits.

3. **Access Your Instance**. Your Vaultwarden instance should now be live and accessible at the domain you configured.

---

## **Step 6: Enable Unattended Startup on Reboot**

To ensure your Vaultwarden stack automatically restarts after the VM reboots, you need to create a systemd service. This service will run the startup.sh script automatically, fetching the secrets and starting the containers.

1. **Create a systemd Service File**.  
   Bash  
   sudo nano /etc/systemd/system/vaultwarden-startup.service

2. Paste the following configuration.  
   You must replace \<YOUR\_USER\>, /path/to/your/project, and \<YOUR\_SECRET\_OCID\_HERE\> with your actual values.  
   Ini, TOML  
   \[Unit\]  
   Description\=Vaultwarden Startup Service  
   Requires\=docker.service  
   After\=network-online.target docker.service

   \[Service\]  
   User\=\<YOUR\_USER\>  
   Group\=\<YOUR\_USER\>  
   WorkingDirectory\=/path/to/your/project  
   Environment\="OCI\_SECRET\_OCID=\<YOUR\_SECRET\_OCID\_HERE\>"  
   ExecStart\=/path/to/your/project/startup.sh  
   Restart\=on\-failure  
   RestartSec\=10

   \[Install\]  
   WantedBy\=multi-user.target

3. **Enable and Start the Service**.  
   Bash  
   \# Reload the systemd manager configuration  
   sudo systemctl daemon-reload

   \# Enable the service to start automatically on boot  
   sudo systemctl enable vaultwarden-startup.service

   \# Start the service now to test it  
   sudo systemctl start vaultwarden-startup.service

4. Verify the Service.  
   Check that the service is active and running without errors.  
   Bash  
   sudo systemctl status vaultwarden-startup.service

   Your Vaultwarden stack is now fully resilient and will start automatically on boot.

---

## **Step 7: Maintenance & Troubleshooting**

### **Troubleshooting**

If you encounter issues, use the diagnose.sh script to check container health, view logs, and test network connectivity.

Bash

./diagnose.sh

### **Backups and Restore**

* **Automated Backups**: A cron job runs every night to create an encrypted backup of your Vaultwarden data and database. It is stored locally in ./data/backups and emailed to you.  
* **Manual Restore**: To restore from a backup, use the interactive restore.sh script. You must provide your backup passphrase to decrypt the file.  
  Bash  
  GPG\_PASSPHRASE='\<your\_backup\_passphrase\>' ./backup/restore.sh  
