# **Vaultwarden on OCI Ampere A1 Flex**

This guide provides a step-by-step process for deploying a secure and resilient Vaultwarden stack on an Oracle Cloud Infrastructure (OCI) Ampere A1 Flex VM running Ubuntu.

The stack is fully containerized using Docker Compose and includes:

* Vaultwarden  
* MariaDB  
* Redis  
* Caddy  
* Fail2ban  
* DDClient  
* Automated Backups

## **Step 1: Prerequisites**

Before you begin, you must have the following:

* An Oracle Cloud Infrastructure (OCI) account.  
* An Ampere A1 Flex VM already provisioned with Ubuntu.  
* SSH access to the VM.  
* A domain name that you will point to this server.

## **Step 2: Prepare the Host VM**

First, you need to configure the OCI network and the Ubuntu operating system.

### **A. Configure Network Security Rules**

You must allow public internet traffic to reach your VM on the standard web ports (80 for HTTP and 443 for HTTPS).

1. In your OCI Console, go to **Networking** \> **Virtual Cloud Networks**.  
2. Choose the VCN your VM is in and go to **Security Lists** or **Network Security Groups**.  
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

**Important:** You must log out and log back in for the Docker group changes to take effect.

### **C. Configure the OCI CLI**

The OCI CLI needs to be configured to interact with your OCI account. This is required for managing secrets in OCI Vault.

1. Run the interactive setup tool:  
   Bash  
   oci setup config

2. Follow the prompts. You will need your User, Tenancy, and Region OCIDs from the OCI console.

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

5. **Set up Docker Maintenance Cron Job** to prune unused Docker resources weekly.  
   Bash  
   sudo crontab \-e

   Add the following line to the file:  
   0 2 \* \* 0 /usr/bin/docker system prune \-af

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

## **Step 4: Secrets Management with OCI Vault**

To improve security, this project stores the settings.env file in OCI Vault instead of leaving it on the disk.

1. Run the Interactive Setup Script.  
   This script will guide you through creating a vault, creating an encryption key, and uploading your settings.env file as a secret.  
   Bash  
   ./oci\_setup.sh

2. **Save the Secret OCID**. At the end of the process, the script will output a **Secret OCID**. Copy this value and save it somewhere safe; you will need it to start the application.

## **Step 5: Deployment**

You can now start the entire application stack.

1. Run the startup.sh Script.  
   Provide the Secret OCID you saved from the previous step as an environment variable:  
   Bash  
   OCI\_SECRET\_OCID=\<YOUR\_SECRET\_OCID\_HERE\> ./startup.sh

2. **How it Works**. This command fetches your settings from OCI Vault into a secure in-memory location, then starts all the Docker containers. The in-memory file is deleted when the script exits.  
3. **Access Your Instance**. Your Vaultwarden instance should now be live and accessible at the domain you configured.

## **Step 6: Maintenance & Troubleshooting**

### **Troubleshooting**

If you encounter issues, use the diagnose.sh script to check container health, view logs, and test network connectivity.

Bash

./diagnose.sh

### **Backups and Restore**

* **Automated Backups**: A cron job runs every night to create an encrypted backup of your Vaultwarden data and database. It is stored locally in ./data/backups and emailed to you.  
* **Manual Restore**: To restore from a backup, use the interactive restore.sh script. You must provide your backup passphrase to decrypt the file.  
  Bash  
  GPG\_PASSPHRASE='\<your\_backup\_passphrase\>' ./backup/restore.sh  
