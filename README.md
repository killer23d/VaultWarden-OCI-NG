
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

### **C. Set Up Automated Security Updates & Maintenance**

To keep the host OS secure and clean, configure automatic updates and maintenance jobs.

1. **Set the Host Timezone** (e.g., America/Los\_Angeles).  
   Bash  
   sudo timedatectl set-timezone America/Los\_Angeles

2. **Install and Enable Automatic Updates**.  
   Bash  
   sudo apt-get install \-y unattended-upgrades    
   sudo dpkg-reconfigure \--priority=low unattended-upgrades

3. **Set up Maintenance Cron Jobs**.  
   Bash  
   sudo crontab \-e

   Add the following lines. **Note:** You must replace \<YOUR\_USER\> with your actual username.  
   \# Prune unused Docker resources every Sunday at 2 AM  
   0 2 \* \* 0 /usr/bin/docker system prune \-af

   \# Update Cloudflare IPs for Caddy every Sunday at 3 AM  
   0 3 \* \* 0 /home/\<YOUR\_USER\>/VaultWarden-OCI/caddy/update\_cloudflare\_ips.sh \>\> /home/\<YOUR\_USER\>/VaultWarden-OCI/data/caddy\_logs/cloudflare\_update.log 2\>&1

---

## **Step 3: Project Setup**

1. **Clone the Repository**.  
   Bash  
   git clone \<URL\_OF\_YOUR\_REPOSITORY\>    
   cd \<REPOSITORY\_DIRECTORY\>

2. Customize settings.env.  
   Open settings.env and replace all placeholder values.  
3. **Set Script Permissions**.  
   Bash  
   chmod \+x \*.sh caddy/\*.sh backup/\*.sh

---

## **Step 4: Secrets Management with OCI Vault**

This step is performed on your **local machine**, not the VM.

1. **Configure OCI CLI Locally**. If you haven't already, configure the OCI CLI on your local computer by running oci setup config.  
2. **Run the Interactive Setup Script**. This script will guide you through creating a vault and uploading your settings.env file as a secret.  
   Bash  
   ./oci\_setup.sh

3. **Save the Secret OCID**. The script will output a **Secret OCID**. Copy this value; you will need it for the VM.

---

## **Step 5: Authorize the VM with IAM**

This allows the VM to securely fetch the secret without storing any user credentials.

1. **Create a Dynamic Group**. In the OCI Console, navigate to **Identity & Security** \> **Dynamic Groups**. Create a new group and add a rule to match your VM's OCID:  
   * resource.id \= 'ocid1.instance.oc1..xxxxx'  
2. **Create an IAM Policy**. Go to **Identity & Security** \> **Policies**. Create a policy in the same compartment as your secret with this statement (replace the group name and secret OCID):  
   * Allow dynamic-group \<YOUR\_GROUP\_NAME\> to read secret-bundles where target.secret.id \= '\<YOUR\_SECRET\_OCID\>'

---

## **Step 6: Unattended Deployment**

The final step is to configure the systemd service on the VM to run the startup script on boot.

1. **Create a systemd Service File**. On the VM, create the file:  
   Bash  
   sudo nano /etc/systemd/system/vaultwarden.service

2. **Paste the Configuration**. You must replace \<YOUR\_USER\> and \<YOUR\_SECRET\_OCID\_HERE\> with your actual values.  
   Ini, TOML  
   \[Unit\]    
   Description\=Vaultwarden Startup Service    
   Requires\=docker.service    
   After\=network-online.target docker.service

   \[Service\]    
   User\=\<YOUR\_USER\>    
   Group\=\<YOUR\_USER\>    
   WorkingDirectory\=/home/\<YOUR\_USER\>/VaultWarden-OCI  
   Environment\="OCI\_SECRET\_OCID=\<YOUR\_SECRET\_OCID\_HERE\>"    
   ExecStart\=/home/\<YOUR\_USER\>/VaultWarden-OCI/startup.sh  
   Restart\=on\-failure    
   RestartSec\=10

   \[Install\]    
   WantedBy\=multi-user.target

3. **Enable and Start the Service**.  
   Bash  
   sudo systemctl daemon-reload    
   sudo systemctl enable \--now vaultwarden.service

4. **Verify the Service**.  
   Bash  
   sudo systemctl status vaultwarden.service

   Your Vaultwarden stack is now fully deployed and will start automatically on boot, securely fetching its configuration from OCI Vault every time.

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
  GPG\_PASSPHRAsE='\<your\_backup\_passphrase\>' ./backup/restore.sh    
