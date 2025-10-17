# Quick Start Guide

> **🎯 Goal**: From zero to a production-ready VaultWarden instance in under 30 minutes, featuring full automation, monitoring, and state-of-the-art security.

## ⚠️ Critical Prerequisites

### System Requirements
*   **OS**: A fresh installation of Ubuntu 24.04 LTS.
*   **RAM**: 2GB minimum (4GB recommended for teams of 10 or more).
*   **Storage**: 20GB minimum (50GB recommended for long-term use).
*   **Network**: A stable internet connection with ports 22, 80, and 443 accessible.
*   **Access**: `root` or `sudo` privileges are required for the initial setup.

### Information You'll Need
*   **A registered domain name**: e.g., `vault.yourdomain.com`, with the DNS 'A' record pointing to your server's public IP address.
*   **An email address**: For receiving administrative notifications from your VaultWarden instance.

## 🚀 30-Minute Deployment

### Phase 1: Server Preparation (5 minutes)

1.  **Connect to your server and update it:**
    ```
    ssh your_user@your_server_ip
    sudo apt-get update && sudo apt-get upgrade -y
    ```
2.  **Clone the repository:**
    ```
    git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
    cd VaultWarden-OCI-NG
    ```
3.  **Make the scripts executable:**
    ```
    chmod +x startup.sh tools/*.sh lib/*.sh
    ```

### Phase 2: Automated Installation (15 minutes)

Run the all-in-one setup script. This script will:
*   Install Docker and Docker Compose.
*   Configure the UFW firewall.
*   Install and configure Fail2ban for intrusion prevention.
*   Generate encrypted secrets using SOPS+Age.
*   Set up the necessary directory structure with secure permissions.
*   Install cron jobs for automated backups and monitoring.

