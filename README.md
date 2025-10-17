# VaultWarden OCI Minimal

A robust, self-hosted VaultWarden stack for small teams (10 or fewer users), engineered to be a "set and forget" system with automated setup, monitoring, backups, and secure secret management via SOPS+Age.

## 🚀 Quick Start

⚠️ IMPORTANT: Always use the provided scripts to manage the stack. Never run `docker compose up` directly.

```bash
# 1. Clone the repository
git clone <your-repository-url>
cd <project-folder-name>

# 2. IMPORTANT: Make scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh

# 3. Run the initial setup script (as root)
# This installs dependencies, configures security, and creates encrypted secrets
sudo ./tools/init-setup.sh

# 4. Start the stack with encrypted secrets
# This loads SOPS+Age configuration and starts containers
./startup.sh

# 5. Check the status
docker compose ps
./tools/check-health.sh
```

## ✨ Key Features

- Secure Secret Management: All sensitive data is encrypted at rest using SOPS+Age and securely mounted into containers at runtime via Docker Secrets.
- Fully Dynamic & Portable: Project names, container names, and paths are generated automatically. Rename the project folder, and everything adapts.
- Automated Setup: A single init-setup.sh script handles everything from Docker installation to firewall configuration and encrypted secret creation.
- Robust Startup: startup.sh is the mandatory entry point, validating secrets and system health before launching services.
- Monitoring & Self-Healing: A cron job runs every 5 minutes to check system health and attempt automatic recovery of failed services.
- Automated Backups: Daily encrypted database backups and weekly full system backups are created and managed automatically.
- Security First: Integrated Fail2ban, UFW firewall, strict file permissions, and hardened Caddy configuration.

---

## Quick Start Guide (docs/QuickStart.md)

> 🎯 Goal: From zero to a production-ready VaultWarden in under 30 minutes.

### ⚠️ Critical Prerequisites

- System: A fresh server running Ubuntu 24.04 LTS with at least 2GB RAM and 20GB storage.
- Access: You must have `sudo` or `root` access.
- Domain: A registered domain name with a DNS A record pointing to your server's public IP.

### 🚀 Deployment Steps

#### 1. Prepare Your Server
Connect to your server via SSH and clone the project.

```bash
# SSH into your server
ssh your_user@your_server_ip

# Clone the repository
git clone <your-repository-url>
cd <project-folder-name>

# CRITICAL: Make all scripts executable
chmod +x startup.sh tools/*.sh lib/*.sh
```

#### 2. Run the Automated Setup
This single command will install Docker, configure the firewall, set up Fail2ban, and generate your encrypted secret configuration.

```bash
sudo ./tools/init-setup.sh
```

Follow the interactive prompts to set your domain and admin email.

#### 3. Edit Your Secrets
After setup, you must edit your encrypted secrets file to add sensitive information like your SMTP password.

```bash
sudo ./tools/edit-secrets.sh
```

Your editor will open the decrypted file. Make your changes, save, and close the file. It will be automatically re-encrypted.

#### 4. Start the Stack
Use the startup.sh script to securely load your secrets and launch the application.

```bash
./startup.sh
```

#### 5. Final Verification
Once the script finishes, verify that everything is running correctly.

```bash
# Check container status (all should be "Up" or "healthy")
docker compose ps

# Run a full system health check
./tools/check-health.sh
```

You can now access your VaultWarden instance at the domain you configured! The admin panel is available at https://your-domain.com/admin. The initial admin token can be viewed with:

```bash
sudo ./tools/edit-secrets.sh --view
```

---

## 🗑️ Files to Delete

To finalize the simplification of your project, the following files and directories are no longer needed and should be deleted:

- `tools/migrate-from-oci.sh` (Legacy migration tool)
- `tools/ci-validate.sh` (Development/CI tool)
- `tools/test-sops-integration.sh` (Development/CI tool)
- `tools/rotate-secrets.sh` (Merged into `edit-secrets.sh`)
- `tools/rotate-all-secrets.sh` (Merged into `edit-secrets.sh`)
- `tools/rotate-admin-token.sh` (Merged into `edit-secrets.sh`)
- `tools/sops-maintenance.sh` (Merged into `check-health.sh`)
- `tools/update-secrets.sh` (Redundant token generator)
- `tools/seal-secrets.sh` (Development/CI tool)
- `tools/startup.sh` (The one in `tools`, keep the one in the root directory)
- `tools/settings.env` (Replaced by the unified `settings.env.example` at the root)
- `docker-compose.swarm.yml` (Over-engineered for a small deployment)

---

