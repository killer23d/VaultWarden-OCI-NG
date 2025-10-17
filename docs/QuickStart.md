# Quick Start Guide

> **🎯 Goal**: From zero to a production-ready VaultWarden instance in under 30 minutes, featuring full automation, monitoring, and state-of-the-art security.

## ⚠️ Critical Prerequisites

### System Requirements
* **OS**: A fresh installation of Ubuntu 24.04 LTS.
* **RAM**: 2GB minimum (4GB recommended for teams of 10 or more).
* **Storage**: 20GB minimum (50GB recommended for long-term use).
* **Network**: A stable internet connection with ports 22, 80, and 443 accessible.
* **Access**: `root` or `sudo` privileges are required for the initial setup.

### Information You'll Need
* **A registered domain name**: e.g., `vault.yourdomain.com`, with the DNS 'A' record pointing to your server's public IP address.
* **An email address**: For receiving administrative notifications from your VaultWarden instance.

## 🚀 30-Minute Deployment

### Phase 1: Server Preparation (5 minutes)

1. **Connect to your server and update it:**
   ```bash
   ssh your_user@your_server_ip
   sudo apt-get update && sudo apt-get upgrade -y
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/killer23d/VaultWarden-OCI-NG.git
   cd VaultWarden-OCI-NG
   ```

3. **Make the scripts executable:**
   ```bash
   chmod +x startup.sh tools/*.sh lib/*.sh
   ```

### Phase 2: Automated Installation (15 minutes)

Run the all-in-one setup script. This script will:
* Install Docker and Docker Compose.
* Configure the UFW firewall.
* Install and configure Fail2ban for intrusion prevention.
* Generate encrypted secrets using SOPS+Age.
* Set up the necessary directory structure with secure permissions.
* Install cron jobs for automated backups and monitoring.

```bash
sudo ./tools/init-setup.sh
```

Follow the on-screen prompts to configure your domain and administrator email address.

### Phase 3: Service Launch (5 minutes)

Start the entire VaultWarden stack using the `startup.sh` script. This script will:
* Load the encrypted secrets.
* Start all services in the correct order.
* Perform health checks to ensure everything is running correctly.

```bash
./startup.sh
```

### Phase 4: Initial Access and Configuration (5 minutes)

1. **Retrieve your admin token:**
   ```bash
   sudo ./tools/edit-secrets.sh --view | grep admin_token
   ```

2. **Access the Admin Panel:**
   Open your web browser and navigate to `https://your-domain.com/admin`. Use the token you just retrieved to log in.

3. **Create your first user:**
   You can either enable sign-ups from the admin panel or create a new user directly.

## ✅ Post-Deployment Verification

Run the built-in health check to verify that all components are functioning correctly:

```bash
./tools/check-health.sh
```

You now have a fully functional, secure, and self-maintaining VaultWarden instance.

## 🔧 Additional Configuration

### SMTP Configuration (Optional)

To enable email notifications and password reset functionality:

```bash
# Edit the encrypted secrets
sudo ./tools/edit-secrets.sh

# Add your SMTP settings to the secrets file:
# smtp_password: "your-smtp-password"

# Then update your settings.env file with SMTP host details
```

### CloudFlare Integration (Recommended)

For enhanced security and DDoS protection:

1. Point your domain to CloudFlare nameservers
2. Configure CloudFlare API token in your secrets
3. Enable the CloudFlare Fail2ban integration

## 🚨 Troubleshooting

### Common Issues

**Permission Denied Errors:**
```bash
chmod +x startup.sh tools/*.sh lib/*.sh
```

**Cannot Access Web Interface:**
```bash
# Check container status
docker compose ps

# Check firewall
sudo ufw status

# Check logs
docker compose logs caddy
```

**SSL Certificate Issues:**
Wait 5-10 minutes for automatic certificate generation. Ensure your domain is publicly accessible.

## 📋 Quick Reference Commands

```bash
# Check system status
./tools/check-health.sh

# View service logs
docker compose logs -f

# Restart services
./startup.sh

# Create manual backup
./tools/create-full-backup.sh

# Edit encrypted secrets
sudo ./tools/edit-secrets.sh

# Stop all services
docker compose down
```

## 🎯 Success Checklist

After completing this guide, you should have:

- [ ] Web access to `https://your-domain.com`
- [ ] Admin panel access with generated token
- [ ] First user account created and tested
- [ ] Valid SSL certificate (check at ssllabs.com)
- [ ] UFW firewall active with proper rules
- [ ] Fail2ban protecting against intrusions
- [ ] Automated backup system configured
- [ ] Health monitoring active

## 📚 Next Steps

1. **Configure team access**: Set up user accounts for your team
2. **Test backups**: Verify the backup system works correctly
3. **Review security**: Check fail2ban logs and SSL configuration
4. **Set up monitoring**: Configure email notifications for system alerts
5. **Documentation**: Record your specific configuration for future reference

For detailed information on any of these topics, refer to the other documentation files in the `docs/` directory.
