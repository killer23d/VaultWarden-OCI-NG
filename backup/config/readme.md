
# Backup Configuration Directory

This directory contains the rclone configuration for backup services.

## Security Notice

⚠️ **IMPORTANT**: This directory contains sensitive authentication credentials.

- Files in this directory are automatically excluded from version control
- Keep file permissions restricted (600 for config files)
- Never share or commit actual configuration files


## Setup Instructions

1. **Copy the template**:

```
cp ../templates/rclone.conf.example ./rclone.conf
```

2. **Edit with your credentials**:

```
nano rclone.conf
```

3. **Set proper permissions**:

```
chmod 600 rclone.conf
```

4. **Test your configuration**:

```
docker compose exec bw_backup rclone lsd your-remote:
```


## Interactive Configuration

For easier setup, use rclone's interactive configuration:

```
docker compose exec bw_backup rclone config
```

This will guide you through setting up your cloud storage provider.

## Supported Providers

- AWS S3
- Backblaze B2
- Google Cloud Storage
- Google Drive
- Microsoft OneDrive
- Dropbox
- SFTP/SSH servers
- Local/Network storage


## Validation

After configuration, validate your setup:

```
# List remotes
docker compose exec bw_backup rclone listremotes

# Test connectivity  
docker compose exec bw_backup rclone lsd remote-name:

# Run a backup test
docker compose exec bw_backup /backup/db-backup.sh --test
```


## Troubleshooting

- Check container logs: docker compose logs bw_backup
- Verify permissions: ls -la rclone.conf should show -rw-------
- Test database connectivity: docker compose exec bw_backup mysqladmin ping -h bw_mariadb

