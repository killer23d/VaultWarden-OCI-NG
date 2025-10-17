# Architecture Overview

The VaultWarden-OCI-NG stack is built upon a foundation of containerized services, orchestrated by Docker Compose. The architecture is designed for security, resilience, and ease of maintenance.

## Core Components

The stack is composed of the following key services:

*   **VaultWarden**: The central application that provides the password management functionality. It's an open-source, Rust-based implementation of the Bitwarden server API.

*   **Caddy**: A modern, powerful web server that serves as a reverse proxy for the VaultWarden service. Its primary roles are:
    *   **Automatic HTTPS**: It automatically obtains and renews SSL/TLS certificates from Let's Encrypt.
    *   **Security**: It's configured with a hardened security policy to protect the application.

*   **Fail2ban**: An intrusion prevention framework that monitors log files for malicious activity, such as repeated failed login attempts, and temporarily bans the offending IP addresses at the firewall level.

*   **Watchtower**: An automated service that monitors for new versions of the running container images. When a new version is available, it gracefully shuts down the container, pulls the new image, and restarts the container with the same configuration.

*   **ddclient**: A dynamic DNS client that periodically checks the server's public IP address and updates the DNS 'A' record with your DNS provider if it has changed. This is an optional service for users who do not have a static IP.

## Secret Management

A cornerstone of this architecture is its secure handling of secrets. All sensitive information, such as API keys, passwords, and tokens, is managed through **SOPS (Secrets OPerationS)** with **Age** encryption.

*   Secrets are stored in an encrypted YAML file (`secrets/secrets.yaml`).
*   The `startup.sh` script decrypts these secrets at runtime and exposes them to the relevant containers as Docker Secrets.
*   This ensures that no sensitive information is ever stored in plain text on the disk or in the Docker Compose file.

## Data Flow

1.  A user makes a request to `https://your-domain.com`.
2.  The request is routed to the **Caddy** container.
3.  Caddy terminates the TLS connection and proxies the request to the **VaultWarden** container.
4.  VaultWarden processes the request, interacting with its SQLite database.
5.  All requests are logged, and the logs are monitored by **Fail2ban**. If malicious activity is detected, Fail2ban will block the source IP address at the firewall.

## Automation

The entire stack is designed around the principle of "set and forget." This is achieved through a suite of automation scripts and services:

*   **`init-setup.sh`**: For fully automated initial server setup.
*   **Cron Jobs**: For automated backups, monitoring, and database maintenance.
*   **Watchtower**: For automated updates of the application stack.
*   **Caddy**: For automated SSL certificate management.

This architecture provides a robust, secure, and low-maintenance platform for self-hosting your own password manager.
