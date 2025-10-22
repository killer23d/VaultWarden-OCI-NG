# Architecture Guide

**System design with defense-in-depth, input validation, and non-root containers**

## High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐      │
│  │ 17+ Tools   │  │ 15+ Libs    │  │    Monitoring       │      │
│  │ (ops-*.sh)  │  │ (lib/*.sh)  │  │   & Automation      │      │
│  └─────────────┘  └─────────────┘  └─────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                      Security Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐      │
│  │ Cloudflare  │  │   fail2ban  │  │   UFW Firewall     │      │
│  │ (DDoS/WAF)  │  │ (IDS/IPS)   │  │ (Cloudflare IPs)   │      │
│  └─────────────┘  └─────────────┘  └─────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐      │
│  │    Caddy    │  │ VaultWarden │  │    Watchtower      │      │
│  │ (Non-Root)  │  │ (Non-Root)  │  │   (Updates)        │      │
│  └─────────────┘  └─────────────┘  └─────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                       Data Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐      │
│  │ SQLite DB   │  │ Encrypted   │  │   Backup System     │      │
│  │ (WAL mode)  │  │ Secrets     │  │  (Age + Email)      │      │
│  └─────────────┘  └─────────────┘  └─────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

- **Input Validation** (`lib/validation.sh`)
  - Validates domain and email during setup and config changes
  - Prevents common misconfiguration errors early

- **Container Security** (`docker-compose.yml`)
  - VaultWarden and Caddy run as non-root (UID/GID 1000)
  - fail2ban retains root + capabilities for iptables
  - ddclient non-root via PUID/PGID

- **Networking and Edge** (Caddy + Cloudflare)
  - TLS termination, HSTS, CSP, basic auth for admin
  - Cloudflare IP trust + WAF and DDoS mitigation

- **Data and Backups**
  - SQLite (WAL), encrypted backups with Age + SOPS
  - Emergency kit workflow with DR runbook

## Security Design Rationale

- **Least Privilege**: Services run with minimum necessary privileges
- **Fail-Safe Defaults**: Input validation rejects unsafe/incorrect values
- **Defense in Depth**: Multi-layer protections from network to data layers
- **Operational Simplicity**: Changes add minimal overhead and align with set-and-forget goals

## Operational Flows

### Initialization Flow (Validated)
1. `install-deps.sh` installs core tools
2. `init-setup.sh` generates keys, config firewall, validates inputs
3. `.env` created with clean domain and admin email
4. Secrets edited via SOPS
5. Startup orchestrates containers with health checks

### Backup & DR Flow
1. Cron triggers database and full backups
2. Backups encrypted with Age, verified with checksums
3. Emergency kit emailed and stored securely
4. Recovery uses kit + scripts to restore in 15–30 minutes

## Future Enhancements (Optional)

- Optional: `no-new-privileges` and `tmpfs` hardening for caddy/vaultwarden
- Optional: Prometheus metrics if moving beyond "set-and-forget"
