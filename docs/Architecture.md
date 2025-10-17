# Architecture Overview

The VaultWarden-OCI-NG stack represents a modern, security-first approach to self-hosted password management. Built on containerized microservices with comprehensive automation, it delivers enterprise-grade security with minimal operational overhead.

## Design Principles

### Security by Default
- **Zero-Trust Architecture**: All communications encrypted, minimal attack surface
- **Defense in Depth**: Multiple security layers from network to application level
- **Encrypted Secrets Management**: SOPS+Age encryption for all sensitive data
- **Automated Security Updates**: Container updates with security patch automation

### Operational Simplicity  
- **One-Command Deployment**: Complete stack deployment with single script
- **Self-Healing Systems**: Automated failure detection and recovery
- **Comprehensive Monitoring**: Health checks, alerting, and performance tracking
- **Simplified Management**: Intuitive scripts for all operational tasks

### Reliability and Resilience
- **Automated Backups**: Encrypted, compressed, and verified backup system
- **Health Monitoring**: Continuous service health validation
- **Graceful Degradation**: Service resilience under failure conditions
- **Recovery Automation**: Automated restoration capabilities

## Core Architecture

### Service Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┼───────────────────────────────────────┐
│                CloudFlare (Optional)                       │
│             DDoS Protection & CDN                          │
└─────────────────────┼───────────────────────────────────────┘
                      │ HTTPS (443)
┌─────────────────────┼───────────────────────────────────────┐
│                 UFW Firewall                               │
│          SSH(22) + HTTP(80) + HTTPS(443)                  │  
└─────────────────────┼───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Caddy Reverse Proxy                        │
│        • Automatic HTTPS (Let's Encrypt)                  │
│        • HTTP/2 & Security Headers                        │
│        • Real IP Detection (CloudFlare)                   │
│        • Rate Limiting & Access Control                   │
└─────────────────────┼───────────────────────────────────────┘
                      │ HTTP (8080)
┌─────────────────────▼───────────────────────────────────────┐
│                 VaultWarden Core                           │
│        • Bitwarden-Compatible API                         │
│        • User Authentication & Management                 │
│        • Vault Data Processing                            │
│        • Push Notification Integration                    │
└─────────────────────┼───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 SQLite Database                            │
│        • User Accounts & Organizations                    │
│        • Encrypted Vault Items                            │
│        • Access Control & Audit Logs                      │
│        • Automated Backup & Optimization                  │
└─────────────────────────────────────────────────────────────┘
```

## Service Components

### Core Application Services

#### VaultWarden
**Role**: Primary application server providing Bitwarden-compatible API

**Key Features**:
- **Rust-based Implementation**: High performance, memory safety, minimal resource usage
- **Bitwarden Compatibility**: Full API compatibility with official Bitwarden clients
- **Multi-tenant Support**: Organizations, collections, and shared vaults
- **Advanced Authentication**: TOTP, WebAuthn, SSO integration capabilities
- **Push Notifications**: Real-time sync across devices

**Security Features**:
- Application-level encryption for vault data
- Secure password hashing (Argon2)
- Rate limiting for authentication attempts
- Session management and timeout controls

**Resource Configuration**:
- Memory Limit: 2GB (configurable)
- CPU Limit: 1.0 cores (configurable)
- Health Check: HTTP endpoint monitoring
- Restart Policy: Unless manually stopped

#### Caddy Reverse Proxy
**Role**: Frontend proxy providing HTTPS termination and security hardening

**Core Capabilities**:
- **Automatic HTTPS**: Let's Encrypt certificate acquisition and renewal
- **HTTP/2 Support**: Enhanced performance for modern browsers  
- **Security Headers**: HSTS, CSP, and other protective headers
- **Real IP Detection**: CloudFlare IP forwarding for accurate logging

**Security Features**:
- TLS 1.3 by default with strong cipher suites
- OCSP stapling for certificate validation
- Automatic redirect HTTP → HTTPS
- CloudFlare IP restriction (when configured)

**Configuration Highlights**:
```caddyfile
{$DOMAIN} {
    reverse_proxy vaultwarden:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    header / {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "same-origin"
    }
}
```

### Security and Monitoring Services

#### Fail2ban
**Role**: Intrusion prevention system with dynamic IP blocking

**Protection Scope**:
- SSH brute force protection
- VaultWarden authentication failures
- Caddy rate limit violations
- HTTP scan and probe attempts

**Advanced Features**:
- **CloudFlare Integration**: API-based IP blocking at CDN level
- **Geographic Filtering**: Country-based access controls
- **Adaptive Banning**: Progressive timeout increases for repeat offenders
- **Email Notifications**: Real-time alerts for security events

**Jail Configuration**:
```ini
[vaultwarden-auth]
enabled = true
filter = vaultwarden-auth
logpath = /var/log/vaultwarden/vaultwarden.log
maxretry = 3
bantime = 3600
findtime = 600
action = cloudflare-api
         iptables-multiport[name=vaultwarden]
```

#### Watchtower  
**Role**: Automated container update management

**Update Strategy**:
- **Rolling Updates**: Zero-downtime service updates
- **Label-based Selection**: Only updates explicitly tagged containers
- **Health Verification**: Post-update health check validation
- **Email Notifications**: Update completion and failure alerts

**Security Considerations**:
- Updates scheduled during maintenance windows
- Automatic rollback on health check failures
- Configuration backup before updates
- Update logging and audit trails

### Support Services

#### ddclient (Dynamic DNS)
**Role**: Automatic DNS record management for dynamic IP addresses

**Supported Providers**:
- CloudFlare DNS API
- Route53, Google Cloud DNS
- Traditional dynamic DNS services

**Configuration Template**:
```ini
protocol=cloudflare
use=web, web=https://ipify.org
server=www.cloudflare.com
login={{CLOUDFLARE_EMAIL}}
password={{CLOUDFLARE_API_TOKEN}}
zone={{DOMAIN_ZONE}}
{{HOSTNAME}}
```

## Data Architecture

### Storage Strategy

#### Primary Data Storage
**SQLite Database**: Default storage engine optimized for small-to-medium deployments

**Advantages**:
- Zero configuration required
- ACID compliance with WAL mode
- Excellent performance for <50 concurrent users
- Simplified backup and recovery

**Database Schema Highlights**:
- **Users Table**: Authentication, settings, premium features
- **Organizations**: Multi-tenant workspace management  
- **Vault Items**: Encrypted password, note, and identity storage
- **Collections**: Organizational vault item groupings
- **Audit Logs**: Access tracking and compliance reporting

#### File System Layout
```
/var/lib/vaultwarden-{project}/
├── data/
│   ├── bwdata/                 # VaultWarden data directory
│   │   ├── db.sqlite3         # Main database file
│   │   ├── attachments/       # User uploaded files
│   │   └── sends/             # Temporary secure file shares
│   ├── backups/               # Automated backup storage
│   │   ├── daily/             # Daily database backups
│   │   └── weekly/            # Full system backups  
│   └── logs/                  # Service log files
│       ├── vaultwarden/       # Application logs
│       ├── caddy/             # Proxy access logs
│       └── fail2ban/          # Security event logs
├── caddy_data/                # Let's Encrypt certificates
└── caddy_config/              # Caddy runtime configuration
```

### Backup Architecture

#### Multi-Tier Backup Strategy
```
┌─────────────────────────────────────────────────────────────┐
│                    Backup Tiers                            │
├─────────────────────────────────────────────────────────────┤
│ Tier 1: Real-time (WAL Mode)                              │
│   • SQLite Write-Ahead Logging                            │
│   • Immediate data durability                             │
│   • Crash recovery capability                             │
├─────────────────────────────────────────────────────────────┤
│ Tier 2: Daily Automated (Database)                        │
│   • Encrypted SQLite dumps                                │
│   • 30-day retention policy                               │
│   • Integrity verification                                │
├─────────────────────────────────────────────────────────────┤
│ Tier 3: Weekly Full System                                │
│   • Complete configuration backup                         │
│   • SSL certificates and keys                             │
│   • 8-week retention policy                               │
├─────────────────────────────────────────────────────────────┤
│ Tier 4: Off-site Storage (Manual)                         │
│   • Cloud storage integration                             │
│   • Geographic redundancy                                 │
│   • Long-term archival                                    │
└─────────────────────────────────────────────────────────────┘
```

## Security Architecture

### Encryption and Secret Management

#### SOPS + Age Encryption Stack
```
┌─────────────────────────────────────────────────────────────┐
│                 Secret Management Flow                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Age Private Key                                │
│         (Generated during init-setup)                      │
│         Stored: /secrets/keys/age-key.txt                  │
│         Permissions: 600 (root only)                       │
└─────────────────────┼───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           Encrypted Secrets File                           │
│         File: secrets/secrets.yaml                         │
│         Format: SOPS encrypted YAML                        │
│         Contents: API keys, passwords, tokens              │
└─────────────────────┼───────────────────────────────────────┘
                      │ Runtime Decryption
┌─────────────────────▼───────────────────────────────────────┐
│            Docker Secrets                                  │
│         Mount Path: /run/secrets/{secret_name}             │
│         Access: Read-only in containers                    │
│         Lifecycle: Created at startup, destroyed at stop  │
└─────────────────────────────────────────────────────────────┘
```

#### Secret Categories
- **admin_token**: VaultWarden administrative access
- **smtp_password**: Email service authentication  
- **backup_passphrase**: Backup encryption key
- **push_installation_key**: Push notification service
- **cloudflare_api_token**: CDN and security integration

### Network Security

#### Firewall Configuration (UFW)
```bash
Default: deny (incoming), allow (outgoing), deny (routed)
Rules:
22/tcp (SSH)     ALLOW IN    # Management access
80/tcp (HTTP)    ALLOW IN    # Let's Encrypt validation  
443/tcp (HTTPS)  ALLOW IN    # Application access
```

#### Container Network Isolation
- **Custom Bridge Network**: Isolated container communication
- **No External Exposure**: Only Caddy proxy exposed to host network
- **Internal DNS**: Container name resolution within stack
- **Dynamic Subnet**: Project-specific IP ranges to avoid conflicts

### Authentication and Access Control

#### Multi-Factor Authentication Support
- **TOTP (Time-based OTP)**: Standard authenticator app support
- **WebAuthn**: Hardware security key integration
- **Email-based 2FA**: Backup authentication method

#### Administrative Access Control
- **Admin Panel**: Separate authentication with dedicated token
- **Role-based Permissions**: User, admin, and organization roles  
- **Session Management**: Configurable timeout and refresh policies
- **Audit Logging**: Comprehensive access and change tracking

## Monitoring and Observability

### Health Monitoring Architecture

#### Multi-Level Health Checks
```
┌─────────────────────────────────────────────────────────────┐
│                 Monitoring Layers                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Container Health                                  │
│   • Docker native health checks                           │
│   • Service-specific endpoints                            │
│   • Resource utilization monitoring                       │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Application Health                               │
│   • API endpoint responsiveness                           │
│   • Database connectivity                                 │
│   • Authentication system status                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: System Health                                    │
│   • SSL certificate validity                              │
│   • Disk space and inode usage                           │
│   • Memory and CPU utilization                           │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Security Monitoring                              │
│   • Firewall rule compliance                             │
│   • Fail2ban jail activity                               │
│   • Failed authentication tracking                        │
└─────────────────────────────────────────────────────────────┘
```

#### Automated Response Systems
- **Service Restart**: Automatic recovery for failed containers
- **Resource Management**: Memory cleanup and optimization
- **Alert Generation**: Email notifications for critical events
- **Log Rotation**: Automatic cleanup to prevent disk exhaustion

## Scalability Considerations

### Vertical Scaling
**Current Capacity**: Supports 10-50 concurrent users efficiently

**Resource Scaling Options**:
- **Memory**: Increase container memory limits for larger user bases
- **CPU**: Additional CPU cores for improved concurrent request handling
- **Storage**: SSD expansion for database growth and backup retention

### Horizontal Scaling Migration
**PostgreSQL Migration Path**: For deployments exceeding 50 users

**Migration Benefits**:
- **Concurrent Connections**: Higher concurrent user support
- **Advanced Features**: Full-text search, JSON operations, extensions
- **Backup Options**: Point-in-time recovery, streaming replication
- **Monitoring**: Enhanced query performance analysis

### High Availability Options
**Load Balancing**: Multiple VaultWarden instances with shared database
**Database Clustering**: PostgreSQL with read replicas  
**Geographic Distribution**: Multi-region deployment with data synchronization

## Deployment Variations

### Development Environment
- **Local Docker**: Single-machine development stack
- **Reduced Security**: Simplified secrets management
- **Debug Logging**: Enhanced troubleshooting capabilities

### Production Environment  
- **Full Security Stack**: Complete security hardening
- **Automated Monitoring**: Comprehensive health checking
- **Backup Automation**: Multi-tier backup strategy
- **Performance Optimization**: Resource limits and monitoring

### Enterprise Environment
- **SSO Integration**: LDAP, SAML, or OAuth2 authentication
- **Compliance Features**: Audit logging, data retention policies
- **Advanced Monitoring**: Integration with enterprise monitoring systems
- **Multi-tenancy**: Organization-based user separation

This architecture provides a robust foundation for self-hosted password management with enterprise-grade security, operational simplicity, and growth capacity. The design emphasizes automation, security, and reliability while maintaining ease of management for small teams and organizations.
