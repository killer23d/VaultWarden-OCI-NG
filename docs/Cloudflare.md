# CloudFlare Integration Guide

> **🎯 CloudFlare Philosophy**: Leverage CloudFlare's global edge network for enhanced performance, security, and reliability while maintaining seamless integration with VaultWarden-OCI-Minimal.

## 🌐 **CloudFlare Integration Overview**

VaultWarden-OCI-Minimal provides **comprehensive CloudFlare integration** that combines edge security, performance optimization, and automated management:

```bash
CloudFlare Integration Features:
├── Edge Security Protection
│   ├── DDoS mitigation and bot detection
│   ├── WAF (Web Application Firewall) rules
│   ├── Geographic access control
│   ├── Rate limiting and challenge pages
│   └── SSL/TLS optimization and security
│
├── Performance Enhancement
│   ├── Global CDN with 300+ locations
│   ├── Smart routing and Argo optimization
│   ├── Caching and compression
│   ├── HTTP/3 and modern protocol support
│   └── Real-time performance analytics
│
├── Automated Management
│   ├── Dynamic IP range updates
│   ├── Fail2ban edge blocking integration
│   ├── DNS management and DDNS support
│   ├── SSL certificate optimization
│   └── API-driven configuration management
│
└── Reliability Features
    ├── Always Online™ caching
    ├── Load balancing and failover
    ├── Health checks and monitoring
    ├── Analytics and threat intelligence
    └── Enterprise-grade uptime SLA
```

### **Integration Architecture**
```bash
CloudFlare → VaultWarden Traffic Flow:
Internet User → CloudFlare Edge → Origin Server (VaultWarden)
                     ↑
            ┌────────┴─────────┐
            │  CloudFlare CDN  │
            │  - DDoS Protection
            │  - Bot Detection
            │  - Rate Limiting
            │  - SSL Termination
            │  - Caching Rules
            └──────────────────┘
                     ↓
            ┌────────┴─────────┐
            │   Origin Server  │
            │  - Caddy Proxy
            │  - VaultWarden App
            │  - Real IP Detection
            │  - Security Headers
            └──────────────────┘
```

## 🚀 **CloudFlare Account Setup**

### **Account Prerequisites**

#### **CloudFlare Account Types**
```bash
CloudFlare Plan Recommendations:

Free Plan:
✅ Suitable for personal use and small teams
✅ Basic DDoS protection and CDN
✅ Universal SSL certificates
✅ Basic analytics and security
⚠️  Limited to 3 page rules
⚠️  Limited security features

Pro Plan ($20/month):
✅ Enhanced security features
✅ Image optimization and Polish
✅ Advanced analytics
✅ 20 page rules
✅ WAF custom rules (limited)

Business Plan ($200/month):
✅ Advanced security and WAF
✅ Load balancing
✅ Custom SSL certificates
✅ PCI compliance features
✅ 50 page rules

Enterprise Plan (Custom):
✅ Advanced bot management
✅ Full WAF capabilities
✅ 24/7 phone support
✅ Custom integrations
✅ Unlimited page rules
```

#### **Required CloudFlare Credentials**
```bash
API Authentication Options:

Global API Key (Legacy - Full Access):
├── Found: CloudFlare Dashboard → My Profile → API Tokens
├── Security: Full account access (use with caution)
├── Usage: Legacy integrations and full automation
└── Recommendation: Use for initial setup only

API Token (Recommended - Scoped Access):
├── Created: CloudFlare Dashboard → My Profile → API Tokens → Create Token
├── Security: Granular permissions and scope control
├── Usage: Automated scripts and fail2ban integration
└── Recommendation: Preferred for production use

Required Permissions for VaultWarden Integration:
├── Zone:Zone:Read (to list zones)
├── Zone:Zone Settings:Edit (to modify security settings)
├── Zone:DNS:Edit (for DDNS and DNS management)
├── User:Firewall Services:Edit (for fail2ban IP blocking)
└── Zone:Analytics:Read (for monitoring and reporting)
```

### **Domain Configuration**

#### **DNS Setup for CloudFlare**
```bash
# Step 1: Add Domain to CloudFlare
# 1. Log in to CloudFlare Dashboard
# 2. Click "Add a Site"
# 3. Enter your domain: yourdomain.com
# 4. Select plan (Free is sufficient for small teams)
# 5. CloudFlare will scan existing DNS records

# Step 2: Update Nameservers
# Replace your domain registrar's nameservers with CloudFlare's:
# Example CloudFlare nameservers (yours will be different):
# ava.ns.cloudflare.com
# ben.ns.cloudflare.com

# Step 3: Configure DNS Records
# A Record Configuration:
Name: vault (or @ for root domain)
IPv4 Address: YOUR_SERVER_IP
Proxy Status: Proxied (Orange Cloud - ENABLED)
TTL: Auto

# CNAME Record (if using subdomain):
Name: vault
Target: yourdomain.com
Proxy Status: Proxied (Orange Cloud - ENABLED)
TTL: Auto

# Step 4: Verify DNS Propagation
nslookup vault.yourdomain.com
dig vault.yourdomain.com

# Expected result should show CloudFlare IP addresses when proxied
```

#### **CloudFlare Proxy Configuration**
```bash
Proxy Settings (Orange Cloud vs Gray Cloud):

Proxied (Orange Cloud) - Recommended:
✅ Traffic routes through CloudFlare edge
✅ DDoS protection and security features active
✅ SSL certificates managed by CloudFlare
✅ Caching and performance optimization
✅ Real visitor IP hidden from logs (requires configuration)
✅ Enhanced security and analytics available

DNS Only (Gray Cloud) - Direct:
⚠️  Traffic goes directly to origin server
⚠️  No DDoS protection or security features
⚠️  SSL certificates must be managed on origin
⚠️  No caching or performance benefits
⚠️  Origin server IP exposed publicly
✅ Simpler configuration, no proxy complexity
```

## 🔐 **Security Configuration**

### **SSL/TLS Security Settings**

#### **SSL/TLS Encryption Modes**
```bash
# Configure: CloudFlare Dashboard → SSL/TLS → Overview

SSL/TLS Encryption Modes:

Off (Not Secure) - ❌ Never Use:
├── No encryption between visitor and CloudFlare
├── No encryption between CloudFlare and origin
└── Completely insecure - not suitable for password manager

Flexible - ❌ Not Recommended:
├── HTTPS between visitor and CloudFlare
├── HTTP between CloudFlare and origin
└── Vulnerable to man-in-the-middle attacks

Full - ⚠️ Basic Security:
├── HTTPS between visitor and CloudFlare  
├── HTTPS between CloudFlare and origin
├── Origin certificate can be self-signed
└── Minimal security for password manager

Full (Strict) - ✅ Recommended:
├── HTTPS between visitor and CloudFlare
├── HTTPS between CloudFlare and origin
├── Origin must have valid SSL certificate
├── Best security for sensitive applications
└── Required for VaultWarden deployment
```

#### **Advanced SSL Settings**
```bash
# CloudFlare Dashboard → SSL/TLS → Edge Certificates

Recommended SSL Configuration:

Always Use HTTPS: Enabled
├── Automatically redirects HTTP to HTTPS
├── Ensures all traffic is encrypted
└── Essential for password manager security

HTTP Strict Transport Security (HSTS): Enabled
├── Max Age: 12 months (31536000 seconds)
├── Include Subdomains: Enabled (if no conflicting subdomains)
├── Preload: Enabled (for maximum security)
└── No-Sniff Header: Enabled

Minimum TLS Version: 1.2
├── Disables older, insecure TLS versions
├── Ensures modern encryption standards
└── Compatible with all modern browsers

TLS 1.3: Enabled
├── Latest TLS protocol with improved security
├── Better performance and reduced latency
└── Supported by all modern clients

Certificate Transparency Monitoring: Enabled
├── Monitors for unauthorized certificates
├── Alerts for potential certificate abuse
└── Enhanced security monitoring
```

### **Web Application Firewall (WAF)**

#### **WAF Configuration for VaultWarden**
```bash
# CloudFlare Dashboard → Security → WAF

CloudFlare WAF Rules for VaultWarden:

Managed Rules (Free Plan):
✅ CloudFlare Managed Ruleset: Enabled
✅ CloudFlare Core Ruleset: Enabled  
✅ CloudFlare WordPress Ruleset: Disabled (not applicable)

Custom Rules (Pro+ Plans):
# Admin Panel Protection
(http.request.uri.path matches "^/admin.*") and (not ip.geoip.country in {"US" "CA"})
Action: Block
Description: Block admin access from non-approved countries

# API Rate Limiting  
(http.request.uri.path matches "^/api.*") and (rate(5m) > 300)
Action: Challenge
Description: Rate limit API requests to prevent abuse

# Suspicious User Agents
(http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent eq "")
Action: Block  
Description: Block known scanning tools and empty user agents
```

#### **Rate Limiting Configuration**
```bash
# CloudFlare Dashboard → Security → Rate Limiting

VaultWarden Rate Limiting Rules:

Login Endpoint Protection:
├── URL Pattern: vault.yourdomain.com/api/accounts/prelogin
├── Requests: 10 requests per minute
├── Source: IP address
├── Action: Block for 10 minutes
└── Description: Prevent brute force login attempts

Admin Panel Protection:  
├── URL Pattern: vault.yourdomain.com/admin/*
├── Requests: 5 requests per minute
├── Source: IP address
├── Action: JS Challenge
└── Description: Protect admin interface from automated attacks

API General Protection:
├── URL Pattern: vault.yourdomain.com/api/*
├── Requests: 100 requests per minute  
├── Source: IP address
├── Action: Block for 1 minute
└── Description: General API abuse prevention

Sync Endpoint Protection:
├── URL Pattern: vault.yourdomain.com/api/sync
├── Requests: 30 requests per minute
├── Source: IP address
├── Action: Block for 5 minutes
└── Description: Prevent sync abuse while allowing normal usage
```

### **Bot Management and Security**

#### **Bot Fight Mode Configuration**
```bash
# CloudFlare Dashboard → Security → Bots

Bot Fight Mode (Free Plan):
✅ Enable Bot Fight Mode
├── Automatically challenges suspicious bots
├── Blocks definitely malicious traffic
├── Allows legitimate search engine bots
└── Provides basic bot analytics

Super Bot Fight Mode (Pro+ Plans):
✅ Enhanced bot detection algorithms
✅ Machine learning based analysis  
✅ Custom rules for bot handling
✅ Detailed bot analytics and reporting
✅ API for bot management automation

Bot Management Configuration:
# Allow legitimate bots
Good Bots: Allow
├── Search engines (Google, Bing, etc.)
├── Monitoring services (uptimerobot, etc.)
├── Security scanners (authorized)

# Challenge suspicious bots  
Likely Bots: JS Challenge
├── Automated tools with suspicious patterns
├── High-frequency requests from single IPs
├── Requests with suspicious user agents

# Block malicious bots
Bad Bots: Block
├── Known malicious crawlers
├── Vulnerability scanners
├── Brute force tools
```

## 🔧 **VaultWarden-Specific Configuration**

### **Caddy Integration with CloudFlare**

#### **Real IP Detection Configuration**
```bash
# CloudFlare IP ranges are automatically updated by:
./tools/update-cloudflare-ips.sh

# This script generates: ./caddy/cloudflare-ips.caddy
# Content example:
# Real IP detection for CloudFlare
real_ip from 173.245.48.0/20
real_ip from 103.21.244.0/22
real_ip from 103.22.200.0/22
real_ip from 103.31.4.0/22
# ... (additional CloudFlare IP ranges)
real_ip header CF-Connecting-IP

# Caddy configuration includes this via:
import /etc/caddy-extra/cloudflare-ips.caddy
```

#### **Caddy CloudFlare Headers**
```bash
# VaultWarden Caddyfile CloudFlare configuration:
{$DOMAIN} {
  encode gzip zstd
  
  reverse_proxy vaultwarden:8080 {
    # CloudFlare real IP detection
    header_up X-Real-IP {http.request.header.CF-Connecting-IP}
    header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}
    
    # Trust CloudFlare proxy headers
    trusted_proxies {
      # CloudFlare IP ranges (auto-updated)
      173.245.48.0/20
      103.21.244.0/22
      # ... (additional ranges from cloudflare-ips.caddy)
    }
  }

  # Security headers optimized for CloudFlare
  header {
    # Remove server information
    -Server
    
    # CloudFlare compatibility headers
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "strict-origin-when-cross-origin"
    
    # Enhanced CSP for password manager with CloudFlare
    Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; form-action 'self'; base-uri 'self'; frame-ancestors 'none';"
  }
}
```

### **Fail2ban CloudFlare Integration**

#### **CloudFlare Action Configuration**
```bash
# File: fail2ban/action.d/cloudflare.conf
# Automatically configured during setup

[Definition]
# CloudFlare API v4 integration for IP blocking
actionstart = 
actionstop = 
actioncheck = 

# Ban IP at CloudFlare edge (blocks before reaching origin)
actionban = curl -s -X POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \
            -H "X-Auth-Email: <cfuser>" \
            -H "X-Auth-Key: <cftoken>" \
            -H "Content-Type: application/json" \
            --data '{"mode":"block","configuration":{"target":"ip","value":"<ip>"},"notes":"Blocked by Fail2Ban on <hostname> - VaultWarden protection"}'

# Unban IP from CloudFlare edge
actionunban = curl -s -X DELETE "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/$( \
              curl -s -X GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?mode=block&configuration_target=ip&configuration_value=<ip>&page=1&per_page=1" \
              -H "X-Auth-Email: <cfuser>" \
              -H "X-Auth-Key: <cftoken>" | \
              jq -r '.result[0].id')" \
              -H "X-Auth-Email: <cfuser>" \
              -H "X-Auth-Key: <cftoken>"

[Init]
# Credentials configured during setup
cfuser = your-cloudflare-email@example.com
cftoken = your-cloudflare-global-api-key-or-token
```

#### **Fail2ban Jail Configuration for CloudFlare**
```bash
# File: fail2ban/jail.d/jail.local (generated during setup)

[DEFAULT]
# CloudFlare action configured automatically based on credentials
banaction = cloudflare  # or nftables-multiport if no CloudFlare creds

# VaultWarden-specific jails with CloudFlare integration
[vaultwarden-auth]
enabled = true
filter = vaultwarden
logpath = /var/log/vaultwarden/vaultwarden.log
ports = 80,443
maxretry = 5
findtime = 10m  
bantime = 2h
# When CloudFlare configured: IPs blocked at edge immediately

[vaultwarden-admin]
enabled = true
filter = vaultwarden-admin  
logpath = /var/log/vaultwarden/vaultwarden.log
ports = 80,443
maxretry = 3
findtime = 10m
bantime = 6h
# Admin panel protection: stricter limits, longer bans

# CloudFlare edge blocking provides:
# - Immediate global IP blocking
# - No origin server resource consumption  
# - Protection against volumetric attacks
# - Centralized threat intelligence
```

### **Dynamic DNS Integration**

#### **CloudFlare DDNS Configuration**
```bash
# For dynamic IP environments (home servers, changing IPs)

DDNS Configuration in settings.json:
{
  "DDCLIENT_ENABLED": true,
  "DDCLIENT_PROTOCOL": "cloudflare",
  "DDCLIENT_LOGIN": "your-email@cloudflare.com", 
  "DDCLIENT_PASSWORD": "your-cloudflare-api-token",
  "DDCLIENT_ZONE": "yourdomain.com",
  "DDCLIENT_HOST": "vault.yourdomain.com"
}

# Generated ddclient configuration:
# File: ddclient/ddclient.conf
protocol=cloudflare
use=web, web=checkip.dyndns.org/, web-skip='IP Address'
login=your-email@cloudflare.com
password=your-cloudflare-api-token  
zone=yourdomain.com
vault.yourdomain.com

# DDNS container automatically updates CloudFlare DNS when IP changes
# Useful for:
# - Home server deployments
# - VPS with dynamic IPs
# - Failover scenarios
# - Geographic server switching
```

## 📊 **Performance Optimization**

### **Caching Configuration**

#### **CloudFlare Caching Rules**
```bash
# CloudFlare Dashboard → Caching → Configuration

Cache Level: Standard
├── Caches static content automatically
├── Respects origin cache headers
├── Good balance for dynamic applications

Browser Cache TTL: 4 hours
├── Reasonable balance for password manager
├── Allows for quick updates when needed
├── Reduces unnecessary requests

Development Mode: Off (Production)
├── Bypasses cache for testing (when enabled)
├── Should be disabled for production
├── Useful during debugging and updates
```

#### **Page Rules for VaultWarden**
```bash
# CloudFlare Dashboard → Rules → Page Rules

VaultWarden-Specific Page Rules:

1. Admin Panel Security (Priority: 1)
   URL: vault.yourdomain.com/admin*
   Settings:
   - Security Level: High
   - Cache Level: Bypass
   - Disable Apps: On
   - Browser Integrity Check: On

2. API Endpoints (Priority: 2)  
   URL: vault.yourdomain.com/api/*
   Settings:
   - Cache Level: Bypass
   - Security Level: Medium
   - Browser Integrity Check: On

3. Static Assets (Priority: 3)
   URL: vault.yourdomain.com/*.css
   URL: vault.yourdomain.com/*.js
   URL: vault.yourdomain.com/*.woff*
   Settings:
   - Cache Level: Cache Everything
   - Edge Cache TTL: 1 month
   - Browser Cache TTL: 1 week

4. Main Application (Priority: 4)
   URL: vault.yourdomain.com/*
   Settings:
   - Cache Level: Standard
   - Security Level: Medium  
   - Always Online: On
   - SSL: Full (Strict)
```

### **Performance Features**

#### **Argo Smart Routing** (Pro+ Plans)
```bash
# CloudFlare Dashboard → Speed → Optimization

Argo Smart Routing:
✅ Intelligent traffic routing via fastest paths
✅ Real-time network optimization
✅ Reduces latency by up to 30%
✅ Especially beneficial for global users
💰 Additional cost: ~$5/month + $0.10/GB

Configuration:
1. Enable Argo Smart Routing
2. Monitor performance improvements
3. Review cost vs. performance benefits
4. Ideal for teams with global distribution
```

#### **HTTP/3 and Modern Protocols**
```bash
# CloudFlare Dashboard → Speed → Optimization

HTTP/3 (QUIC): Enabled
✅ Latest HTTP protocol
✅ Improved performance over unreliable connections  
✅ Better mobile performance
✅ Automatic fallback to HTTP/2

0-RTT Connection Resumption: Enabled
✅ Faster subsequent connections
✅ Reduced latency for returning visitors
✅ Maintains security while improving speed

Brotli Compression: Enabled
✅ Better compression than gzip
✅ Reduced bandwidth usage
✅ Faster page loads
✅ Automatic for supported browsers
```

## 🛡️ **Advanced Security Features**

### **Access Control**

#### **CloudFlare Access (Zero Trust)**
```bash
# For enhanced security (Teams/Enterprise plans)
# CloudFlare Dashboard → Zero Trust → Access

Access Policies for VaultWarden:

Admin Panel Access Policy:
├── Application: vault.yourdomain.com/admin*
├── Policy Name: VaultWarden Admin Access
├── Action: Allow
├── Rules: Email domain (@company.com) AND Country (US, CA)
├── Session Duration: 1 hour
└── Additional: Require device certificate

Employee Access Policy:  
├── Application: vault.yourdomain.com/*
├── Policy Name: VaultWarden Employee Access
├── Action: Allow  
├── Rules: Email domain (@company.com) OR IP range (office network)
├── Session Duration: 8 hours
└── Additional: Multi-factor authentication required

Geo-blocking Policy:
├── Application: vault.yourdomain.com/*
├── Policy Name: Geographic Restrictions
├── Action: Block
├── Rules: Country NOT IN (allowed countries list)
├── Exceptions: Known good IPs (travel, remote workers)
└── Bypass: Emergency access codes
```

#### **IP Access Rules**
```bash
# CloudFlare Dashboard → Security → WAF → Tools

IP Access Rules for VaultWarden:

Office Network Allowlist:
├── IP Range: 203.0.113.0/24 (example office network)
├── Action: Whitelist
├── Zone: vault.yourdomain.com
└── Note: "Office network - bypass security checks"

Known Malicious IPs:
├── Action: Block  
├── Source: Threat intelligence feeds
├── Scope: Entire account
└── Auto-managed: Via fail2ban integration

Country-Based Rules:
├── Action: Block or Challenge
├── Countries: High-risk regions (configurable)
├── Exceptions: Allowlist for legitimate users
└── Review: Monthly review of blocked countries
```

### **Advanced Threat Protection**

#### **DDoS Protection Configuration**
```bash
# Automatic DDoS Protection (All Plans):

Layer 3/4 Protection:
✅ Automatic detection and mitigation
✅ Volumetric attack protection  
✅ Protocol attack mitigation
✅ Network-level filtering

Layer 7 Protection:
✅ Application-layer attack detection
✅ HTTP flood protection
✅ Slow Loris and similar attack mitigation
✅ Challenge pages for suspicious traffic

Advanced DDoS (Enterprise):
✅ Custom mitigation rules
✅ Advanced analytics and reporting
✅ SLA guarantees for uptime
✅ Dedicated support for attacks
```

#### **Threat Intelligence Integration**
```bash
# CloudFlare's Global Threat Intelligence:

Automatic Protection:
├── Known malicious IPs blocked automatically
├── Botnet and malware C&C servers blocked
├── Phishing and malware domains blocked
├── Threat feeds updated in real-time

Custom Threat Lists:
├── Import custom threat intelligence feeds
├── Block lists from security vendors
├── Industry-specific threat indicators
├── Organization-specific IOCs

Integration with VaultWarden:
├── Fail2ban feeds blocked IPs to CloudFlare
├── CloudFlare threat data informs local security
├── Coordinated response to targeted attacks
├── Shared intelligence across deployments
```

## 📈 **Analytics and Monitoring**

### **CloudFlare Analytics**

#### **Traffic Analytics**
```bash
# CloudFlare Dashboard → Analytics & Logs → Traffic

Key Metrics for VaultWarden:

Traffic Overview:
├── Total Requests: Monitor for unusual spikes
├── Cached vs Uncached: Verify caching efficiency  
├── Bandwidth: Track data transfer usage
├── Unique Visitors: Understand user base

Geographic Distribution:
├── Requests by Country: Verify expected usage patterns
├── Threat Analysis: Identify attack sources
├── Performance by Region: Optimize for user locations
└── Compliance: Verify data residency requirements

Performance Metrics:
├── Origin Response Time: Monitor VaultWarden performance
├── Edge Response Time: CloudFlare performance impact
├── Cache Ratio: Effectiveness of caching rules
└── Error Rate: Application and infrastructure issues
```

#### **Security Analytics**
```bash
# CloudFlare Dashboard → Security → Overview

Security Event Monitoring:

Threat Categories:
├── Malicious Bot Traffic: Automated attacks blocked
├── DDoS Attacks: Volumetric and application attacks
├── WAF Triggers: Security rule activations
├── Rate Limiting: Abuse prevention activations
└── Access Control: Authentication and authorization events

Threat Intelligence:
├── Top Threat Countries: Geographic attack sources
├── Attack Vectors: Methods used by attackers
├── Blocked Requests: Prevented malicious traffic
├── Challenge Solve Rate: Legitimate vs automated traffic

Security Recommendations:
├── Suggested rule adjustments based on traffic patterns
├── Threat mitigation improvements
├── Performance optimization opportunities
└── Security posture enhancements
```

### **Logging and SIEM Integration**

#### **CloudFlare Logs Export**
```bash
# For advanced monitoring and compliance (Enterprise plan)

Logpush Configuration:
├── Destination: Syslog, S3, Google Cloud, Azure
├── Fields: Customizable log field selection
├── Filtering: Include only relevant events
├── Format: JSON, CSV, or custom formats

SIEM Integration Examples:

Splunk Integration:
├── CloudFlare Add-on for Splunk
├── Pre-built dashboards and alerts
├── Correlation with VaultWarden application logs
└── Advanced threat hunting capabilities

ELK Stack Integration:
├── Logstash input for CloudFlare logs
├── Elasticsearch indexing and search
├── Kibana dashboards for visualization
└── Custom alerting via Watcher

Custom SIEM:
├── API access to CloudFlare Analytics
├── Real-time log streaming
├── Custom correlation rules
└── Integration with existing security tools
```

## 🔧 **Management and Automation**

### **API Management**

#### **CloudFlare API Usage**
```bash
# VaultWarden-OCI-Minimal automated API usage:

Automated IP Range Updates:
├── Script: ./tools/update-cloudflare-ips.sh
├── Frequency: Daily via cron (3:00 AM)
├── Purpose: Maintain accurate real IP detection
├── API Calls: ~2 requests/day (minimal impact)

Fail2ban Integration:
├── Action: Block/unblock IPs via CloudFlare API
├── Frequency: As needed (attack-dependent)
├── Purpose: Edge-level IP blocking
├── API Calls: Variable based on attack volume

DNS Updates (DDNS):
├── Service: ddclient with CloudFlare protocol
├── Frequency: When IP changes detected
├── Purpose: Dynamic IP management
├── API Calls: Minimal (only on IP change)

Health Monitoring:
├── Script: ./tools/monitor.sh --cloudflare-check
├── Frequency: Every 5 minutes (optional)
├── Purpose: Verify CloudFlare integration health
├── API Calls: 288/day (within free limits)
```

#### **API Rate Limits and Best Practices**
```bash
CloudFlare API Rate Limits:

Global API Key:
├── Rate Limit: 1,200 requests per 5 minutes
├── Burst Limit: 100 requests per second
├── Recommendation: Use for setup only

API Token (Scoped):
├── Rate Limit: Varies by permissions
├── Burst Limit: Lower than Global API Key
├── Recommendation: Use for all automation

Best Practices:
├── Implement exponential backoff on failures
├── Cache responses when appropriate
├── Use webhooks instead of polling where possible
├── Monitor API usage via CloudFlare Dashboard
└── Implement circuit breakers for resilience
```

### **Maintenance Automation**

#### **Automated CloudFlare Maintenance**
```bash
# Maintenance tasks automatically handled:

Daily Tasks:
├── IP range updates (./tools/update-cloudflare-ips.sh)
├── Security event review (./tools/monitor.sh --security)
├── Performance monitoring (CloudFlare analytics)
└── Failed IP blocking coordination (fail2ban)

Weekly Tasks:
├── Analytics review and reporting
├── Security rule effectiveness analysis
├── Cache performance optimization
└── Threat intelligence updates

Monthly Tasks:
├── Access policy review (if using CloudFlare Access)
├── Geographic blocking rule updates
├── Performance optimization recommendations
└── Cost analysis and optimization
```

#### **Integration Health Monitoring**
```bash
# Monitor CloudFlare integration health:
./tools/monitor.sh --cloudflare-health

CloudFlare Integration Health Check:
✅ DNS Resolution: CloudFlare IPs returned
✅ Proxy Status: Orange cloud active
✅ SSL Certificate: Valid and CloudFlare-issued
✅ Real IP Detection: CF-Connecting-IP header present
✅ Fail2ban Integration: API credentials valid
✅ Security Rules: WAF and rate limiting active
✅ Performance: Response times within expected range

# Alert on integration issues:
# - DNS resolution failures
# - SSL certificate problems
# - API authentication errors
# - Performance degradation
# - Security rule bypass detection
```

## 🚨 **Troubleshooting CloudFlare Issues**

### **Common Integration Problems**

#### **SSL/TLS Issues**
```bash
# Problem: SSL certificate errors or warnings

Diagnostic Steps:
1. Check SSL/TLS mode in CloudFlare Dashboard
   - Must be "Full (Strict)" for VaultWarden
2. Verify origin certificate validity
   - ./tools/monitor.sh --certificate-check
3. Check HSTS settings
   - Headers may conflict with CloudFlare settings
4. Test SSL Labs rating
   - https://www.ssllabs.com/ssltest/

Common Solutions:
├── Change SSL mode to "Full (Strict)"
├── Regenerate origin certificates (Caddy automatic)
├── Clear CloudFlare cache (purge everything)
├── Verify Caddy configuration includes CloudFlare IPs
└── Check for mixed content issues
```

#### **Real IP Detection Problems**
```bash
# Problem: Logs show CloudFlare IPs instead of visitor IPs

Diagnostic Steps:
1. Verify CloudFlare IP ranges are current
   ./tools/update-cloudflare-ips.sh --verify
2. Check Caddy configuration includes ranges
   cat ./caddy/cloudflare-ips.caddy
3. Verify CF-Connecting-IP header present
   curl -H "Host: vault.yourdomain.com" http://localhost:80 -v
4. Test with debug logging enabled
   DEBUG=1 ./startup.sh

Solutions:
├── Update CloudFlare IP ranges: ./tools/update-cloudflare-ips.sh
├── Restart Caddy to reload configuration: docker compose restart caddy
├── Verify proxy_protocol is NOT enabled in Caddy
├── Check trusted_proxies configuration in Caddyfile
└── Confirm orange cloud (proxied) status in CloudFlare DNS
```

#### **Performance Issues**
```bash
# Problem: Slow response times through CloudFlare

Investigation Steps:
1. Compare direct vs CloudFlare response times
   # Direct: curl -w "@curl-format.txt" http://SERVER_IP/
   # CloudFlare: curl -w "@curl-format.txt" https://vault.yourdomain.com/
2. Check CloudFlare cache hit ratio
   # CloudFlare Dashboard → Caching → Analytics
3. Review cache rules and page rules
4. Monitor origin server performance
   ./tools/monitor.sh --performance

Optimization Solutions:
├── Adjust caching rules for better hit ratio
├── Enable Argo Smart Routing (if cost-effective)
├── Optimize origin server performance
├── Configure appropriate cache TTLs
├── Enable Brotli compression
├── Use HTTP/3 where supported
└── Review and optimize page rules
```

### **Emergency Procedures**

#### **CloudFlare Bypass (Emergency Access)**
```bash
# Emergency procedure if CloudFlare causes issues

Immediate Bypass (Gray Cloud):
1. CloudFlare Dashboard → DNS → Records
2. Click orange cloud next to A record (turn to gray)
3. Wait for DNS propagation (up to 5 minutes)
4. Access site directly: http://SERVER_IP or https://SERVER_IP

Complete CloudFlare Disable:
1. Change nameservers back to original registrar
2. Update DNS A record to point directly to server
3. Wait for DNS propagation (up to 48 hours)
4. Note: Loses all CloudFlare protection and performance benefits

Partial Bypass (Maintenance):
1. Enable Development Mode (bypasses cache for 3 hours)
2. Adjust security settings temporarily
3. Use "Pause CloudFlare on Site" for complete bypass
4. Remember to re-enable after maintenance
```

#### **Incident Response with CloudFlare**
```bash
# Security incident response involving CloudFlare

Immediate Actions:
1. Enable "Under Attack Mode" if experiencing DDoS
   # CloudFlare Dashboard → Overview → Quick Actions
2. Review CloudFlare Security Events
   # Dashboard → Security → Events
3. Implement emergency IP blocking
   # Dashboard → Security → WAF → Tools → IP Access Rules
4. Enable additional security measures
   # Increase security level to "High" or "I'm Under Attack"

Investigation:
1. Export CloudFlare logs (if Enterprise plan)
2. Correlate with VaultWarden application logs
3. Review fail2ban activity and CloudFlare blocks
4. Analyze attack patterns and sources

Recovery:
1. Gradually reduce security measures after attack subsides
2. Update security rules based on attack patterns
3. Review and improve detection capabilities
4. Document incident and response for future reference
```

This comprehensive CloudFlare integration guide ensures optimal security, performance, and reliability for your VaultWarden deployment while leveraging CloudFlare's global edge network capabilities."""
