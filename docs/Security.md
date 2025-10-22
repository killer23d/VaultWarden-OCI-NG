# Security Configuration Guide

**Comprehensive security hardening and best practices for VaultWarden-OCI-NG**

This guide provides detailed security configuration, threat modeling, and hardening procedures to achieve enterprise-grade security for your VaultWarden deployment. VaultWarden-OCI-NG implements defense-in-depth security principles with enhanced container security and input validation.

## 🎯 **Security Architecture Overview**

### **Multi-Layer Security Model**
1. **Network Layer** - Firewall, DDoS protection, IP allowlisting
2. **Transport Layer** - TLS encryption, certificate management
3. **Application Layer** - Authentication, authorization, rate limiting
4. **Container Layer** - Non-root execution, privilege separation, resource limits
5. **Data Layer** - Encryption at rest, secure key management
6. **Operations Layer** - Secure backup, audit logging, monitoring
7. **Input Layer** - Comprehensive validation, sanitization, error handling

### **Enhanced Security Features**
- **Container Security** - Non-root execution for VaultWarden and Caddy containers
- **Input Validation** - RFC-compliant email and domain validation with sanitization
- **Privilege Separation** - Services run with minimum required privileges
- **Defense-in-Depth** - Multiple security layers with intelligent failure handling

### **Threat Model Coverage**
- **External Attacks** - DDoS, brute force, exploitation attempts
- **Insider Threats** - Privilege escalation, data exfiltration
- **Infrastructure Compromise** - Container escape, host compromise, privilege escalation
- **Data Breaches** - Database theft, backup compromise
- **Social Engineering** - Phishing, credential theft
- **Supply Chain** - Dependency vulnerabilities, image tampering
- **Configuration Errors** - Invalid inputs, misconfigurations, setup mistakes

## 🔒 **Container Security Implementation**

### **Non-Root Container Execution**

#### **Container User Configuration**
```yaml
# docker-compose.yml - Security-hardened container configuration
services:
  vaultwarden:
    image: vaultwarden/server:1.30.5
    user: "1000:1000"  # Non-root execution
    security_opt:
      - no-new-privileges:true  # Prevent privilege escalation
    read_only: false  # VaultWarden needs write access to data volume
    tmpfs:
      - /tmp:noexec,nosuid,nodev  # Secure temporary filesystem

  caddy:
    image: caddy:2.7.6
    user: "1000:1000"  # Non-root execution
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Required for ports 80/443

  fail2ban:
    # INTENTIONALLY runs as root - requires iptables access
    image: lscr.io/linuxserver/fail2ban:1.1.0
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - PUID=0  # Root required for iptables manipulation
      - PGID=0
```

#### **Volume Security for Non-Root Containers**
```bash
# Volume ownership configuration for non-root containers
setup_container_security() {
    local project_state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"

    log_info "Configuring secure volume ownership for non-root containers..."

    # Set ownership for VaultWarden data
    sudo chown -R 1000:1000 "$project_state_dir/data"
    sudo chmod -R 750 "$project_state_dir/data"

    # Set ownership for Caddy configuration and logs
    sudo chown -R 1000:1000 "$project_state_dir/logs/caddy"
    sudo chmod -R 750 "$project_state_dir/logs/caddy"

    # Caddy volumes (Docker managed)
    docker volume inspect caddy_data >/dev/null 2>&1 || docker volume create caddy_data
    docker volume inspect caddy_config >/dev/null 2>&1 || docker volume create caddy_config

    # Set secure permissions on configuration files
    sudo chown -R 1000:1000 ./caddy/
    sudo chmod -R 644 ./caddy/*.caddy ./caddy/Caddyfile

    log_success "Container security configuration completed"
}
```

#### **Container Security Validation**
```bash
# Container security verification
verify_container_security() {
    log_info "Verifying container security configuration..."

    local errors=0

    # Check VaultWarden user
    if ! docker exec vaultwarden_vaultwarden whoami | grep -E "^(vaultwarden|1000)$" >/dev/null; then
        log_error "VaultWarden container not running as non-root user"
        ((errors++))
    else
        log_success "VaultWarden container running as non-root user"
    fi

    # Check Caddy user  
    if ! docker exec caddy_container whoami | grep -E "^(caddy|1000)$" >/dev/null; then
        log_error "Caddy container not running as non-root user"
        ((errors++))
    else
        log_success "Caddy container running as non-root user"
    fi

    # Verify fail2ban runs as root (required)
    if docker exec fail2ban_container whoami | grep "^root$" >/dev/null; then
        log_success "fail2ban container correctly running as root (required for iptables)"
    else
        log_error "fail2ban container not running as root (iptables access required)"
        ((errors++))
    fi

    # Check no-new-privileges setting
    for container in vaultwarden_vaultwarden caddy_container; do
        if docker inspect "$container" | grep -q '"NoNewPrivileges": true'; then
            log_success "Container $container has no-new-privileges enabled"
        else
            log_warn "Container $container missing no-new-privileges setting"
        fi
    done

    return $errors
}
```

### **Container Resource Limits**

#### **Security-Focused Resource Configuration**
```yaml
# Resource limits for security (prevent resource exhaustion attacks)
services:
  vaultwarden:
    deploy:
      resources:
        limits:
          memory: 1.5G      # Prevent memory exhaustion
          cpus: '0.75'      # CPU limit
          pids: 1000        # Process limit
        reservations:
          memory: 256M      # Guaranteed memory
    ulimits:
      nofile: 65536         # File descriptor limit
      nproc: 4096          # Process limit

  caddy:
    deploy:
      resources:
        limits:
          memory: 384M      # Caddy is lightweight
          cpus: '0.25'
          pids: 200
        reservations:
          memory: 64M
    ulimits:
      nofile: 32768
      nproc: 1024
```

## 🛡️ **Input Validation Security**

### **Email Validation Implementation**

#### **RFC-Compliant Email Validation**
```bash
# lib/validation.sh - Email validation with security focus
validate_email_format() {
    local email="$1"

    # Security: Check for empty input
    if [[ -z "$email" ]]; then
        log_error "Email cannot be empty (security requirement)"
        return 1
    fi

    # Security: Check for maximum length (prevent buffer overflow)
    if [[ ${#email} -gt 320 ]]; then  # RFC 5321 limit
        log_error "Email too long (max 320 characters): $email"
        return 1
    fi

    # Security: Check for basic format validity  
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        log_info "Expected format: user@domain.com (no spaces, special chars)"
        return 1
    fi

    # Security: Additional validation for common attack patterns
    if [[ "$email" =~ [<>"'\\;] ]]; then
        log_error "Email contains potentially dangerous characters: $email"
        return 1
    fi

    # Security: Check for null bytes
    if [[ "$email" == *$'\0'* ]]; then
        log_error "Email contains null bytes (security risk): $email"
        return 1
    fi

    log_success "Email format valid and secure: $email"
    return 0
}
```

#### **Domain Validation with Security Hardening**
```bash
# lib/validation.sh - Domain validation with security focus
validate_domain_format() {
    local domain="$1"
    local clean_domain="$domain"

    # Security: Check for empty input
    if [[ -z "$clean_domain" ]]; then
        log_error "Domain cannot be empty (security requirement)"
        return 1
    fi

    # Security: Remove protocol if present (with warning)
    if [[ "$clean_domain" =~ ^https?:// ]]; then
        log_warn "Security: Removing protocol from domain: $clean_domain"
        clean_domain="${clean_domain#http://}"
        clean_domain="${clean_domain#https://}"
        log_info "Using sanitized domain: $clean_domain"
    fi

    # Security: Check for maximum length (DNS limit)
    if [[ ${#clean_domain} -gt 253 ]]; then
        log_error "Domain too long (max 253 characters): $domain"
        return 1
    fi

    # Security: Check for dangerous characters
    if [[ "$clean_domain" =~ [<>"'\\;\$\`] ]]; then
        log_error "Domain contains dangerous characters: $domain"
        return 1
    fi

    # Security: Check for null bytes
    if [[ "$clean_domain" == *$'\0'* ]]; then
        log_error "Domain contains null bytes (security risk): $domain"
        return 1
    fi

    # Security: Validate domain format (RFC 1123 compliant)
    if [[ ! "$clean_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $domain"
        log_info "Expected format: vault.example.com (no protocol, valid TLD)"
        return 1
    fi

    # Security: Check for consecutive dots (potential path traversal)
    if [[ "$clean_domain" == *".."* ]]; then
        log_error "Domain contains consecutive dots (security risk): $domain"
        return 1
    fi

    # Security: Validate TLD requirements
    if [[ ! "$clean_domain" =~ \.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid Top-Level Domain (TLD): $domain (min 2 letters)"
        return 1
    fi

    # Security: Check for localhost/internal domains in production
    if [[ "$clean_domain" =~ ^(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        log_warn "Security warning: Using internal/localhost domain: $clean_domain"
        log_info "This may not work for Let's Encrypt certificates"
    fi

    log_success "Domain format valid and secure: $clean_domain"
    return 0
}
```

### **Configuration Security Validation**

#### **Secrets Validation with Security Checks**
```bash
# Enhanced secrets validation in lib/sops.sh
validate_secrets_security() {
    local secrets_file="$1"
    local validation_errors=0

    log_info "Performing security validation of secrets..."

    # Decrypt and validate secrets securely
    local temp_secrets="/tmp/secrets-validation-$$"
    umask 077

    if ! sops -d "$secrets_file" > "$temp_secrets" 2>/dev/null; then
        log_error "Failed to decrypt secrets for validation"
        rm -f "$temp_secrets"
        return 1
    fi

    # Validate critical secrets
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue  # Skip comments
        [[ -z "$key" ]] && continue  # Skip empty lines

        key=$(echo "$key" | tr -d ' ')
        value=$(echo "$value" | tr -d '"'"'"' | tr -d '"')

        case "$key" in
            "ADMIN_BASIC_AUTH_PASSWORD")
                if [[ ${#value} -lt 12 ]]; then
                    log_error "Admin password too short (min 12 characters)"
                    ((validation_errors++))
                fi
                if [[ ! "$value" =~ [A-Z] ]] || [[ ! "$value" =~ [a-z] ]] || [[ ! "$value" =~ [0-9] ]]; then
                    log_error "Admin password must contain uppercase, lowercase, and numbers"
                    ((validation_errors++))
                fi
                ;;
            "SMTP_PASSWORD")
                if [[ ${#value} -lt 8 ]]; then
                    log_error "SMTP password too short (min 8 characters)"
                    ((validation_errors++))
                fi
                ;;
            "DOMAIN")
                validate_domain_format "$value" || ((validation_errors++))
                ;;
            "ADMIN_EMAIL")
                validate_email_format "$value" || ((validation_errors++))
                ;;
            "SMTP_FROM")
                validate_email_format "$value" || ((validation_errors++))
                ;;
        esac
    done < "$temp_secrets"

    # Secure cleanup
    shred -vfz -n 3 "$temp_secrets" 2>/dev/null
    rm -f "$temp_secrets"

    if [[ $validation_errors -eq 0 ]]; then
        log_success "All secrets passed security validation"
        return 0
    else
        log_error "Secrets validation failed with $validation_errors errors"
        return 1
    fi
}
```

## 🔐 **Enhanced Container Monitoring**

### **Container Security Monitoring**

#### **Runtime Security Monitoring**
```bash
# Container security monitoring in lib/monitoring.sh
monitor_container_security() {
    log_info "Monitoring container security status..."

    local security_issues=0

    # Check container users
    for service in vaultwarden caddy; do
        local container_name="${COMPOSE_PROJECT_NAME}_${service}"
        if docker ps --format "{{.Names}}" | grep -q "$container_name"; then
            local user_id
            user_id=$(docker exec "$container_name" id -u 2>/dev/null)

            if [[ "$user_id" != "1000" ]] && [[ "$service" != "fail2ban" ]]; then
                log_error "Container $container_name running as user $user_id (expected 1000)"
                ((security_issues++))
            else
                log_success "Container $container_name running as non-root user $user_id"
            fi
        fi
    done

    # Monitor for privilege escalation attempts
    check_privilege_escalation_attempts || ((security_issues++))

    # Check for resource limit violations
    check_resource_limit_violations || ((security_issues++))

    # Verify no-new-privileges settings
    verify_security_options || ((security_issues++))

    if [[ $security_issues -eq 0 ]]; then
        log_success "Container security monitoring: All checks passed"
        return 0
    else
        log_error "Container security monitoring: $security_issues issues detected"
        send_notification "Container Security Alert" "$security_issues security issues detected in containers"
        return 1
    fi
}

check_privilege_escalation_attempts() {
    log_debug "Checking for privilege escalation attempts..."

    # Check for setuid/setgid files in containers
    for container in vaultwarden_vaultwarden caddy_container; do
        if docker ps --format "{{.Names}}" | grep -q "$container"; then
            local setuid_files
            setuid_files=$(docker exec "$container" find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)

            if [[ $setuid_files -gt 10 ]]; then  # Reasonable threshold
                log_warn "Container $container has $setuid_files setuid/setgid files"
                return 1
            fi
        fi
    done

    return 0
}

verify_security_options() {
    log_debug "Verifying container security options..."

    for container in vaultwarden_vaultwarden caddy_container; do
        if docker ps --format "{{.Names}}" | grep -q "$container"; then
            # Check no-new-privileges
            if ! docker inspect "$container" | grep -q '"NoNewPrivileges": true'; then
                log_warn "Container $container missing no-new-privileges setting"
                return 1
            fi
        fi
    done

    return 0
}
```

## 🔒 **Core Security Components** (Enhanced)

### **Age Encryption Implementation**

#### **Key Management Security**
```bash
# Age key security configuration with enhanced protection
readonly AGE_KEY_PERMISSIONS="600"        # Owner-only access
readonly AGE_KEY_FILE="secrets/keys/age-key.txt"
readonly AGE_KEY_BACKUP_DIR="secrets/keys/backups"

# Enhanced key generation with secure entropy
generate_age_key_secure() {
    log_info "Generating Age encryption key with enhanced security..."

    # Ensure secure directory exists
    mkdir -p "$(dirname "$AGE_KEY_FILE")"
    mkdir -p "$AGE_KEY_BACKUP_DIR"

    # Set restrictive permissions on directory
    chmod 700 "$(dirname "$AGE_KEY_FILE")"
    chmod 700 "$AGE_KEY_BACKUP_DIR"

    # Generate key with secure entropy
    if ! age-keygen -o "$AGE_KEY_FILE"; then
        log_error "Failed to generate Age key"
        return 1
    fi

    # Set secure permissions
    chmod 600 "$AGE_KEY_FILE"
    chown $(id -u):$(id -g) "$AGE_KEY_FILE"

    # Generate public key
    if ! age-keygen -y "$AGE_KEY_FILE" > "secrets/keys/age-public-key.txt"; then
        log_error "Failed to generate public key"
        return 1
    fi

    chmod 644 "secrets/keys/age-public-key.txt"

    # Verify key integrity
    if ! age -e -R "secrets/keys/age-public-key.txt" <<< "test" | age -d -i "$AGE_KEY_FILE" >/dev/null 2>&1; then
        log_error "Age key verification failed"
        return 1
    fi

    log_success "Age key generated and verified successfully"
    return 0
}
```

### **Network Security with Container Awareness**

#### **Firewall Configuration for Container Security**
```bash
# Enhanced firewall configuration accounting for container network
configure_container_aware_firewall() {
    log_info "Configuring container-aware firewall rules..."

    # Reset and set secure defaults
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing

    # Allow SSH (restrict to management IPs in production)
    sudo ufw limit ssh comment "Rate-limited SSH access"

    # Container network security
    # Block direct access to Docker bridge networks
    sudo ufw deny from 172.16.0.0/12 to any
    sudo ufw deny to 172.16.0.0/12

    # Allow Cloudflare IPs only for web traffic
    configure_cloudflare_firewall_rules

    # Enable firewall with logging
    sudo ufw logging on
    sudo ufw --force enable

    log_success "Container-aware firewall configured"
}

configure_cloudflare_firewall_rules() {
    local cloudflare_ips_v4=(
        "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
        "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
        "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15" "104.16.0.0/13"
        "104.24.0.0/14" "172.64.0.0/13" "131.0.72.0/22"
    )

    local cloudflare_ips_v6=(
        "2400:cb00::/32" "2606:4700::/32" "2803:f800::/32" "2405:b500::/32"
        "2405:8100::/32" "2a06:98c0::/29" "2c0f:f248::/32"
    )

    # Allow HTTP/HTTPS from Cloudflare IPs only
    for ip in "${cloudflare_ips_v4[@]}"; do
        sudo ufw allow from "$ip" to any port 80,443 comment "Cloudflare IPv4"
    done

    for ip in "${cloudflare_ips_v6[@]}"; do
        sudo ufw allow from "$ip" to any port 80,443 comment "Cloudflare IPv6"
    done
}
```

### **Enhanced Application Security**

#### **VaultWarden Container Hardening**
```yaml
# Enhanced VaultWarden security configuration
ROCKET_LIMITS: '{json=10485760,forms=32768}'  # Limit payload sizes
ROCKET_CLI_COLORS: 'off'                      # Disable color codes in logs
PASSWORD_ITERATIONS: 600000                   # High iteration count
SIGNUPS_ALLOWED: false                        # Admin-controlled registration
INVITATIONS_ALLOWED: true                     # Email invitation only
SIGNUPS_VERIFY: true                          # Email verification required
DISABLE_2FA_REMEMBER: false                   # Allow 2FA remember
REQUIRE_DEVICE_EMAIL: true                    # Email for new devices
PASSWORD_HINTS_ALLOWED: false                # Disable password hints
SHOW_PASSWORD_HINT: false                     # Never show hints
EMERGENCY_ACCESS_ALLOWED: false              # Disable emergency access
SENDS_ALLOWED: true                           # Allow Bitwarden Send
WEBSOCKET_ENABLED: true                       # Secure WebSocket
WEBSOCKET_ADDRESS: '0.0.0.0'                 # Internal container address
WEBSOCKET_PORT: 3012                         # Internal container port
```

## 📊 **Enhanced Security Monitoring**

### **Container Security Audit**

#### **Comprehensive Container Security Audit**
```bash
# Enhanced security audit including container security
perform_comprehensive_security_audit() {
    log_header "Performing Comprehensive Security Audit"

    local audit_errors=0

    # Standard security checks
    check_file_permissions || ((audit_errors++))
    verify_encryption_keys || ((audit_errors++))
    check_certificate_expiry "$DOMAIN" || ((audit_errors++))

    # Container security checks
    verify_container_security || ((audit_errors++))
    monitor_container_security || ((audit_errors++))
    check_container_resource_usage || ((audit_errors++))

    # Input validation checks
    validate_current_configuration || ((audit_errors++))

    # Network security with container awareness
    verify_container_network_security || ((audit_errors++))

    if [[ $audit_errors -eq 0 ]]; then
        log_success "Comprehensive security audit completed successfully"
        return 0
    else
        log_error "Security audit found $audit_errors issues requiring attention"
        return 1
    fi
}

validate_current_configuration() {
    log_info "Validating current system configuration..."

    local config_errors=0

    # Validate environment variables
    if [[ -f ".env" ]]; then
        local domain admin_email
        domain=$(grep "^DOMAIN=" .env | cut -d'=' -f2)
        admin_email=$(grep "^ADMIN_EMAIL=" .env | cut -d'=' -f2)

        validate_domain_format "$domain" || ((config_errors++))
        validate_email_format "$admin_email" || ((config_errors++))
    fi

    # Validate secrets if accessible
    if [[ -f "secrets/secrets.yaml" ]] && command -v sops >/dev/null; then
        validate_secrets_security "secrets/secrets.yaml" || ((config_errors++))
    fi

    return $config_errors
}
```

## 🔄 **Enhanced Security Operations**

### **Container Security Maintenance**

#### **Container Security Update Procedures**
```bash
# Container security maintenance
maintain_container_security() {
    log_info "Performing container security maintenance..."

    # Update container images with security patches
    docker compose pull

    # Recreate containers with updated images
    docker compose up -d --force-recreate

    # Verify security configuration after update
    sleep 30  # Allow containers to start
    verify_container_security || {
        log_error "Container security verification failed after update"
        return 1
    }

    # Clean up old images
    docker image prune -f

    log_success "Container security maintenance completed"
}
```

---

## 📋 **Enhanced Security Checklist**

### **Container Security Tasks**
- [ ] Verify containers running as non-root users (except fail2ban)
- [ ] Check volume permissions for non-root containers
- [ ] Validate no-new-privileges settings
- [ ] Monitor container resource usage
- [ ] Check for privilege escalation attempts

### **Input Validation Tasks**
- [ ] Test domain validation with various inputs
- [ ] Test email validation with edge cases
- [ ] Verify secrets validation catches weak passwords
- [ ] Test configuration validation during setup
- [ ] Validate error handling for invalid inputs

### **Daily Security Tasks**
- [ ] Review security logs for anomalies
- [ ] Check firewall status and rules
- [ ] Verify certificate validity
- [ ] Monitor failed login attempts
- [ ] Validate container security status
- [ ] Check input validation logs

### **Weekly Security Tasks**
- [ ] Run comprehensive security audit (including container security)
- [ ] Check for container image updates
- [ ] Review user access patterns
- [ ] Test emergency procedures
- [ ] Validate backup encryption and integrity
- [ ] Review container resource usage

---

## 🎯 **Enhanced Security Best Practices**

### **Container Security Principles**
1. **Non-Root Execution** - Run containers as non-privileged users when possible
2. **Privilege Separation** - Only grant root access when functionally required
3. **Resource Limits** - Prevent resource exhaustion attacks
4. **Network Isolation** - Secure container networking
5. **Image Security** - Use official, updated container images

### **Input Validation Principles**
1. **Validate Early** - Check inputs at the earliest possible point
2. **Sanitize Safely** - Clean inputs without breaking functionality
3. **Fail Securely** - Provide helpful error messages without exposing internals
4. **Log Validation Failures** - Track validation attempts for security monitoring
5. **Defense in Depth** - Multiple validation layers

---

**🔒 Enhanced Security**: VaultWarden-OCI-NG now provides container-level security hardening and comprehensive input validation to prevent configuration errors and reduce attack surface.

**📚 For container troubleshooting, see [Troubleshooting Guide](Troubleshooting.md)**

**🚨 For container-specific incident response, consult [Operations Runbook](OperationsRunbook.md)**
