#!/bin/bash

# ===========================================
# VAULTWARDEN-OCI CONFIGURATION VALIDATOR
# ===========================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SETTINGS_FILE="settings.env"
ERRORS=0
WARNINGS=0

echo "🔍 Validating Vaultwarden-OCI Configuration..."
echo "================================================"

# Check if settings.env exists
if [[ ! -f "$SETTINGS_FILE" ]]; then
    echo -e "${RED}❌ ERROR: $SETTINGS_FILE not found${NC}"
    exit 1
fi

# Function to check for placeholder values
check_placeholder() {
    local var_name=$1
    local var_value=$2
    local is_required=${3:-true}
    
    if [[ -z "$var_value" ]]; then
        if [[ "$is_required" == "true" ]]; then
            echo -e "${RED}❌ ERROR: $var_name is empty${NC}"
            ((ERRORS++))
        else
            echo -e "${YELLOW}⚠️  WARNING: Optional variable $var_name is empty${NC}"
            ((WARNINGS++))
        fi
        return
    fi
    
    # Check for common placeholder patterns
    if [[ "$var_value" =~ \<.*\> ]] || \
       [[ "$var_value" == "your."* ]] || \
       [[ "$var_value" == "example."* ]] || \
       [[ "$var_value" == "token" ]] || \
       [[ "$var_value" == "mycloud" ]]; then
        if [[ "$is_required" == "true" ]]; then
            echo -e "${RED}❌ ERROR: $var_name contains placeholder value: $var_value${NC}"
            ((ERRORS++))
        else
            echo -e "${YELLOW}⚠️  WARNING: $var_name may contain placeholder: $var_value${NC}"
            ((WARNINGS++))
        fi
    else
        echo -e "${GREEN}✅ $var_name: OK${NC}"
    fi
}

# Load environment variables
source "$SETTINGS_FILE"

echo ""
echo "🏠 Domain Configuration"
echo "----------------------"
check_placeholder "DOMAIN_NAME" "$DOMAIN_NAME"
check_placeholder "APP_DOMAIN" "$APP_DOMAIN"

echo ""
echo "🗄️  Database Configuration"
echo "--------------------------"
check_placeholder "MARIADB_ROOT_PASSWORD" "$MARIADB_ROOT_PASSWORD"
check_placeholder "MARIADB_PASSWORD" "$MARIADB_PASSWORD"
check_placeholder "DATABASE_URL" "$DATABASE_URL"

echo ""
echo "🔐 Security Configuration"
echo "-------------------------"
check_placeholder "ADMIN_TOKEN" "$ADMIN_TOKEN"
check_placeholder "REDIS_PASSWORD" "$REDIS_PASSWORD"

echo ""
echo "📧 Email Configuration"
echo "----------------------"
check_placeholder "SMTP_HOST" "$SMTP_HOST"
check_placeholder "SMTP_USER" "$SMTP_USER"
check_placeholder "SMTP_PASSWORD" "$SMTP_PASSWORD"
check_placeholder "SMTP_FROM" "$SMTP_FROM"

echo ""
echo "☁️  Backup Configuration"
echo "------------------------"
check_placeholder "BACKUP_PASSPHRASE" "$BACKUP_PASSPHRASE"
check_placeholder "RCLONE_REMOTE_NAME" "$RCLONE_REMOTE_NAME" false
check_placeholder "RCLONE_REMOTE_PATH" "$RCLONE_REMOTE_PATH" false

echo ""
echo "🌐 DNS Configuration"
echo "--------------------"
check_placeholder "CF_API_TOKEN" "$CF_API_TOKEN" false
check_placeholder "DDCLIENT_LOGIN" "$DDCLIENT_LOGIN" false

echo ""
echo "🔔 Push Notifications (Optional)"
echo "--------------------------------"
check_placeholder "PUSH_INSTALLATION_ID" "$PUSH_INSTALLATION_ID" false
check_placeholder "PUSH_INSTALLATION_KEY" "$PUSH_INSTALLATION_KEY" false

# Check for required directories
echo ""
echo "📁 Directory Structure"
echo "----------------------"
REQUIRED_DIRS=(
    "data"
    "caddy"
    "fail2ban"
    "backup"
    "ddclient"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        echo -e "${GREEN}✅ Directory $dir: exists${NC}"
    else
        echo -e "${YELLOW}⚠️  WARNING: Directory $dir does not exist${NC}"
        ((WARNINGS++))
    fi
done

# Check for required files
echo ""
echo "📄 Required Files"
echo "----------------"
REQUIRED_FILES=(
    "caddy/Caddyfile"
    "fail2ban/jail.local"
    "backup/Dockerfile"
    "docker-compose.yml"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✅ File $file: exists${NC}"
    else
        echo -e "${RED}❌ ERROR: Required file $file is missing${NC}"
        ((ERRORS++))
    fi
done

# Password strength check
echo ""
echo "🔒 Password Strength"
echo "-------------------"
check_password_strength() {
    local var_name=$1
    local password=$2
    
    if [[ ${#password} -lt 16 ]]; then
        echo -e "${YELLOW}⚠️  WARNING: $var_name should be at least 16 characters${NC}"
        ((WARNINGS++))
    else
        echo -e "${GREEN}✅ $var_name: Good length${NC}"
    fi
}

if [[ ! "$MARIADB_ROOT_PASSWORD" =~ \<.*\> ]]; then
    check_password_strength "MARIADB_ROOT_PASSWORD" "$MARIADB_ROOT_PASSWORD"
fi

if [[ ! "$ADMIN_TOKEN" =~ \<.*\> ]]; then
    check_password_strength "ADMIN_TOKEN" "$ADMIN_TOKEN"
fi

# Final summary
echo ""
echo "📊 Validation Summary"
echo "===================="

if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}🎉 All checks passed! Configuration is ready for deployment.${NC}"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Configuration has $WARNINGS warnings but no critical errors.${NC}"
    echo -e "${YELLOW}Review warnings above before deployment.${NC}"
    exit 0
else
    echo -e "${RED}❌ Configuration has $ERRORS critical errors and $WARNINGS warnings.${NC}"
    echo -e "${RED}Fix all errors before deployment.${NC}"
    exit 1
fi
