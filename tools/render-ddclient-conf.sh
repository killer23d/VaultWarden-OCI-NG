#!/usr/bin/env bash
# tools/render-ddclient-conf.sh - Renders the ddclient configuration file using environment variables

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    # Define minimal log functions if logging.sh failed
    log_info() { echo "[render-ddclient-conf.sh][INFO] $*"; }
    log_warn() { echo "[render-ddclient-conf.sh][WARN] $*"; }
    log_error() { echo "[render-ddclient-conf.sh][ERROR] $*" >&2; }
    log_success() { echo "[render-ddclient-conf.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    log_header() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
else
    # Source logging if found
    source "lib/logging.sh"
fi

# Additional libraries as needed (add after logging.sh)
# Source config library (essential for getting variables)
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    # load_config should be called later in the script when needed
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    exit 1 # Cannot function without config
fi
# Source constants if available
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# P3.9 FIX: Add standardized error handling
trap 'log_error "Script failed at line $LINENO in $(basename "${BASH_SOURCE[0]}")"; exit 1' ERR

# --- Configuration ---
# Use constants if available, else defaults
readonly TEMPLATE_FILE="${TEMPLATE_FILE:-templates/ddclient.conf.tmpl}"
readonly OUTPUT_FILE="${DDCLIENT_OUTPUT_FILE:-ddclient/ddclient.conf}"
readonly OUTPUT_DIR="${DDCLIENT_OUTPUT_DIR:-ddclient}"

# --- Functions ---

# The main function to render the template
render_template() {
    log_info "Rendering ddclient configuration from template '$TEMPLATE_FILE'..."

    # Check for required command 'envsubst'
     if ! command -v envsubst >/dev/null 2>&1; then
         log_error "'envsubst' command not found. Cannot render template."
         log_info "On Debian/Ubuntu, install it via: sudo apt install gettext-base"
         return 1
     fi
     # Check if template file exists
      if [[ ! -f "$TEMPLATE_FILE" ]]; then
          log_error "Template file not found: $TEMPLATE_FILE"
          return 1
      fi

    # Load all configuration from .env and SOPS secrets (should already be loaded if called by startup.sh)
    # Re-load here using load_config from config.sh (idempotent).
    log_info "Loading project configuration..."
    if ! load_config; then
        log_error "Failed to load project configuration. Cannot determine variables for ddclient config."
        return 1
    fi
    log_success "Project configuration loaded."

    # Validate that required variables *for the template* are present in the environment
    # These depend on the content of ddclient.conf.tmpl
    local required_vars=() template_content
    # Read template to find likely variables (simple ${VAR} or $VAR syntax)
    template_content=$(cat "$TEMPLATE_FILE") || { log_error "Failed to read template file '$TEMPLATE_FILE'"; return 1; }

    # Extract variable names within ${...} or $... (simple cases)
     while IFS= read -r line; do
         # Match ${VAR_NAME}
         while [[ "$line" =~ \$\{([A-Za-z0-9_]+)\} ]]; do
             required_vars+=("${BASH_REMATCH[1]}")
             # Remove matched part to find next var in the same line
             line="${line#*\$\{${BASH_REMATCH[1]}\}}"
         done
          # Match $VAR_NAME (excluding those already matched with {})
          # This regex is trickier to avoid matching things like $$, $?, etc.
          # Match word starting with $, followed by alphanumeric/underscore
          # Use grep -oP for simplicity if available, otherwise more complex bash matching
          if command -v grep >/dev/null && grep -oP '\$[A-Za-z_][A-Za-z0-9_]*' <<< "$line" &>/dev/null; then
              local simple_vars
              simple_vars=$(grep -oP '\$[A-Za-z_][A-Za-z0-9_]*' <<< "$line" | sed 's/\$//')
              for svar in $simple_vars; do
                   # Avoid adding if already found via ${...}
                   if ! printf '%s
' "${required_vars[@]}" | grep -Fxq "$svar"; then
                        required_vars+=("$svar")
                   fi
              done
          fi
     done <<< "$template_content"

     # Add specific essential vars manually if parsing misses some or they are conditionally required
     required_vars+=("DDCLIENT_PROTOCOL" "DDCLIENT_LOGIN" "DDCLIENT_ZONE" "DDCLIENT_HOST")
     # P2.3 FIX: Cloudflare requires CLOUDFLARE_API_TOKEN (used as password in template)
     local ddclient_protocol
     ddclient_protocol=$(get_config_value "DDCLIENT_PROTOCOL" "") # Get from loaded config
      if [[ "$ddclient_protocol" == "cloudflare" ]]; then
          # P2.3 FIX: Ensure proper variable name for Cloudflare API token
          required_vars+=("CLOUDFLARE_API_TOKEN") # Must be provided via secrets
          log_info "Cloudflare protocol detected, requiring CLOUDFLARE_API_TOKEN for authentication"
      fi
      # Remove duplicates and sort
      required_vars=($(printf "%s
" "${required_vars[@]}" | sort -u))

    _log_debug "Required variables identified for template: ${required_vars[*]}"
    local missing=0 var_value var_source

    for var in "${required_vars[@]}"; do
        # Check if variable is set and non-empty using get_config_value (checks env/secrets)
        var_value=$(get_config_value "$var" "") # Get value or empty string

        if [[ -z "$var_value" ]]; then
            log_error "Missing required configuration variable for ddclient template: '$var'"
            # P2.3 FIX: Provide specific guidance for Cloudflare token
            if [[ "$var" == "CLOUDFLARE_API_TOKEN" ]]; then
                log_error "Cloudflare API token is required for Cloudflare protocol."
                log_info "Configure it using: ./tools/edit-secrets.sh"
                log_info "Add 'cloudflare_api_token: your_token_here' to the secrets file"
            fi
            ((missing++))
            var_source="MISSING"
        else
             # Check if value seems like a placeholder (optional check)
             if [[ "$var_value" =~ ^CHANGE_ME|^PASTE_.*_HERE$|^your_.*_here$ ]]; then
                  log_warn "Variable '$var' appears to contain a placeholder value ('${var_value:0:20}...'). Ensure it's correctly set."
                  # Don't increment missing count, but warn
             fi
             var_source="Found" # Indicate it was found (source env/secrets handled by get_config_value)
        fi
         _log_debug "Variable check: $var = $var_source"
    done

    if [[ $missing -gt 0 ]]; then
        log_error "Aborting ddclient config rendering due to $missing missing required variable(s)."
        log_info "Ensure these variables are correctly set in '.env' or (preferably for secrets) 'secrets/secrets.yaml'."
        return 1
    fi
    log_success "All required variables for rendering are present in configuration."

    # Ensure output directory exists
     if ! mkdir -p "$OUTPUT_DIR"; then
         log_error "Failed to create output directory: $OUTPUT_DIR"
         return 1
     fi

    # Use envsubst to replace variables in the template and write to output file
    log_info "Writing rendered config to '$OUTPUT_FILE'..."
    # Prepare list of variables for envsubst (e.g., '$VAR1,$VAR2')
    # Important: envsubst replaces based on exported environment variables.
    # load_config should export them.
    local envsubst_vars
    # Create list like '${VAR1},${VAR2}'
    envsubst_vars=$(printf '${%s},' "${required_vars[@]}" | sed 's/,$//')  # Remove trailing comma

    _log_debug "Running envsubst with variables: $envsubst_vars"

    # Perform substitution, handle potential errors
    local subst_output subst_rc=0
    # Use process substitution to avoid temp file for envsubst input if possible
    # Ensure all required vars are exported for envsubst to see them
    # (load_config is expected to handle this)
    subst_output=$(envsubst "$envsubst_vars" < "$TEMPLATE_FILE" 2>&1) || subst_rc=$?

    if [[ $subst_rc -ne 0 ]]; then
         log_error "envsubst command failed during template rendering (rc=$subst_rc)."
         log_error "Output/Error: $subst_output"
         # Check if error is due to unset variables (should have been caught earlier)
         if [[ "$subst_output" == *"variable is not set"* ]]; then
              log_error "envsubst reported unset variables. Check if load_config correctly exported them."
         fi
         return 1
    fi

    # Write the substituted content to the output file
    if echo "$subst_output" > "$OUTPUT_FILE"; then
        # Secure the output file (readable only by owner, maybe group readable?)
        # Use constant if defined, else default
        local output_perms="${DDCLIENT_CONFIG_PERMS:-600}"
        if ! chmod "$output_perms" "$OUTPUT_FILE"; then
             log_warn "Failed to set permissions '$output_perms' on $OUTPUT_FILE."
        fi
        log_success "Successfully rendered ddclient configuration to $OUTPUT_FILE"

        # P2.3 FIX: Verify that Cloudflare token was properly substituted
        if [[ "$ddclient_protocol" == "cloudflare" ]]; then
            if grep -q "your_cloudflare_token_here\|CLOUDFLARE_API_TOKEN" "$OUTPUT_FILE"; then
                log_error "Cloudflare API token was not properly substituted in rendered config"
                log_error "Check that CLOUDFLARE_API_TOKEN is properly exported by load_config"
                return 1
            else
                log_success "Cloudflare API token successfully rendered in configuration"
            fi
        fi

        return 0
    else
        log_error "Failed to write rendered content to output file: $OUTPUT_FILE"
        rm -f "$OUTPUT_FILE" # Clean up potentially incomplete file
        return 1
    fi
}

# --- Main Execution ---
main() {
    # Load config first to check if DDClient is enabled
     if ! load_config; then
        log_error "Failed to load project configuration. Cannot determine if ddclient is enabled."
        exit 1
     fi

    # Check if DDClient is actually enabled before rendering
     local ddclient_enabled
     ddclient_enabled=$(get_config_value "DDCLIENT_ENABLED" "false") # Default to false if not set

     if [[ "$ddclient_enabled" != "true" ]]; then
         log_info "DDCLIENT_ENABLED is not 'true' in configuration. Skipping ddclient config rendering."
         # Optionally remove existing config file if disabled?
          if [[ -f "$OUTPUT_FILE" ]]; then
             log_info "Removing existing ddclient config file '$OUTPUT_FILE' as service is disabled."
             rm -f "$OUTPUT_FILE" || log_warn "Failed to remove existing file: $OUTPUT_FILE"
          fi
         exit 0 # Success, nothing to do
     fi

     log_info "DDCLIENT_ENABLED=true. Proceeding with configuration rendering..."
    if ! render_template; then
        log_error "ddclient configuration rendering failed."
        exit 1 # Error occurred during rendering
    fi
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Add debug flag if needed: export DEBUG=true
    main
fi
