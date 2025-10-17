#!/usr/bin/env bash
# lib/logging.sh - Centralized logging and output formatting library
#
# This library provides consistent logging functionality across all scripts including:
# - Color-coded output with consistent formatting
# - Multiple log levels (debug, info, warning, error, success)
# - Structured logging with timestamps
# - Header formatting for script sections
# - Safe output handling for non-interactive environments
#
# Dependencies: None (standalone library)
# Author: VaultWarden OCI Minimal Project
# License: MIT
#

set -euo pipefail

# Color definitions (safe for all terminals)
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly PURPLE='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m' # No Color
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly PURPLE=''
    readonly CYAN=''
    readonly WHITE=''
    readonly BOLD=''
    readonly NC=''
fi

# Logging configuration
LOG_LEVEL="${LOG_LEVEL:-info}"
LOG_TIMESTAMPS="${LOG_TIMESTAMPS:-true}"
LOG_PREFIX="${LOG_PREFIX:-}"

# Log level hierarchy (higher numbers = more verbose)
declare -A LOG_LEVELS=(
    ["error"]=1
    ["warning"]=2
    ["info"]=3
    ["success"]=3
    ["debug"]=4
)

# Get current timestamp for logging
_get_timestamp() {
    if [[ "$LOG_TIMESTAMPS" == "true" ]]; then
        date -u '+%Y-%m-%d %H:%M:%S UTC'
    fi
}

# Check if log level should be output
_should_log() {
    local level="$1"
    local current_level_num="${LOG_LEVELS[$LOG_LEVEL]:-3}"
    local message_level_num="${LOG_LEVELS[$level]:-3}"
    
    [[ $message_level_num -le $current_level_num ]]
}

# Core logging function
_log() {
    local level="$1"
    local color="$2"
    local symbol="$3"
    shift 3
    local message="$*"
    
    if ! _should_log "$level"; then
        return 0
    fi
    
    local timestamp prefix output
    timestamp="$(_get_timestamp)"
    prefix="${LOG_PREFIX:+[$LOG_PREFIX] }"
    
    # Build output string
    if [[ -n "$timestamp" ]]; then
        output="${color}${symbol} ${timestamp} ${prefix}${message}${NC}"
    else
        output="${color}${symbol} ${prefix}${message}${NC}"
    fi
    
    # Output to stderr for errors, stdout for everything else
    if [[ "$level" == "error" ]]; then
        echo -e "$output" >&2
    else
        echo -e "$output"
    fi
}

# Public logging functions
_log_error() {
    _log "error" "$RED" "✗" "$@"
}

_log_warning() {
    _log "warning" "$YELLOW" "⚠" "$@"
}

_log_info() {
    _log "info" "$BLUE" "ℹ" "$@"
}

_log_success() {
    _log "success" "$GREEN" "✓" "$@"
}

_log_debug() {
    _log "debug" "$PURPLE" "🔍" "$@"
}

# Special formatting functions
_log_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    if _should_log "info"; then
        echo
        echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
        echo -e "${CYAN}$(printf '%*s' $padding '')${BOLD}$title${NC}${CYAN}$(printf '%*s' $padding '')${NC}"
        echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
        echo
    fi
}

_log_section() {
    local title="$1"
    
    if _should_log "info"; then
        echo
        echo -e "${BLUE}▶ ${BOLD}$title${NC}"
        echo -e "${BLUE}$(printf -- '-%.0s' $(seq 1 ${#title}))${NC}"
    fi
}

_log_subsection() {
    local title="$1"
    
    if _should_log "info"; then
        echo -e "${CYAN}  ▸ $title${NC}"
    fi
}

# Progress indicators
_log_progress() {
    local message="$1"
    local current="${2:-}"
    local total="${3:-}"
    
    if ! _should_log "info"; then
        return 0
    fi
    
    if [[ -n "$current" ]] && [[ -n "$total" ]]; then
        local percentage=$(( (current * 100) / total ))
        echo -e "${BLUE}⏳ $message [$current/$total - ${percentage}%]${NC}"
    else
        echo -e "${BLUE}⏳ $message...${NC}"
    fi
}

_log_step() {
    local step_num="$1"
    local step_total="$2"
    local message="$3"
    
    if _should_log "info"; then
        echo -e "${GREEN}Step $step_num/$step_total:${NC} $message"
    fi
}

# Utility functions for formatted output
_print_key_value() {
    local key="$1"
    local value="$2"
    local key_width="${3:-20}"
    
    if _should_log "info"; then
        printf "${CYAN}%-${key_width}s${NC} : %s\n" "$key" "$value"
    fi
}

_print_table_header() {
    local -a headers=("$@")
    local width=20
    
    if _should_log "info"; then
        echo -e "${BOLD}${BLUE}"
        printf "%-${width}s" "${headers[@]}"
        echo -e "${NC}"
        
        # Print separator line
        local total_width=$((width * ${#headers[@]}))
        printf "${BLUE}%${total_width}s${NC}\n" | tr ' ' '-'
    fi
}

_print_table_row() {
    local -a values=("$@")
    local width=20
    
    if _should_log "info"; then
        printf "%-${width}s" "${values[@]}"
        echo
    fi
}

# List formatting
_log_list_item() {
    local item="$1"
    local indent="${2:-2}"
    
    if _should_log "info"; then
        printf "%*s${GREEN}•${NC} %s\n" "$indent" "" "$item"
    fi
}

_log_numbered_item() {
    local number="$1"
    local item="$2"
    local indent="${3:-2}"
    
    if _should_log "info"; then
        printf "%*s${GREEN}%d.${NC} %s\n" "$indent" "" "$number" "$item"
    fi
}

# Status indicators
_log_status_ok() {
    local service="$1"
    _log "success" "$GREEN" "✓" "$service: OK"
}

_log_status_fail() {
    local service="$1"
    local reason="${2:-Failed}"
    _log "error" "$RED" "✗" "$service: $reason"
}

_log_status_warning() {
    local service="$1"
    local reason="${2:-Warning}"
    _log "warning" "$YELLOW" "⚠" "$service: $reason"
}

_log_status_unknown() {
    local service="$1"
    _log "info" "$BLUE" "?" "$service: Unknown"
}

# Interactive prompts with logging
_log_prompt() {
    local prompt="$1"
    local default="${2:-}"
    
    if [[ -n "$default" ]]; then
        echo -e "${CYAN}$prompt [${default}]: ${NC}" >&2
    else
        echo -e "${CYAN}$prompt: ${NC}" >&2
    fi
}

_log_confirm() {
    local prompt="$1"
    local default="${2:-N}"
    
    case "$default" in
        [yY]*) echo -e "${CYAN}$prompt [Y/n]: ${NC}" >&2 ;;
        *) echo -e "${CYAN}$prompt [y/N]: ${NC}" >&2 ;;
    esac
}

# Log configuration and control
_set_log_level() {
    local level="$1"
    
    if [[ -n "${LOG_LEVELS[$level]:-}" ]]; then
        LOG_LEVEL="$level"
        _log_debug "Log level set to: $level"
    else
        _log_error "Invalid log level: $level"
        _log_info "Valid levels: ${!LOG_LEVELS[*]}"
        return 1
    fi
}

_enable_log_timestamps() {
    LOG_TIMESTAMPS="true"
}

_disable_log_timestamps() {
    LOG_TIMESTAMPS="false"
}

_set_log_prefix() {
    LOG_PREFIX="$1"
}

_clear_log_prefix() {
    LOG_PREFIX=""
}

# Utility function to suppress output
_log_quietly() {
    local old_level="$LOG_LEVEL"
    LOG_LEVEL="error"
    "$@"
    LOG_LEVEL="$old_level"
}

# Function to capture and log command output
_log_command() {
    local cmd="$1"
    local description="${2:-Running command}"
    
    _log_debug "$description: $cmd"
    
    if [[ "$LOG_LEVEL" == "debug" ]]; then
        # In debug mode, show command output
        eval "$cmd"
    else
        # Otherwise, capture and only show on error
        local output
        if output=$(eval "$cmd" 2>&1); then
            _log_debug "Command completed successfully"
            return 0
        else
            local exit_code=$?
            _log_error "Command failed with exit code $exit_code"
            _log_error "Command: $cmd"
            _log_error "Output: $output"
            return $exit_code
        fi
    fi
}

# Spinner for long-running operations
_show_spinner() {
    local pid="$1"
    local message="${2:-Processing}"
    
    if ! _should_log "info" || [[ ! -t 1 ]]; then
        return 0
    fi
    
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    # Hide cursor
    echo -ne "\033[?25l"
    
    while kill -0 "$pid" 2>/dev/null; do
        local char="${spin:$i:1}"
        echo -ne "\r${BLUE}$char${NC} $message..."
        i=$(( (i + 1) % ${#spin} ))
        sleep 0.1
    done
    
    # Show cursor and clear line
    echo -ne "\r\033[?25h\033[2K"
}

# Export functions for use in other scripts
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Script is being sourced
    _log_debug "lib/logging.sh loaded successfully"
else
    # Script is being executed directly
    echo "lib/logging.sh should be sourced, not executed directly" >&2
    exit 1
fi
