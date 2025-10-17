#!/usr/bin/env bash
# tools/check-health.sh - User-facing health check tool for VaultWarden deployments.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source the consolidated monitoring library
source "$ROOT_DIR/lib/monitoring.sh"

_set_log_prefix "health-check"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    --sops-only         Check only SOPS+Age system health
    --containers-only   Check only container health
    --system-only       Check only system resources
    --network-only      Check only network connectivity
    --comprehensive     Full comprehensive health check (default)
    --quiet             Suppress non-error output
    --verbose           Enable detailed debug output
    --json              Output results in JSON format
    --alert             Send email alerts for critical failures
    --help              Show this help message
EOF
}

# Generate health report summary
generate_health_summary() {
    _log_header "Health Check Summary"

    local total_checks=${#HEALTH_RESULTS[@]}
    local passed_checks=0
    local warning_checks=$WARNINGS_COUNT
    local failed_checks=$CRITICAL_COUNT
    local skipped_checks=0

    # Count skipped checks
    for key in "${!HEALTH_RESULTS[@]}"; do
        local result="${HEALTH_RESULTS[$key]}"
        local status="${result%%:*}"
        if [[ "$status" == "SKIP" ]]; then
            ((skipped_checks++))
        fi
    done
    
    passed_checks=$((total_checks - warning_checks - failed_checks - skipped_checks))

    # Display summary
    _log_info "Health Check Results:"
    _log_info "  Total Checks: $total_checks"
    _log_info "  ✅ Passed: $passed_checks"
    _log_info "  ⚠️  Warnings: $warning_checks"  
    _log_info "  ❌ Failed: $failed_checks"
    _log_info "  ⏭️  Skipped: $skipped_checks"

    # Overall system status
    if [[ $failed_checks -eq 0 ]] && [[ $warning_checks -eq 0 ]]; then
        _log_success "🎉 System Status: EXCELLENT - All checks passed"
        return 0
    elif [[ $failed_checks -eq 0 ]]; then
        _log_warning "⚠️  System Status: GOOD - $warning_checks warning(s) detected"
        return 1
    else
        _log_error "❌ System Status: CRITICAL - $failed_checks failure(s) detected"
        return 2
    fi
}

# JSON output generation
generate_json_output() {
    local output="{"
    output+='"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",'
    output+='"hostname":"'$(hostname)'",'
    output+='"sops_integration_available":'$([[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]] && echo "true" || echo "false")','
    output+='"summary":{'
    output+='"total_checks":'${#HEALTH_RESULTS[@]}','
    output+='"warnings":'$WARNINGS_COUNT','
    output+='"critical_failures":'$CRITICAL_COUNT
    output+='},'
    output+='"results":{'

    local first=true
    for key in "${!HEALTH_RESULTS[@]}"; do
        if [[ "$first" != "true" ]]; then
            output+=','
        fi
        first=false

        local result="${HEALTH_RESULTS[$key]}"
        local status="${result%%:*}"
        local message="${result#*:}"

        output+='"'$key'":{'
        output+='"status":"'$status'",'
        output+='"message":"'$message'"'
        output+='}'
    done

    output+='}}'
    echo "$output" | jq '.' 2>/dev/null || echo "$output"
}

# Main health check execution
main() {
    local check_mode="comprehensive"
    local json_output=false
    local quiet=false
    local send_alerts=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --sops-only) check_mode="sops"; shift ;;
            --containers-only) check_mode="containers"; shift ;;
            --system-only) check_mode="system"; shift ;;
            --network-only) check_mode="network"; shift ;;
            --comprehensive) check_mode="comprehensive"; shift ;;
            --quiet) quiet=true; shift ;;
            --verbose) export DEBUG=1; shift ;;
            --json) json_output=true; shift ;;
            --alert) send_alerts=true; shift ;;
            --help|-h) usage; exit 0 ;;
            *) _log_error "Unknown argument: $1"; usage; exit 3 ;;
        esac
    done

    # Set quiet mode if JSON output requested
    if [[ "$json_output" == "true" ]]; then
        quiet=true
        exec 1>/dev/null  # Suppress stdout for JSON mode
    fi

    if [[ "$quiet" != "true" ]]; then
        _log_header "VaultWarden Health Check"
        _log_info "Mode: $check_mode"
    fi

    # Execute health checks based on mode
    case "$check_mode" in
        "sops") check_sops_system_health ;;
        "containers") check_container_health ;;
        "system") check_system_health ;;
        "network") check_network_health ;;
        "comprehensive"|*)
            check_sops_system_health
            check_container_health  
            check_system_health
            check_network_health
            check_backup_health
            check_service_integration
            ;;
    esac

    # Generate output
    if [[ "$json_output" == "true" ]]; then
        exec 1>&2  # Restore stdout for JSON output
        generate_json_output
    else
        local exit_code
        generate_health_summary
        exit_code=$?

        if [[ "$send_alerts" == "true" ]]; then
            alert_on_sops_failures "Manual Health Check" "$CRITICAL_COUNT critical failures found."
        fi

        exit $exit_code
    fi
}

main "$@"