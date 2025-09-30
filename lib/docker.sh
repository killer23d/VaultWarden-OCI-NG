#!/usr/bin/env bash
# lib/docker.sh - Docker and Docker Compose helper functions

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/common.sh"

# ================================
# DOCKER COMPOSE FUNCTIONS
# ================================

# Get compose project name
get_compose_project() {
    docker compose config --format json | jq -r '.name' 2>/dev/null || echo "vaultwardenoci"
}

# Check if compose stack is running
is_stack_running() {
    local running_services
    running_services=$(docker compose ps --services --filter status=running | wc -l)
    [[ $running_services -gt 0 ]]
}

# Get all compose services
get_compose_services() {
    docker compose config --services 2>/dev/null || echo ""
}

# Start compose stack
start_stack() {
    local env_file="${1:-}"
    local compose_args=()
    
    if [[ -n "$env_file" ]]; then
        compose_args+=(--env-file "$env_file")
    fi
    
    log_info "Starting Docker Compose stack..."
    
    if docker compose "${compose_args[@]}" up -d --remove-orphans; then
        log_success "Stack started successfully"
        return 0
    else
        log_error "Failed to start stack"
        return 1
    fi
}

# Stop compose stack
stop_stack() {
    log_info "Stopping Docker Compose stack..."
    
    if docker compose down; then
        log_success "Stack stopped successfully"
        return 0
    else
        log_error "Failed to stop stack"
        return 1
    fi
}

# Restart compose stack
restart_stack() {
    log_info "Restarting Docker Compose stack..."
    
    if docker compose restart; then
        log_success "Stack restarted successfully"
        return 0
    else
        log_error "Failed to restart stack"
        return 1
    fi
}

# ================================
# SERVICE MANAGEMENT FUNCTIONS
# ================================

# Start specific service
start_service() {
    local service="$1"
    log_info "Starting service: $service"
    
    if docker compose up -d "$service"; then
        log_success "Service $service started"
        return 0
    else
        log_error "Failed to start service: $service"
        return 1
    fi
}

# Stop specific service
stop_service() {
    local service="$1"
    log_info "Stopping service: $service"
    
    if docker compose stop "$service"; then
        log_success "Service $service stopped"
        return 0
    else
        log_error "Failed to stop service: $service"
        return 1
    fi
}

# Restart specific service
restart_service() {
    local service="$1"
    log_info "Restarting service: $service"
    
    if docker compose restart "$service"; then
        log_success "Service $service restarted"
        return 0
    else
        log_error "Failed to restart service: $service"
        return 1
    fi
}

# ================================
# CONTAINER INSPECTION FUNCTIONS
# ================================

# Get detailed container info
get_container_info() {
    local service="$1"
    local container_id
    container_id=$(get_container_id "$service")
    
    if [[ -z "$container_id" ]]; then
        echo "Service $service not found or not running"
        return 1
    fi
    
    local status health created
    status=$(get_container_status "$container_id")
    health=$(get_container_health "$container_id")
    created=$(docker inspect --format='{{.Created}}' "$container_id" 2>/dev/null)
    
    cat <<EOF
Service: $service
Container ID: $container_id
Status: $status
Health: $health
Created: $created
EOF
}

# Get container resource usage
get_container_stats() {
    local service="$1"
    local container_id
    container_id=$(get_container_id "$service")
    
    if [[ -z "$container_id" ]]; then
        echo "Service $service not found or not running"
        return 1
    fi
    
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}" "$container_id"
}

# ================================
# HEALTH CHECK FUNCTIONS
# ================================

# Perform comprehensive health check
perform_health_check() {
    local failed_services=()
    
    log_info "Performing comprehensive health check..."
    
    for service in "${SERVICES[@]}"; do
        local container_id
        container_id=$(get_container_id "$service")
        
        if [[ -z "$container_id" ]]; then
            # Check if service should be running (not in profiles)
            if ! docker compose config --services 2>/dev/null | grep -q "^$service$"; then
                log_debug "Service $service not in current profile, skipping"
                continue
            fi
            
            log_warning "Service $service not running"
            failed_services+=("$service")
            continue
        fi
        
        local status health
        status=$(get_container_status "$container_id")
        health=$(get_container_health "$container_id")
        
        case "$status" in
            "running")
                case "$health" in
                    "healthy")
                        log_success "Service $service is running and healthy"
                        ;;
                    "unhealthy")
                        log_warning "Service $service is running but unhealthy"
                        failed_services+=("$service")
                        ;;
                    "starting")
                        log_info "Service $service is starting..."
                        ;;
                    "no-health-check")
                        log_info "Service $service is running (no health check)"
                        ;;
                    *)
                        log_warning "Service $service health status: $health"
                        ;;
                esac
                ;;
            *)
                log_error "Service $service status: $status"
                failed_services+=("$service")
                ;;
        esac
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log_success "All services are healthy"
        return 0
    else
        log_warning "Failed services: ${failed_services[*]}"
        return 1
    fi
}

# Wait for service to be healthy
wait_for_service() {
    local service="$1"
    local timeout="${2:-300}" # 5 minutes default
    local interval="${3:-10}" # 10 seconds default
    local elapsed=0
    
    log_info "Waiting for service $service to be healthy (timeout: ${timeout}s)..."
    
    while [[ $elapsed -lt $timeout ]]; do
        if is_service_healthy "$service"; then
            log_success "Service $service is healthy"
            return 0
        fi
        
        sleep "$interval"
        elapsed=$((elapsed + interval))
        log_debug "Waiting for $service... (${elapsed}s elapsed)"
    done
    
    log_error "Service $service did not become healthy within ${timeout}s"
    return 1
}

# ================================
# NETWORK FUNCTIONS
# ================================

# Test internal connectivity
test_internal_connectivity() {
    local failed_tests=()
    
    log_info "Testing internal connectivity..."
    
    # Test Vaultwarden
    local vw_id
    vw_id=$(get_container_id "vaultwarden")
    if [[ -n "$vw_id" ]]; then
        if docker exec "$vw_id" curl -f http://localhost:80/alive --max-time 10 >/dev/null 2>&1; then
            log_success "Vaultwarden HTTP endpoint accessible"
        else
            log_warning "Vaultwarden HTTP endpoint not accessible"
            failed_tests+=("vaultwarden-http")
        fi
    fi
    
    # Test MariaDB
    local db_id
    db_id=$(get_container_id "bw_mariadb")
    if [[ -n "$db_id" ]]; then
        if docker exec "$db_id" mysqladmin ping -h localhost --silent 2>/dev/null; then
            log_success "MariaDB is responsive"
        else
            log_warning "MariaDB is not responsive"
            failed_tests+=("mariadb")
        fi
    fi
    
    # Test Redis
    local redis_id
    redis_id=$(get_container_id "bw_redis")
    if [[ -n "$redis_id" ]]; then
        if docker exec "$redis_id" redis-cli ping >/dev/null 2>&1; then
            log_success "Redis is responsive"
        else
            log_warning "Redis is not responsive"
            failed_tests+=("redis")
        fi
    fi
    
    # Test inter-service connectivity
    if [[ -n "$vw_id" && -n "$db_id" ]]; then
        if docker exec "$vw_id" nc -z bw_mariadb 3306 2>/dev/null; then
            log_success "Vaultwarden can connect to MariaDB"
        else
            log_warning "Vaultwarden cannot connect to MariaDB"
            failed_tests+=("vw-db-connectivity")
        fi
    fi
    
    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        log_success "All internal connectivity tests passed"
        return 0
    else
        log_warning "Failed connectivity tests: ${failed_tests[*]}"
        return 1
    fi
}

# ================================
# BACKUP FUNCTIONS
# ================================

# Create container snapshot
create_container_snapshot() {
    local service="$1"
    local snapshot_name="${2:-${service}_snapshot_$(date +%Y%m%d_%H%M%S)}"
    
    local container_id
    container_id=$(get_container_id "$service")
    
    if [[ -z "$container_id" ]]; then
        log_error "Service $service not found"
        return 1
    fi
    
    log_info "Creating snapshot of service: $service"
    
    if docker commit "$container_id" "$snapshot_name"; then
        log_success "Snapshot created: $snapshot_name"
        echo "$snapshot_name"
        return 0
    else
        log_error "Failed to create snapshot"
        return 1
    fi
}

# ================================
# TROUBLESHOOTING FUNCTIONS
# ================================

# Collect diagnostic information
collect_diagnostics() {
    local output_dir="${1:-./diagnostics_$(date +%Y%m%d_%H%M%S)}"
    
    log_info "Collecting diagnostic information to: $output_dir"
    mkdir -p "$output_dir"
    
    # System info
    {
        echo "=== System Information ==="
        uname -a
        echo
        echo "=== Docker Version ==="
        docker --version
        docker compose version
        echo
        echo "=== Docker Info ==="
        docker info
        echo
        echo "=== Docker Compose Config ==="
        docker compose config
    } > "$output_dir/system_info.txt"
    
    # Service status
    docker compose ps > "$output_dir/service_status.txt"
    
    # Collect logs for each service
    for service in "${SERVICES[@]}"; do
        if is_service_running "$service"; then
            docker compose logs "$service" > "$output_dir/${service}_logs.txt" 2>&1
        fi
    done
    
    # Resource usage
    docker stats --no-stream > "$output_dir/resource_usage.txt" 2>&1
    
    # Network info
    {
        echo "=== Docker Networks ==="
        docker network ls
        echo
        echo "=== Compose Network Details ==="
        local network_name
        network_name=$(get_compose_project)_default
        docker network inspect "$network_name" 2>/dev/null || echo "Network $network_name not found"
    } > "$output_dir/network_info.txt"
    
    log_success "Diagnostic information collected in: $output_dir"
    echo "$output_dir"
}
