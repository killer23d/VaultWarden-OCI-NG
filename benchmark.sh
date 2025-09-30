#!/usr/bin/env bash
# benchmark.sh -- Performance benchmarking tool for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_benchmark_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/performance.sh"

# Benchmark configuration
BENCHMARK_RESULTS_DIR="./benchmarks"
BENCHMARK_DURATION="${BENCHMARK_DURATION:-60}"  # seconds
BENCHMARK_SAMPLES="${BENCHMARK_SAMPLES:-12}"    # number of samples

# ================================
# BENCHMARK FUNCTIONS
# ================================

# Initialize benchmark environment
init_benchmark() {
    log_info "Initializing benchmark environment..."
    
    # Create results directory
    mkdir -p "$BENCHMARK_RESULTS_DIR"
    
    # Ensure stack is running
    if ! is_stack_running; then
        log_error "VaultWarden stack is not running. Please start it first with ./startup.sh"
    fi
    
    # Wait for services to be fully ready
    log_info "Waiting for services to be fully ready..."
    for service in "vaultwarden" "bw_mariadb" "bw_redis"; do
        if ! wait_for_service "$service" 120 10; then
            log_error "Service $service is not ready for benchmarking"
        fi
    done
    
    log_success "Benchmark environment ready"
}

# System benchmark
run_system_benchmark() {
    local output_file="$1"
    local duration="$2"
    
    log_info "Running system benchmark for ${duration}s..."
    
    local start_time end_time
    start_time=$(date +%s)
    end_time=$((start_time + duration))
    
    # Collect system metrics
    local metrics=()
    while [[ $(date +%s) -lt $end_time ]]; do
        local timestamp cpu_usage memory_usage disk_io load_avg
        timestamp=$(date -Iseconds)
        cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
        memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
        load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
        
        # Get disk I/O stats
        if command -v iostat >/dev/null 2>&1; then
            disk_io=$(iostat -d 1 1 | tail -n +4 | awk '{sum+=$4} END {print sum}' 2>/dev/null || echo "0")
        else
            disk_io="0"
        fi
        
        local metric_json
        metric_json=$(jq -n --arg timestamp "$timestamp" \
                           --argjson cpu "$cpu_usage" \
                           --argjson memory "$memory_usage" \
                           --argjson load "$load_avg" \
                           --argjson disk_io "$disk_io" \
                           '{
                               timestamp: $timestamp,
                               cpu_usage: $cpu,
                               memory_usage: $memory,
                               load_average: $load,
                               disk_io: $disk_io
                           }')
        
        metrics+=("$metric_json")
        sleep 5
    done
    
    # Calculate statistics
    local cpu_values memory_values load_values
    cpu_values=$(printf '%s\n' "${metrics[@]}" | jq -r '.cpu_usage')
    memory_values=$(printf '%s\n' "${metrics[@]}" | jq -r '.memory_usage')
    load_values=$(printf '%s\n' "${metrics[@]}" | jq -r '.load_average')
    
    local cpu_avg cpu_max memory_avg memory_max load_avg_val load_max
    cpu_avg=$(echo "$cpu_values" | awk '{sum+=$1} END {print sum/NR}')
    cpu_max=$(echo "$cpu_values" | sort -n | tail -1)
    memory_avg=$(echo "$memory_values" | awk '{sum+=$1} END {print sum/NR}')
    memory_max=$(echo "$memory_values" | sort -n | tail -1)
    load_avg_val=$(echo "$load_values" | awk '{sum+=$1} END {print sum/NR}')
    load_max=$(echo "$load_values" | sort -n | tail -1)
    
    # Generate report
    local report
    report=$(jq -n --arg timestamp "$(date -Iseconds)" \
                   --argjson duration "$duration" \
                   --argjson sample_count "${#metrics[@]}" \
                   --argjson cpu_avg "$cpu_avg" \
                   --argjson cpu_max "$cpu_max" \
                   --argjson memory_avg "$memory_avg" \
                   --argjson memory_max "$memory_max" \
                   --argjson load_avg "$load_avg_val" \
                   --argjson load_max "$load_max" \
                   --argjson samples "$(printf '%s\n' "${metrics[@]}" | jq -s '.')" \
                   '{
                       benchmark_type: "system",
                       timestamp: $timestamp,
                       duration_seconds: $duration,
                       sample_count: $sample_count,
                       results: {
                           cpu: {
                               average: $cpu_avg,
                               maximum: $cpu_max,
                               unit: "percent"
                           },
                           memory: {
                               average: $memory_avg,
                               maximum: $memory_max,
                               unit: "percent"
                           },
                           load: {
                               average: $load_avg,
                               maximum: $load_max,
                               unit: "load_average"
                           }
                       },
                       samples: $samples
                   }')
    
    echo "$report" > "$output_file"
    log_success "System benchmark completed: $output_file"
}

# Database benchmark
run_database_benchmark() {
    local output_file="$1"
    local duration="$2"
    
    log_info "Running database benchmark for ${duration}s..."
    
    if ! is_service_running "bw_mariadb"; then
        log_error "MariaDB service is not running"
        return 1
    fi
    
    local db_id
    db_id=$(get_container_id "bw_mariadb")
    
    local start_time end_time
    start_time=$(date +%s)
    end_time=$((start_time + duration))
    
    # Collect database metrics
    local metrics=()
    while [[ $(date +%s) -lt $end_time ]]; do
        local timestamp connections threads_running slow_queries queries_per_sec
        timestamp=$(date -Iseconds)
        
        # Get database metrics
        connections=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" -s -N 2>/dev/null | cut -f2 || echo "0")
        threads_running=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Threads_running';" -s -N 2>/dev/null | cut -f2 || echo "0")
        slow_queries=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';" -s -N 2>/dev/null | cut -f2 || echo "0")
        queries_per_sec=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Queries';" -s -N 2>/dev/null | cut -f2 || echo "0")
        
        local metric_json
        metric_json=$(jq -n --arg timestamp "$timestamp" \
                           --argjson connections "$connections" \
                           --argjson threads_running "$threads_running" \
                           --argjson slow_queries "$slow_queries" \
                           --argjson queries_per_sec "$queries_per_sec" \
                           '{
                               timestamp: $timestamp,
                               connections: $connections,
                               threads_running: $threads_running,
                               slow_queries: $slow_queries,
                               total_queries: $queries_per_sec
                           }')
        
        metrics+=("$metric_json")
        sleep 5
    done
    
    # Calculate query rate
    local first_queries last_queries query_rate
    first_queries=$(echo "${metrics[0]}" | jq -r '.total_queries')
    last_queries=$(echo "${metrics[-1]}" | jq -r '.total_queries')
    query_rate=$(echo "scale=2; ($last_queries - $first_queries) / $duration" | bc -l 2>/dev/null || echo "0")
    
    # Calculate averages
    local conn_values threads_values
    conn_values=$(printf '%s\n' "${metrics[@]}" | jq -r '.connections')
    threads_values=$(printf '%s\n' "${metrics[@]}" | jq -r '.threads_running')
    
    local conn_avg conn_max threads_avg threads_max
    conn_avg=$(echo "$conn_values" | awk '{sum+=$1} END {print sum/NR}')
    conn_max=$(echo "$conn_values" | sort -n | tail -1)
    threads_avg=$(echo "$threads_values" | awk '{sum+=$1} END {print sum/NR}')
    threads_max=$(echo "$threads_values" | sort -n | tail -1)
    
    # Generate report
    local report
    report=$(jq -n --arg timestamp "$(date -Iseconds)" \
                   --argjson duration "$duration" \
                   --argjson sample_count "${#metrics[@]}" \
                   --argjson query_rate "$query_rate" \
                   --argjson conn_avg "$conn_avg" \
                   --argjson conn_max "$conn_max" \
                   --argjson threads_avg "$threads_avg" \
                   --argjson threads_max "$threads_max" \
                   --argjson samples "$(printf '%s\n' "${metrics[@]}" | jq -s '.')" \
                   '{
                       benchmark_type: "database",
                       timestamp: $timestamp,
                       duration_seconds: $duration,
                       sample_count: $sample_count,
                       results: {
                           query_rate: {
                               value: $query_rate,
                               unit: "queries_per_second"
                           },
                           connections: {
                               average: $conn_avg,
                               maximum: $conn_max,
                               unit: "count"
                           },
                           threads_running: {
                               average: $threads_avg,
                               maximum: $threads_max,
                               unit: "count"
                           }
                       },
                       samples: $samples
                   }')
    
    echo "$report" > "$output_file"
    log_success "Database benchmark completed: $output_file"
}

# Redis benchmark
run_redis_benchmark() {
    local output_file="$1"
    local duration="$2"
    
    log_info "Running Redis benchmark for ${duration}s..."
    
    if ! is_service_running "bw_redis"; then
        log_error "Redis service is not running"
        return 1
    fi
    
    local redis_id
    redis_id=$(get_container_id "bw_redis")
    
    # Run redis-benchmark if available
    local benchmark_result
    if docker exec "$redis_id" redis-benchmark -q -t set,get -n 1000 -c 10 >/dev/null 2>&1; then
        benchmark_result=$(docker exec "$redis_id" redis-benchmark -q -t set,get -n 1000 -c 10 2>/dev/null)
    else
        log_warning "redis-benchmark not available, using basic metrics"
        benchmark_result=""
    fi
    
    local start_time end_time
    start_time=$(date +%s)
    end_time=$((start_time + duration))
    
    # Collect Redis metrics
    local metrics=()
    while [[ $(date +%s) -lt $end_time ]]; do
        local timestamp clients used_memory hits misses
        timestamp=$(date -Iseconds)
        
        # Get Redis info
        local info_output
        info_output=$(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" INFO 2>/dev/null)
        
        clients=$(echo "$info_output" | grep "^connected_clients:" | cut -d: -f2 | tr -d '\r' || echo "0")
        used_memory=$(echo "$info_output" | grep "^used_memory:" | cut -d: -f2 | tr -d '\r' || echo "0")
        hits=$(echo "$info_output" | grep "^keyspace_hits:" | cut -d: -f2 | tr -d '\r' || echo "0")
        misses=$(echo "$info_output" | grep "^keyspace_misses:" | cut -d: -f2 | tr -d '\r' || echo "0")
        
        local metric_json
        metric_json=$(jq -n --arg timestamp "$timestamp" \
                           --argjson clients "$clients" \
                           --argjson used_memory "$used_memory" \
                           --argjson hits "$hits" \
                           --argjson misses "$misses" \
                           '{
                               timestamp: $timestamp,
                               connected_clients: $clients,
                               used_memory: $used_memory,
                               keyspace_hits: $hits,
                               keyspace_misses: $misses
                           }')
        
        metrics+=("$metric_json")
        sleep 5
    done
    
    # Calculate hit ratio
    local first_hits first_misses last_hits last_misses hit_ratio
    first_hits=$(echo "${metrics[0]}" | jq -r '.keyspace_hits')
    first_misses=$(echo "${metrics[0]}" | jq -r '.keyspace_misses')
    last_hits=$(echo "${metrics[-1]}" | jq -r '.keyspace_hits')
    last_misses=$(echo "${metrics[-1]}" | jq -r '.keyspace_misses')
    
    local total_requests=$((last_hits - first_hits + last_misses - first_misses))
    if [[ $total_requests -gt 0 ]]; then
        hit_ratio=$(echo "scale=2; (($last_hits - $first_hits) * 100) / $total_requests" | bc -l 2>/dev/null || echo "0")
    else
        hit_ratio="0"
    fi
    
    # Generate report
    local report
    report=$(jq -n --arg timestamp "$(date -Iseconds)" \
                   --argjson duration "$duration" \
                   --argjson sample_count "${#metrics[@]}" \
                   --argjson hit_ratio "$hit_ratio" \
                   --argjson total_requests "$total_requests" \
                   --arg benchmark_result "$benchmark_result" \
                   --argjson samples "$(printf '%s\n' "${metrics[@]}" | jq -s '.')" \
                   '{
                       benchmark_type: "redis",
                       timestamp: $timestamp,
                       duration_seconds: $duration,
                       sample_count: $sample_count,
                       results: {
                           cache_hit_ratio: {
                               value: $hit_ratio,
                               unit: "percent"
                           },
                           total_requests: {
                               value: $total_requests,
                               unit: "count"
                           },
                           benchmark_output: $benchmark_result
                       },
                       samples: $samples
                   }')
    
    echo "$report" > "$output_file"
    log_success "Redis benchmark completed: $output_file"
}

# HTTP response time benchmark
run_http_benchmark() {
    local output_file="$1"
    local duration="$2"
    
    log_info "Running HTTP benchmark for ${duration}s..."
    
    # Load configuration to get domain
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        source "$SETTINGS_FILE"
        set +a
    fi
    
    local test_url="${DOMAIN:-http://localhost}"
    local health_endpoint="${test_url}/alive"
    
    local start_time end_time
    start_time=$(date +%s)
    end_time=$((start_time + duration))
    
    local response_times=()
    local successful_requests=0
    local failed_requests=0
    
    while [[ $(date +%s) -lt $end_time ]]; do
        local response_time
        response_time=$(curl -o /dev/null -s -w "%{time_total}" --max-time 10 "$health_endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && [[ -n "$response_time" ]]; then
            response_times+=("$response_time")
            successful_requests=$((successful_requests + 1))
        else
            failed_requests=$((failed_requests + 1))
        fi
        
        sleep 2
    done
    
    # Calculate statistics
    local total_requests avg_response_time min_response_time max_response_time
    total_requests=$((successful_requests + failed_requests))
    
    if [[ ${#response_times[@]} -gt 0 ]]; then
        avg_response_time=$(printf '%s\n' "${response_times[@]}" | awk '{sum+=$1} END {print sum/NR}')
        min_response_time=$(printf '%s\n' "${response_times[@]}" | sort -n | head -1)
        max_response_time=$(printf '%s\n' "${response_times[@]}" | sort -n | tail -1)
    else
        avg_response_time="0"
        min_response_time="0"
        max_response_time="0"
    fi
    
    local success_rate
    success_rate=$(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l 2>/dev/null || echo "0")
    
    # Generate report
    local report
    report=$(jq -n --arg timestamp "$(date -Iseconds)" \
                   --argjson duration "$duration" \
                   --arg test_url "$health_endpoint" \
                   --argjson total_requests "$total_requests" \
                   --argjson successful_requests "$successful_requests" \
                   --argjson failed_requests "$failed_requests" \
                   --argjson success_rate "$success_rate" \
                   --argjson avg_response_time "$avg_response_time" \
                   --argjson min_response_time "$min_response_time" \
                   --argjson max_response_time "$max_response_time" \
                   --argjson response_times "$(printf '%s\n' "${response_times[@]}" | jq -R . | jq -s 'map(tonumber)')" \
                   '{
                       benchmark_type: "http",
                       timestamp: $timestamp,
                       duration_seconds: $duration,
                       test_url: $test_url,
                       results: {
                           total_requests: $total_requests,
                           successful_requests: $successful_requests,
                           failed_requests: $failed_requests,
                           success_rate: {
                               value: $success_rate,
                               unit: "percent"
                           },
                           response_time: {
                               average: $avg_response_time,
                               minimum: $min_response_time,
                               maximum: $max_response_time,
                               unit: "seconds"
                           }
                       },
                       response_times: $response_times
                   }')
    
    echo "$report" > "$output_file"
    log_success "HTTP benchmark completed: $output_file"
}

# ================================
# COMPARISON AND ANALYSIS
# ================================

# Compare benchmark results
compare_benchmarks() {
    local baseline_file="$1"
    local current_file="$2"
    local output_file="$3"
    
    log_info "Comparing benchmarks: $baseline_file vs $current_file"
    
    if [[ ! -f "$baseline_file" ]]; then
        log_error "Baseline file not found: $baseline_file"
        return 1
    fi
    
    if [[ ! -f "$current_file" ]]; then
        log_error "Current file not found: $current_file"
        return 1
    fi
    
    local baseline_data current_data
    baseline_data=$(cat "$baseline_file")
    current_data=$(cat "$current_file")
    
    # Generate comparison
    local comparison
    comparison=$(jq -n --argjson baseline "$baseline_data" \
                       --argjson current "$current_data" \
                       --arg timestamp "$(date -Iseconds)" \
                       '{
                           comparison_type: "benchmark",
                           timestamp: $timestamp,
                           baseline: $baseline,
                           current: $current,
                           performance_delta: {
                               cpu: {
                                   baseline: $baseline.results.cpu.average,
                                   current: $current.results.cpu.average,
                                   change_percent: (($current.results.cpu.average - $baseline.results.cpu.average) / $baseline.results.cpu.average * 100)
                               },
                               memory: {
                                   baseline: $baseline.results.memory.average,
                                   current: $current.results.memory.average,
                                   change_percent: (($current.results.memory.average - $baseline.results.memory.average) / $baseline.results.memory.average * 100)
                               }
                           }
                       }')
    
    echo "$comparison" > "$output_file"
    log_success "Benchmark comparison completed: $output_file"
}

# Generate benchmark report
generate_benchmark_report() {
    local benchmark_files=("$@")
    local output_file="$BENCHMARK_RESULTS_DIR/benchmark_report_$(date +%Y%m%d_%H%M%S).html"
    
    log_info "Generating benchmark report..."
    
    cat > "$output_file" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>VaultWarden-OCI Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .metric { display: inline-block; margin: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .good { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VaultWarden-OCI Benchmark Report</h1>
        <p>Generated: $(date)</p>
        <p>System: $(hostname)</p>
    </div>
    
    <div class="section">
        <h2>Benchmark Results</h2>
EOF
    
    # Process each benchmark file
    for file in "${benchmark_files[@]}"; do
        if [[ -f "$file" ]]; then
            local benchmark_type
            benchmark_type=$(jq -r '.benchmark_type' "$file")
            
            cat >> "$output_file" <<EOF
        <h3>$(echo "$benchmark_type" | tr '[:lower:]' '[:upper:]') Benchmark</h3>
        <div class="metric">
            <strong>Timestamp:</strong> $(jq -r '.timestamp' "$file")
        </div>
        <div class="metric">
            <strong>Duration:</strong> $(jq -r '.duration_seconds' "$file")s
        </div>
        <div class="metric">
            <strong>Samples:</strong> $(jq -r '.sample_count' "$file")
        </div>
EOF
            
            # Add type-specific metrics
            case "$benchmark_type" in
                "system")
                    cat >> "$output_file" <<EOF
        <div class="metric">
            <strong>CPU Average:</strong> $(jq -r '.results.cpu.average' "$file")%
        </div>
        <div class="metric">
            <strong>Memory Average:</strong> $(jq -r '.results.memory.average' "$file")%
        </div>
        <div class="metric">
            <strong>Load Average:</strong> $(jq -r '.results.load.average' "$file")
        </div>
EOF
                    ;;
                "database")
                    cat >> "$output_file" <<EOF
        <div class="metric">
            <strong>Query Rate:</strong> $(jq -r '.results.query_rate.value' "$file") queries/sec
        </div>
        <div class="metric">
            <strong>Avg Connections:</strong> $(jq -r '.results.connections.average' "$file")
        </div>
EOF
                    ;;
                "redis")
                    cat >> "$output_file" <<EOF
        <div class="metric">
            <strong>Cache Hit Ratio:</strong> $(jq -r '.results.cache_hit_ratio.value' "$file")%
        </div>
        <div class="metric">
            <strong>Total Requests:</strong> $(jq -r '.results.total_requests.value' "$file")
        </div>
EOF
                    ;;
                "http")
                    cat >> "$output_file" <<EOF
        <div class="metric">
            <strong>Success Rate:</strong> $(jq -r '.results.success_rate.value' "$file")%
        </div>
        <div class="metric">
            <strong>Avg Response Time:</strong> $(jq -r '.results.response_time.average' "$file")s
        </div>
EOF
                    ;;
            esac
        fi
    done
    
    cat >> "$output_file" <<EOF
    </div>
</body>
</html>
EOF
    
    log_success "Benchmark report generated: $output_file"
    echo "$output_file"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local command="${1:-help}"
    
    case "$command" in
        "run")
            local benchmark_type="${2:-all}"
            local duration="${3:-$BENCHMARK_DURATION}"
            local timestamp=$(date +%Y%m%d_%H%M%S)
            
            init_benchmark
            
            case "$benchmark_type" in
                "system")
                    run_system_benchmark "$BENCHMARK_RESULTS_DIR/system_$timestamp.json" "$duration"
