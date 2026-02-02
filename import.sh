#!/bin/bash
# CrowdSec Blocklist Import
# Imports 28+ public threat feeds directly into CrowdSec
#
# v1.1.0 - Selective blocklists, custom URLs, dry-run mode, per-source stats
#           Fixes: MODE case sensitivity (#12), DOCKER_API_VERSION auto-detect (#12)
#           Curl-based Docker socket fallback (#12)
#           --version, --help, --list-sources, --dry-run flags (#13)
#           ENABLE_* env var validation (#14)

set -e

VERSION="1.1.0"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"
DECISION_DURATION="${DECISION_DURATION:-24h}"
TEMP_DIR="/tmp/blocklist-import"

# Fetch timeout in seconds (increase for slow connections)
FETCH_TIMEOUT="${FETCH_TIMEOUT:-60}"

# Mode: "docker" or "native" (auto-detected if not set)
# Accept both MODE and mode env vars, case-insensitive (fixes #12)
_raw_mode="${MODE:-${mode:-auto}}"
MODE="$(echo "$_raw_mode" | tr '[:upper:]' '[:lower:]')"

# Docker API version override (fixes #12 - Docker CLI 24 vs Engine 25+ mismatch)
# If not set, will be auto-detected from the Docker daemon
[ -n "${DOCKER_API_VERSION:-}" ] && export DOCKER_API_VERSION

# Dry-run mode: show what would be imported without making changes (closes #3)
DRY_RUN="${DRY_RUN:-false}"

# Custom blocklist URLs, comma-separated (closes #2)
CUSTOM_BLOCKLISTS="${CUSTOM_BLOCKLISTS:-}"

# Telemetry (enabled by default, set TELEMETRY_ENABLED=false to disable)
TELEMETRY_ENABLED="${TELEMETRY_ENABLED:-true}"
TELEMETRY_URL="https://bouncer-telemetry.ms2738.workers.dev/ping"

# Docker socket path (configurable for non-standard setups like Unraid)
DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"

# Counters
SOURCES_OK=0
SOURCES_FAILED=0
SOURCES_SKIPPED=0

# Track whether we should use socket fallback
USE_SOCKET_FALLBACK=false

# All known blocklist sources (shared between functions to avoid duplication)
ALL_SOURCES=(
    "IPsum"
    "Spamhaus DROP"
    "Spamhaus EDROP"
    "Blocklist.de all"
    "Blocklist.de SSH"
    "Blocklist.de Apache"
    "Blocklist.de mail"
    "Firehol level1"
    "Firehol level2"
    "Feodo Tracker"
    "SSL Blacklist"
    "URLhaus"
    "Emerging Threats"
    "Binary Defense"
    "Bruteforce Blocker"
    "DShield"
    "CI Army"
    "Darklist"
    "Talos"
    "Charles Haley"
    "Botvrij"
    "myip.ms"
    "GreenSnow"
    "StopForumSpam"
    "Tor exit nodes"
    "Tor (dan.me.uk)"
    "Shodan scanners"
    "Censys"
)

# Logging
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    case "$LOG_LEVEL" in
        DEBUG) levels="DEBUG INFO WARN ERROR" ;;
        INFO)  levels="INFO WARN ERROR" ;;
        WARN)  levels="WARN ERROR" ;;
        ERROR) levels="ERROR" ;;
        *)     levels="INFO WARN ERROR" ;;
    esac

    if echo "$levels" | grep -qw "$level"; then
        echo "[$timestamp] [$level] $msg"
    fi
}

debug() { log "DEBUG" "$@"; }
info()  { log "INFO" "$@"; }
warn()  { log "WARN" "$@"; }
error() { log "ERROR" "$@"; }

# Normalize a source name to an env var name (closes #1)
# "IPsum" -> "IPSUM", "Spamhaus DROP" -> "SPAMHAUS_DROP", "Blocklist.de all" -> "BLOCKLIST_DE_ALL"
# "Tor (dan.me.uk)" -> "TOR_DAN_ME_UK", "myip.ms" -> "MYIP_MS"
normalize_source_name() {
    local name="$1"
    echo "$name" | tr '[:lower:]' '[:upper:]' | sed 's/[[:space:]\.()-]/_/g' | sed 's/__*/_/g' | sed 's/^_//;s/_$//'
}

# Check if a blocklist source is enabled via ENABLE_<NAME> env var (closes #1)
# Default: all sources enabled (true)
is_source_enabled() {
    local name="$1"
    local var_name="ENABLE_$(normalize_source_name "$name")"
    local value="${!var_name:-true}"
    [ "$value" = "true" ]
}

# Record per-source statistics (closes #4)
record_stat() {
    local name="$1"
    local count="$2"
    echo "${name}|${count}" >> "$TEMP_DIR/.stats"
}

# Display per-source statistics summary table (closes #4)
show_stats() {
    local stats_file="$TEMP_DIR/.stats"
    if [ ! -f "$stats_file" ] || [ ! -s "$stats_file" ]; then
        return
    fi

    info "--- Source Statistics ---"
    printf "  %-30s %s\n" "Source" "IPs" | while read -r line; do info "$line"; done
    printf "  %-30s %s\n" "------------------------------" "--------" | while read -r line; do info "$line"; done

    local total=0
    while IFS='|' read -r source count; do
        printf "  %-30s %s\n" "$source" "$count" | while read -r line; do info "$line"; done
        total=$((total + count))
    done < "$stats_file"

    printf "  %-30s %s\n" "------------------------------" "--------" | while read -r line; do info "$line"; done
    printf "  %-30s %s\n" "TOTAL (before dedup)" "$total" | while read -r line; do info "$line"; done
    info "------------------------"
}

# Log disabled sources at startup (closes #1)
show_source_overrides() {
    local has_overrides=false

    for source in "${ALL_SOURCES[@]}"; do
        local var_name="ENABLE_$(normalize_source_name "$source")"
        local value="${!var_name:-}"
        if [ "$value" = "false" ]; then
            if [ "$has_overrides" = false ]; then
                info "Source overrides:"
                has_overrides=true
            fi
            info "  $var_name=false (disabled)"
        fi
    done

    if [ "$has_overrides" = true ]; then
        info ""
    fi
}

# Validate ENABLE_* environment variables and warn about typos (closes #14)
validate_enable_vars() {
    # Build list of valid ENABLE_ var names
    local valid_vars=()
    for source in "${ALL_SOURCES[@]}"; do
        valid_vars+=("ENABLE_$(normalize_source_name "$source")")
    done

    # Check all ENABLE_* env vars against valid list
    while IFS='=' read -r var_name var_value; do
        [[ "$var_name" != ENABLE_* ]] && continue

        local is_valid=false
        for valid in "${valid_vars[@]}"; do
            if [ "$var_name" = "$valid" ]; then
                is_valid=true
                break
            fi
        done

        if [ "$is_valid" = false ]; then
            # Try to suggest the closest match using prefix substring matching
            local suggestion=""
            local var_suffix="${var_name#ENABLE_}"
            for valid in "${valid_vars[@]}"; do
                local valid_suffix="${valid#ENABLE_}"
                # Check if first 4+ chars overlap
                if [ "${#var_suffix}" -ge 4 ] && [ "${#valid_suffix}" -ge 4 ]; then
                    if [[ "$valid_suffix" == *"${var_suffix:0:4}"* ]] || [[ "$var_suffix" == *"${valid_suffix:0:4}"* ]]; then
                        suggestion="$valid"
                        break
                    fi
                elif [[ "$valid_suffix" == *"$var_suffix"* ]] || [[ "$var_suffix" == *"$valid_suffix"* ]]; then
                    suggestion="$valid"
                    break
                fi
            done

            if [ -n "$suggestion" ]; then
                warn "Unknown variable: ${var_name}=${var_value} (did you mean ${suggestion}?)"
            else
                warn "Unknown variable: ${var_name}=${var_value} (not a recognized source)"
            fi
        fi
    done < <(env)
}

# Send telemetry
send_telemetry() {
    local ip_count="$1"
    if [ "$TELEMETRY_ENABLED" != "true" ]; then
        return
    fi
    curl -s -X POST "$TELEMETRY_URL" \
        -H "Content-Type: application/json" \
        -d "{\"tool\":\"blocklist-import\",\"version\":\"$VERSION\",\"ip_count\":$ip_count}" \
        --max-time 5 >/dev/null 2>&1 || true
    debug "Telemetry sent"
}

# Auto-detect Docker API version from the daemon (fixes #12)
# Queries the Docker socket directly via curl, then falls back to docker CLI
auto_detect_docker_api_version() {
    if [ -n "${DOCKER_API_VERSION:-}" ]; then
        debug "Docker API version already set: $DOCKER_API_VERSION"
        return 0
    fi

    # Try to query the Docker daemon for its API version via the socket
    if [ -S "$DOCKER_SOCKET" ]; then
        local version_info
        version_info=$(curl -s --unix-socket "$DOCKER_SOCKET" http://localhost/version 2>/dev/null) || true
        if [ -n "$version_info" ]; then
            local api_version
            # Extract ApiVersion from JSON response (works without jq)
            api_version=$(echo "$version_info" | grep -oE '"ApiVersion"\s*:\s*"[0-9.]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+')
            if [ -n "$api_version" ]; then
                export DOCKER_API_VERSION="$api_version"
                debug "Auto-detected Docker API version: $DOCKER_API_VERSION"
                return 0
            fi
        fi
    fi

    # Fallback: try docker version command
    local server_api
    server_api=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null) || true
    if [ -n "$server_api" ]; then
        export DOCKER_API_VERSION="$server_api"
        debug "Docker API version from docker CLI: $DOCKER_API_VERSION"
        return 0
    fi

    debug "Could not auto-detect Docker API version"
    return 1
}

# Check if a container exists and is running using curl against Docker socket (fixes #12)
# Fallback when docker exec fails due to API version mismatch
docker_socket_container_running() {
    local container_name="$1"

    if [ ! -S "$DOCKER_SOCKET" ]; then
        return 1
    fi

    # Query Docker API for container info
    local response
    response=$(curl -s --unix-socket "$DOCKER_SOCKET" \
        "http://localhost/containers/${container_name}/json" 2>/dev/null) || return 1

    # Check if container is running (look for "Running":true in the State object)
    if echo "$response" | grep -q '"Running"\s*:\s*true'; then
        return 0
    fi

    return 1
}

# Execute a command in a container using curl against Docker socket (fixes #12)
# Used as fallback when docker exec fails due to API version mismatch
docker_socket_exec() {
    local container_name="$1"
    shift
    local cmd_json=""

    # Build the JSON command array
    local first=true
    for arg in "$@"; do
        local escaped_arg
        escaped_arg=$(printf '%s' "$arg" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" = true ]; then
            cmd_json="\"$escaped_arg\""
            first=false
        else
            cmd_json="$cmd_json, \"$escaped_arg\""
        fi
    done

    # Create exec instance via Docker API
    local exec_response
    exec_response=$(curl -s --unix-socket "$DOCKER_SOCKET" \
        -X POST "http://localhost/containers/${container_name}/exec" \
        -H "Content-Type: application/json" \
        -d "{\"AttachStdout\": true, \"AttachStderr\": true, \"Cmd\": [$cmd_json]}" \
        2>/dev/null) || return 1

    # Extract exec ID from response
    local exec_id
    exec_id=$(echo "$exec_response" | grep -oE '"Id"\s*:\s*"[a-f0-9]+"' | head -1 | grep -oE '[a-f0-9]{12,}')
    if [ -z "$exec_id" ]; then
        return 1
    fi

    # Start exec and capture output
    local output
    output=$(curl -s --unix-socket "$DOCKER_SOCKET" \
        -X POST "http://localhost/exec/${exec_id}/start" \
        -H "Content-Type: application/json" \
        -d '{"Detach": false, "Tty": false}' \
        2>/dev/null) || return 1

    # Check exec exit code
    local inspect
    inspect=$(curl -s --unix-socket "$DOCKER_SOCKET" \
        "http://localhost/exec/${exec_id}/json" 2>/dev/null) || true
    local exit_code
    exit_code=$(echo "$inspect" | grep -oE '"ExitCode"\s*:\s*[0-9]+' | grep -oE '[0-9]+$') || true

    echo "$output"

    if [ -n "$exit_code" ] && [ "$exit_code" -ne 0 ]; then
        return 1
    fi

    return 0
}

# Execute a command in a container using curl, with stdin support (fixes #12)
# Writes stdin data to a temp file inside the container, then runs the command
# reading from that file. This avoids the complexity of Docker's multiplexed
# stream protocol for interactive stdin.
docker_socket_exec_stdin() {
    local container_name="$1"
    shift

    # Read all stdin data first
    local stdin_data
    stdin_data=$(cat)

    local tmpfile="/tmp/.blocklist-import-$$"

    # Replace "-i -" in the command args with "-i $tmpfile"
    local new_args=()
    local prev_was_i=false
    for arg in "$@"; do
        if [ "$prev_was_i" = true ] && [ "$arg" = "-" ]; then
            new_args+=("$tmpfile")
            prev_was_i=false
        else
            new_args+=("$arg")
            [ "$arg" = "-i" ] && prev_was_i=true || prev_was_i=false
        fi
    done

    # Write the data into the container via base64 encoding to avoid quoting issues
    local escaped_data
    escaped_data=$(printf '%s' "$stdin_data" | base64)

    docker_socket_exec "$container_name" sh -c "echo '$escaped_data' | base64 -d > $tmpfile" &>/dev/null || return 1

    # Run the actual command with the temp file
    local result
    result=$(docker_socket_exec "$container_name" "${new_args[@]}")
    local rc=$?

    # Clean up temp file
    docker_socket_exec "$container_name" rm -f "$tmpfile" &>/dev/null || true

    echo "$result"
    return $rc
}

# Run cscli command (handles Docker, native, and socket fallback modes)
run_cscli() {
    if [ "$MODE" = "native" ]; then
        cscli "$@"
    elif [ "$USE_SOCKET_FALLBACK" = true ]; then
        docker_socket_exec "$CROWDSEC_CONTAINER" cscli "$@"
    else
        docker exec "$CROWDSEC_CONTAINER" cscli "$@"
    fi
}

# Run cscli with stdin (for import)
run_cscli_stdin() {
    if [ "$MODE" = "native" ]; then
        cscli "$@"
    elif [ "$USE_SOCKET_FALLBACK" = true ]; then
        docker_socket_exec_stdin "$CROWDSEC_CONTAINER" cscli "$@"
    else
        docker exec -i "$CROWDSEC_CONTAINER" cscli "$@"
    fi
}

# Find CrowdSec container (Docker mode only)
find_crowdsec_container() {
    local specified="$1"

    # First, check if Docker is accessible
    if ! docker ps &>/dev/null; then
        # Docker CLI failed -- try the socket directly (fixes #12)
        if [ -S "$DOCKER_SOCKET" ]; then
            debug "Docker CLI failed, trying Docker socket directly..."
            local socket_response
            socket_response=$(curl -s --unix-socket "$DOCKER_SOCKET" \
                "http://localhost/containers/json" 2>/dev/null) || true

            if [ -z "$socket_response" ]; then
                error "Cannot access Docker. Ensure Docker socket is mounted (-v /var/run/docker.sock:/var/run/docker.sock:ro)"
                return 1
            fi

            # Docker socket works but CLI doesn't -- use socket fallback
            debug "Docker socket accessible, CLI is not -- using socket fallback mode"

            # Check if the specified container exists via socket
            if docker_socket_container_running "$specified"; then
                USE_SOCKET_FALLBACK=true
                echo "$specified"
                return 0
            fi

            # Try case-insensitive search via socket
            local container_names
            container_names=$(echo "$socket_response" | grep -oE '"Names"\s*:\s*\["/[^"]+"\]' | grep -oE '/[^"]+' | sed 's|^/||')
            for name in $container_names; do
                if echo "$name" | grep -qi "^${specified}$"; then
                    if docker_socket_container_running "$name"; then
                        warn "Found container '$name' via Docker socket (note: container names are case-sensitive)"
                        warn "Set CROWDSEC_CONTAINER=$name for exact match"
                        USE_SOCKET_FALLBACK=true
                        echo "$name"
                        return 0
                    fi
                fi
            done

            # Try to find any crowdsec container via socket
            for name in $container_names; do
                if echo "$name" | grep -qi 'crowdsec'; then
                    if docker_socket_container_running "$name"; then
                        warn "Auto-detected CrowdSec container via socket: '$name'"
                        warn "Set CROWDSEC_CONTAINER=$name to avoid this warning"
                        USE_SOCKET_FALLBACK=true
                        echo "$name"
                        return 0
                    fi
                fi
            done

            error "Docker socket accessible but cannot find CrowdSec container '$specified'"
            return 1
        fi

        error "Cannot access Docker. Ensure Docker socket is mounted (-v /var/run/docker.sock:/var/run/docker.sock:ro)"
        return 1
    fi

    # Try the specified container first (exact match) using docker exec
    if docker exec "$specified" cscli version &>/dev/null; then
        echo "$specified"
        return 0
    fi

    # docker exec failed -- could be API version mismatch (fixes #12)
    # Try curl-based socket fallback to verify the container exists
    if [ -S "$DOCKER_SOCKET" ] && docker_socket_container_running "$specified"; then
        debug "docker exec failed but container '$specified' is running (API version mismatch?)"
        debug "Switching to Docker socket fallback mode"

        # Verify cscli is accessible via socket exec
        if docker_socket_exec "$specified" cscli version &>/dev/null; then
            USE_SOCKET_FALLBACK=true
            warn "Using Docker socket API fallback (docker exec failed, likely API version mismatch)"
            warn "Set DOCKER_API_VERSION=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo '1.43') to fix"
            echo "$specified"
            return 0
        else
            # Socket exec also failed for cscli -- container exists but cscli isn't available
            debug "Container '$specified' is running but cscli is not accessible via socket exec either"
        fi
    fi

    # Try case-insensitive match of specified name
    local case_match=$(docker ps --format '{{.Names}}' | grep -i "^${specified}$" 2>/dev/null | head -1)
    if [ -n "$case_match" ]; then
        if docker exec "$case_match" cscli version &>/dev/null; then
            warn "Found container '$case_match' (note: container names are case-sensitive)"
            warn "Set CROWDSEC_CONTAINER=$case_match for exact match"
            echo "$case_match"
            return 0
        fi

        # Try socket fallback for case-insensitive match
        if [ -S "$DOCKER_SOCKET" ] && docker_socket_container_running "$case_match"; then
            if docker_socket_exec "$case_match" cscli version &>/dev/null; then
                USE_SOCKET_FALLBACK=true
                warn "Found container '$case_match' via socket fallback (note: container names are case-sensitive)"
                warn "Set CROWDSEC_CONTAINER=$case_match for exact match"
                echo "$case_match"
                return 0
            fi
        fi
    fi

    debug "Container '$specified' not found or not running CrowdSec"

    # Try to auto-detect
    debug "Searching for CrowdSec containers..."
    local candidates=$(docker ps --format '{{.Names}}' | grep -iE 'crowdsec|cscli' 2>/dev/null || true)

    if [ -z "$candidates" ]; then
        # Try checking all containers for cscli
        for container in $(docker ps --format '{{.Names}}'); do
            if docker exec "$container" which cscli &>/dev/null 2>&1; then
                candidates="$container"
                break
            fi
        done
    fi

    for candidate in $candidates; do
        if docker exec "$candidate" cscli version &>/dev/null; then
            warn "Auto-detected CrowdSec container: '$candidate'"
            warn "Set CROWDSEC_CONTAINER=$candidate to avoid this warning"
            echo "$candidate"
            return 0
        fi

        # Try socket fallback for each candidate
        if [ -S "$DOCKER_SOCKET" ] && docker_socket_container_running "$candidate"; then
            if docker_socket_exec "$candidate" cscli version &>/dev/null; then
                USE_SOCKET_FALLBACK=true
                warn "Auto-detected CrowdSec container via socket fallback: '$candidate'"
                warn "Set CROWDSEC_CONTAINER=$candidate to avoid this warning"
                echo "$candidate"
                return 0
            fi
        fi
    done

    return 1
}

# Detect and configure CrowdSec access mode
setup_crowdsec() {
    # Auto-detect Docker API version before any Docker operations (fixes #12)
    if [ "$MODE" != "native" ]; then
        auto_detect_docker_api_version
    fi

    if [ "$MODE" = "native" ]; then
        # User explicitly requested native mode
        if ! command -v cscli &>/dev/null; then
            error "Native mode requested but 'cscli' not found in PATH"
            error "Install CrowdSec or use Docker mode"
            exit 1
        fi
        if ! cscli version &>/dev/null; then
            error "Cannot run 'cscli version' - check CrowdSec installation"
            exit 1
        fi
        info "Using native CrowdSec (cscli in PATH)"
        return
    fi

    if [ "$MODE" = "docker" ]; then
        # User explicitly requested Docker mode
        CROWDSEC_CONTAINER=$(find_crowdsec_container "$CROWDSEC_CONTAINER") || {
            error "Docker mode requested but cannot find CrowdSec container"
            show_docker_help
            exit 1
        }
        if [ "$USE_SOCKET_FALLBACK" = true ]; then
            info "Using Docker socket API mode with container '$CROWDSEC_CONTAINER'"
        else
            info "Using Docker mode with container '$CROWDSEC_CONTAINER'"
        fi
        return
    fi

    # Auto-detect mode
    debug "Auto-detecting CrowdSec mode..."

    # Try native first (if cscli is in PATH and working)
    if command -v cscli &>/dev/null && cscli version &>/dev/null 2>&1; then
        MODE="native"
        info "Auto-detected native CrowdSec (cscli in PATH)"
        return
    fi

    # Try Docker
    if CROWDSEC_CONTAINER=$(find_crowdsec_container "$CROWDSEC_CONTAINER" 2>/dev/null); then
        MODE="docker"
        if [ "$USE_SOCKET_FALLBACK" = true ]; then
            info "Auto-detected Docker socket API mode with container '$CROWDSEC_CONTAINER'"
        else
            info "Auto-detected Docker mode with container '$CROWDSEC_CONTAINER'"
        fi
        return
    fi

    # Neither worked
    error "Cannot find CrowdSec installation"
    error ""
    error "Options:"
    error "  1. Native install: Make sure 'cscli' is in your PATH"
    error "  2. Docker: Mount the socket and set CROWDSEC_CONTAINER"
    error ""
    show_docker_help
    exit 1
}

show_docker_help() {
    error "Docker troubleshooting:"
    error "  1. Mount socket: -v /var/run/docker.sock:/var/run/docker.sock:ro"
    error "  2. Find container: docker ps | grep -i crowdsec"
    error "  3. Set name: -e CROWDSEC_CONTAINER=your_container_name"
    error ""
    if docker ps &>/dev/null 2>&1; then
        error "Available containers:"
        docker ps --format '  {{.Names}} ({{.Image}})' 2>/dev/null || true
    elif [ -S "$DOCKER_SOCKET" ]; then
        error "Available containers (via socket):"
        curl -s --unix-socket "$DOCKER_SOCKET" "http://localhost/containers/json" 2>/dev/null | \
            grep -oE '"Names"\s*:\s*\["/[^"]+"\]' | grep -oE '/[^"]+' | sed 's|^/|  |' || true
    fi
}

# Fetch a blocklist (with source-enable check and per-source stats)
fetch_list() {
    local name="$1"
    local url="$2"
    local output="$3"
    local filter="${4:-cat}"

    # Check if this source is enabled (closes #1)
    if ! is_source_enabled "$name"; then
        debug "$name: SKIPPED (disabled via ENABLE_$(normalize_source_name "$name")=false)"
        touch "$output"
        ((SOURCES_SKIPPED++)) || true
        record_stat "$name (disabled)" 0
        return
    fi

    debug "Fetching $name..."
    if curl -sL --max-time "$FETCH_TIMEOUT" "$url" 2>/dev/null | eval "$filter" > "$output"; then
        local count=$(wc -l < "$output" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            debug "$name: $count entries"
            ((SOURCES_OK++)) || true
            record_stat "$name" "$count"
        else
            debug "$name: empty response"
            ((SOURCES_FAILED++)) || true
            record_stat "$name" 0
        fi
    else
        debug "$name: unavailable (will retry next run)"
        touch "$output"
        ((SOURCES_FAILED++)) || true
        record_stat "$name" 0
    fi
}

# List all available blocklist sources with their ENABLE_ var names (closes #13)
list_sources() {
    echo "Available blocklist sources (${#ALL_SOURCES[@]} built-in):"
    for source in "${ALL_SOURCES[@]}"; do
        local var_name="ENABLE_$(normalize_source_name "$source")"
        local value="${!var_name:-true}"
        local status="enabled"
        [ "$value" = "false" ] && status="disabled"
        printf "  %-38s %s (%s)\n" "${var_name}=true" "$source" "$status"
    done
}

# Main import logic
main() {
    info "========================================="
    info "CrowdSec Blocklist Import v$VERSION"
    info "========================================="
    info "Decision duration: $DECISION_DURATION"
    [ "$DRY_RUN" = "true" ] && info "DRY RUN MODE - no changes will be made"
    [ -n "$CUSTOM_BLOCKLISTS" ] && info "Custom blocklists: configured"
    [ -n "${DOCKER_API_VERSION:-}" ] && info "Docker API version: $DOCKER_API_VERSION"

    # Show any disabled source overrides
    show_source_overrides

    # Validate ENABLE_* env vars for typos (closes #14)
    validate_enable_vars

    setup_crowdsec

    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    rm -f *.txt *.list .stats 2>/dev/null || true

    # Initialize stats file
    touch "$TEMP_DIR/.stats"

    # Count enabled built-in sources
    local total_builtin=${#ALL_SOURCES[@]}
    info "Fetching blocklist sources (${total_builtin} built-in)..."

    # IPsum - aggregated threat intel (level 3+ = on 3+ lists)
    fetch_list "IPsum" \
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
        "ipsum.txt" \
        "grep -v '^#' | awk '{print \$1}'"

    # Spamhaus DROP/EDROP
    fetch_list "Spamhaus DROP" \
        "https://www.spamhaus.org/drop/drop.txt" \
        "spamhaus_drop.txt" \
        "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"

    fetch_list "Spamhaus EDROP" \
        "https://www.spamhaus.org/drop/edrop.txt" \
        "spamhaus_edrop.txt" \
        "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"

    # Blocklist.de
    fetch_list "Blocklist.de all" \
        "https://lists.blocklist.de/lists/all.txt" \
        "blocklist_de.txt" \
        "grep -v '^#'"

    fetch_list "Blocklist.de SSH" \
        "https://lists.blocklist.de/lists/ssh.txt" \
        "blocklist_ssh.txt" \
        "grep -v '^#'"

    fetch_list "Blocklist.de Apache" \
        "https://lists.blocklist.de/lists/apache.txt" \
        "blocklist_apache.txt" \
        "grep -v '^#'"

    fetch_list "Blocklist.de mail" \
        "https://lists.blocklist.de/lists/mail.txt" \
        "blocklist_mail.txt" \
        "grep -v '^#'"

    # Firehol
    fetch_list "Firehol level1" \
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" \
        "firehol_l1.txt" \
        "grep -v '^#'"

    fetch_list "Firehol level2" \
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset" \
        "firehol_l2.txt" \
        "grep -v '^#'"

    # Abuse.ch
    fetch_list "Feodo Tracker" \
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
        "feodo.txt" \
        "grep -v '^#'"

    fetch_list "SSL Blacklist" \
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
        "sslbl.txt" \
        "grep -v '^#'"

    fetch_list "URLhaus" \
        "https://urlhaus.abuse.ch/downloads/text_online/" \
        "urlhaus.txt" \
        "grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'"

    # Other sources
    fetch_list "Emerging Threats" \
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" \
        "et_compromised.txt" \
        "grep -v '^#'"

    fetch_list "Binary Defense" \
        "https://www.binarydefense.com/banlist.txt" \
        "binarydefense.txt" \
        "grep -v '^#'"

    fetch_list "Bruteforce Blocker" \
        "https://danger.rulez.sk/projects/bruteforceblocker/blist.php" \
        "bruteforce.txt" \
        "grep -v '^#'"

    fetch_list "DShield" \
        "https://www.dshield.org/block.txt" \
        "dshield.txt" \
        "grep -v '^#' | awk '{print \$1}'"

    fetch_list "CI Army" \
        "https://cinsscore.com/list/ci-badguys.txt" \
        "ciarm.txt" \
        "grep -v '^#'"

    fetch_list "Darklist" \
        "https://www.darklist.de/raw.php" \
        "darklist.txt" \
        "grep -v '^#'"

    fetch_list "Talos" \
        "https://www.talosintelligence.com/documents/ip-blacklist" \
        "talos.txt" \
        "grep -v '^#'"

    fetch_list "Charles Haley" \
        "https://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt" \
        "haley.txt" \
        "grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'"

    fetch_list "Botvrij" \
        "https://www.botvrij.eu/data/ioclist.ip-dst.raw" \
        "botvrij.txt" \
        "grep -v '^#'"

    fetch_list "myip.ms" \
        "https://myip.ms/files/blacklist/general/full_blacklist_database.txt" \
        "myip.txt" \
        "grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'"

    fetch_list "GreenSnow" \
        "https://blocklist.greensnow.co/greensnow.txt" \
        "greensnow.txt" \
        "grep -v '^#'"

    fetch_list "StopForumSpam" \
        "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt" \
        "stopforumspam.txt" \
        "grep -v '^#'"

    # Tor exit nodes
    fetch_list "Tor exit nodes" \
        "https://check.torproject.org/torbulkexitlist" \
        "tor_exit.txt" \
        "grep -v '^#'"

    fetch_list "Tor (dan.me.uk)" \
        "https://www.dan.me.uk/torlist/?exit" \
        "tor_dan.txt" \
        "grep -v '^#'"

    # Scanners
    fetch_list "Shodan scanners" \
        "https://gist.githubusercontent.com/jfqd/4ff7fa70950626a11832a4bc39451c1c/raw" \
        "shodan.txt" \
        "grep -v '^#'"

    # Censys (static list)
    if is_source_enabled "Censys"; then
        cat << EOF > censys.txt
192.35.168.0/23
162.142.125.0/24
74.120.14.0/24
167.248.133.0/24
EOF
        ((SOURCES_OK++)) || true
        record_stat "Censys" 4
    else
        touch censys.txt
        debug "Censys: SKIPPED (disabled via ENABLE_CENSYS=false)"
        ((SOURCES_SKIPPED++)) || true
        record_stat "Censys (disabled)" 0
    fi

    # Custom blocklists (closes #2)
    if [ -n "$CUSTOM_BLOCKLISTS" ]; then
        local custom_num=0
        IFS=',' read -ra CUSTOM_URLS <<< "$CUSTOM_BLOCKLISTS"
        for custom_url in "${CUSTOM_URLS[@]}"; do
            # Trim whitespace
            custom_url=$(echo "$custom_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [ -z "$custom_url" ] && continue
            ((custom_num++)) || true
            fetch_list "Custom #${custom_num}" \
                "$custom_url" \
                "custom_${custom_num}.txt" \
                "grep -v '^#'"
        done
        info "Processed $custom_num custom blocklist(s)"
    fi

    info "Sources: $SOURCES_OK successful, $SOURCES_FAILED unavailable, $SOURCES_SKIPPED disabled"

    # Show per-source statistics (closes #4)
    show_stats

    info "Combining and deduplicating..."

    # Extract valid IPv4 addresses
    cat *.txt 2>/dev/null | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        awk -F'.' '{
            if ($1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255)
                printf "%d.%d.%d.%d\n", $1, $2, $3, $4
        }' | \
        sort -u > combined.txt

    # Filter private/reserved ranges
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.|100\.(6[4-9]|[7-9][0-9]|1[0-2][0-7])\.)" combined.txt | \
    grep -vE "^(1\.0\.0\.1|1\.1\.1\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|208\.67\.(222|220)\.(222|220))$" > filtered_private.txt

    # Get existing decisions to avoid duplicates
    if [ "$DRY_RUN" = "true" ]; then
        info "[DRY RUN] Skipping existing decisions check"
        touch existing.txt
    else
        info "Checking existing CrowdSec decisions..."
        run_cscli decisions list 2>/dev/null | \
            awk -F'|' '{print $4}' | \
            grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
            sort -u > existing.txt || touch existing.txt

        existing_count=$(wc -l < existing.txt)
        debug "Found $existing_count existing decisions"
    fi

    # Remove already-imported IPs
    comm -23 filtered_private.txt existing.txt > to_import.txt

    import_count=$(wc -l < to_import.txt)
    total_ips=$(wc -l < filtered_private.txt)

    if [[ $import_count -eq 0 ]]; then
        info "No new IPs to import (all $total_ips IPs already in CrowdSec)"
    elif [ "$DRY_RUN" = "true" ]; then
        # Dry-run mode (closes #3)
        info "[DRY RUN] Would import $import_count new IPs into CrowdSec (total coverage: $total_ips IPs)"
        info "[DRY RUN] Decision duration would be: $DECISION_DURATION"
        info "[DRY RUN] No changes were made"
    else
        info "Importing $import_count new IPs into CrowdSec..."
        result=$(cat to_import.txt | run_cscli_stdin decisions import -i - --format values --duration "$DECISION_DURATION" --reason "external_blocklist" 2>&1)
        info "Import complete: $import_count IPs added (total coverage: $total_ips IPs)"
    fi

    # Send telemetry
    send_telemetry "$total_ips"

    # Cleanup
    rm -rf "$TEMP_DIR"

    info "Done!"
}

# Parse command-line arguments (closes #13)
case "${1:-}" in
    --version|-v)
        echo "crowdsec-blocklist-import v$VERSION"
        exit 0
        ;;
    --help|-h)
        cat <<HELP
crowdsec-blocklist-import v$VERSION
Imports 28+ public threat feeds into CrowdSec as ban decisions.

Usage: import.sh [OPTIONS]

Options:
  --help, -h          Show this help message
  --version, -v       Show version number
  --list-sources      List all available blocklist sources
  --dry-run           Run without making changes (same as DRY_RUN=true)

Environment variables:
  CROWDSEC_CONTAINER  CrowdSec container name (default: crowdsec)
  DECISION_DURATION   How long bans last (default: 24h)
  DRY_RUN             Set to "true" for dry-run mode
  MODE                "docker", "native", or "auto" (default: auto)
  LOG_LEVEL           DEBUG, INFO, WARN, ERROR (default: INFO)
  CUSTOM_BLOCKLISTS   Comma-separated URLs of additional blocklists
  DOCKER_API_VERSION  Override Docker API version (auto-detected if not set)
  DOCKER_SOCKET       Docker socket path (default: /var/run/docker.sock)
  FETCH_TIMEOUT       Timeout in seconds for fetching blocklists (default: 60)
  TELEMETRY_ENABLED   Anonymous usage stats, set "false" to disable (default: true)

Full documentation: https://github.com/wolffcatskyy/crowdsec-blocklist-import
HELP
        exit 0
        ;;
    --list-sources)
        list_sources
        exit 0
        ;;
    --dry-run)
        DRY_RUN=true
        shift
        main "$@"
        exit $?
        ;;
    "")
        # No arguments -- run normally
        main "$@"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run 'import.sh --help' for usage information."
        exit 1
        ;;
esac
