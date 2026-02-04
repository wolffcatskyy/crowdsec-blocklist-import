#!/bin/bash
# CrowdSec Blocklist Import
# Imports 28+ public threat feeds directly into CrowdSec
#
# v2.1.1 - Default MAX_DECISIONS=40000 to prevent bouncer overload (fixes #21)
# v2.0.0 - Direct LAPI mode: no Docker socket needed (closes #9, #10)
# v1.1.0 - Selective blocklists, custom URLs, dry-run mode, per-source stats
#           Fixes: MODE case sensitivity (#12), DOCKER_API_VERSION support (#12)

set -e

# Ensure standard paths are available (fixes: "sudo ./import.sh" not finding docker/cscli)
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/snap/bin:$PATH"

VERSION="2.1.1"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"
DECISION_DURATION="${DECISION_DURATION:-24h}"
TEMP_DIR="/tmp/blocklist-import"

# Fetch timeout in seconds (increase for slow connections)
FETCH_TIMEOUT="${FETCH_TIMEOUT:-60}"

# Mode: "lapi", "docker", or "native" (auto-detected if not set)
# Accept both MODE and mode env vars (fixes #12)
MODE="${MODE:-${mode:-auto}}"

# LAPI mode: connect directly to CrowdSec API — no Docker socket needed (closes #9)
CROWDSEC_LAPI_URL="${CROWDSEC_LAPI_URL:-}"
CROWDSEC_MACHINE_ID="${CROWDSEC_MACHINE_ID:-}"
CROWDSEC_MACHINE_PASSWORD="${CROWDSEC_MACHINE_PASSWORD:-}"
LAPI_BATCH_SIZE="${LAPI_BATCH_SIZE:-1000}"
LAPI_TOKEN=""

# Docker API version override (fixes #12 - Docker CLI 24 vs Engine 25+ mismatch)
# Set DOCKER_API_VERSION=1.43 (or appropriate version) if you get API version errors
[ -n "$DOCKER_API_VERSION" ] && export DOCKER_API_VERSION

# Dry-run mode: show what would be imported without making changes (closes #3)
DRY_RUN="${DRY_RUN:-false}"

# Maximum total decisions to maintain in CrowdSec (importer-side guardrail)
# If set, the importer will stop adding IPs once this total is reached.
# Works with the bouncer-side memory guardrail (ensure-rules.sh) for two-layer protection.
# Default: 40000 (safe for all tested UniFi devices including UDR).
# Set to 0 or "unlimited" to disable the cap entirely (NOT recommended with embedded bouncers).
# Recommended values by device:
#   UDM SE / UDM Pro: 50000
#   UDR:              15000
#   USG-3P:           8000
#   Linux server:     unlimited (set MAX_DECISIONS=0)
MAX_DECISIONS="${MAX_DECISIONS:-40000}"

# Device memory-aware importing (two-layer guardrail)
# SSH target for the UniFi device running the bouncer, e.g. "root@192.168.1.1"
# If set, the importer will:
#   1. Deploy a lightweight memory agent on first run
#   2. Query device memory before importing
#   3. Calculate safe headroom and cap the import accordingly
# Multiple devices: comma-separated, e.g. "root@192.168.1.1,root@192.168.21.1"
# The device with the least headroom determines the cap.
BOUNCER_SSH="${BOUNCER_SSH:-}"

# Minimum MemAvailable (kB) to leave on the device after importing.
# The importer will not add IPs if doing so would push memory below this.
DEVICE_MEM_FLOOR="${DEVICE_MEM_FLOOR:-300000}"

# Custom blocklist URLs, comma-separated (closes #2)
CUSTOM_BLOCKLISTS="${CUSTOM_BLOCKLISTS:-}"

# Telemetry (enabled by default, set TELEMETRY_ENABLED=false to disable)
TELEMETRY_ENABLED="${TELEMETRY_ENABLED:-true}"
TELEMETRY_URL="https://bouncer-telemetry.ms2738.workers.dev/ping"

# Counters
SOURCES_OK=0
SOURCES_FAILED=0
SOURCES_SKIPPED=0

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
    local all_sources=(
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
        "AbuseIPDB"
        "Cybercrime Tracker"
        "Monty Security C2"
        "DShield Top Attackers"
        "VXVault"
        "IPsum level4"
        "Firehol level3"
        "Maltrail scanners"
    )

    for source in "${all_sources[@]}"; do
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

# --- Device memory query (two-layer guardrail) ---

# Deploy memory agent to device if not present
deploy_memory_agent() {
    local ssh_target="$1"
    local agent_path="/data/crowdsec-bouncer/memory-agent.sh"

    # Check if agent already exists
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$ssh_target" "test -f $agent_path" 2>/dev/null; then
        debug "Memory agent already deployed on $ssh_target"
        return 0
    fi

    info "Deploying memory agent to $ssh_target..."
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$ssh_target" "cat > $agent_path && chmod +x $agent_path" 2>/dev/null << 'AGENT'
#!/bin/bash
# CrowdSec memory agent — reports device state for safe importing
# Deployed by crowdsec-blocklist-import
IPSET_NAME="crowdsec-blacklists"
MEM_AVAIL=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
MEM_TOTAL=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
IPSET_COUNT=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
IPSET_MAXELEM=$(ipset list "$IPSET_NAME" -t 2>/dev/null | grep -oP 'maxelem \K[0-9]+')
echo "mem_avail=${MEM_AVAIL:-0} mem_total=${MEM_TOTAL:-0} entries=${IPSET_COUNT:-0} maxelem=${IPSET_MAXELEM:-0}"
AGENT

    if [ $? -eq 0 ]; then
        debug "Memory agent deployed to $ssh_target"
        return 0
    else
        warn "Failed to deploy memory agent to $ssh_target"
        return 1
    fi
}

# Query device for current memory and ipset state
query_device() {
    local ssh_target="$1"
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$ssh_target" "/data/crowdsec-bouncer/memory-agent.sh" 2>/dev/null
}

# Calculate how many IPs we can safely add across all monitored devices
# Returns the minimum headroom across all devices
calculate_device_headroom() {
    if [ -z "$BOUNCER_SSH" ]; then
        return
    fi

    local min_headroom=""
    local tightest_device=""

    IFS=',' read -ra DEVICES <<< "$BOUNCER_SSH"
    for device in "${DEVICES[@]}"; do
        device=$(echo "$device" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -z "$device" ] && continue

        # Deploy agent if needed
        deploy_memory_agent "$device" || continue

        # Query current state
        local state
        state=$(query_device "$device")
        if [ -z "$state" ]; then
            warn "Cannot query $device — skipping device check"
            continue
        fi

        # Parse response
        local mem_avail mem_total entries maxelem
        eval "$state"

        info "Device $device: ${mem_avail}kB available, $entries entries loaded, maxelem=$maxelem"

        # How much memory headroom above the floor?
        local mem_headroom=$((mem_avail - DEVICE_MEM_FLOOR))
        if [ "$mem_headroom" -le 0 ]; then
            warn "Device $device already below memory floor (${mem_avail}kB < ${DEVICE_MEM_FLOOR}kB)"
            echo "0"
            return
        fi

        # How much ipset headroom below maxelem?
        local ipset_headroom=999999
        if [ "$maxelem" -gt 0 ]; then
            ipset_headroom=$((maxelem - entries))
        fi

        # Use the smaller of the two constraints
        local device_headroom="$ipset_headroom"
        if [ "$device_headroom" -gt "$ipset_headroom" ]; then
            device_headroom="$ipset_headroom"
        fi

        # Track the tightest device
        if [ -z "$min_headroom" ] || [ "$device_headroom" -lt "$min_headroom" ]; then
            min_headroom="$device_headroom"
            tightest_device="$device"
        fi
    done

    if [ -n "$min_headroom" ]; then
        info "Device headroom: $min_headroom entries (limited by $tightest_device)"
        echo "$min_headroom"
    fi
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

# Run cscli command (handles both Docker and native modes)
run_cscli() {
    if [ "$MODE" = "native" ]; then
        cscli "$@"
    else
        docker exec "$CROWDSEC_CONTAINER" cscli "$@"
    fi
}

# Run cscli with stdin (for import)
run_cscli_stdin() {
    if [ "$MODE" = "native" ]; then
        cscli "$@"
    else
        docker exec -i "$CROWDSEC_CONTAINER" cscli "$@"
    fi
}

# Find CrowdSec container (Docker mode only)
find_crowdsec_container() {
    local specified="$1"

    # First, check if Docker is accessible
    if ! docker ps &>/dev/null; then
        error "Cannot access Docker. Ensure Docker socket is mounted (-v /var/run/docker.sock:/var/run/docker.sock:ro)"
        return 1
    fi

    # Try the specified container first (exact match)
    if docker exec "$specified" cscli version &>/dev/null; then
        echo "$specified"
        return 0
    fi

    # Try case-insensitive match of specified name
    local case_match=$(docker ps --format '{{.Names}}' | grep -i "^${specified}$" 2>/dev/null | head -1)
    if [ -n "$case_match" ] && docker exec "$case_match" cscli version &>/dev/null; then
        warn "Found container '$case_match' (note: container names are case-sensitive)"
        warn "Set CROWDSEC_CONTAINER=$case_match for exact match"
        echo "$case_match"
        return 0
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
    done

    return 1
}

# Detect and configure CrowdSec access mode
setup_crowdsec() {
    if [ "$MODE" = "lapi" ]; then
        # User explicitly requested LAPI mode
        if [ -z "$CROWDSEC_LAPI_URL" ]; then
            error "LAPI mode requires CROWDSEC_LAPI_URL"
            exit 1
        fi
        if [ -z "$CROWDSEC_MACHINE_ID" ] || [ -z "$CROWDSEC_MACHINE_PASSWORD" ]; then
            error "LAPI mode requires CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD"
            error ""
            error "On your CrowdSec host, run:"
            error "  cscli machines add blocklist-importer --password YOUR_PASSWORD"
            exit 1
        fi
        lapi_login || exit 1
        info "Using LAPI mode (${CROWDSEC_LAPI_URL})"
        return
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
        info "Using Docker mode with container '$CROWDSEC_CONTAINER'"
        return
    fi

    # Auto-detect mode
    debug "Auto-detecting CrowdSec mode..."

    # Try LAPI first (if URL and credentials are set)
    if [ -n "$CROWDSEC_LAPI_URL" ] && [ -n "$CROWDSEC_MACHINE_ID" ] && [ -n "$CROWDSEC_MACHINE_PASSWORD" ]; then
        if lapi_login 2>/dev/null; then
            MODE="lapi"
            info "Auto-detected LAPI mode (${CROWDSEC_LAPI_URL})"
            return
        fi
        warn "LAPI credentials provided but login failed, trying other modes..."
    fi

    # Try native (if cscli is in PATH and working)
    if command -v cscli &>/dev/null && cscli version &>/dev/null 2>&1; then
        MODE="native"
        info "Auto-detected native CrowdSec (cscli in PATH)"
        return
    fi

    # Try Docker
    if CROWDSEC_CONTAINER=$(find_crowdsec_container "$CROWDSEC_CONTAINER" 2>/dev/null); then
        MODE="docker"
        info "Auto-detected Docker mode with container '$CROWDSEC_CONTAINER'"
        return
    fi

    # Neither worked
    error "Cannot find CrowdSec installation"
    error ""
    error "Options:"
    error "  1. LAPI: Set CROWDSEC_LAPI_URL, CROWDSEC_MACHINE_ID, CROWDSEC_MACHINE_PASSWORD"
    error "  2. Native: Make sure 'cscli' is in your PATH"
    error "  3. Docker: Mount the socket and set CROWDSEC_CONTAINER"
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
    fi
}

# --- LAPI mode functions (closes #9, #10) ---

# Strip trailing slash from URL
normalize_url() {
    echo "${1%/}"
}

# Login to CrowdSec LAPI, get JWT token
lapi_login() {
    local url="$(normalize_url "$CROWDSEC_LAPI_URL")"
    debug "LAPI login to $url..."

    local response
    response=$(curl -s -X POST "${url}/v1/watchers/login" \
        -H "Content-Type: application/json" \
        -d "{\"machine_id\":\"${CROWDSEC_MACHINE_ID}\",\"password\":\"${CROWDSEC_MACHINE_PASSWORD}\"}" \
        --max-time 10 2>&1) || {
        error "LAPI login request failed (connection error)"
        return 1
    }

    # Extract token (no jq dependency)
    LAPI_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*"' | head -1 | sed 's/"token":"//;s/"$//')

    if [ -z "$LAPI_TOKEN" ]; then
        error "LAPI login failed"
        # Check for common errors
        if echo "$response" | grep -qi "password"; then
            error "Check CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD"
        elif echo "$response" | grep -qi "connection refused"; then
            error "Cannot reach LAPI at $url"
        else
            error "Response: $response"
        fi
        return 1
    fi

    debug "LAPI login successful"
}

# List existing decisions via LAPI (for dedup)
lapi_list_decisions() {
    local url="$(normalize_url "$CROWDSEC_LAPI_URL")"
    local page=0
    local limit=1000
    local all_ips=""

    # Paginate through alerts with active decisions
    while true; do
        local offset=$((page * limit))
        local response
        response=$(curl -s "${url}/v1/alerts?has_active_decision=true&limit=${limit}&offset=${offset}" \
            -H "Authorization: Bearer $LAPI_TOKEN" \
            --max-time 30 2>/dev/null) || break

        # Extract IPs from decisions in alerts
        local ips
        ips=$(echo "$response" | grep -oE '"value":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | \
            sed 's/"value":"//;s/"$//')

        [ -z "$ips" ] && break

        echo "$ips"
        # If we got fewer than limit, we've reached the end
        local count=$(echo "$ips" | wc -l)
        [ "$count" -lt "$limit" ] && break
        page=$((page + 1))
    done | sort -u
}

# Import a batch of IPs via POST /v1/alerts
lapi_import_batch() {
    local batch_file="$1"
    local batch_num="$2"
    local url="$(normalize_url "$CROWDSEC_LAPI_URL")"
    local now=$(date -u "+%Y-%m-%dT%H:%M:%SZ")
    local payload_file="$TEMP_DIR/payload_${batch_num}.json"

    # Build JSON payload using awk (fast, no jq needed)
    awk -v dur="$DECISION_DURATION" -v now="$now" -v bn="$batch_num" '
        BEGIN {
            printf "[{\"scenario\":\"crowdsec-blocklist-import/external_blocklist\","
            printf "\"scenario_hash\":\"\",\"scenario_version\":\"\","
            printf "\"message\":\"External blocklist import batch %s\",", bn
            printf "\"events_count\":1,"
            printf "\"start_at\":\"%s\",\"stop_at\":\"%s\",", now, now
            printf "\"capacity\":0,\"leakspeed\":\"0\",\"simulated\":false,"
            printf "\"events\":[],\"source\":{\"scope\":\"ip\",\"value\":\"127.0.0.1\"},"
            printf "\"decisions\":["
            first=1
        }
        NF {
            if (!first) printf ","
            printf "{\"origin\":\"cscli\",\"type\":\"ban\",\"scope\":\"ip\","
            printf "\"value\":\"%s\",\"duration\":\"%s\",",$0, dur
            printf "\"scenario\":\"crowdsec-blocklist-import/external_blocklist\"}"
            first=0
        }
        END {
            printf "]}]"
        }
    ' "$batch_file" > "$payload_file"

    local response
    response=$(curl -s -X POST "${url}/v1/alerts" \
        -H "Authorization: Bearer $LAPI_TOKEN" \
        -H "Content-Type: application/json" \
        -d @"$payload_file" \
        --max-time 120 2>&1)

    rm -f "$payload_file"

    # Check for success (response is array of alert IDs)
    if echo "$response" | grep -qE '^\['; then
        return 0
    else
        warn "Batch $batch_num: $response"
        return 1
    fi
}

# Import all IPs via LAPI in batches
lapi_import() {
    local ip_file="$1"
    local total=$(wc -l < "$ip_file")
    local imported=0
    local batch_num=0
    local failed=0

    while [ $imported -lt $total ]; do
        batch_num=$((batch_num + 1))
        local batch_file="$TEMP_DIR/batch_${batch_num}.txt"

        # Extract batch
        tail -n +$((imported + 1)) "$ip_file" | head -n "$LAPI_BATCH_SIZE" > "$batch_file"
        local batch_count=$(wc -l < "$batch_file")

        if lapi_import_batch "$batch_file" "$batch_num"; then
            debug "Batch $batch_num: $batch_count IPs imported"
        else
            ((failed++)) || true
        fi

        imported=$((imported + batch_count))
        rm -f "$batch_file"
    done

    if [ $failed -gt 0 ]; then
        warn "$failed batch(es) had errors"
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

# Main import logic
main() {
    info "========================================="
    info "CrowdSec Blocklist Import v$VERSION"
    info "========================================="
    info "Decision duration: $DECISION_DURATION"
    if [ -n "$MAX_DECISIONS" ] && [ "$MAX_DECISIONS" != "0" ] && [ "$MAX_DECISIONS" != "unlimited" ]; then
        info "Max decisions: $MAX_DECISIONS (set MAX_DECISIONS=0 to disable)"
    else
        warn "Max decisions: UNLIMITED (no cap — not recommended with embedded bouncers)"
    fi
    [ "$DRY_RUN" = "true" ] && info "DRY RUN MODE - no changes will be made"
    [ -n "$CUSTOM_BLOCKLISTS" ] && info "Custom blocklists: configured"
    [ -n "$DOCKER_API_VERSION" ] && info "Docker API version: $DOCKER_API_VERSION"
    [ -n "$CROWDSEC_LAPI_URL" ] && info "LAPI: $CROWDSEC_LAPI_URL"
    [ -n "$BOUNCER_SSH" ] && info "Device monitoring: $BOUNCER_SSH"

    # Show any disabled source overrides
    show_source_overrides

    setup_crowdsec

    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    rm -f *.txt *.list .stats 2>/dev/null || true

    # Initialize stats file
    touch "$TEMP_DIR/.stats"

    # Count enabled built-in sources
    local total_builtin=36
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

    # --- New Tier 1 High Priority Blocklists ---

    # AbuseIPDB 99% confidence (via borestad mirror)
    fetch_list "AbuseIPDB" \
        "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-1d.ipv4" \
        "abuseipdb.txt" \
        "grep -v '^#' | awk '{print \$1}'"

    # Cybercrime Tracker C2 (FireHOL mirror)
    fetch_list "Cybercrime Tracker" \
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset" \
        "cybercrime.txt" \
        "grep -v '^#'"

    # Monty Security C2 Tracker
    fetch_list "Monty Security C2" \
        "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt" \
        "monty_c2.txt" \
        "cat"

    # DShield Top Attackers
    fetch_list "DShield Top Attackers" \
        "https://feeds.dshield.org/top10-2.txt" \
        "dshield_top.txt" \
        "awk '{print \$1}' | grep -E '^[0-9]'"

    # VXVault Malware (FireHOL mirror)
    fetch_list "VXVault" \
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/vxvault.ipset" \
        "vxvault.txt" \
        "grep -v '^#'"

    # --- New Tier 2 Extended Coverage Blocklists ---

    # IPsum Level 4+ (higher confidence than existing level 3)
    fetch_list "IPsum level4" \
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt" \
        "ipsum4.txt" \
        "grep -v '^#' | awk '{print \$1}'"

    # Firehol Level 3 (extended 30-day coverage)
    fetch_list "Firehol level3" \
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset" \
        "firehol_l3.txt" \
        "grep -v '^#'"

    # Maltrail mass scanners
    fetch_list "Maltrail scanners" \
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt" \
        "maltrail_scanner.txt" \
        "grep -v '^#' | awk '{print \$1}'"

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
    elif [ "$MODE" = "lapi" ]; then
        info "Checking existing CrowdSec decisions via LAPI..."
        lapi_list_decisions > existing.txt 2>/dev/null || touch existing.txt
        existing_count=$(wc -l < existing.txt)
        debug "Found $existing_count existing decisions"
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

    # Guardrail 1: cap total decisions (hard limit)
    # MAX_DECISIONS=0 or "unlimited" disables the cap
    local max_decisions_active=true
    if [ -z "$MAX_DECISIONS" ] || [ "$MAX_DECISIONS" = "0" ] || [ "$MAX_DECISIONS" = "unlimited" ]; then
        max_decisions_active=false
    fi

    if [ "$max_decisions_active" = true ] && [ "$import_count" -gt 0 ]; then
        existing_total=$(wc -l < existing.txt)
        local projected_total=$((existing_total + import_count))
        headroom=$((MAX_DECISIONS - existing_total))
        if [ "$headroom" -le 0 ]; then
            warn "MAX_DECISIONS=$MAX_DECISIONS reached ($existing_total existing). Skipping import."
            import_count=0
            : > to_import.txt
        elif [ "$import_count" -gt "$headroom" ]; then
            warn "Capping import: $import_count new IPs would exceed MAX_DECISIONS=$MAX_DECISIONS ($existing_total existing + $import_count new = $projected_total)"
            head -n "$headroom" to_import.txt > to_import_capped.txt
            mv to_import_capped.txt to_import.txt
            import_count=$headroom
            info "Importing $import_count IPs (capped to stay within MAX_DECISIONS=$MAX_DECISIONS)"
        fi
    elif [ "$max_decisions_active" = false ] && [ "$import_count" -gt 0 ]; then
        # No cap set — warn if total exceeds common embedded device limits
        existing_total=$(wc -l < existing.txt)
        local projected_total=$((existing_total + import_count))
        if [ "$projected_total" -gt 65536 ]; then
            warn "No MAX_DECISIONS cap set. Projected total: $projected_total decisions."
            warn "This exceeds the default ipset maxelem (65536) on most embedded devices."
            warn "If using a UniFi/embedded bouncer, set MAX_DECISIONS to prevent crashes."
            warn "  UDM SE/Pro: MAX_DECISIONS=50000 | UDR: MAX_DECISIONS=15000 | USG: MAX_DECISIONS=8000"
        fi
    fi

    # Guardrail 2: query device memory (adaptive limit)
    if [ -n "$BOUNCER_SSH" ] && [ "$import_count" -gt 0 ]; then
        device_headroom=$(calculate_device_headroom)
        if [ -n "$device_headroom" ] && [ "$device_headroom" -ge 0 ]; then
            if [ "$device_headroom" -eq 0 ]; then
                warn "Device has no headroom. Skipping import."
                import_count=0
                : > to_import.txt
            elif [ "$import_count" -gt "$device_headroom" ]; then
                warn "Device headroom is $device_headroom entries — capping import (was $import_count)"
                head -n "$device_headroom" to_import.txt > to_import_capped.txt
                mv to_import_capped.txt to_import.txt
                import_count=$device_headroom
                info "Importing $import_count IPs (capped by device memory)"
            fi
        fi
    fi

    if [[ $import_count -eq 0 ]]; then
        info "No new IPs to import (all $total_ips IPs already in CrowdSec)"
    elif [ "$DRY_RUN" = "true" ]; then
        # Dry-run mode (closes #3)
        info "[DRY RUN] Would import $import_count new IPs into CrowdSec (total coverage: $total_ips IPs)"
        info "[DRY RUN] Decision duration would be: $DECISION_DURATION"
        info "[DRY RUN] No changes were made"
    elif [ "$MODE" = "lapi" ]; then
        info "Importing $import_count new IPs via LAPI..."
        lapi_import to_import.txt
        info "Import complete: $import_count IPs added (total coverage: $total_ips IPs)"
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

main "$@"
