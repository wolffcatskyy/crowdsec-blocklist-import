#!/bin/bash
# CrowdSec Blocklist Import
# Imports 28+ public threat feeds directly into CrowdSec

set -e

VERSION="1.0.5"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"
DECISION_DURATION="${DECISION_DURATION:-24h}"
TEMP_DIR="/tmp/blocklist-import"

# Fetch timeout in seconds (increase for slow connections)
FETCH_TIMEOUT="${FETCH_TIMEOUT:-60}"

# Mode: "docker" or "native" (auto-detected if not set)
MODE="${MODE:-auto}"

# Telemetry (enabled by default, set TELEMETRY_ENABLED=false to disable)
TELEMETRY_ENABLED="${TELEMETRY_ENABLED:-true}"
TELEMETRY_URL="https://bouncer-telemetry.ms2738.workers.dev/ping"

# Counters
SOURCES_OK=0
SOURCES_FAILED=0

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

    # Try native first (if cscli is in PATH and working)
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
    fi
}

# Fetch a blocklist
fetch_list() {
    local name="$1"
    local url="$2"
    local output="$3"
    local filter="${4:-cat}"

    debug "Fetching $name..."
    if curl -sL --max-time "$FETCH_TIMEOUT" "$url" 2>/dev/null | eval "$filter" > "$output"; then
        local count=$(wc -l < "$output" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            debug "$name: $count entries"
            ((SOURCES_OK++)) || true
        else
            debug "$name: empty response"
            ((SOURCES_FAILED++)) || true
        fi
    else
        debug "$name: unavailable (will retry next run)"
        touch "$output"
        ((SOURCES_FAILED++)) || true
    fi
}

# Main import logic
main() {
    info "CrowdSec Blocklist Import v$VERSION"
    info "Decision duration: $DECISION_DURATION"

    setup_crowdsec

    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    rm -f *.txt *.list 2>/dev/null || true

    info "Fetching from 28 blocklist sources..."

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
    cat << EOF > censys.txt
192.35.168.0/23
162.142.125.0/24
74.120.14.0/24
167.248.133.0/24
EOF
    ((SOURCES_OK++)) || true

    info "Sources: $SOURCES_OK successful, $SOURCES_FAILED unavailable (normal - public lists are sometimes down)"

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
    info "Checking existing CrowdSec decisions..."
    run_cscli decisions list 2>/dev/null | \
        awk -F'|' '{print $4}' | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        sort -u > existing.txt || touch existing.txt

    existing_count=$(wc -l < existing.txt)
    debug "Found $existing_count existing decisions"

    # Remove already-imported IPs
    comm -23 filtered_private.txt existing.txt > to_import.txt

    import_count=$(wc -l < to_import.txt)
    total_ips=$(wc -l < filtered_private.txt)

    if [[ $import_count -eq 0 ]]; then
        info "No new IPs to import (all $total_ips IPs already in CrowdSec)"
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
