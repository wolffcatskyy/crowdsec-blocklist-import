#!/bin/bash
# CrowdSec Blocklist Import — One-Line Installer
# Detects your CrowdSec instance, configures LAPI access, and starts importing.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/install.sh | bash
#
# Works with: Pangolin, Docker Compose, standalone Docker, native installs

set -euo pipefail

# Ensure standard paths are available (fixes: "sudo ./install.sh" not finding docker/cscli)
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/snap/bin:$PATH"

INSTALL_DIR="${INSTALL_DIR:-$HOME/.crowdsec-blocklist-import}"
IMAGE="ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest"
MACHINE_ID="blocklist-importer"
MACHINE_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
CRON_SCHEDULE="0 4 * * *"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}!${NC} $1"; }
err()   { echo -e "${RED}✗${NC} $1"; }
step()  { echo -e "\n${BLUE}${BOLD}$1${NC}"; }

banner() {
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   CrowdSec Blocklist Import Installer    ║"
    echo "  ║   60,000+ IPs from 28 free threat feeds  ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# --- Detection ---

detect_crowdsec() {
    step "Detecting CrowdSec..."

    # Check Docker is available
    if ! command -v docker &>/dev/null; then
        # Try native cscli
        if command -v cscli &>/dev/null && cscli version &>/dev/null 2>&1; then
            CS_MODE="native"
            info "Found native CrowdSec (cscli in PATH)"
            return 0
        fi
        err "Docker not found and cscli not in PATH."
        err "Install Docker or CrowdSec first."
        exit 1
    fi

    if ! docker ps &>/dev/null 2>&1; then
        err "Docker is installed but not running or not accessible."
        err "Start Docker or run this script with appropriate permissions."
        exit 1
    fi

    # Search for CrowdSec containers
    local containers
    containers=$(docker ps --format '{{.Names}}|{{.Image}}|{{.ID}}' 2>/dev/null)

    # Try common names first, then image-based detection
    local found_name="" found_id=""

    # Pass 1: exact name matches (covers Pangolin's "crowdsec", manual "crowdsec", etc.)
    for name in crowdsec CrowdSec crowdsec-1 crowdsec_crowdsec_1 pangolin-crowdsec-1 pangolin_crowdsec_1; do
        local match
        match=$(echo "$containers" | grep -i "^${name}|" | head -1) || true
        if [ -n "$match" ]; then
            found_name=$(echo "$match" | cut -d'|' -f1)
            found_id=$(echo "$match" | cut -d'|' -f3)
            break
        fi
    done

    # Pass 2: image name contains crowdsec
    if [ -z "$found_name" ]; then
        local match
        match=$(echo "$containers" | grep -i 'crowdsecurity/crowdsec\|crowdsec/crowdsec' | head -1) || true
        if [ -n "$match" ]; then
            found_name=$(echo "$match" | cut -d'|' -f1)
            found_id=$(echo "$match" | cut -d'|' -f3)
        fi
    fi

    # Pass 3: any container with cscli
    if [ -z "$found_name" ]; then
        for cname in $(docker ps --format '{{.Names}}'); do
            if docker exec "$cname" which cscli &>/dev/null 2>&1; then
                found_name="$cname"
                break
            fi
        done
    fi

    if [ -z "$found_name" ]; then
        err "No CrowdSec container found."
        echo ""
        echo "  Running containers:"
        docker ps --format '    {{.Names}} ({{.Image}})' 2>/dev/null
        echo ""
        echo "  If CrowdSec is running under a different name, set it manually:"
        echo "    CROWDSEC_CONTAINER=your_name curl -sL ... | bash"
        exit 1
    fi

    CS_CONTAINER="$found_name"
    info "Found CrowdSec container: ${BOLD}$CS_CONTAINER${NC}"

    # Verify cscli works
    if ! docker exec "$CS_CONTAINER" cscli version &>/dev/null 2>&1; then
        err "Container '$CS_CONTAINER' exists but cscli is not responding."
        err "Is CrowdSec fully started? Try: docker logs $CS_CONTAINER --tail 20"
        exit 1
    fi

    local cs_version
    cs_version=$(docker exec "$CS_CONTAINER" cscli version 2>/dev/null | head -1 || echo "unknown")
    info "CrowdSec version: $cs_version"

    # Detect the Docker network CrowdSec is on
    CS_NETWORKS=$(docker inspect "$CS_CONTAINER" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | xargs)
    info "Networks: $CS_NETWORKS"

    # Detect LAPI port
    CS_LAPI_PORT=$(docker exec "$CS_CONTAINER" sh -c 'grep -oP "listen_uri.*:\K[0-9]+" /etc/crowdsec/config.yaml 2>/dev/null || echo 8080')

    CS_MODE="docker"
    return 0
}

# --- Setup ---

setup_lapi_credentials() {
    step "Setting up LAPI credentials..."

    # Check if machine already exists
    if docker exec "$CS_CONTAINER" cscli machines list 2>/dev/null | grep -q "$MACHINE_ID"; then
        warn "Machine '$MACHINE_ID' already registered — removing and re-creating"
        docker exec "$CS_CONTAINER" cscli machines delete "$MACHINE_ID" &>/dev/null || true
    fi

    # Register machine
    if docker exec "$CS_CONTAINER" cscli machines add "$MACHINE_ID" --password "$MACHINE_PASS" --force &>/dev/null 2>&1; then
        info "Registered machine: $MACHINE_ID"
    else
        err "Failed to register machine. Try manually:"
        err "  docker exec $CS_CONTAINER cscli machines add $MACHINE_ID --password YOUR_PASSWORD"
        exit 1
    fi

    # Build LAPI URL (container name resolves on shared network)
    CS_LAPI_URL="http://${CS_CONTAINER}:${CS_LAPI_PORT}"
    info "LAPI URL: $CS_LAPI_URL"
}

setup_native() {
    step "Setting up native mode..."

    # Register machine for LAPI access
    if cscli machines list 2>/dev/null | grep -q "$MACHINE_ID"; then
        warn "Machine '$MACHINE_ID' already registered — removing and re-creating"
        cscli machines delete "$MACHINE_ID" &>/dev/null || true
    fi

    if cscli machines add "$MACHINE_ID" --password "$MACHINE_PASS" --force &>/dev/null 2>&1; then
        info "Registered machine: $MACHINE_ID"
    else
        err "Failed to register machine."
        exit 1
    fi

    # Detect local LAPI URL
    local lapi_url
    lapi_url=$(cscli config show 2>/dev/null | grep -oP 'url:\s*\K\S+' | head -1 || echo "http://127.0.0.1:8080")
    CS_LAPI_URL="$lapi_url"
    info "LAPI URL: $CS_LAPI_URL"
}

generate_compose() {
    step "Generating docker-compose.yml..."

    mkdir -p "$INSTALL_DIR"

    # Pick the first non-default network (prefer project networks over bridge/host)
    local ext_network=""
    for net in $CS_NETWORKS; do
        case "$net" in
            bridge|host|none) continue ;;
            *) ext_network="$net"; break ;;
        esac
    done

    # If only default networks, fall back to bridge and use container IP
    if [ -z "$ext_network" ]; then
        warn "CrowdSec is on default bridge network only"
        warn "Using host network mode for connectivity"
        cat > "$INSTALL_DIR/docker-compose.yml" << EOF
services:
  crowdsec-blocklist-import:
    image: ${IMAGE}
    container_name: crowdsec-blocklist-import
    restart: "no"
    network_mode: host
    environment:
      - CROWDSEC_LAPI_URL=${CS_LAPI_URL}
      - CROWDSEC_MACHINE_ID=${MACHINE_ID}
      - CROWDSEC_MACHINE_PASSWORD=${MACHINE_PASS}
      - DECISION_DURATION=24h
      - TZ=${TZ:-UTC}
EOF
    else
        info "Using network: ${BOLD}$ext_network${NC}"
        cat > "$INSTALL_DIR/docker-compose.yml" << EOF
services:
  crowdsec-blocklist-import:
    image: ${IMAGE}
    container_name: crowdsec-blocklist-import
    restart: "no"
    networks:
      - crowdsec_net
    environment:
      - CROWDSEC_LAPI_URL=${CS_LAPI_URL}
      - CROWDSEC_MACHINE_ID=${MACHINE_ID}
      - CROWDSEC_MACHINE_PASSWORD=${MACHINE_PASS}
      - DECISION_DURATION=24h
      - TZ=${TZ:-UTC}

networks:
  crowdsec_net:
    external: true
    name: ${ext_network}
EOF
    fi

    info "Wrote $INSTALL_DIR/docker-compose.yml"
}

test_run() {
    step "Running first import..."

    if ! docker compose -f "$INSTALL_DIR/docker-compose.yml" pull 2>/dev/null; then
        docker pull "$IMAGE" 2>/dev/null || true
    fi

    # Run with output visible
    if docker compose -f "$INSTALL_DIR/docker-compose.yml" up --abort-on-container-exit 2>&1; then
        info "First import completed successfully!"
        return 0
    else
        warn "First run had issues — check output above"
        warn "Common fixes:"
        warn "  1. Verify CrowdSec is fully started: docker logs $CS_CONTAINER --tail 10"
        warn "  2. Check network connectivity between containers"
        warn "  3. Try running manually: docker compose -f $INSTALL_DIR/docker-compose.yml up"
        return 1
    fi
}

setup_cron() {
    step "Setting up daily schedule..."

    local cron_cmd="docker compose -f $INSTALL_DIR/docker-compose.yml up --abort-on-container-exit > /dev/null 2>&1"

    # Check if already in crontab
    if crontab -l 2>/dev/null | grep -qF "crowdsec-blocklist-import"; then
        warn "Cron entry already exists — skipping"
        return
    fi

    echo ""
    echo "  Add daily cron job (runs at 4 AM)?"
    echo "    $CRON_SCHEDULE $cron_cmd"
    echo ""
    read -rp "  Add to crontab? [Y/n] " answer
    answer="${answer:-Y}"

    if [[ "$answer" =~ ^[Yy] ]]; then
        (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE $cron_cmd # crowdsec-blocklist-import") | crontab -
        info "Cron job added — blocklists will refresh daily at 4 AM"
    else
        info "Skipped. Run manually anytime with:"
        echo "    docker compose -f $INSTALL_DIR/docker-compose.yml up --abort-on-container-exit"
    fi
}

show_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Installation complete!${NC}"
    echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════${NC}"
    echo ""
    echo "  Config:    $INSTALL_DIR/docker-compose.yml"
    echo "  Mode:      LAPI (direct API, no Docker socket needed)"
    echo "  LAPI URL:  $CS_LAPI_URL"
    echo "  Network:   $CS_NETWORKS"
    echo ""
    echo "  Commands:"
    echo "    Run now:      docker compose -f $INSTALL_DIR/docker-compose.yml up"
    echo "    Dry run:      DRY_RUN=true docker compose -f $INSTALL_DIR/docker-compose.yml up"
    echo "    Uninstall:    rm -rf $INSTALL_DIR && docker exec $CS_CONTAINER cscli machines delete $MACHINE_ID"
    echo ""
    echo "  Docs: https://github.com/wolffcatskyy/crowdsec-blocklist-import"
    echo ""
}

# --- Main ---

banner

# Allow overriding container name
CS_CONTAINER="${CROWDSEC_CONTAINER:-}"
CS_MODE=""
CS_NETWORKS=""
CS_LAPI_URL=""
CS_LAPI_PORT="8080"

detect_crowdsec

if [ "$CS_MODE" = "native" ]; then
    setup_native
    # Native mode: just run import.sh directly
    info "For native installs, run directly:"
    echo "  curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/import.sh | \\"
    echo "    CROWDSEC_LAPI_URL=$CS_LAPI_URL CROWDSEC_MACHINE_ID=$MACHINE_ID CROWDSEC_MACHINE_PASSWORD=$MACHINE_PASS bash"
    exit 0
fi

setup_lapi_credentials
generate_compose
test_run
setup_cron
show_summary
