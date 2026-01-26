# CrowdSec Blocklist Import

![Installs](https://img.shields.io/endpoint?url=https://bouncer-telemetry.ms2738.workers.dev/badge/blocklist-import)
![License](https://img.shields.io/github/license/wolffcatskyy/crowdsec-blocklist-import)
![Docker](https://img.shields.io/badge/docker-ready-blue)

**Get premium-level threat protection for FREE.** Import 60,000+ IPs from 28 public threat feeds directly into CrowdSec - no subscription required.

## Why Use This?

| | CrowdSec Free | CrowdSec Pro | **Free + This Tool** |
|---|:---:|:---:|:---:|
| Community Intel (CAPI) | ~22k IPs | ~22k IPs | ~22k IPs |
| Premium Blocklists | ❌ | ✅ | ✅ **60k+ IPs** |
| Tor Exit Nodes | ❌ | ✅ | ✅ |
| Scanner Blocking | ❌ | ✅ | ✅ |
| All Your Bouncers | ✅ | ✅ | ✅ |
| **Monthly Cost** | **$0** | **$50+** | **$0** |

**How it works:** Import blocklists once into CrowdSec → All your bouncers automatically enforce them. One import, network-wide protection.

> **Have a UniFi router?** Use our companion tool **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** to sync these bans directly to your router's firewall - block threats at the network edge!

## Features

- **28+ Free Blocklists**: IPsum, Spamhaus, Firehol, Abuse.ch, Emerging Threats, and more
- **Smart Deduplication**: Skips IPs already in CrowdSec (CAPI, Console lists, local detections)
- **Private IP Filtering**: Automatically excludes RFC1918 and reserved ranges
- **Docker Ready**: Run as a container with Docker socket access
- **Cron Friendly**: Designed for daily runs with 24h decision expiration

## Included Blocklists

| Source | Description |
|--------|-------------|
| IPsum (level 3+) | Aggregated threat intel (on 3+ blocklists) |
| Spamhaus DROP/EDROP | Known hijacked/malicious netblocks |
| Blocklist.de | IPs reported for attacks (all/ssh/apache/mail) |
| Firehol level1 + level2 | High confidence bad IPs |
| Feodo Tracker | Banking trojan C2 servers |
| SSL Blacklist | Malicious SSL certificate IPs |
| Emerging Threats | Compromised IPs |
| Binary Defense | Ban list |
| Bruteforce Blocker | SSH/FTP brute force sources |
| DShield | SANS Internet Storm Center top attackers |
| CI Army | Cinsscore bad reputation |
| Darklist | SSH brute force |
| URLhaus | Malware distribution IPs |
| Talos Intelligence | Cisco threat intel |
| Charles Haley | SSH dictionary attacks |
| Botvrij | Botnet C2 IPs |
| myip.ms | Blacklist database |
| GreenSnow | Attacker IPs |
| StopForumSpam | Toxic spam IPs |
| **Tor exit nodes** | Official Tor Project + dan.me.uk |
| **Shodan scanners** | Known Shodan scanner IPs |
| **Censys scanners** | Censys scanner IP ranges |

## Quick Start

### Docker Compose (Recommended)

```yaml
version: "3.8"

services:
  crowdsec-blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    container_name: crowdsec-blocklist-import
    restart: "no"
    environment:
      - CROWDSEC_CONTAINER=crowdsec
      - DECISION_DURATION=24h
      - TZ=America/New_York
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

Run once: `docker compose up`

### Scheduled via Cron (Host)

```bash
# Run daily at 4am to refresh blocklists
0 4 * * * docker compose -f /path/to/docker-compose.yml up --abort-on-container-exit
```

### Standalone Docker Run

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CROWDSEC_CONTAINER=crowdsec \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

### Direct Mode (No Docker Socket)

If you prefer not to mount the Docker socket, you can run the script directly on the host:

```bash
# Download and run directly (requires curl, cscli in PATH)
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/import.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import
./import.sh
```

**Note:** Direct mode requires CrowdSec installed natively (not in Docker) with `cscli` in your PATH.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MODE` | `auto` | `auto`, `native`, or `docker` - how to access CrowdSec |
| `CROWDSEC_CONTAINER` | `crowdsec` | Name of your CrowdSec container (Docker mode) |
| `DECISION_DURATION` | `24h` | How long decisions last (refresh daily) |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARN, ERROR) |
| `TZ` | `UTC` | Timezone for logs |
| `TELEMETRY_ENABLED` | `true` | Anonymous usage stats (set false to disable) |

### Mode Selection

The script auto-detects how CrowdSec is running:

1. **Native** (preferred if available): Uses `cscli` directly from PATH
2. **Docker**: Falls back to `docker exec` if native not found

Force a specific mode:
```bash
# Native CrowdSec (installed on host)
MODE=native ./import.sh

# Docker CrowdSec
MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh
```

## Security

### Docker Socket Access

**The reality:** Docker socket access = root-equivalent access on the host. The `:ro` mount flag only prevents writing to the socket *file itself*, not API commands through it. Any container with socket access can run arbitrary containers, exec into others, etc.

**This is the same trust model as:** Portainer, Watchtower, Traefik, Nginx Proxy Manager, Dozzle, and dozens of other popular self-hosted tools that mount the Docker socket.

### Why Trust This Tool?

| Factor | This Tool |
|--------|-----------|
| **Code size** | ~200 lines of bash |
| **Audit time** | 5-10 minutes to read entirely |
| **Persistence** | Runs once and exits immediately |
| **What it does** | Downloads text files, runs one `cscli` command |
| **Source** | 100% open source, inspect before running |

**The only Docker commands it runs:**
```bash
docker exec $CONTAINER cscli version          # Check CrowdSec exists
docker exec $CONTAINER cscli decisions list   # Get existing IPs
docker exec $CONTAINER cscli decisions import # Import new IPs
```

### Don't Want Socket Access?

**Option 1: Native mode** (CrowdSec on host, not Docker)
```bash
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/import.sh | bash
```

**Option 2: Run script directly on Docker host**
```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import
MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh
```

**Option 3: Coming soon** - Direct LAPI mode ([Issue #9](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/9)) will import via HTTP API with zero Docker access

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    ONE IMPORT = ALL BOUNCERS                    │
└─────────────────────────────────────────────────────────────────┘

     28 Free Blocklists ──► crowdsec-blocklist-import ──► CrowdSec
                                                              │
                    ┌─────────────────────────────────────────┤
                    │                    │                    │
                    ▼                    ▼                    ▼
              UniFi Firewall      NPM/Nginx WAF      Cloudflare Worker
              (router-level)      (reverse proxy)    (edge blocking)
                    │                    │                    │
                    └────────────────────┴────────────────────┘
                              Network-Wide Protection
```

1. **Fetch**: Downloads 28+ blocklists from public sources
2. **Combine**: Merges all IPs and removes duplicates
3. **Filter**: Excludes private ranges (10.x, 192.168.x, etc.)
4. **Dedupe**: Queries CrowdSec for existing decisions to avoid duplicates
5. **Import**: Bulk imports new IPs via `cscli decisions import`

## Viewing Imported Decisions

```bash
# Count imported decisions
docker exec crowdsec cscli decisions list | grep external_blocklist | wc -l

# List recent decisions
docker exec crowdsec cscli decisions list -l 20

# Remove all imported decisions (if needed)
docker exec crowdsec cscli decisions delete --all --reason external_blocklist
```

## Troubleshooting

### "Cannot access CrowdSec container"

The tool uses `docker exec` to run commands inside your CrowdSec container. Common issues:

**1. Wrong container name**
```bash
# Find your actual CrowdSec container name
docker ps --format '{{.Names}}' | grep -i crowdsec
```
If using Docker Compose, the name might be `projectname_crowdsec_1` or `projectname-crowdsec-1`.

**2. Docker socket not mounted**
Make sure you have `-v /var/run/docker.sock:/var/run/docker.sock:ro` in your docker run/compose.

**3. Different Docker host**
This tool must run on the same Docker host as CrowdSec. It cannot connect to remote Docker daemons.

### "No new IPs to import"

This means all IPs from the blocklists are already in your CrowdSec decisions (from CAPI, console lists, or previous imports). This is normal on subsequent runs.

### Source Fetch Warnings

Some blocklists may be temporarily unavailable. The script will show:
```
Sources: 25 successful, 3 unavailable (normal - public lists are sometimes down)
```

This is expected - public lists occasionally go offline. The script continues with available sources and will retry unavailable ones on the next run.

### Prerequisites

Before using this tool, you need:
1. **CrowdSec running** in a Docker container (or natively for direct mode)
2. **CrowdSec LAPI working** - verify with: `docker exec crowdsec cscli decisions list`
3. **Docker socket access** for Docker mode (or `cscli` in PATH for direct mode)

## Related Projects

| Project | Description |
|---------|-------------|
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Sync CrowdSec decisions to UniFi firewall groups |

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
