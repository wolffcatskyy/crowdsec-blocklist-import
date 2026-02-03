# CrowdSec Blocklist Import

![Installs](https://img.shields.io/endpoint?url=https://bouncer-telemetry.ms2738.workers.dev/badge/blocklist-import)
![License](https://img.shields.io/github/license/wolffcatskyy/crowdsec-blocklist-import)
![Docker](https://img.shields.io/badge/docker-ready-blue)

**Get premium-level threat protection for FREE.** Import 60,000+ IPs from 28 public threat feeds directly into CrowdSec - no subscription required.

---

### We've Reinvented Contributing

Every issue in this repo is **AI-Ready** — structured with full context, file paths, implementation guides, acceptance criteria, and a ready-to-use AI prompt at the bottom.

**Pick an issue. Copy the prompt. Paste into your AI tool. Submit a PR.**

No codebase knowledge required. No onboarding docs to read. Just pick an issue and go.

[**Browse AI-Ready Issues →**](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready)

---

## Why Use This?

| | CrowdSec Free | CrowdSec Premium | **Free + This Tool** |
|---|:---:|:---:|:---:|
| Community Intel (CAPI) | ~15k IPs | 25k-100k+ IPs* | ~15k IPs |
| Premium Blocklists | ❌ | ✅ | ✅ **60k+ IPs** |
| Tor Exit Nodes | ❌ | ✅ | ✅ |
| Scanner Blocking | ❌ | ✅ | ✅ |
| All Your Bouncers | ✅ | ✅ | ✅ |
| **Monthly Cost** | **$0** | **$29+** | **$0** |

*Premium IPs vary based on enabled blocklists and scenarios; lists refresh every 5 minutes.

**How it works:** Import blocklists once into CrowdSec → All your bouncers automatically enforce them. One import, network-wide protection.

### When to Use This vs Premium

**This tool is ideal for:**
- 🏠 Homelabs and personal projects
- Learning and experimenting with threat intel
- Maximum coverage without subscription costs

**Consider CrowdSec Premium when:**
- 🏢 Business/production environments needing SLA support
- Concerns about false positives on VPN/proxy traffic
- Need curated, lower-noise blocklists
- Want the official 25k-100k+ threat feed with 5-minute updates

> *More feeds isn't always better for every use case.* For businesses, you may need to be careful about false positives, VPN traffic, or noisy sources. This tool is perfect for homelabs; evaluate your threat model for production use.

> **Have a UniFi router?** Use our companion tool **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** to sync these bans directly to your router's firewall - block threats at the network edge!

## Features

- **28+ Free Blocklists**: IPsum, Spamhaus, Firehol, Abuse.ch, Emerging Threats, and more
- **Smart Deduplication**: Skips IPs already in CrowdSec (CAPI, Console lists, local detections)
- **Private IP Filtering**: Automatically excludes RFC1918 and reserved ranges
- **Direct LAPI Mode** *(v2.0.0)*: Connect directly to CrowdSec's API — no Docker socket needed
- **Docker Ready**: Run as a container with Docker socket access
- **Cron Friendly**: Designed for daily runs with 24h decision expiration
- **Selective Sources** *(v1.1.0)*: Enable/disable individual blocklists via `ENABLE_<SOURCE>` env vars
- **Custom Blocklist URLs** *(v1.1.0)*: Import your own threat feeds via `CUSTOM_BLOCKLISTS`
- **Dry Run Mode** *(v1.1.0)*: Preview imports without making changes (`DRY_RUN=true`)
- **Per-Source Statistics** *(v1.1.0)*: Summary table showing IP counts from each source
- **Docker API Compatibility** *(v1.1.0)*: `DOCKER_API_VERSION` override for CLI/Engine version mismatches

## Included Blocklists

| Source | Description |
|--------|-------------|
| [IPsum](https://github.com/stamparm/ipsum) (level 3+) | Aggregated threat intel (on 3+ blocklists) |
| [Spamhaus](https://www.spamhaus.org/drop/) DROP/EDROP | Known hijacked/malicious netblocks |
| [Blocklist.de](https://www.blocklist.de/) | IPs reported for attacks (all/ssh/apache/mail) |
| [Firehol](https://github.com/firehol/blocklist-ipsets) level1 + level2 | High confidence bad IPs |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C2 servers |
| [SSL Blacklist](https://sslbl.abuse.ch/) | Malicious SSL certificate IPs |
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised IPs |
| [Binary Defense](https://www.binarydefense.com/) | Ban list |
| [Bruteforce Blocker](https://danger.rulez.sk/projects/bruteforceblocker/) | SSH/FTP brute force sources |
| [DShield](https://www.dshield.org/) | SANS Internet Storm Center top attackers |
| [CI Army](https://cinsscore.com/) | Cinsscore bad reputation |
| [Darklist](https://www.darklist.de/) | SSH brute force |
| [URLhaus](https://urlhaus.abuse.ch/) | Malware distribution IPs |
| [Talos Intelligence](https://www.talosintelligence.com/) | Cisco threat intel |
| [Charles Haley](https://charles.the-haleys.org/) | SSH dictionary attacks |
| [Botvrij](https://www.botvrij.eu/) | Botnet C2 IPs |
| [myip.ms](https://myip.ms/) | Blacklist database |
| [GreenSnow](https://blocklist.greensnow.co/) | Attacker IPs |
| [StopForumSpam](https://www.stopforumspam.com/) | Toxic spam IPs |
| [Tor Project](https://check.torproject.org/) + [dan.me.uk](https://www.dan.me.uk/torlist/) | Tor exit nodes |
| **Shodan scanners** | Known Shodan scanner IPs |
| [Censys](https://censys.io/) scanners | Censys scanner IP ranges |

## Quick Start

### LAPI Mode (Recommended — v2.0.0)

No Docker socket. No `cscli`. Just a URL and credentials.

```yaml
services:
  crowdsec-blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    container_name: crowdsec-blocklist-import
    restart: "no"
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_MACHINE_ID=blocklist-importer
      - CROWDSEC_MACHINE_PASSWORD=your_password_here
      - DECISION_DURATION=24h
      - TZ=America/New_York
```

**Setup:** On your CrowdSec host, register the machine:
```bash
cscli machines add blocklist-importer --password your_password_here
```

Then: `docker compose up`

### Docker Mode (Legacy)

```yaml
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
# LAPI mode (no socket needed)
docker run --rm \
  -e CROWDSEC_LAPI_URL=http://your-crowdsec:8080 \
  -e CROWDSEC_MACHINE_ID=blocklist-importer \
  -e CROWDSEC_MACHINE_PASSWORD=your_password \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest

# Docker mode (legacy)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CROWDSEC_CONTAINER=crowdsec \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

### Native Mode (No Docker)

Run directly on the host if `cscli` is in your PATH:

```bash
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/import.sh | bash
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MODE` | `auto` | `auto`, `lapi`, `native`, or `docker` - how to access CrowdSec |
| **LAPI mode** | | |
| `CROWDSEC_LAPI_URL` | _(empty)_ | CrowdSec LAPI URL (e.g., `http://crowdsec:8080`) |
| `CROWDSEC_MACHINE_ID` | _(empty)_ | Machine ID (from `cscli machines add`) |
| `CROWDSEC_MACHINE_PASSWORD` | _(empty)_ | Machine password |
| `LAPI_BATCH_SIZE` | `1000` | IPs per API request (reduce if hitting timeouts) |
| **Docker mode** | | |
| `CROWDSEC_CONTAINER` | `crowdsec` | Name of your CrowdSec container (case-sensitive!) |
| `DOCKER_API_VERSION` | _(auto)_ | Override Docker API version (set `1.43` for Docker CLI 24 + Engine 25+) |
| **General** | | |
| `DECISION_DURATION` | `24h` | How long decisions last (refresh daily) |
| `FETCH_TIMEOUT` | `60` | Timeout in seconds for fetching blocklists (increase for slow connections) |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARN, ERROR) |
| `TZ` | `UTC` | Timezone for logs |
| `TELEMETRY_ENABLED` | `true` | Anonymous usage stats (set false to disable) |
| `DRY_RUN` | `false` | Preview mode - shows what would be imported without making changes |
| `ENABLE_<SOURCE>` | `true` | Disable individual sources: `ENABLE_IPSUM=false`, `ENABLE_TOR_EXIT_NODES=false`, etc. |
| `CUSTOM_BLOCKLISTS` | _(empty)_ | Comma-separated URLs of additional blocklists to import |

> **Note:** Container names are case-sensitive! If your container is named `Crowdsec` (capital C), set `CROWDSEC_CONTAINER=Crowdsec`.

### Mode Selection

The script auto-detects how CrowdSec is running:

1. **LAPI** (preferred): Direct API connection — if `CROWDSEC_LAPI_URL` and machine credentials are set
2. **Native**: Uses `cscli` directly from PATH
3. **Docker**: Falls back to `docker exec`

Force a specific mode:
```bash
# LAPI mode (no Docker socket, no cscli needed)
MODE=lapi CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  CROWDSEC_MACHINE_ID=blocklist-importer \
  CROWDSEC_MACHINE_PASSWORD=mypass ./import.sh

# Native CrowdSec (installed on host)
MODE=native ./import.sh

# Docker CrowdSec
MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh
```

### Selective Blocklists (v1.1.0)

Control which sources are imported using `ENABLE_<SOURCE>` environment variables:

```bash
# Disable specific sources
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CROWDSEC_CONTAINER=crowdsec \
  -e ENABLE_TOR_EXIT_NODES=false \
  -e ENABLE_TOR_DAN_ME_UK=false \
  -e ENABLE_STOPFORUMSPAM=false \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

Source name mapping: `IPsum` → `ENABLE_IPSUM`, `Spamhaus DROP` → `ENABLE_SPAMHAUS_DROP`, `Blocklist.de all` → `ENABLE_BLOCKLIST_DE_ALL`, `Tor (dan.me.uk)` → `ENABLE_TOR_DAN_ME_UK`

### Custom Blocklists (v1.1.0)

```bash
-e CUSTOM_BLOCKLISTS="https://example.com/my-blocklist.txt,https://example.com/another.txt"
```

## Security

### Docker Socket Access

**The reality:** Docker socket access = root-equivalent access on the host. The `:ro` mount flag only prevents writing to the socket *file itself*, not API commands through it. Any container with socket access can run arbitrary containers, exec into others, etc.

**This is the same trust model as:** Portainer, Watchtower, Traefik, Nginx Proxy Manager, Dozzle, and dozens of other popular self-hosted tools that mount the Docker socket.

### Why Trust This Tool?

| Factor | This Tool |
|--------|-----------|
| **Code size** | ~600 lines of bash |
| **Audit time** | 15-20 minutes to read entirely |
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

**Use LAPI mode** (v2.0.0) — connects directly to CrowdSec's API. No Docker socket, no `cscli`, no `docker exec`. Just a URL and machine credentials. See [Quick Start](#quick-start).

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

**4. Docker API version mismatch** *(v1.1.0 fix)*
If you see errors like `Error response from daemon: client version X.XX is too new`, set:
```bash
-e DOCKER_API_VERSION=1.43
```

### "No new IPs to import"

This means all IPs from the blocklists are already in your CrowdSec decisions (from CAPI, console lists, or previous imports). This is normal on subsequent runs.

### Source Fetch Warnings

Some blocklists may be temporarily unavailable. The script will show:
```
Sources: 25 successful, 3 unavailable, 0 disabled
```

This is expected - public lists occasionally go offline. The script continues with available sources and will retry unavailable ones on the next run.

### Prerequisites

Before using this tool, you need:
1. **CrowdSec running** in a Docker container (or natively for direct mode)
2. **CrowdSec LAPI working** - verify with: `docker exec crowdsec cscli decisions list`
3. **Docker socket access** for Docker mode (or `cscli` in PATH for direct mode)

## Roadmap

- [x] **Per-feed enable/disable** (v1.1.0) - `ENABLE_<SOURCE>` env vars
- [x] **Custom feed URLs** (v1.1.0) - `CUSTOM_BLOCKLISTS` env var
- [x] **Dry run mode** (v1.1.0) - `DRY_RUN=true`
- [x] **Per-source statistics** (v1.1.0) - Summary table after each run
- [x] **Direct LAPI mode** (v2.0.0) - Import via HTTP API without Docker socket ([#9](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/9))
- [ ] **Prometheus metrics** ([#6](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/6)) - Export import statistics

## Related Projects

| Project | Description |
|---------|-------------|
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Run CrowdSec's native firewall bouncer on UniFi OS — 100k+ IPs, 15MB RAM, survives firmware updates |
| **[emby-playback-guardian](https://github.com/wolffcatskyy/emby-playback-guardian)** | Protect Emby/Jellyfin playback by pausing tasks during streaming |

## License

MIT License - see [LICENSE](LICENSE)
