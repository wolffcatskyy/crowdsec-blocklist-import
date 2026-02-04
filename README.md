# CrowdSec Blocklist Import

---
**Note:** This project was developed with and is supported exclusively by AI. There is no human support — issues and PRs are triaged and responded to by AI agents. If AI-assisted software isn't for you, no hard feelings — but you might want to reconsider, since so is most of the software you already use.

---

![Installs](https://img.shields.io/endpoint?url=https://bouncer-telemetry.ms2738.workers.dev/badge/blocklist-import)
![License](https://img.shields.io/github/license/wolffcatskyy/crowdsec-blocklist-import)
![Docker](https://img.shields.io/badge/docker-ready-blue)

**Get premium-level threat protection for FREE.** Import 120,000+ IPs from 36 public threat feeds directly into CrowdSec - no subscription required.

> **New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs. It works like fail2ban but with crowd-sourced threat intelligence and a modern bouncer ecosystem. Install it, connect bouncers to your firewalls/proxies, and threats get blocked network-wide. Get started with the [official install guide](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/).

## Why Use This?

| | CrowdSec Free | CrowdSec Premium | **Free + This Tool** |
|---|:---:|:---:|:---:|
| Community Intel (CAPI) | ~15k IPs | 25k-100k+ IPs* | ~15k IPs |
| Premium Blocklists | ❌ | ✅ | ✅ **120k+ IPs** |
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

> **WARNING: Embedded device users (UniFi, pfSense, OPNsense)** — Importing all 120K+ IPs will crash the UniFi Network app and may make your router unresponsive. The default `MAX_DECISIONS=40000` cap prevents this. See [Firewall Bouncer Limits](#firewall-bouncer-limits--ipset-sizing) for per-device recommendations.

## Features

- **36+ Free Blocklists**: IPsum, Spamhaus, Firehol, Abuse.ch, AbuseIPDB, C2 Trackers, and more
- **Smart Deduplication**: Skips IPs already in CrowdSec (CAPI, Console lists, local detections)
- **Private IP Filtering**: Automatically excludes RFC1918 and reserved ranges
- **One-Line Installer** *(v2.1.0)*: Auto-detects CrowdSec and sets everything up
- **Direct LAPI Mode** *(v2.0.0)*: Connect directly to CrowdSec's API — no Docker socket needed
- **Cron Friendly**: Designed for daily runs with 24h decision expiration
- **Selective Sources** *(v1.1.0)*: Enable/disable individual blocklists via `ENABLE_<SOURCE>` env vars
- **Custom Blocklist URLs** *(v1.1.0)*: Import your own threat feeds via `CUSTOM_BLOCKLISTS`
- **Dry Run Mode** *(v1.1.0)*: Preview imports without making changes (`DRY_RUN=true`)
- **Per-Source Statistics** *(v1.1.0)*: Summary table showing IP counts from each source
- **Docker API Compatibility** *(v1.1.0)*: `DOCKER_API_VERSION` override for CLI/Engine version mismatches

## Included Blocklists

### Tier 1: High-Priority Threat Feeds

| Source | Description | IPs |
|--------|-------------|-----|
| **[AbuseIPDB](https://www.abuseipdb.com/)** (99% confidence) | Most reported IPs (updated daily) | ~74k |
| [IPsum](https://github.com/stamparm/ipsum) (level 3 + level 4) | Aggregated threat intel (on 3+ / 4+ blocklists) | ~23k |
| [Spamhaus](https://www.spamhaus.org/drop/) DROP/EDROP | Known hijacked/malicious netblocks | ~1k |
| [Blocklist.de](https://www.blocklist.de/) | IPs reported for attacks (all/ssh/apache/mail) | ~15k |
| [Firehol](https://github.com/firehol/blocklist-ipsets) (level 1-3) | High confidence bad IPs (1-day, 7-day, 30-day) | ~70k |
| **[Cybercrime Tracker](https://github.com/firehol/blocklist-ipsets)** C2 | Active C2 servers | ~200 |
| **[Monty Security C2](https://github.com/montysecurity/C2-Tracker)** | Command & Control tracker | ~2.5k |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C2 servers | ~300 |
| **[VXVault](https://github.com/firehol/blocklist-ipsets)** | Malware distribution IPs | ~60 |

### Tier 2: Brute Force & Attack Sources

| Source | Description | IPs |
|--------|-------------|-----|
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised IPs | ~3k |
| [Binary Defense](https://www.binarydefense.com/) | Ban list | ~5k |
| [Bruteforce Blocker](https://danger.rulez.sk/projects/bruteforceblocker/) | SSH/FTP brute force sources | ~10k |
| [DShield](https://www.dshield.org/) | SANS Internet Storm Center attackers | ~20k |
| **[DShield Top Attackers](https://feeds.dshield.org/)** | Top 10 most active attackers | ~20 |
| [CI Army](https://cinsscore.com/) | Cinsscore bad reputation | ~15k |
| [Darklist](https://www.darklist.de/) | SSH brute force | ~5k |
| [Charles Haley](https://charles.the-haleys.org/) | SSH dictionary attacks | ~500 |
| [GreenSnow](https://blocklist.greensnow.co/) | Attacker IPs | ~8k |

### Tier 3: Malware, Spam & Scanning

| Source | Description | IPs |
|--------|-------------|-----|
| [SSL Blacklist](https://sslbl.abuse.ch/) | Malicious SSL certificate IPs | deprecated |
| [URLhaus](https://urlhaus.abuse.ch/) | Malware distribution IPs | ~2k |
| [Talos Intelligence](https://www.talosintelligence.com/) | Cisco threat intel | ~500 |
| [Botvrij](https://www.botvrij.eu/) | Botnet C2 IPs | ~200 |
| [myip.ms](https://myip.ms/) | Blacklist database | ~3k |
| [StopForumSpam](https://www.stopforumspam.com/) | Toxic spam IPs | ~400k |
| **[Maltrail](https://github.com/stamparm/maltrail)** mass scanners | Research/malicious scanners | ~17k |

### Tier 4: Scanners & Research Networks

| Source | Description | IPs |
|--------|-------------|-----|
| [Tor Project](https://check.torproject.org/) + [dan.me.uk](https://www.dan.me.uk/torlist/) | Tor exit nodes | ~1.5k |
| [Shodan](https://www.shodan.io/) scanners | Known Shodan scanner IPs | ~60 |
| [Censys](https://censys.io/) scanners | Censys scanner IP ranges | 4 |

**Total: ~120,000 unique IPs** (after deduplication)

## Quick Start

### One-Line Install (Recommended)

Auto-detects your CrowdSec instance (works with Pangolin, Docker Compose, standalone, native):

```bash
curl -sL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-blocklist-import/main/install.sh | bash
```

The installer will:
1. Find your running CrowdSec container (any name, any network)
2. Create LAPI credentials automatically
3. Join the correct Docker network
4. Generate a `docker-compose.yml` in `~/.crowdsec-blocklist-import/`
5. Run the first import
6. Optionally set up a daily cron job

> **Pangolin users:** The installer auto-detects CrowdSec installed by the Pangolin installer script. No extra configuration needed.

### LAPI Mode (Manual — v2.0.0)

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
| `MAX_DECISIONS` | `40000` | Max total decisions to import. Prevents bouncer overload. Set `0` to disable. See [Firewall Bouncer Limits](#firewall-bouncer-limits--ipset-sizing). |
| `BOUNCER_SSH` | _(empty)_ | SSH target(s) for live device memory checks, e.g. `root@192.168.1.1`. Comma-separated for multiple devices. |
| `DEVICE_MEM_FLOOR` | `300000` | Minimum MemAvailable (kB) to preserve on monitored devices |
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

- ~600 lines of bash — fully auditable in minutes
- Runs once and exits (no persistent daemon)
- LAPI mode (default) needs only a URL and machine credentials — no Docker socket, no privileged access
- 100% open source — inspect before running

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    ONE IMPORT = ALL BOUNCERS                    │
└─────────────────────────────────────────────────────────────────┘

     36 Free Blocklists ──► crowdsec-blocklist-import ──► CrowdSec
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

1. **Fetch**: Downloads 36+ blocklists from public sources
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

## Firewall Bouncer Limits / ipset Sizing

**This section is critical if you use CrowdSec with a firewall bouncer on an embedded device** (UniFi Dream Machines, USGs, pfSense boxes, etc.).

### The Problem

When this tool imports 120K+ IPs into CrowdSec, the firewall bouncer pushes all of them into an `ipset` (or `nftset`) on the firewall device. Embedded devices have hard limits on how many entries their kernel can handle. Exceeding these limits **crashes the UniFi Network application**, making all routers appear offline and requiring manual recovery from the console. ([#21](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/21))

### Recommended `MAX_DECISIONS` by Device

| Device | ipset maxelem | Recommended `MAX_DECISIONS` | Notes |
|--------|:------------:|:--------------------------:|-------|
| **UDM SE / UDM Pro** | 120,000 | `50000` | Tested stable at 60K active entries |
| **UDM (base)** | 65,536 | `40000` (default) | Default kernel limit |
| **UDR** | 40,000 | `15000` | Tested stable at 20K entries |
| **USG-3P** | ~15,000 | `8000` | Estimate — lower CPU/RAM |
| **Linux server** | Unlimited | `0` (disables cap) | No practical limit |
| **pfSense / OPNsense** | Varies | Test your device | Check `pfctl -t` table limits |

> **Default: `MAX_DECISIONS=40000`** — safe for all tested UniFi devices. Override for your specific hardware.

### Configuration Examples

```yaml
# UDM SE — can handle more entries
environment:
  - MAX_DECISIONS=50000

# UDR — lower limit needed
environment:
  - MAX_DECISIONS=15000

# Linux server bouncer — no limit needed
environment:
  - MAX_DECISIONS=0
```

### Two-Layer Protection (Advanced)

For the safest setup, combine `MAX_DECISIONS` with live device monitoring via `BOUNCER_SSH`:

```yaml
environment:
  - MAX_DECISIONS=50000
  - BOUNCER_SSH=root@192.168.1.1
  - DEVICE_MEM_FLOOR=300000
```

This queries your device's actual memory and ipset state before importing, and caps the import to whatever headroom remains. The tightest constraint wins — if your device only has room for 5,000 more entries, that becomes the cap regardless of `MAX_DECISIONS`.

For multiple devices, comma-separate the SSH targets:
```yaml
  - BOUNCER_SSH=root@192.168.1.1,root@192.168.21.1
```

### Recovery: Network App Crash

If the UniFi Network app has already crashed from too many ipset entries:

```bash
# 1. SSH into your UDM
ssh root@192.168.1.1

# 2. Flush the ipset
ipset flush crowdsec-blacklists

# 3. Restart the Network app
unifi-os restart

# 4. On your CrowdSec host, delete the excess decisions
cscli decisions delete --scenario "crowdsec-blocklist-import/external_blocklist"
# Or from Docker:
docker exec crowdsec cscli decisions delete --scenario "crowdsec-blocklist-import/external_blocklist"

# 5. Re-run the importer with a safe MAX_DECISIONS value
MAX_DECISIONS=15000 docker compose up
```

## Troubleshooting

### "Cannot find CrowdSec"

```bash
# Find your CrowdSec container
docker ps --format '{{.Names}}' | grep -i crowdsec
```

If the name differs from `crowdsec`, set it explicitly:
```bash
-e CROWDSEC_CONTAINER=your_container_name
```

With Docker Compose, the name might be `projectname-crowdsec-1`.

### LAPI connection refused

Ensure the blocklist-import container shares a Docker network with CrowdSec:
```bash
docker inspect crowdsec --format '{{json .NetworkSettings.Networks}}'
```
Add that network as `external` in your compose file, or use the one-line installer which handles this automatically.

### "No new IPs to import"

All IPs from the blocklists are already in your CrowdSec decisions (from CAPI, console lists, or previous imports). This is normal on subsequent runs.

### Source Fetch Warnings

Some blocklists may be temporarily unavailable:
```
Sources: 25 successful, 3 unavailable, 0 disabled
```

This is expected — public lists occasionally go offline. The script continues with available sources and retries on the next run.

## Roadmap

- [x] **Per-feed enable/disable** (v1.1.0) - `ENABLE_<SOURCE>` env vars
- [x] **Custom feed URLs** (v1.1.0) - `CUSTOM_BLOCKLISTS` env var
- [x] **Dry run mode** (v1.1.0) - `DRY_RUN=true`
- [x] **Per-source statistics** (v1.1.0) - Summary table after each run
- [x] **Direct LAPI mode** (v2.0.0) - Import via HTTP API without Docker socket ([#9](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/9))
- [x] **One-line installer** (v2.1.0) - Auto-detect CrowdSec, configure LAPI, set up cron
- [x] **Decision cap** (v2.1.1) - `MAX_DECISIONS=40000` default prevents bouncer overload ([#21](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/21))
- [ ] **Prometheus metrics** ([#6](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/6)) - Export import statistics
- [ ] **Built-in scheduler** ([#5](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/5)) - Continuously running container with auto-refresh

## Related Projects

| Project | Description |
|---------|-------------|
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Get CrowdSec-parseable firewall logs from UniFi Dream Machines — detect port scans and brute force from your UDM/UDR |
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Run CrowdSec's native firewall bouncer on UniFi OS — 100k+ IPs, 15MB RAM, survives firmware updates |
| **[emby-playback-guardian](https://github.com/wolffcatskyy/emby-playback-guardian)** | Protect Emby/Jellyfin playback by pausing tasks during streaming |

> **Complete UniFi + CrowdSec suite:** Use all three UniFi projects together for a full detect → decide → enforce feedback loop. The **parser** gives CrowdSec visibility into your firewall, this tool feeds it **threat intelligence**, and the **bouncer** enforces bans at the network edge.

---

### We've Reinvented Contributing

Every issue in this repo is **AI-Ready** — structured with full context, file paths, implementation guides, acceptance criteria, and a ready-to-use AI prompt at the bottom.

**Pick an issue. Copy the prompt. Paste into your AI tool. Submit a PR.**

No codebase knowledge required. No onboarding docs to read. Just pick an issue and go.

[**Browse AI-Ready Issues →**](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready)

## License

MIT License - see [LICENSE](LICENSE)
