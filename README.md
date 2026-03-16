# crowdsec-blocklist-import

**Import 28+ threat intelligence feeds into CrowdSec with automatic deduplication, normalization, and real-time sync.**

[![GitHub Stars](https://img.shields.io/github/stars/wolffcatskyy/crowdsec-blocklist-import?style=flat-square&logo=github)](https://github.com/wolffcatskyy/crowdsec-blocklist-import/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/wolffcatskyy/crowdsec-blocklist-import/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/wolffcatskyy/crowdsec-blocklist-import/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/wolffcatskyy/crowdsec-blocklist-import?style=flat-square&label=release)](https://github.com/wolffcatskyy/crowdsec-blocklist-import/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![GHCR](https://img.shields.io/badge/GHCR-container-blue?style=flat-square&logo=github)](https://github.com/wolffcatskyy/crowdsec-blocklist-import/pkgs/container/crowdsec-blocklist-import)
[![Awesome CrowdSec](https://img.shields.io/badge/awesome-crowdsec-green?style=flat-square)](https://github.com/wolffcatskyy/awesome-crowdsec)

```
  Threat Feeds (28+)          crowdsec-blocklist-import           CrowdSec LAPI
 ┌──────────────────┐        ┌────────────────────────┐        ┌──────────────┐
 │ IPsum            │───────>│  Fetch & Normalize     │        │              │
 │ Spamhaus DROP    │───────>│  Deduplicate vs LAPI   │───────>│  Decisions   │──> Bouncers
 │ Firehol L1/L2/L3 │───────>│  Batch Import          │        │  Database    │    (fw, CDN,
 │ Abuse.ch Feodo   │───────>│  Allowlist Filtering   │        │              │     nginx...)
 │ 24 more feeds... │───────>│  Webhook + Metrics     │        └──────────────┘
 └──────────────────┘        └────────────────────────┘
```

---

**Table of Contents:**
[Why This Tool](#why-ip-freshness-matters) | [Features](#core-features) | [Quickstart](#quickstart) | [Installation](#installation) | [Configuration](#configuration) | [Blocklists](#supported-blocklists) | [CLI Usage](#cli-usage) | [Advanced Usage](#advanced-usage) | [Monitoring](#monitoring) | [Troubleshooting](#troubleshooting) | [Contributing](#contributing)

---

## Why IP Freshness Matters

Most blocklist tools suffer from a critical flaw: **staleness**. They fetch blocklists on a schedule, cache them, and enforce stale entries for days or weeks. By then, threat actors have rotated to new infrastructure, but your firewall still blocks addresses that were compromised weeks ago.

**crowdsec-blocklist-import solves this:**

- **Fresh IPs propagate instantly** -- New threats from 28+ feeds hit your network within minutes, not days
- **Expired threats are removed immediately** -- Recovered IPs are automatically delisted, not held for weeks
- **No cron delays** -- Run hourly or on-demand via built-in scheduler
- **No stale drift** -- Every sync is a complete refresh; no orphaned entries linger

This is the difference between reactive security (waiting for alerts) and **active threat intelligence** (staying ahead of attackers).

---

## Core Features

- **Deduplication Engine** -- Detects IPs already in CrowdSec, eliminating redundant processing and API calls
- **Normalization Layer** -- Strips comments, validates CIDR blocks, removes duplicates, enforces consistent formatting across all feeds
- **Real-Time Sync** -- No caching, no delays. Every import is a complete refresh with live threat data
- **28+ Threat Feeds** -- IPsum, Spamhaus, Blocklist.de, Firehol, Abuse.ch, Emerging Threats, Binary Defense, DShield, Talos, Tor nodes, scanner IPs, and more
- **Per-Feed Control** -- Enable or disable individual blocklists via environment variables
- **Allowlist Support** -- Three-tier system: static IP lists, CIDR ranges, and provider-specific exceptions (GitHub IPs)
- **Built-in Scheduler** -- Long-lived daemon mode with `INTERVAL=3600`. Graceful SIGTERM/SIGINT shutdown
- **Webhook Notifications** -- Push import results to Discord, Slack, or any generic webhook endpoint
- **AbuseIPDB Integration** -- Public mirror (no key needed) plus optional direct API for higher rate limits and fresher data
- **Prometheus Metrics** -- Push to Pushgateway for monitoring imports, deduplication rates, and feed health
- **Grafana Dashboard** -- Pre-built [dashboard](grafana-dashboard.json) for visualizing import metrics
- **Docker Secrets** -- All credential variables support `_FILE` suffix for mounted secret files
- **Consolidated Alerts** -- Optionally batch all IPs into a single alert per run to save CrowdSec alert quota

---

## Quickstart

### 1. Prerequisites

You need CrowdSec running with LAPI credentials:

```bash
# Create machine credentials (for writing decisions)
cscli machines add blocklist-import --password 'SecurePassword123'

# Create bouncer key (for reading existing decisions)
cscli bouncers add blocklist-import -o raw
# Save the output -- you'll need it below
```

### 2. Docker Compose (Recommended)

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    restart: unless-stopped
    networks:
      - crowdsec
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY=YOUR_BOUNCER_KEY
      - CROWDSEC_MACHINE_ID=blocklist-import
      - CROWDSEC_MACHINE_PASSWORD=SecurePassword123
      - DECISION_DURATION=24h
      - INTERVAL=3600           # Run every hour (built-in scheduler)
      - LOG_LEVEL=INFO

networks:
  crowdsec:
    external: true
```

```bash
docker compose up -d
```

With `INTERVAL=3600`, the container runs as a long-lived daemon and repeats every hour. No cron or systemd timer needed. Set `INTERVAL=0` (default) for a single run.

### 3. One-Shot Mode (Cron/Timer)

If you prefer external scheduling, omit `INTERVAL` and use `restart: "no"`:

```bash
# Daily at 4am
0 4 * * * docker compose -f /path/to/compose.yml up --abort-on-container-exit
```

---

## Installation

### Docker (Recommended)

```bash
docker run --rm --network crowdsec \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=YOUR_KEY \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=YourPassword \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

### Homebrew (macOS/Linux)

```bash
brew tap wolffcatskyy/crowdsec
brew install crowdsec-blocklist-import
```

### pip (Python 3.9+)

```bash
pip install git+https://github.com/wolffcatskyy/crowdsec-blocklist-import.git

cp .env.example .env
# Edit .env with your credentials

crowdsec-blocklist-import
```

### From Source

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials

python blocklist_import.py
```

### Build Docker Image Locally

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import
docker build -t crowdsec-blocklist-import .
docker run --rm --network crowdsec -e ... crowdsec-blocklist-import
```

For detailed configuration options, see [Configuration Reference](docs/config-reference.md).

---

## Configuration

### Minimal Setup

Edit `.env` with your CrowdSec credentials:

```bash
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=your_bouncer_key
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=your_password
DECISION_DURATION=24h
```

All credential variables support Docker Secrets via `_FILE` suffix (e.g., `CROWDSEC_LAPI_KEY_FILE=/run/secrets/lapi_key`).

### Common Settings

| Variable | Default | Purpose |
|----------|---------|---------|
| `DECISION_DURATION` | `24h` | How long imported decisions last |
| `BATCH_SIZE` | `1000` | IPs per batch (memory vs. speed tradeoff) |
| `DECISION_TYPE` | `ban` | Type of decision (`ban`, `captcha`, `throttle`) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `DRY_RUN` | `false` | Preview without importing |
| `INTERVAL` | `0` | Daemon mode: seconds between runs (0 = single run) |
| `CONSOLIDATE_ALERTS` | `false` | Batch all IPs into one alert per run (saves alert quota) |

### Notification Settings

| Variable | Default | Purpose |
|----------|---------|---------|
| `WEBHOOK_URL` | *(none)* | Webhook URL for import notifications |
| `WEBHOOK_TYPE` | `generic` | Webhook format: `generic`, `discord`, `slack` |

### AbuseIPDB

`ENABLE_ABUSE_IPDB=true` fetches the **public mirror** maintained by [@borestad](https://github.com/borestad/blocklist-abuseipdb) — no API key required.

For higher rate limits and fresher data, you can optionally configure a **direct API key**:

| Variable | Default | Purpose |
|----------|---------|---------|
| `ABUSEIPDB_API_KEY` | *(none)* | Optional: direct API key for higher rate limits |
| `ABUSEIPDB_API_KEY_FILE` | *(none)* | Optional: API key file path (Docker Secrets) |
| `ABUSEIPDB_MIN_CONFIDENCE` | `90` | Minimum confidence score (1-100) |
| `ABUSEIPDB_LIMIT` | `10000` | Max IPs to fetch per direct API query |

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/). The free tier allows 5 blacklist checks per day.

### Selective Blocklists

All blocklists are enabled by default. Disable feeds you don't need:

```bash
ENABLE_IPSUM=true           # Aggregated threats (recommended)
ENABLE_SPAMHAUS=true        # Spamhaus DROP
ENABLE_TOR=false            # Tor exit nodes (may cause false positives)
ENABLE_SCANNERS=false       # Shodan/Censys scanners
```

See [Configuration Reference](docs/config-reference.md) for the full list of `ENABLE_*` variables.

### Allowlists

Protect trusted IPs from being blocked:

```bash
# Comma-separated IPs and/or CIDR ranges
ALLOWLIST="1.2.3.4,5.6.7.8,192.168.0.0/16,10.0.0.0/8"

# Auto-fetch GitHub IP ranges (git, web, api, hooks, actions)
ALLOWLIST_GITHUB=true
```

---

## Supported Blocklists

crowdsec-blocklist-import pulls from 28+ threat intelligence sources:

| Source | Purpose | Type |
|--------|---------|------|
| **IPsum** | Aggregated threat intel (IPs on 3+ blocklists) | Aggregated |
| **Spamhaus DROP** | Known hijacked networks | Network blocks |
| **Blocklist.de** | SSH, web, mail attacks (all categories) | Attack vectors |
| **Firehol Level 1/2/3** | Malware, C2, compromised hosts | Malware |
| **Abuse.ch** | Feodo (banking malware), SSL blacklist, URLhaus | Malware |
| **Emerging Threats** | Compromised IP detection | Threats |
| **Binary Defense** | Malware, DoS, botnet IPs | Malware |
| **Bruteforce Blocker** | SSH/RDP brute force attacks | Attacks |
| **DShield** | Top attacking IPs (Internet Storm Center) | Threats |
| **CI Army** | Bad reputation hosts | Threats |
| **AbuseIPDB** | Reported malicious IPs (public mirror; direct API optional) | Threats |
| **Cybercrime Tracker** | Cybercrime infrastructure | Malware |
| **Monty Security C2** | Command and control servers | Malware |
| **VX Vault** | Malware hosting IPs | Malware |
| **Botvrij** | Botnet C2 servers | Malware |
| **GreenSnow** | Attacker IPs | Threats |
| **StopForumSpam** | Forum spam sources | Spam |
| **Tor Exit Nodes** | Tor network exit points | Privacy |
| **Scanner IPs** | Shodan, Censys, Internet scanners | Scanners |

For a complete list with URLs and threat types, see [Examples](docs/examples.md).

---

## CLI Usage

```
python blocklist_import.py [options]

Options:
  -h, --help                Show help
  -v, --version             Show version and exit
  -n, --dry-run             Preview without importing
  -d, --debug               Enable debug logging
  --setup                   Launch interactive setup wizard
  --lapi-url URL            Override LAPI URL
  --lapi-key KEY            Override LAPI key
  --duration DURATION       Override decision duration
  --batch-size SIZE         Override batch size
  --list-sources            List all available blocklist sources
  --validate                Validate configuration and exit
  --pushgateway-url URL     Override Prometheus Pushgateway URL
  --no-metrics              Disable Prometheus metrics for this run
  --interval SECONDS        Daemon mode: repeat every N seconds
  --webhook-url URL         Webhook URL for notifications
  --webhook-type TYPE       Webhook format: generic, discord, slack
  --mode MODE               Filter blocklist sources regarding rate-limiting: all, frequent, limited
```

### Examples

```bash
# Launch interactive setup wizard
python blocklist_import.py --setup

# Dry-run to see what would be imported
python blocklist_import.py --dry-run

# List all available sources
python blocklist_import.py --list-sources

# Import with custom duration and batch size
python blocklist_import.py --duration 48h --batch-size 500

# Validate configuration without running
python blocklist_import.py --validate
```

---

## Advanced Usage

### Daemon Mode (Built-in Scheduler)

Run as a long-lived service instead of using cron:

```bash
INTERVAL=3600         # Run every hour
RUN_ON_START=false    # Skip the first run and wait for the interval
```

The daemon handles SIGTERM/SIGINT gracefully -- it finishes the current run, then exits. This makes it Docker-friendly with `restart: unless-stopped`.

### Webhook Notifications

Get notified after each import run:

```bash
# Discord
WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK
WEBHOOK_TYPE=discord

# Slack
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
WEBHOOK_TYPE=slack

# Generic JSON POST
WEBHOOK_URL=https://your-endpoint.example.com/webhook
WEBHOOK_TYPE=generic
```

### AbuseIPDB Direct API

By default, `ENABLE_ABUSE_IPDB=true` fetches the **public mirror** (no API key needed). To use the direct API for higher rate limits and fresher data:

```bash
ABUSEIPDB_API_KEY=your_api_key_here
# or ABUSEIPDB_API_KEY_FILE=your_api_key_file_path_here
ABUSEIPDB_MIN_CONFIDENCE=90   # Only IPs with 90%+ confidence
ABUSEIPDB_LIMIT=10000         # Max IPs to fetch
```

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/). The free tier allows 5 blacklist checks per day.

> **Note:** The public mirror (via `ENABLE_ABUSE_IPDB`) and the direct API are complementary. When an API key is configured, both sources are queried and deduplicated.

### Docker Secrets

All credential variables support the `_FILE` suffix for Docker Secrets:

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    environment:
      - CROWDSEC_LAPI_KEY_FILE=/run/secrets/lapi_key
      - CROWDSEC_MACHINE_PASSWORD_FILE=/run/secrets/machine_password
    secrets:
      - lapi_key
      - machine_password

secrets:
  lapi_key:
    file: ./secrets/lapi_key.txt
  machine_password:
    file: ./secrets/machine_password.txt
```

### Docker with Custom Config

Mount your `.env` file:

```bash
docker run --rm \
  --network crowdsec \
  -v /path/to/.env:/app/.env:ro \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

### Scheduling with Systemd Timer

<details>
<summary>Systemd service and timer unit files</summary>

Create `/etc/systemd/system/blocklist-import.service`:

```ini
[Unit]
Description=CrowdSec Blocklist Import
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=docker compose -f /opt/compose/blocklist-import.yml up --abort-on-container-exit
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/blocklist-import.timer`:

```ini
[Unit]
Description=CrowdSec Blocklist Import Timer
Requires=blocklist-import.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
AccuracySec=1min

[Install]
WantedBy=timers.target
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now blocklist-import.timer
```

</details>

For more examples, see [Advanced Usage](docs/examples.md).

---

## Monitoring

### Prometheus Metrics

Push metrics to Prometheus Pushgateway:

```bash
METRICS_PUSHGATEWAY_URL=http://prometheus:9091
```

Metrics tracked:
- Total IPs imported per source
- Deduplicated entries skipped
- Failed imports per source
- Import duration per run

### Grafana Dashboard

A pre-built Grafana dashboard is included at [`grafana-dashboard.json`](grafana-dashboard.json). Import it into Grafana to visualize import activity, deduplication rates, and feed health over time.

---

## Part of the CrowdSec UniFi Ecosystem

crowdsec-blocklist-import works great with any CrowdSec setup. It also pairs perfectly with the UniFi-specific projects below for a complete detect → decide → enforce stack on UniFi hardware:

| Project | Description |
|---------|-------------|
| [crowdsec-unifi-suite](https://github.com/wolffcatskyy/crowdsec-unifi-suite) | One-command installer for the full stack |
| [crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) | Enforce CrowdSec decisions on UniFi firewalls |
| [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) | Parse UniFi firewall logs for CrowdSec |

---

## Troubleshooting

### CrowdSec Connection Failed

```bash
# Verify LAPI is reachable
curl http://crowdsec:8080/health

# If using Docker, ensure containers share a network
docker network inspect crowdsec
```

### Authentication Error

```bash
# Test bouncer key
curl -H "X-Api-Key: YOUR_KEY" http://crowdsec:8080/decisions

# Test machine login
curl -X POST http://crowdsec:8080/watchers/login \
  -H "Content-Type: application/json" \
  -d '{"machine_id":"blocklist-import","password":"YourPassword"}'
```

### No IPs Imported

```bash
docker logs blocklist-import        # Docker logs
python blocklist_import.py --debug  # Detailed output
```

Common causes:
- All blocklists disabled (check `ENABLE_*` variables)
- CrowdSec already has all IPs (check deduplication count in logs)
- Network connectivity issue (check `curl https://example.com`)

### Memory Issues

```bash
BATCH_SIZE=100          # Reduce from default 1000
ENABLE_IPSUM=false      # IPsum is the largest feed
```

For more troubleshooting, see [FAQ](docs/faq.md).

---

## Technical Details

| Attribute | Value |
|-----------|-------|
| **Language** | Python 3.9+ |
| **Architecture** | Single-file, ~650 lines of production code |
| **Dependencies** | `requests`, `python-dotenv` (+ optional `prometheus-client`) |
| **Memory** | ~50-100 MB streaming processing (300k+ IPs) |
| **Speed** | 500-1000 IPs/second depending on network and LAPI |
| **Docker Image** | `ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest` (~150 MB) |
| **Auth** | CrowdSec LAPI machine credentials (JWT) + bouncer key |

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- **Report bugs:** [GitHub Issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues)
- **Suggest features:** [GitHub Discussions](https://github.com/wolffcatskyy/crowdsec-blocklist-import/discussions)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)
- **Roadmap:** [ROADMAP.md](ROADMAP.md)

---

## License

MIT License -- See [LICENSE](LICENSE) for details.

---

## Credits

**Maintained by** [wolffcatskyy](https://github.com/wolffcatskyy). Developed with assistance from Claude AI.

**Contributors:** [gaelj](https://github.com/gaelj)

**Special Thanks:**
- [CrowdSec](https://www.crowdsec.net/) for the threat detection platform
- The security community for maintaining public threat feeds
- [Awesome CrowdSec](https://github.com/wolffcatskyy/awesome-crowdsec) community

---

<details>
<summary>Security Advisory</summary>

This is the official CrowdSec blocklist import tool maintained at [wolffcatskyy/crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import). If you downloaded this from another source or a different GitHub user, you may be using an impostor repository. Always verify you're using the official source.

</details>
