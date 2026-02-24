# crowdsec-blocklist-import

**Real-time, deduplicated, normalized CrowdSec blocklists — instantly enforced across all your firewalls, CDNs, and network devices.**

[![Awesome CrowdSec](https://img.shields.io/badge/awesome-crowdsec-green?style=flat-square)](https://github.com/wolffcatskyy/awesome-crowdsec)
[![Version](https://img.shields.io/badge/version-3.5.0-blue?style=flat-square)](https://github.com/wolffcatskyy/crowdsec-blocklist-import)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![GHCR](https://img.shields.io/badge/GHCR-crowdsec--blocklist--import--python-blue?style=flat-square&logo=github)](https://github.com/wolffcatskyy/crowdsec-blocklist-import/pkgs/container/crowdsec-blocklist-import-python)

---

## Security Advisory

This is the official CrowdSec blocklist import tool maintained at [wolffcatskyy/crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import).

If you downloaded this from another source or a different GitHub user, you may be using an impostor repository with malicious code. Always verify you're using the official source.

---

## AI Disclosure

This project was developed with assistance from Claude AI. We disclose this transparently because you deserve to know how your security tools are built.

---

## Why IP Freshness Matters

Most blocklist tools suffer from a critical flaw: **staleness**. They fetch blocklists on a schedule, cache them, and enforce stale entries for days or weeks. By then, threat actors have rotated to new infrastructure, but your firewall still blocks addresses that were compromised weeks ago.

**crowdsec-blocklist-import solves this:**

- **Fresh IPs propagate instantly** — New threats from 24+ feeds hit your network within minutes, not days
- **Expired threats are removed immediately** — Recovered IPs are automatically delisted, not held for weeks
- **No cron delays** — Run hourly or on-demand without overhead
- **No stale drift** — Every sync is a complete refresh; no orphaned entries linger

This is the difference between reactive security (waiting for alerts) and **active threat intelligence** (staying ahead of attackers).

---

## Core Features

**Deduplication Engine** — Automatically detects IPs already in CrowdSec, eliminating redundant processing and API calls.

**Normalization Layer** — Strips comments, validates CIDR blocks, removes duplicates, enforces consistent formatting across all 24+ threat feeds.

**Real-Time Sync** — No caching, no delays. Every import is a complete refresh with live threat data.

**24+ Threat Feeds** — IPsum, Spamhaus, Blocklist.de, Firehol, Abuse.ch, Emerging Threats, Binary Defense, DShield, Talos, Tor nodes, scanner IPs, and more.

**Per-Feed Control** — Enable or disable individual blocklists via environment variables. Want just Spamhaus? Set `ENABLE_SPAMHAUS=true` and disable the rest.

**Allowlist Support** — Three-tier allowlist system: static IP lists, CIDR ranges, and provider-specific exceptions. Whitelist your ISP, CDN, or trusted partners.

**Built-in Scheduler** — Run as a long-lived daemon with `INTERVAL=3600` instead of managing cron or systemd timers. Graceful shutdown on SIGTERM/SIGINT.

**Webhook Notifications** — Get import results pushed to Discord, Slack, or any generic webhook endpoint.

**AbuseIPDB Direct API** — Query AbuseIPDB's blacklist API directly with your API key for higher-quality results than the community mirror.

**Prometheus Metrics** — Push metrics to Prometheus Pushgateway for monitoring imports, deduplication rates, and feed health.

---

## Quickstart

### 1. Prerequisites

You need CrowdSec running and LAPI credentials:

```bash
# Create machine credentials (for writing decisions)
cscli machines add blocklist-import --password 'SecurePassword123'

# Create bouncer key (for reading existing decisions)
cscli bouncers add blocklist-import -o raw
# Copy the output — you'll need it below
```

### 2. Docker Compose (Recommended)

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
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

Run it:

```bash
docker compose up -d
```

> **Note:** With `INTERVAL=3600`, the container runs as a long-lived daemon and repeats every hour. No cron or systemd timer needed. Set `INTERVAL=0` (default) for a single run.

### 3. One-Shot Mode (Cron/Timer)

If you prefer external scheduling, omit `INTERVAL` and use `restart: "no"`:

```bash
# Daily at 4am
0 4 * * * docker compose -f /path/to/compose.yml up --abort-on-container-exit
```

---

## Installation

### Docker (Fastest)

```bash
# One-liner using Docker run
docker run --rm --network crowdsec \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=YOUR_KEY \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=YourPassword \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
```

### pip (Requires Python 3.11+)

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials

python blocklist_import.py
```

### From Source

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import
docker build -t my-blocklist-import .
docker run --rm --network crowdsec -e ... my-blocklist-import
```

For detailed installation instructions, see [Configuration Reference](docs/config-reference.md).

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

### Common Settings

| Variable | Default | Purpose |
|----------|---------|---------|
| `DECISION_DURATION` | `24h` | How long imported decisions last |
| `BATCH_SIZE` | `1000` | IPs per batch (memory vs. speed tradeoff) |
| `DECISION_TYPE` | `ban` | Type of decision (ban, captcha, throttle) |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARN, ERROR |
| `DRY_RUN` | `false` | Preview without importing |
| `INTERVAL` | `0` | Daemon mode: seconds between runs (0 = once) |
| `WEBHOOK_URL` | *(none)* | Webhook URL for import notifications |
| `WEBHOOK_TYPE` | `generic` | Webhook format: `generic`, `discord`, `slack` |
| `ABUSEIPDB_API_KEY` | *(none)* | AbuseIPDB API key for direct blacklist query |
| `ABUSEIPDB_MIN_CONFIDENCE` | `90` | Minimum confidence score (1-100) |

### Selective Blocklists

Disable feeds you don't need:

```bash
ENABLE_IPSUM=true           # Keep aggregated threats
ENABLE_SPAMHAUS=true        # Keep Spamhaus
ENABLE_TOR=false            # Disable Tor (may cause false positives)
ENABLE_SCANNERS=false       # Disable scanner detection
```

All blocklists are enabled by default. See [Configuration Reference](docs/config-reference.md) for the full list.

### Allowlists

Protect trusted IPs from being blocked:

```bash
# Comma-separated IPs and/or CIDR ranges
ALLOWLIST="1.2.3.4,5.6.7.8,192.168.0.0/16,10.0.0.0/8"

# Auto-fetch GitHub IP ranges (covers git, web, api, hooks, actions)
ALLOWLIST_GITHUB=true
```

---

## Supported Blocklists

crowdsec-blocklist-import pulls from 24+ threat intelligence sources:

| Source | Purpose | Type |
|--------|---------|------|
| **IPsum** | Aggregated threat intel (IPs on 3+ blocklists) | Aggregated |
| **Spamhaus DROP/EDROP** | Known hijacked networks | Network blocks |
| **Blocklist.de** | SSH, web, mail attacks (all categories) | Attack vectors |
| **Firehol Level 1/2/3** | Malware, C2, compromised hosts | Malware |
| **Abuse.ch** | Feodo (banking malware), SSL blacklist, URLhaus | Malware |
| **Emerging Threats** | Compromised IP detection | Threats |
| **Binary Defense** | Malware, DoS, botnet IPs | Malware |
| **Bruteforce Blocker** | SSH/RDP brute force attacks | Attacks |
| **DShield** | Top attacking IPs (Internet Storm Center) | Threats |
| **CI Army** | Bad reputation hosts | Threats |
| **Abuse IPDB** | Reported malicious IPs | Threats |
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

```bash
python blocklist_import.py [options]

Options:
  -h, --help                Show help
  -v, --version             Show version and exit
  -n, --dry-run             Preview without importing
  -d, --debug               Enable debug logging
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
```

### Examples

Dry-run to see what would be imported:

```bash
python blocklist_import.py --dry-run
```

List all available sources:

```bash
python blocklist_import.py --list-sources
```

Import with custom settings:

```bash
python blocklist_import.py --duration 48h --batch-size 500
```

---

## Advanced Usage

### Custom Allowlist

Combine static IPs, CIDR ranges, and provider allowlists:

```bash
# Static IPs and CIDR ranges
ALLOWLIST="192.168.1.1,203.0.113.5,198.51.100.0/24"

# Auto-fetch GitHub IP ranges (git, web, api, hooks, actions)
ALLOWLIST_GITHUB=true
```

### Daemon Mode (Built-in Scheduler)

Run as a long-lived service instead of using cron:

```bash
# Run every hour
INTERVAL=3600

# Run every 30 minutes
INTERVAL=1800

# Skip the first run and wait for the interval
RUN_ON_START=false
```

The daemon handles SIGTERM/SIGINT gracefully — it finishes the current run, then exits. This makes it Docker-friendly with `restart: unless-stopped`.

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

Query the AbuseIPDB blacklist API directly for higher-quality results than the community mirror:

```bash
ABUSEIPDB_API_KEY=your_api_key_here
ABUSEIPDB_MIN_CONFIDENCE=90   # Only IPs with 90%+ confidence
ABUSEIPDB_LIMIT=10000         # Max IPs to fetch
```

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/). The free tier allows 5 blacklist checks per day.

> **Note:** The AbuseIPDB community mirror (via `ENABLE_ABUSE_IPDB`) is still fetched separately. The direct API provides more IPs with configurable confidence thresholds.

### Prometheus Metrics

Push metrics to Pushgateway:

```bash
METRICS_PUSHGATEWAY_URL=http://prometheus:9091
```

Metrics tracked:
- Total IPs imported
- Deduplicated entries
- Failed imports per source
- Import duration

### Docker with Custom Config

Mount your `.env` file:

```bash
docker run --rm \
  --network crowdsec \
  -v /path/to/.env:/app/.env:ro \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
```

### Scheduling with Systemd Timer

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

For more examples, see [Advanced Usage](docs/examples.md).

---

## Complete CrowdSec Suite

crowdsec-blocklist-import is part of a complete threat detection and enforcement stack:

| Tool | Purpose | Status |
|------|---------|--------|
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Import threat feeds into CrowdSec | Published |
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Enforce decisions on UniFi networks | Published |
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Parse UniFi logs into CrowdSec | Published |

Deploy all three for defense-in-depth: threat feeds → CrowdSec detection → UniFi enforcement.

---

## Troubleshooting

### CrowdSec Connection Failed

Check LAPI URL:

```bash
curl http://crowdsec:8080/health
```

Should return `200 OK`. If using Docker, ensure the container is on the same network:

```bash
docker network inspect crowdsec
```

### Authentication Error

Verify credentials:

```bash
# Test bouncer key
curl -H "X-Api-Key: YOUR_KEY" http://crowdsec:8080/decisions

# Test machine login
curl -X POST http://crowdsec:8080/watchers/login \
  -H "Content-Type: application/json" \
  -d '{"machine_id":"blocklist-import","password":"YourPassword"}'
```

### No IPs Imported

Check logs:

```bash
docker logs blocklist-import  # If running in Docker
python blocklist_import.py --debug  # For detailed output
```

Common causes:
- All blocklists disabled (check `ENABLE_*` variables)
- CrowdSec already has all IPs (check deduplication in logs)
- Network connectivity issue (check `curl https://example.com`)

### Memory Issues

Reduce batch size:

```bash
BATCH_SIZE=100  # Default is 1000
```

Or disable large feeds:

```bash
ENABLE_IPSUM=false  # IPsum is the largest feed
```

For more troubleshooting, see [FAQ](docs/faq.md).

---

## Technical Details

**Language:** Python 3.11+

**Architecture:** Single file, ~650 lines of production code

**Dependencies:** `requests`, `python-dotenv`, `prometheus-client`

**Memory:** ~50-100MB streaming processing (300k+ IPs)

**Speed:** 500-1000 IPs/second depending on network

**Docker Image:** `ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest` (~150MB)

**Authentication:** CrowdSec LAPI with machine credentials (JWT) + bouncer key for deduplication

**Database:** Direct LAPI HTTP API (no direct database access)

---

## Contributing

We welcome contributions. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Report bugs:** [GitHub Issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues)

**Suggest features:** [GitHub Discussions](https://github.com/wolffcatskyy/crowdsec-blocklist-import/discussions)

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Credits

**Maintained by** [wolffcatskyy](https://github.com/wolffcatskyy). Developed with assistance from Claude AI.

**Special Thanks:**
- [CrowdSec](https://www.crowdsec.net/) for the excellent threat detection platform
- The security community for maintaining public threat feeds
- [Awesome CrowdSec](https://github.com/wolffcatskyy/awesome-crowdsec) community

---

**Have questions?** Open an [issue](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues) or start a [discussion](https://github.com/wolffcatskyy/crowdsec-blocklist-import/discussions).

**Want to help?** Fork, improve, and submit a PR. We're always looking for better feed sources, optimization ideas, and platform support.
