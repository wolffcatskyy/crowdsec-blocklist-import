# CrowdSec Blocklist Import - Python Edition

Memory-efficient Python 3.11+ implementation of [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) using the LAPI HTTP API directly.

## Features

- **LAPI Mode Only**: Direct HTTP API calls, no Docker socket needed
- **Memory Efficient**: Streaming downloads, line-by-line processing
- **Batch Processing**: Configurable batch size (default 1000 IPs)
- **Full IPv4/IPv6 Support**: Uses Python's `ipaddress` module
- **Automatic Deduplication**: Skips existing CrowdSec decisions
- **Retry Logic**: Exponential backoff for failed requests
- **Type Hints**: Full type annotations for IDE support
- **28+ Blocklists**: Same sources as the bash version
- **Per-feed Control**: Enable/disable individual blocklist sources

## Quick Start

### Prerequisites

CrowdSec LAPI requires **machine credentials** to write decisions. Create them first:

```bash
# On your CrowdSec host (or docker exec crowdsec ...)
cscli machines add blocklist-import --password 'YourSecurePassword'

# Also create a bouncer key for reading existing decisions
cscli bouncers add blocklist-import -o raw
```

### Docker Compose

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    networks:
      - crowdsec  # Must be on same network as CrowdSec
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY=${CROWDSEC_LAPI_KEY}
      - CROWDSEC_MACHINE_ID=blocklist-import
      - CROWDSEC_MACHINE_PASSWORD=${CROWDSEC_MACHINE_PASSWORD}
      - DECISION_DURATION=24h
      - TZ=America/New_York

networks:
  crowdsec:
    external: true
```

### Direct Execution

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your credentials

# Run
python blocklist_import.py

# Or dry-run first
python blocklist_import.py --dry-run
```

## CLI Options

```
usage: blocklist_import.py [-h] [-v] [-n] [-d] [--lapi-url LAPI_URL]
                           [--lapi-key LAPI_KEY] [--duration DURATION]
                           [--batch-size BATCH_SIZE]

options:
  -h, --help            show this help message and exit
  -v, --version         show version and exit
  -n, --dry-run         don't import, just show what would be done
  -d, --debug           enable debug logging
  --lapi-url LAPI_URL   CrowdSec LAPI URL
  --lapi-key LAPI_KEY   CrowdSec LAPI key (bouncer)
  --duration DURATION   decision duration (e.g., 24h, 48h)
  --batch-size SIZE     IPs per import batch
```

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI URL (default: `http://localhost:8080`) |
| `CROWDSEC_LAPI_KEY` | Bouncer API key for reading decisions |
| `CROWDSEC_MACHINE_ID` | Machine ID for writing decisions |
| `CROWDSEC_MACHINE_PASSWORD` | Machine password for authentication |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `DECISION_DURATION` | `24h` | How long decisions last |
| `BATCH_SIZE` | `1000` | IPs per import batch |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARN, ERROR |
| `DRY_RUN` | `false` | Set to true for dry run |
| `TELEMETRY_ENABLED` | `true` | Anonymous usage telemetry |

### Blocklist Toggles

All blocklists are enabled by default. Set to `false` to disable:

| Variable | Source |
|----------|--------|
| `ENABLE_IPSUM` | IPsum (aggregated threat intel) |
| `ENABLE_SPAMHAUS` | Spamhaus DROP/EDROP |
| `ENABLE_BLOCKLIST_DE` | Blocklist.de (all feeds) |
| `ENABLE_FIREHOL` | Firehol level1/2 |
| `ENABLE_ABUSE_CH` | Feodo, SSL Blacklist, URLhaus |
| `ENABLE_EMERGING_THREATS` | Emerging Threats |
| `ENABLE_BINARY_DEFENSE` | Binary Defense |
| `ENABLE_BRUTEFORCE_BLOCKER` | Bruteforce Blocker |
| `ENABLE_DSHIELD` | DShield |
| `ENABLE_CI_ARMY` | CI Army |
| `ENABLE_DARKLIST` | Darklist |
| `ENABLE_TALOS` | Talos Intelligence |
| `ENABLE_CHARLES_HALEY` | Charles Haley |
| `ENABLE_BOTVRIJ` | Botvrij |
| `ENABLE_MYIP_MS` | myip.ms |
| `ENABLE_GREENSNOW` | GreenSnow |
| `ENABLE_STOPFORUMSPAM` | StopForumSpam |
| `ENABLE_TOR` | Tor exit nodes |
| `ENABLE_SCANNERS` | Shodan/Censys |

## Authentication

CrowdSec LAPI uses two types of authentication:

1. **Bouncer API Key** (`X-Api-Key` header) - Read-only access to decisions
2. **Machine Credentials** (JWT token via `/watchers/login`) - Full access including writing alerts/decisions

This tool requires both:
- Bouncer key for checking existing decisions (deduplication)
- Machine credentials for writing new decisions via the `/alerts` endpoint

## Memory Efficiency

This implementation is designed to handle 500k+ IPs without memory issues:

1. **Streaming Downloads**: Blocklists are processed line-by-line, never fully loaded
2. **Batch Imports**: IPs are sent to LAPI in configurable batches
3. **Set Deduplication**: Only unique IPs are tracked (O(1) lookup)

Typical memory usage: ~50-100MB even with millions of IPs processed.

## Scheduling

### Cron (Linux)

```cron
# Daily at 4am
0 4 * * * /path/to/blocklist_import.py >> /var/log/blocklist-import.log 2>&1
```

### Docker Compose with Cron

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    restart: "no"
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY=${CROWDSEC_LAPI_KEY}
      - CROWDSEC_MACHINE_ID=blocklist-import
      - CROWDSEC_MACHINE_PASSWORD=${CROWDSEC_MACHINE_PASSWORD}
```

Schedule with:
```bash
0 4 * * * docker compose -f /path/to/compose.yaml up --abort-on-container-exit
```

## Comparison with Bash Version

| Feature | Bash | Python |
|---------|------|--------|
| CrowdSec Access | Docker exec / Native cscli | LAPI HTTP only |
| Memory Usage | ~200MB+ (temp files) | ~50-100MB (streaming) |
| Dependencies | curl, awk, grep, sort | requests, python-dotenv |
| IPv6 Support | Limited | Full (ipaddress module) |
| Per-feed Control | No | Yes (ENABLE_* vars) |
| Type Safety | No | Yes (type hints) |
| Error Handling | Basic | Retry with backoff |
| Authentication | None (uses cscli) | Machine JWT + Bouncer key |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy blocklist_import.py

# Linting
ruff check blocklist_import.py
```

## License

MIT License - see [LICENSE](LICENSE)

### Allow-lists (v2.2.0)

Remove specific IPs or CIDRs from blocklists before import:

```bash
# Inline allow-list
-e ALLOWLIST="140.82.121.3,140.82.121.4,8.8.8.8"

# From URL
-e ALLOWLIST_URL="https://example.com/my-allowlist.txt"

# From file
-e ALLOWLIST_FILE="/path/to/allowlist.txt"
```

Allow-list format: One IP or CIDR per line, `#` for comments.
