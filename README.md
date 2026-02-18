# CrowdSec Blocklist Import - Python Edition

Memory-efficient Python 3.11+ implementation of [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) using the LAPI HTTP API directly.

[![NixOS packaging](https://img.shields.io/badge/NixOS-packaging%20in%20progress-5277C3?logo=nixos&logoColor=white)](https://github.com/NixOS/nixpkgs/pull/486054)

## Features

- **LAPI Mode Only**: Direct HTTP API calls, no Docker socket needed
- **Memory Efficient**: Streaming downloads, line-by-line processing
- **Batch Processing**: Configurable batch size (default 1000 IPs)
- **Full IPv4/IPv6 Support**: Uses Python's `ipaddress` module
- **Automatic Deduplication**: Skips existing CrowdSec decisions
- **Retry Logic**: Exponential backoff for failed requests
- **Type Hints**: Full type annotations for IDE support
- **30+ Blocklists**: Same sources as the bash version
- **Per-feed Control**: Enable/disable individual blocklist sources
- **Prometheus Metrics**: Built-in metrics endpoint for monitoring

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

### Docker Compose with Secrets

For production deployments, use Docker secrets instead of environment variables:

```yaml
secrets:
  crowdsec_lapi_key:
    file: ./secrets/crowdsec_lapi_key.txt
  crowdsec_machine_password:
    file: ./secrets/crowdsec_machine_password.txt

services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    networks:
      - crowdsec
    secrets:
      - crowdsec_lapi_key
      - crowdsec_machine_password
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY_FILE=/run/secrets/crowdsec_lapi_key
      - CROWDSEC_MACHINE_ID=blocklist-import
      - CROWDSEC_MACHINE_PASSWORD_FILE=/run/secrets/crowdsec_machine_password
      - DECISION_DURATION=24h
      - TZ=America/New_York

networks:
  crowdsec:
    external: true
```

Create the secrets files:

```bash
mkdir -p ./secrets
echo "your-bouncer-api-key" > ./secrets/crowdsec_lapi_key.txt
echo "your-machine-password" > ./secrets/crowdsec_machine_password.txt
chmod 600 ./secrets/*.txt
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

### NixOS

A NixOS package and module is being packaged in [nixpkgs#486054](https://github.com/NixOS/nixpkgs/pull/486054). Once merged, install with:

```nix
services.crowdsec-blocklist-import = {
  enable = true;
  # Configuration options available — see the NixOS module for details
};
```

## CLI Options

### Bash Script (import.sh)

```text
Usage: import.sh [OPTIONS]

Options:
  --help, -h          Show help message and exit
  --version, -v       Show version number and exit
  --list-sources      List all available blocklist sources with their toggle variables
  --dry-run           Run without making changes (same as DRY_RUN=true)

Examples:
  ./import.sh --version           # Show version
  ./import.sh --help              # Show help
  ./import.sh --list-sources      # List all 30 blocklist sources
  ./import.sh --dry-run           # Preview what would be imported
  ENABLE_TOR_EXIT_NODES=false ./import.sh  # Run with Tor sources disabled
```

### Python Script (blocklist_import.py)

```text
usage: blocklist_import.py [-h] [-v] [-n] [-d] [--lapi-url LAPI_URL]
                           [--lapi-key LAPI_KEY] [--duration DURATION]
                           [--batch-size BATCH_SIZE] [--validate]
                           [--list-sources] [--metrics-port PORT]
                           [--no-metrics]

options:
  -h, --help            show this help message and exit
  -v, --version         show version and exit
  -n, --dry-run         don't import, just show what would be done
  -d, --debug           enable debug logging
  --lapi-url LAPI_URL   CrowdSec LAPI URL
  --lapi-key LAPI_KEY   CrowdSec LAPI key (bouncer)
  --duration DURATION   decision duration (e.g., 24h, 48h)
  --batch-size SIZE     IPs per import batch
  --validate            validate configuration and exit
  --list-sources        list all available blocklist sources
  --metrics-port PORT   port for Prometheus metrics (default: 9102)
  --no-metrics          disable Prometheus metrics endpoint
```

## Environment Variable Validation

The tool validates all `ENABLE_*` environment variables at startup:

1. **Value validation**: All `ENABLE_*` variables must be valid boolean strings (`true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off`)
2. **Typo detection**: Unknown `ENABLE_*` variables generate warnings with suggestions for similar valid names

### Validation Examples

```bash
# Validate configuration without running import
./blocklist_import.py --validate

# List all available blocklist sources and their status
./blocklist_import.py --list-sources
```

### Error Messages

Invalid values will cause the program to exit with a clear error message:

```text
[ERROR] Configuration validation failed:
[ERROR]
[ERROR]   Invalid value for ENABLE_IPSUM: 'maybe'
[ERROR]     Expected one of: true, false, 1, 0, yes, no, on, off (case-insensitive)
[ERROR]
[ERROR] Fix the above errors and try again.
[ERROR] Use --list-sources to see all valid ENABLE_* variables.
```

Typos in variable names generate warnings but don't stop execution:

```text
[WARNING] Unknown environment variable: ENABLE_IPSOM=false
[WARNING]   Did you mean: ENABLE_IPSUM?
```

## Removing all blocked IPs

All added decisions have their origin set to `blocklist-import`, so they can be cleared by running:

```bash
cscli decisions delete --origin blocklist-import
```

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI URL (default: `http://localhost:8080`) |
| `CROWDSEC_LAPI_KEY` or `CROWDSEC_LAPI_KEY_FILE` | Bouncer API key / key file for reading decisions |
| `CROWDSEC_MACHINE_ID` | Machine ID for writing decisions |
| `CROWDSEC_MACHINE_PASSWORD` or `CROWDSEC_MACHINE_PASSWORD_FILE` | Machine password / password file for authentication |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWLIST` | `` | Comma-separated list of blocklist row data to ignore |
| `DECISION_DURATION` | `24h` | How long decisions last |
| `LOG_TIMESTAMPS` | `true` | Include timestamps in logs |
| `DECISION_REASON` | `external_blocklist` | The decision identifier |
| `DECISION_TYPE` | `ban` | The type of decision applied |
| `DECISION_ORIGIN` | `blocklist-import` | The decision origin name |
| `DECISION_SCENARIO` | `external/blocklist` | The decision scenario name |
| `BATCH_SIZE` | `1000` | IPs per import batch |
| `FETCH_TIMEOUT` | `60` | The fetch timeout in seconds |
| `MAX_RETRIES` | `3` | How many times to retry fetching in case of error |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARN, ERROR |
| `DRY_RUN` | `false` | Set to true for dry run |
| `TELEMETRY_ENABLED` | `true` | Anonymous usage telemetry |
| `TELEMETRY_URL` | `https://bouncer-telemetry.ms2738.workers.dev/ping` | Anonymous usage telemetry URL |
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `METRICS_PORT` | `9102` | Port for Prometheus metrics HTTP server |

### Blocklist Toggles

All blocklists are enabled by default. Set to `false` to disable:

| Variable | Source |
|----------|--------|
| `ENABLE_IPSUM` | IPsum (aggregated threat intel) |
| `ENABLE_SPAMHAUS` | Spamhaus DROP/EDROP |
| `ENABLE_BLOCKLIST_DE` | Blocklist.de (all feeds) |
| `ENABLE_FIREHOL` | Firehol levels 1/2/3 |
| `ENABLE_ABUSE_CH` | Feodo, URLhaus |
| `ENABLE_EMERGING_THREATS` | Emerging Threats |
| `ENABLE_BINARY_DEFENSE` | Binary Defense |
| `ENABLE_BRUTEFORCE_BLOCKER` | Bruteforce Blocker |
| `ENABLE_DSHIELD` | DShield |
| `ENABLE_CI_ARMY` | CI Army |
| `ENABLE_BOTVRIJ` | Botvrij |
| `ENABLE_GREENSNOW` | GreenSnow |
| `ENABLE_STOPFORUMSPAM` | StopForumSpam |
| `ENABLE_TOR` | Tor exit nodes |
| `ENABLE_SCANNERS` | Shodan/Censys/Maltrail |
| `ENABLE_ABUSE_IPDB` | Abuse IPDB |
| `ENABLE_CYBERCRIME_TRACKER` | Cybercrime tracker |
| `ENABLE_MONTY_SECURITY_C2` | Monty Security C2 |
| `ENABLE_VXVAULT` | VX Vault |

## Authentication

CrowdSec LAPI uses two types of authentication:

1. **Bouncer API Key** (`X-Api-Key` header) - Read-only access to decisions
2. **Machine Credentials** (JWT token via `/watchers/login`) - Full access including writing alerts/decisions

This tool requires both:

- Bouncer key for checking existing decisions (deduplication)
- Machine credentials for writing new decisions via the `/alerts` endpoint

## Allow-lists

The `ALLOWLIST` environment variable can be used to specify block-list rows to ignore.

If the original row to ignore ends contains comment, it should not be included in the allow-list item

## Prometheus Metrics

The blocklist importer exposes Prometheus metrics on port 9102 (configurable via `METRICS_PORT`).

### Enabling Metrics

Metrics are enabled by default. To expose them in Docker:

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    ports:
      - "9102:9102"
    environment:
      - METRICS_ENABLED=true
      - METRICS_PORT=9102
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `blocklist_import_total_ips` | Gauge | Total number of IPs imported in the last run |
| `blocklist_import_last_run_timestamp` | Gauge | Unix timestamp of the last import run |
| `blocklist_import_sources_enabled` | Gauge | Number of enabled blocklist sources |
| `blocklist_import_sources_successful` | Gauge | Number of sources successfully fetched |
| `blocklist_import_sources_failed` | Gauge | Number of sources that failed to fetch |
| `blocklist_import_existing_decisions` | Gauge | Number of existing CrowdSec decisions found |
| `blocklist_import_new_ips` | Gauge | Number of new unique IPs added |
| `blocklist_import_errors_total` | Counter | Total number of errors (labels: `error_type`) |
| `blocklist_import_duration_seconds` | Histogram | Duration of import run in seconds |

### Error Types

The `blocklist_import_errors_total` counter uses the `error_type` label:

- `fetch` - Failed to download a blocklist source
- `parse` - Failed to parse an IP address from blocklist
- `encoding` - Character encoding errors
- `import` - Failed to import IPs to CrowdSec LAPI

### Example Prometheus Config

```yaml
scrape_configs:
  - job_name: 'blocklist-import'
    static_configs:
      - targets: ['blocklist-import:9102']
    scrape_interval: 5m
```

### Example Grafana Queries

```promql
# IPs imported over time
blocklist_import_total_ips

# Import success rate
blocklist_import_sources_successful / blocklist_import_sources_enabled

# Time since last run (for alerting on stale imports)
time() - blocklist_import_last_run_timestamp

# Error rate by type
rate(blocklist_import_errors_total[1h])
```

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

## Contributors

A huge thanks to those who have helped make this project better!

- **[@gaelj](https://github.com/gaelj)** - Major contributor to v3.3.0, implementing Docker secrets support (`_FILE` env vars), allowlist functionality, CLI enhancements, Prometheus metrics, environment validation with typo detection, and adding multiple new blocklist sources. [PR #30](https://github.com/wolffcatskyy/crowdsec-blocklist-import/pull/30)

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE)

### Allow-lists (v2.2.0)

Remove specific IPs or CIDRs from blocklists before import:

```bash
# Inline allow-list (comma-separated)
-e ALLOWLIST="140.82.121.3,140.82.121.4,8.8.8.8"
```

> **Note:** URL-based (`ALLOWLIST_URL`) and file-based (`ALLOWLIST_FILE`) allowlists are planned for a future release. Currently only the inline `ALLOWLIST` variable is supported.
