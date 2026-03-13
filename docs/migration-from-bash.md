# Migration Guide: Bash to Python Edition

The legacy bash script (`import.sh`) is **deprecated** and no longer maintained. The Python edition offers significant improvements in performance, features, and maintainability.

---

## Why Migrate?

### Limitations of the Bash Edition

- **Limited features** — Only supports basic LAPI and Docker socket modes
- **Memory inefficiency** — Entire blocklists loaded into memory; slow with large feeds
- **Hard to extend** — Bash doesn't scale well for new sources or features
- **No structured metrics** — Can't push metrics to Prometheus
- **No webhooks** — No way to notify external systems of import results
- **Device memory support** — Requires complex SSH agent deployment
- **Python dependency** — Still requires jq or other parsing tools for some modes

### Advantages of Python Edition

- **Streaming processing** — Processes 300k+ IPs without exhausting memory (~50-100MB vs. 500MB+)
- **Faster imports** — 500-1000 IPs/second vs. 100-200 IPs/second in bash
- **Daemon mode** — Built-in scheduler (no cron/systemd timer needed)
- **Webhook notifications** — Discord, Slack, or generic webhooks
- **AbuseIPDB API** — Direct integration with AbuseIPDB for higher-quality lists
- **Prometheus metrics** — Full observability with push-to-gateway support
- **Better error handling** — Structured logging with retry logic and exponential backoff
- **IPv6 support** — Full IPv6 address validation and deduplication
- **Type safety** — Full type hints for better code maintenance

---

## Environment Variable Mapping

| Bash Variable | Python Variable | Notes |
|:---|:---|:---|
| `CROWDSEC_LAPI_URL` | `CROWDSEC_LAPI_URL` | Same |
| `CROWDSEC_MACHINE_ID` | `CROWDSEC_MACHINE_ID` | Same |
| `CROWDSEC_MACHINE_PASSWORD` | `CROWDSEC_MACHINE_PASSWORD` | Same |
| `DECISION_DURATION` | `DECISION_DURATION` | Same format (e.g., `24h`, `1d`) |
| `LOG_LEVEL` | `LOG_LEVEL` | Same (DEBUG, INFO, WARN, ERROR) |
| `DRY_RUN` | `DRY_RUN` | Same (true/false) |
| `MAX_DECISIONS` | *(removed)* | Not needed — Python uses streaming |
| `BOUNCER_SSH` | *(removed)* | Not needed — Python handles memory efficiently |
| `DEVICE_MEM_FLOOR` | *(removed)* | Not needed |
| `ALLOWLIST` | `ALLOWLIST` | Same (comma-separated IPs/CIDR) |
| `ALLOWLIST_URL` | `ALLOWLIST_URL` | Same |
| `ALLOWLIST_FILE` | `ALLOWLIST_FILE` | Same |
| `CUSTOM_BLOCKLISTS` | `CUSTOM_BLOCKLISTS` | Same (comma-separated URLs) |
| `TELEMETRY_ENABLED` | `TELEMETRY_ENABLED` | Same |
| `FETCH_TIMEOUT` | `FETCH_TIMEOUT` | Same (in seconds) |
| `MODE` | *(removed)* | Python uses LAPI directly (no Docker socket mode) |
| `CROWDSEC_CONTAINER` | *(removed)* | Not applicable |
| `DOCKER_API_VERSION` | *(removed)* | Not applicable |
| `LAPI_BATCH_SIZE` | `BATCH_SIZE` | Renamed; Python default is 1000 |
| | `DECISION_TYPE` | **NEW** — Type of decision (ban, captcha, throttle) |
| | `INTERVAL` | **NEW** — Daemon mode interval (seconds, 0=once) |
| | `RUN_ON_START` | **NEW** — Run immediately vs. wait for first interval |
| | `WEBHOOK_URL` | **NEW** — Webhook URL for notifications |
| | `WEBHOOK_TYPE` | **NEW** — Webhook format (generic, discord, slack) |
| | `ABUSEIPDB_API_KEY` | **NEW** — AbuseIPDB direct API integration |
| | `ABUSEIPDB_MIN_CONFIDENCE` | **NEW** — Minimum AbuseIPDB confidence (1-100) |
| | `METRICS_PUSHGATEWAY_URL` | **NEW** — Prometheus Pushgateway URL |
| | `ALLOWLIST_GITHUB` | **NEW** — Auto-fetch GitHub IP ranges |

---

## Key Differences

### 1. **CrowdSec Access Mode**

**Bash:**
```bash
# MODE could be "docker", "native", or "lapi"
MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh

# Or with Docker socket
docker run -v /var/run/docker.sock:/var/run/docker.sock:ro ...

# Or LAPI
CROWDSEC_LAPI_URL=http://crowdsec:8080 \
CROWDSEC_MACHINE_ID=blocklist-import \
CROWDSEC_MACHINE_PASSWORD=secret ./import.sh
```

**Python:**
```bash
# Python uses LAPI exclusively (no Docker socket mode)
CROWDSEC_LAPI_URL=http://crowdsec:8080 \
CROWDSEC_LAPI_KEY=your_bouncer_key \
CROWDSEC_MACHINE_ID=blocklist-import \
CROWDSEC_MACHINE_PASSWORD=secret python blocklist_import.py
```

**Key change:** Python **requires** `CROWDSEC_LAPI_KEY` (bouncer key) for reading existing decisions. The bash version didn't require this.

### 2. **Batch Size**

**Bash:**
```bash
LAPI_BATCH_SIZE=1000 ./import.sh
```

**Python:**
```bash
BATCH_SIZE=1000 python blocklist_import.py
# Or via CLI
python blocklist_import.py --batch-size 1000
```

### 3. **Device Memory Guardrails**

**Bash:**
```bash
# Complex two-layer guardrail system with SSH queries
MAX_DECISIONS=40000
BOUNCER_SSH="root@192.168.1.1,root@192.168.21.1"
DEVICE_MEM_FLOOR=300000
```

**Python:**
```bash
# Not needed — Python's streaming processing handles this automatically
# You can still set a soft limit if desired
MAX_DECISIONS=40000  # (optional, mainly informational)
```

The Python version doesn't need device memory queries because:
- Streaming processing uses minimal memory
- LAPI handles all validation
- Deduplication is efficient

### 4. **Blocklist Enable/Disable**

Both bash and Python support the same mechanism, but Python has better validation:

**Bash:**
```bash
ENABLE_TOR_EXIT_NODES=false ENABLE_CENSYS=false ./import.sh
```

**Python:**
```bash
ENABLE_TOR=false ENABLE_SCANNERS=false python blocklist_import.py
```

**Note:** Python simplifies the variable names (e.g., `ENABLE_TOR` instead of `ENABLE_TOR_EXIT_NODES`).

---

## Step-by-Step Migration for Docker Users

### 1. Update Your Compose File

**Before (Bash):**
```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - crowdsec
    environment:
      - CROWDSEC_CONTAINER=crowdsec
      - DECISION_DURATION=24h
      - MAX_DECISIONS=40000
```

**After (Python):**
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
      - INTERVAL=3600  # Run every hour (optional, default=0)
      - LOG_LEVEL=INFO
```

### 2. Create CrowdSec Credentials

On your CrowdSec host, create credentials:

```bash
# Machine credentials (for writing decisions)
cscli machines add blocklist-import --password 'SecurePassword123'

# Bouncer key (for reading existing decisions)
cscli bouncers add blocklist-import -o raw
# Copy the output — use it as CROWDSEC_LAPI_KEY
```

### 3. Update Environment Variables

Replace your bash `.env` file:

```bash
# Old bash variables
CROWDSEC_CONTAINER=crowdsec
MAX_DECISIONS=40000
BOUNCER_SSH=""

# New Python variables
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=your_bouncer_key_here
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=SecurePassword123
DECISION_DURATION=24h
INTERVAL=3600
LOG_LEVEL=INFO
```

### 4. Remove Docker Socket Requirement

Python doesn't need the Docker socket. Remove this line if present:

```yaml
# REMOVE THIS
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

### 5. Test and Deploy

```bash
# Test with dry-run
docker compose run --rm blocklist-import \
  python blocklist_import.py --dry-run

# Deploy
docker compose up -d
docker compose logs -f blocklist-import
```

---

## Step-by-Step Migration for Standalone Users

### 1. Install Python 3.11+

```bash
# Debian/Ubuntu
sudo apt install python3.11 python3-pip

# CentOS/RHEL
sudo dnf install python3.11 python3-pip

# macOS
brew install python@3.11
```

### 2. Clone and Install

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

# Create virtual environment (recommended)
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Create `.env` File

```bash
cp .env.example .env

# Edit with your credentials
$EDITOR .env
```

### 4. Create CrowdSec Credentials

```bash
# On CrowdSec host
cscli machines add blocklist-import --password 'SecurePassword123'
cscli bouncers add blocklist-import -o raw
```

### 5. Set Environment Variables

Edit `.env`:

```bash
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=your_bouncer_key_here
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=SecurePassword123
DECISION_DURATION=24h
LOG_LEVEL=INFO

# Optional: Enable daemon mode
INTERVAL=3600
RUN_ON_START=true
```

### 6. Test

```bash
# Single run
python blocklist_import.py

# Dry-run to preview
python blocklist_import.py --dry-run

# Daemon mode (runs every hour)
INTERVAL=3600 python blocklist_import.py
```

### 7. Schedule with Systemd Timer (Optional)

Create `/etc/systemd/system/blocklist-import.service`:

```ini
[Unit]
Description=CrowdSec Blocklist Import
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/blocklist-import
ExecStart=/opt/blocklist-import/venv/bin/python blocklist_import.py
EnvironmentFile=/opt/blocklist-import/.env
Restart=unless-stopped
RestartSec=300

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now blocklist-import.service
sudo systemctl status blocklist-import.service
```

---

## New Features After Migration

### 1. **Daemon Mode**

Run continuously without external scheduling:

```bash
INTERVAL=3600 python blocklist_import.py
```

The container will:
- Run immediately at startup
- Sleep for 3600 seconds
- Repeat indefinitely
- Handle SIGTERM gracefully (finish current run, then exit)

### 2. **Webhook Notifications**

Get notified in Discord, Slack, or a generic webhook:

```bash
# Discord
WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
WEBHOOK_TYPE=discord

# Slack
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
WEBHOOK_TYPE=slack

# Generic JSON
WEBHOOK_URL=https://your-api.example.com/webhook
WEBHOOK_TYPE=generic
```

Notification includes:
- Total IPs imported
- Deduplication stats
- Import duration
- Any errors or warnings

### 3. **AbuseIPDB Direct API**

Higher-quality threat intelligence with confidence scoring:

```bash
ABUSEIPDB_API_KEY=your_free_api_key
ABUSEIPDB_MIN_CONFIDENCE=90  # Only 90%+ confidence
ABUSEIPDB_LIMIT=10000
```

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/). Free tier: 5 blacklist checks per day.

### 4. **Prometheus Metrics**

Full observability with push-to-gateway:

```bash
METRICS_PUSHGATEWAY_URL=http://prometheus:9091
```

Metrics tracked:
- Total IPs imported
- IPs deduplicated
- Failed imports per source
- Import duration per source
- Status (success/failure)

### 5. **Allowlist from GitHub**

Auto-fetch GitHub's IP ranges to whitelist GitHub Actions, webhooks, etc.:

```bash
ALLOWLIST_GITHUB=true
```

This covers:
- github.com (web)
- api.github.com
- Webhook delivery
- Actions runners

### 6. **Better Logging**

Structured logging with timestamps and severity:

```bash
LOG_LEVEL=DEBUG python blocklist_import.py
```

Output includes:
- Per-source status and counts
- Detailed error messages with context
- Import timings
- Deduplication statistics

### 7. **CLI Improvements**

```bash
# List all sources
python blocklist_import.py --list-sources

# Override LAPI URL
python blocklist_import.py --lapi-url http://crowdsec:8080

# Override decision duration
python blocklist_import.py --duration 48h

# Validate config and exit
python blocklist_import.py --validate

# Custom Prometheus URL
python blocklist_import.py --pushgateway-url http://prometheus:9091

# Daemon mode with custom interval
python blocklist_import.py --interval 1800
```

---

## Migration Checklist

- [ ] **Read migration guide** (you are here!)
- [ ] **Update CrowdSec credentials**
  - [ ] Create machine: `cscli machines add blocklist-import`
  - [ ] Create bouncer: `cscli bouncers add blocklist-import -o raw`
  - [ ] Copy bouncer key for `CROWDSEC_LAPI_KEY`
- [ ] **Update Docker Compose** (if applicable)
  - [ ] Remove Docker socket volume
  - [ ] Update image to `ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest`
  - [ ] Add `CROWDSEC_LAPI_URL`, `CROWDSEC_LAPI_KEY`, machine credentials
- [ ] **Update environment variables**
  - [ ] Rename `LAPI_BATCH_SIZE` → `BATCH_SIZE`
  - [ ] Remove `MAX_DECISIONS`, `BOUNCER_SSH`, `DEVICE_MEM_FLOOR`
  - [ ] Keep: `ALLOWLIST*`, `CUSTOM_BLOCKLISTS`, `DECISION_DURATION`, `DRY_RUN`, `LOG_LEVEL`
- [ ] **Test with dry-run**
  - [ ] `python blocklist_import.py --dry-run`
  - [ ] Review output for errors
- [ ] **Deploy**
  - [ ] Start the container or systemd service
  - [ ] Monitor logs: `docker logs -f blocklist-import` or `journalctl -u blocklist-import -f`
  - [ ] Verify imports in CrowdSec: `cscli decisions list --limit 20`
- [ ] **Verify new features** (optional)
  - [ ] Test daemon mode: `INTERVAL=3600 python blocklist_import.py`
  - [ ] Test webhooks
  - [ ] Test Prometheus metrics
  - [ ] Test AbuseIPDB integration

---

## Troubleshooting

### "CROWDSEC_LAPI_KEY not found"

You need a bouncer key for reading existing decisions:

```bash
cscli bouncers add blocklist-import -o raw
# Copy the output and set CROWDSEC_LAPI_KEY
```

### "Cannot reach LAPI at http://crowdsec:8080"

Verify CrowdSec is running and LAPI is enabled:

```bash
# From CrowdSec container
curl http://localhost:8080/health

# From importing container (Docker)
curl http://crowdsec:8080/health
```

### "No IPs imported"

Check logs and ensure blocklists are enabled:

```bash
python blocklist_import.py --debug
python blocklist_import.py --list-sources
```

Verify at least one feed is enabled (not set to `false`).

### Memory Issues

Reduce batch size:

```bash
BATCH_SIZE=100 python blocklist_import.py
```

Or disable large feeds:

```bash
ENABLE_IPSUM=false python blocklist_import.py
```

### Docker Network Issues

Ensure both containers are on the same network:

```bash
docker network inspect crowdsec
docker ps | grep crowdsec
```

---

## Rollback Plan

If you need to roll back to bash:

1. Keep the old bash image tag: `ghcr.io/wolffcatskyy/crowdsec-blocklist-import:v2.2.0`
2. Revert Docker Compose to use Docker socket
3. Restore old environment variables

However, **we recommend staying with Python** — it's faster, more reliable, and actively maintained.

---

## Support

- **Issues:** https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues
- **Discussions:** https://github.com/wolffcatskyy/crowdsec-blocklist-import/discussions
- **Documentation:** https://github.com/wolffcatskyy/crowdsec-blocklist-import/tree/main/docs

---

## FAQ

### Q: Will the bash version still work?

A: The bash script is marked as deprecated and won't receive updates. It may not work with newer CrowdSec versions or external blocklist feeds. Migrate to Python for ongoing support.

### Q: Do I lose any features by switching?

A: No. Python has all features from bash, plus many new ones. The main difference is the access mode (no Docker socket).

### Q: Can I run both versions simultaneously?

A: Not recommended. They'll both try to import the same IPs, causing duplicate entries. Migrate completely to one or the other.

### Q: Does Python require Docker?

A: No. Python can run standalone with `pip install -r requirements.txt`. Docker is optional but recommended.

### Q: What about performance?

A: Python is faster (500-1000 IPs/sec vs. 100-200 IPs/sec) and uses less memory (50-100MB vs. 500MB+).

### Q: How do I update to a new version?

A: If running in Docker:
```bash
docker pull ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
docker compose up -d
```

If running standalone:
```bash
cd /path/to/blocklist-import
git pull origin main
pip install -r requirements.txt --upgrade
```
