# crowdsec-blocklist-import Repository State Report
**Generated:** 2026-02-22
**Current Version:** v3.4.0 (Released 2026-02-20)
**Repository:** https://github.com/wolffcatskyy/crowdsec-blocklist-import
**Stars:** 170
**License:** MIT

---

## 1. PROJECT OVERVIEW

### Description
"10-20x more blocks for your CrowdSec bouncers — 120k+ IPs from 36 free threat feeds"

### Key Statistics
- **Language:** Python 3.11+ (recent rewrite from Bash)
- **Framework:** Minimal dependencies (requests, python-dotenv, prometheus-client)
- **Latest Release:** v3.4.0 (2026-02-20) - CIDR allowlists + Prometheus Push Gateway
- **Topics:** blocklist, crowdsec, cybersecurity, docker, firewall, ip-blocklist, security, threat-feeds, threat-intelligence, tor-exit-nodes

### File Structure
```
.env.example                      # Config template with all environment variables
.github/                          # GitHub workflows (Docker publish CI/CD)
CONTRIBUTING.md                   # AI-Ready Issues contributing guide
Dockerfile                        # Multi-stage Python 3.11-slim build
LICENSE                           # MIT
README.md                         # Full documentation
ROADMAP.md                        # v3.5.0 (notifications/scheduling) and v4.0.0 (IPv6/AbuseIPDB)
SECURITY.md                       # Security policy, malicious clone warnings
blocklist_import.py              # Main Python script (~650 lines, type-hinted)
docker-compose.yml               # Docker Compose example with environment variables
grafana-dashboard.json           # Pre-built Grafana dashboard for metrics
import.sh                        # Legacy bash script (deprecated, marked for removal)
install.sh                       # Installation helper
requirements.txt                 # Python dependencies (3 packages)
```

---

## 2. CURRENT FEATURES (v3.4.0)

### Core Capabilities
✅ **LAPI Mode Only** - Direct HTTP API calls (no Docker socket needed)
✅ **Memory Efficient** - Streaming downloads, line-by-line processing (~50-100MB typical)
✅ **Batch Processing** - Configurable batch size (default 1000 IPs)
✅ **Full IPv4/IPv6 Support** - Uses Python's `ipaddress` module
✅ **Automatic Deduplication** - Skips existing CrowdSec decisions via bouncer key
✅ **Retry Logic** - Exponential backoff for failed requests
✅ **Type Hints** - Full type annotations throughout
✅ **30+ Blocklists** - Same sources as bash version
✅ **Per-feed Control** - Enable/disable individual blocklist sources via ENABLE_* env vars
✅ **Prometheus Metrics** - Push Gateway integration (NEW in v3.4.0)
✅ **CIDR Allowlists** - IP ranges in allowlist via CIDR notation (NEW in v3.4.0)
✅ **Provider Allowlists** - Auto-fetch GitHub IP ranges (NEW in v3.4.0)

### Blocklist Sources (20 ENABLED + 4 Optional = 24 Total in README, Config shows 19)
**Always-enabled sources:**
1. IPsum (aggregated threat intel - 3+ blocklists)
2. Spamhaus DROP (hijacked netblocks)
3. Blocklist.de (all/ssh/apache/mail feeds)
4. Firehol (levels 1/2/3)
5. Abuse.ch (Feodo, URLhaus)
6. Emerging Threats (compromised IPs)
7. Binary Defense (ban list)
8. Bruteforce Blocker
9. DShield (top attackers)
10. CI Army (bad reputation)
11. Botvrij (botnet C2)
12. GreenSnow (attacker IPs)
13. StopForumSpam (toxic IPs)
14. Tor exit nodes (may cause false positives)
15. Scanners (Shodan/Censys/Maltrail)
16. Abuse IPDB
17. Cybercrime Tracker
18. Monty Security C2
19. VX Vault

**All can be disabled via** `ENABLE_*=false` environment variables.

### Authentication
- **Bouncer API Key** (`X-Api-Key` header) - Read-only access to existing decisions
- **Machine Credentials** (JWT via `/watchers/login`) - Write access to decisions

---

## 3. INSTALLATION & DEPLOYMENT

### Prerequisites
```bash
# CrowdSec LAPI requires machine credentials
cscli machines add blocklist-import --password 'YourSecurePassword'
cscli bouncers add blocklist-import -o raw  # Get API key for reading decisions
```

### Docker Compose (Recommended)
```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    container_name: blocklist-import
    restart: "no"  # Runs once and exits
    networks:
      - crowdsec
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_LAPI_KEY=${CROWDSEC_LAPI_KEY}
      - CROWDSEC_MACHINE_ID=blocklist-import
      - CROWDSEC_MACHINE_PASSWORD=${CROWDSEC_MACHINE_PASSWORD}
      - DECISION_DURATION=24h
      - TZ=America/New_York
```

### Docker Secrets Support (v3.3.0+)
```yaml
secrets:
  crowdsec_lapi_key:
    file: ./secrets/crowdsec_lapi_key.txt
services:
  blocklist-import:
    environment:
      - CROWDSEC_LAPI_KEY_FILE=/run/secrets/crowdsec_lapi_key
      - CROWDSEC_MACHINE_PASSWORD_FILE=/run/secrets/crowdsec_machine_password
```

### Direct Python Execution
```bash
pip install -r requirements.txt
cp .env.example .env  # Edit with your credentials
python blocklist_import.py --dry-run  # Preview before importing
```

### NixOS (In Progress)
NixOS package being added to nixpkgs PR #486054 (targeting Q1 2026 merge).

---

## 4. ENVIRONMENT VARIABLES

### Required
| Variable | Description |
|----------|-------------|
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI URL (default: `http://localhost:8080`) |
| `CROWDSEC_LAPI_KEY` OR `CROWDSEC_LAPI_KEY_FILE` | Bouncer API key / file |
| `CROWDSEC_MACHINE_ID` | Machine ID (e.g., `blocklist-import`) |
| `CROWDSEC_MACHINE_PASSWORD` OR `CROWDSEC_MACHINE_PASSWORD_FILE` | Machine password / file |

### Decision Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DECISION_DURATION` | `24h` | How long decisions last |
| `DECISION_REASON` | `external_blocklist` | Visible in cscli decisions list |
| `DECISION_TYPE` | `ban` | Type of decision (ban, captcha, throttle) |
| `DECISION_ORIGIN` | `blocklist-import` | Origin for filtering |
| `DECISION_SCENARIO` | `external/blocklist` | Scenario name |

### Allowlists (NEW in v3.4.0)
| Variable | Description | Example |
|----------|-------------|---------|
| `ALLOWLIST` | Comma-separated IPs/CIDR ranges | `140.82.112.0/20,185.199.108.0/22,1.2.3.4` |
| `ALLOWLIST_GITHUB` | Auto-fetch GitHub IP ranges | `true` |

### Processing
| Variable | Default | Description |
|----------|---------|-------------|
| `BATCH_SIZE` | `1000` | IPs per import batch |
| `FETCH_TIMEOUT` | `60` | Fetch timeout (seconds) |
| `MAX_RETRIES` | `3` | Retry count on failure |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARN, ERROR |
| `DRY_RUN` | `false` | Preview without importing |

### Metrics & Telemetry
| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLED` | `true` | Push Prometheus metrics |
| `METRICS_PUSHGATEWAY_URL` | `localhost:9091` | Push gateway endpoint |
| `TELEMETRY_ENABLED` | `true` | Anonymous usage telemetry |
| `TELEMETRY_URL` | `https://bouncer-telemetry.ms2738.workers.dev/ping` | Telemetry endpoint |

### Blocklist Toggles (All default to true)
Use `ENABLE_SOURCENAME=false` to disable. Example: `ENABLE_TOR=false` disables Tor exit nodes.

Valid toggle variables:
- `ENABLE_IPSUM`, `ENABLE_SPAMHAUS`, `ENABLE_BLOCKLIST_DE`, `ENABLE_FIREHOL`
- `ENABLE_ABUSE_CH`, `ENABLE_EMERGING_THREATS`, `ENABLE_BINARY_DEFENSE`
- `ENABLE_BRUTEFORCE_BLOCKER`, `ENABLE_DSHIELD`, `ENABLE_CI_ARMY`
- `ENABLE_BOTVRIJ`, `ENABLE_GREENSNOW`, `ENABLE_STOPFORUMSPAM`
- `ENABLE_TOR`, `ENABLE_SCANNERS`, `ENABLE_ABUSE_IPDB`
- `ENABLE_CYBERCRIME_TRACKER`, `ENABLE_MONTY_SECURITY_C2`, `ENABLE_VXVAULT`

**Environment validation:** Unknown ENABLE_* vars generate warnings with typo suggestions.

---

## 5. CLI INTERFACE

### Python Script (`blocklist_import.py`)
```bash
blocklist_import.py [-h] [-v] [-n] [-d] [--lapi-url URL] [--lapi-key KEY]
  [--duration DURATION] [--batch-size SIZE] [--validate] [--list-sources]
  [--pushgateway-url URL] [--no-metrics]

Options:
  -h, --help              Show help
  -v, --version           Show version (3.4.0)
  -n, --dry-run           Preview without importing
  -d, --debug             Enable debug logging
  --validate              Validate config and exit
  --list-sources          List all blocklist sources and their enable status
```

### Legacy Bash Script (`import.sh` - Deprecated)
```bash
import.sh [OPTIONS]
  --help, -h              Show help
  --version, -v           Show version
  --list-sources          List all 30 blocklist sources
  --dry-run               Run without changes (same as DRY_RUN=true)
```

**Status:** Marked for removal in upcoming release (Issue #37 "Drop the legacy bash script")

---

## 6. PROMETHEUS METRICS (NEW in v3.4.0)

### Architecture
- **Push model** (not scrape) — pushes to Pushgateway on each run
- **Why:** Container runs once and exits; Prometheus can't scrape a dead container
- **Pushgateway URL:** Configurable via `METRICS_PUSHGATEWAY_URL` (default: localhost:9091)

### Available Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `blocklist_import_total_ips` | Gauge | Total IPs imported in last run |
| `blocklist_import_last_run_timestamp` | Gauge | Unix timestamp of last run |
| `blocklist_import_sources_enabled` | Gauge | Number of enabled sources |
| `blocklist_import_sources_successful` | Gauge | Sources fetched successfully |
| `blocklist_import_sources_failed` | Gauge | Sources that failed |
| `blocklist_import_existing_decisions` | Gauge | Existing CrowdSec decisions found |
| `blocklist_import_new_ips` | Gauge | New unique IPs added |
| `blocklist_import_errors_total` | Counter | Total errors (with `error_type` label) |
| `blocklist_import_duration_seconds` | Histogram | Import duration |

### Grafana Dashboard
Pre-built dashboard included: `grafana-dashboard.json`
- Import into Prometheus + Grafana for visualization
- Shows: IPs over time, success rate, error rates, time since last run

---

## 7. ALLOWLISTS & FILTERING

### Static Allowlist
```bash
# Individual IPs
ALLOWLIST="140.82.121.3,8.8.8.8"

# CIDR ranges (NEW in v3.4.0)
ALLOWLIST="140.82.112.0/20,185.199.108.0/22"

# Mixed
ALLOWLIST="1.2.3.4,140.82.112.0/20,8.8.8.8"
```

### Provider Allowlists (NEW in v3.4.0)
```bash
# Auto-fetch GitHub IP ranges from https://api.github.com/meta
ALLOWLIST_GITHUB=true
```
- Covers: git, web, api, hooks, actions endpoints
- Falls back to hardcoded ranges if GitHub API unavailable
- Can combine with manual ALLOWLIST entries

### Clearing Decisions
```bash
# Remove all blocklist-import decisions
cscli decisions delete --origin blocklist-import
```

---

## 8. OPEN ISSUES & ROADMAP

### Current Issues
| ID | Title | Labels | Status |
|----|----|--------|--------|
| 41 | Docker release tag 3.3.2 downloads 3.3.0 | — | OPEN |
| 37 | Drop the legacy bash script | `accepted` | OPEN |
| 15 | Add AbuseIPDB as a blocklist source | `enhancement` | OPEN |
| 8 | IPv6 support | `enhancement`, `ai-ready` | OPEN |
| 7 | Webhook notifications (Discord, Slack, generic) | `enhancement`, `ai-ready` | OPEN |
| 5 | Built-in cron/scheduled mode | `enhancement`, `ai-ready` | OPEN |

### Planned Releases

#### v3.5.0 (Q2 2026) — Notifications & Scheduling
- **Built-in Scheduled Mode** (Issue #5)
  - New env vars: `INTERVAL` (seconds), `SCHEDULE` (cron expr)
  - Daemon mode that stays running and re-runs on schedule
  - Graceful shutdown on SIGTERM/SIGINT
  
- **Webhook Notifications** (Issue #7)
  - Platforms: Discord (rich embeds), Slack (Block Kit), generic webhooks
  - Env vars: `WEBHOOK_URL`, `WEBHOOK_TYPE`
  - Payload: status, IP count, source stats, timestamp

#### v4.0.0 (Q3 2026) — IPv6 & AbuseIPDB
- **Full IPv6 Support** (Issue #8)
  - Extract both IPv4 and IPv6 from blocklists
  - Filter IPv6 reserved ranges (::1, fe80::/10, fc00::/7, etc.)
  - CIDR notation for IPv6
  - Statistics breakdown by protocol

- **AbuseIPDB Integration** (Issue #15)
  - New env vars: `ENABLE_ABUSEIPDB`, `ABUSEIPDB_API_KEY`
  - Confidence threshold: `ABUSEIPDB_CONFIDENCE_MINIMUM` (default: 90)
  - Rate limit: Free tier = 5 API calls/day, up to 10k results
  - Default disabled (requires API key)

### Future Considerations
- Additional blocklist sources (Shodan, GreyNoise RIOT, Project Honeypot)
- Multi-instance coordination (distributed locking, leader election)
- Config file support (YAML/TOML as alternative to env vars)
- Web dashboard (read-only stats UI)

---

## 9. CONTRIBUTING & DEVELOPMENT

### Contribution Model: AI-Ready Issues
Every GitHub issue is structured for AI tools:

```markdown
## Context
[2-3 sentence project overview]

## Current Behavior
[What happens now with code snippets]

## Desired Behavior
[What should happen with examples]

## Implementation Guide
### File: `path/to/file.ext`
[Step-by-step: what to add, where, example code]

## Acceptance Criteria
- [ ] Specific, testable condition
- [ ] Another condition

## Constraints
- **[Rule]** — [Why]

## AI Prompt
[Single paragraph with file paths, function names, constraints]
```

### Development Setup
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

### Commit Message Convention
- `Fix:` — Bug fixes
- `Feature:` — New features
- `Docs:` — Documentation

### PR Process
1. Fork and create feature branch (naming: `fix/`, `feature/`, `docs/`)
2. Develop and test locally with `--dry-run`
3. Verify both Docker and direct Python execution modes
4. Submit PR with description, test environment, and checklist

---

## 10. DEPLOYMENT RECOMMENDATIONS

### Typical Production Setup
```bash
# 1. Create CrowdSec credentials
docker exec crowdsec cscli machines add blocklist-import --password 'SecurePassword123'
docker exec crowdsec cscli bouncers add blocklist-import -o raw

# 2. Save to .env file
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=your_bouncer_key
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=SecurePassword123
DECISION_DURATION=24h
ALLOWLIST_GITHUB=true

# 3. Deploy with Docker Compose
docker compose up --abort-on-container-exit

# 4. Schedule daily via cron
0 4 * * * docker compose -f /path/to/compose.yaml up --abort-on-container-exit
```

### Scheduling Options
- **Cron:** `0 4 * * * /path/to/blocklist_import.py >> /var/log/blocklist-import.log 2>&1`
- **Docker Compose:** `docker compose up --abort-on-container-exit` (restart: "no")
- **Kubernetes:** CronJob with image `ghcr.io/wolffcatskyy/crowdsec-blocklist-import`
- **Synology Task Scheduler:** Create task calling `docker compose up`
- **Future (v3.5.0):** Built-in daemon mode with `INTERVAL=86400` (24 hours)

### Memory Efficiency
- Handles 500k+ IPs without issues
- Typical usage: 50-100MB
- Streaming downloads (never fully loaded)
- Set deduplication (O(1) lookup)

---

## 11. SECURITY CONSIDERATIONS

### Official Repositories
Only trust these GitHub URLs:
- https://github.com/wolffcatskyy/crowdsec-blocklist-import
- https://github.com/wolffcatskyy/crowdsec-unifi-bouncer
- https://github.com/wolffcatskyy/crowdsec-unifi-parser

### Known Malicious Clones
⚠️ Do NOT use repositories offering:
- ZIP file downloads
- Executable installers
- "One-click" desktop applications

This project is scripts + config only (Python + YAML).

### Credential Security
- Use Docker secrets for credentials in production (v3.3.0+)
- Support for `*_FILE` env vars (e.g., `CROWDSEC_LAPI_KEY_FILE`)
- Non-root user in Docker container
- Environment validation warns about typos in ENABLE_* vars

### TELEMETRY
- Anonymous usage telemetry enabled by default
- Sends ping to: `https://bouncer-telemetry.ms2738.workers.dev/ping`
- Disable with: `TELEMETRY_ENABLED=false`
- No personal data or decision contents sent

---

## 12. COMPARISON WITH ALTERNATIVES

### Python vs. Bash Version
| Feature | Bash | Python (Current) |
|---------|------|------------------|
| CrowdSec Access | Docker exec / cscli | LAPI HTTP only |
| Memory Usage | ~200MB+ (temp files) | ~50-100MB (streaming) |
| Dependencies | curl, awk, grep, sort | requests, python-dotenv, prometheus-client |
| IPv6 Support | Limited | Full (planned v4.0 expansion) |
| Per-feed Control | No | Yes (ENABLE_* vars) |
| Type Safety | No | Yes (type hints) |
| Error Handling | Basic | Retry with exponential backoff |
| Docker Secrets | No | Yes (v3.3.0+) |
| Prometheus | No | Yes (Push Gateway) |

---

## 13. KEY TECHNICAL DETAILS

### Architecture
- **Single Python file:** ~650 lines with type hints
- **Streaming model:** Line-by-line processing, never full file in memory
- **Batch imports:** Configurable batch size to LAPI
- **Deduplication:** Reads existing decisions via bouncer key, skips IPs already banned
- **Error handling:** Per-source failures don't stop overall import; retry with exponential backoff
- **Validation:** All ENABLE_* vars checked at startup with typo detection

### Docker Image
- **Base:** `python:3.11-slim` (multi-stage build)
- **Non-root user:** `blocklist` (security)
- **Size:** Minimal (slim base + 3 lightweight deps)
- **Registry:** `ghcr.io/wolffcatskyy/crowdsec-blocklist-import`
- **Health check:** Script is runnable (not actually importable)

### Python Dependencies
```
requests>=2.28.0,<3.0.0          # HTTP client with retry
python-dotenv>=1.0.0,<2.0.0      # .env file loading (optional)
prometheus-client>=0.17.0,<1.0.0 # Metrics (optional but recommended)
```

### CI/CD
- GitHub Actions workflow for Docker publish
- Docker image auto-built on tag push
- Version verification: git tag matches `__version__` in code (enforced by CI)

---

## 14. QUICK REFERENCE

### Installation (One-liner)
```bash
docker run --rm -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=your_key \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=your_password \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

### Dry Run
```bash
python blocklist_import.py --dry-run --debug
```

### List All Sources
```bash
python blocklist_import.py --list-sources
```

### Validate Configuration
```bash
python blocklist_import.py --validate
```

### Custom Import Duration
```bash
python blocklist_import.py --duration 48h
```

### Disable Tor Nodes
```bash
ENABLE_TOR=false python blocklist_import.py
```

### Import with GitHub Allowlist
```bash
ALLOWLIST_GITHUB=true python blocklist_import.py
```

---

## SUMMARY

**crowdsec-blocklist-import** is a production-ready Python tool for importing 24+ public threat blocklists into CrowdSec. It emphasizes:

1. **Simplicity** - Minimal dependencies, single Python file
2. **Efficiency** - Streaming downloads, ~50-100MB memory usage
3. **Control** - Per-source toggles, allowlists (static + provider), CIDR support
4. **Reliability** - Retry logic, deduplication, validation
5. **Observability** - Prometheus metrics, full logging, dry-run mode
6. **AI-Friendly** - Type hints, structured AI-ready issues, clear architecture

**Current:** v3.4.0 (Feb 20, 2026)
**Next:** v3.5.0 Q2 2026 (scheduling + webhooks) → v4.0.0 Q3 2026 (IPv6 + AbuseIPDB)

