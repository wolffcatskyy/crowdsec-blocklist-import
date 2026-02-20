# Roadmap

This document outlines the planned features and improvements for `crowdsec-blocklist-import`. We welcome community contributions to any of these items.

**Current Version:** v3.4.0
**GitHub Stars:** 167

---

## v3.4.0 — CIDR Allowlists & Prometheus Push Gateway

**Status:** Released
**Target:** Q1 2026

Adds CIDR-aware allowlist matching and provider allowlists (GitHub), plus Prometheus Push Gateway support.

### Changes
- [x] Switch from Prometheus scrape endpoint to Push Gateway (PR #35)
- [x] Add `PUSHGATEWAY_URL` environment variable
- [x] Include Grafana dashboard JSON for easy monitoring setup
- [x] Fix credential file reading regression from v3.3.0
- [x] CIDR-aware allowlist matching (`ALLOWLIST="140.82.112.0/20"`) (#38)
- [x] `ALLOWLIST_GITHUB=true` provider allowlist - auto-fetches GitHub IP ranges
- [x] Backwards-compatible: individual IPs in ALLOWLIST still work

---

## v3.5.0 — Notifications & Scheduling

**Status:** Planned
**Target:** Q2 2026

Two highly requested features that improve operational visibility and ease deployment.

### Built-in Scheduled Mode ([#5](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/5))

Currently the container runs once and exits, requiring external cron or Kubernetes CronJobs. This release adds native scheduling support.

**New Environment Variables:**
| Variable | Description |
|----------|-------------|
| `INTERVAL` | Seconds between runs (e.g., `21600` for 6 hours) |
| `SCHEDULE` | Cron expression (e.g., `0 */6 * * *`) |

**Behavior:**
- If neither is set, current run-once behavior is preserved
- Container stays running in daemon mode
- Graceful shutdown on SIGTERM/SIGINT
- Failed runs log warnings but don't kill the daemon

### Webhook Notifications ([#7](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/7))

Get notified when imports complete, fail, or encounter issues.

**Supported Platforms:**
- Discord (rich embeds with color-coded status)
- Slack (Block Kit messages)
- Generic webhooks (JSON POST)

**New Environment Variables:**
| Variable | Description |
|----------|-------------|
| `WEBHOOK_URL` | Webhook endpoint URL |
| `WEBHOOK_TYPE` | `auto` (default), `discord`, `slack`, or `generic` |

**Notification Payload:**
- Import status (success/warning/error)
- IPs imported count
- Sources OK/failed/skipped
- Version and timestamp

---

## v4.0.0 — IPv6 & AbuseIPDB

**Status:** Planned
**Target:** Q3 2026

Major feature release adding IPv6 support and the most-requested new blocklist source.

### Full IPv6 Support ([#8](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/8))

Currently only IPv4 addresses are extracted from blocklists. Many sources (Firehol, Blocklist.de, Spamhaus, Emerging Threats) include IPv6 that is silently discarded.

**Changes:**
- Extract both IPv4 and IPv6 from all blocklist sources
- Filter IPv6 private/reserved ranges:
  - `::1` (loopback)
  - `fe80::/10` (link-local)
  - `fc00::/7` (unique local)
  - `::ffff:0:0/96` (IPv4-mapped)
  - `2001:db8::/32` (documentation)
- Support CIDR notation for IPv6
- Update statistics to show IPv4/IPv6 breakdown

### AbuseIPDB Integration ([#15](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/15))

AbuseIPDB is one of the largest crowd-sourced IP reputation databases with millions of reported IPs.

**New Environment Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_ABUSEIPDB` | `false` | Enable AbuseIPDB source |
| `ABUSEIPDB_API_KEY` | — | API key for authentication |
| `ABUSEIPDB_CONFIDENCE_MINIMUM` | `90` | Minimum abuse confidence score |
| `ABUSEIPDB_LIMIT` | `500` | Max IPs to fetch per run |

**Note:** AbuseIPDB free tier allows 5 API calls/day with up to 10,000 results.

---

## Future Considerations

These items are under consideration but not yet scheduled:

### Additional Blocklist Sources
- Shodan honeypot data
- GreyNoise RIOT dataset
- Project Honeypot

### Multi-Instance Coordination
- Distributed locking to prevent duplicate imports
- Leader election for clustered deployments

### Configuration File Support
- YAML/TOML config file as alternative to environment variables
- Per-source configuration with timeouts and retry settings

### Web Dashboard
- Simple read-only web UI showing import statistics
- Historical import data visualization

---

## Contributing

We use **AI-Ready Issues** — every issue includes implementation details, acceptance criteria, and a ready-to-paste prompt for AI coding tools. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**Want to contribute?** Browse [`ai-ready` issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready) to get started.

---

## Release History

| Version | Date | Highlights |
|---------|------|------------|
| v3.4.0 | 2026-02-20 | CIDR allowlists, ALLOWLIST_GITHUB provider, Prometheus push gateway |
| v3.3.2 | 2026-02-17 | Allowlist parsing fix |
| v3.3.1 | 2026-02-17 | CrowdSec credential file fix |
| v3.3.0 | 2026-02-16 | Docker secrets, allowlists, CLI enhancements, Prometheus metrics, env validation |
| v3.1.0 | 2026-02-12 | Dead sources cleanup, allowlists |
| v3.0.0 | 2026-02-12 | Python Edition — complete rewrite with LAPI mode, streaming, per-feed control |
