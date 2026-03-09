# Roadmap

This document outlines the planned features and improvements for `crowdsec-blocklist-import`. We welcome community contributions to any of these items.

**Current Version:** v3.6.0
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

**Status:** Released
**Released:** 2026-02-23

Two highly requested features that improve operational visibility and ease deployment.

### Built-in Scheduled Mode ([#5](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/5))

- [x] `INTERVAL` environment variable for daemon mode (seconds between runs)
- [x] Graceful shutdown on SIGTERM/SIGINT
- [x] `RUN_ON_START` flag to control first-run behavior

### Webhook Notifications ([#7](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/7))

- [x] Discord, Slack, and generic JSON webhook support
- [x] `WEBHOOK_URL` and `WEBHOOK_TYPE` environment variables

### AbuseIPDB Direct API ([#15](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/15))

- [x] `ABUSEIPDB_API_KEY` for direct API queries
- [x] Configurable confidence threshold and limit

### Per-Source Prometheus Metrics

- [x] Error message sanitization for label cardinality control
- [x] Per-source status, IP count, and duration tracking

---

## v3.6.0 — Consolidation, Sentinel & CI

**Status:** Released
**Released:** 2026-03-07

### Changes

- [x] `CONSOLIDATE_ALERTS` option — single alert per run to reduce CrowdSec console alert count (#57)
- [x] Sentinel Turris blocklist source (#55, by @gaelj)
- [x] `ABUSEIPDB_API_KEY_FILE` Docker secrets support (#50, by @gaelj)
- [x] Enhanced Grafana dashboard (#54, by @gaelj)
- [x] 429 rate-limit freeze fix (#53, by @gaelj)
- [x] CI workflow with pytest, flake8, syntax checks
- [x] `pyproject.toml` for pip installation
- [x] Removed deprecated Spamhaus EDROP source (#56)
- [x] `MAX_DECISIONS` cap to prevent ipset overflow on hardware firewalls

---

## v4.0.0 — IPv6 & Advanced Features

**Status:** Planned
**Target:** Q3 2026

### Full IPv6 Support ([#8](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/8))

Currently only IPv4 addresses are extracted from blocklists. Many sources include IPv6 that is silently discarded.

**Changes:**
- Extract both IPv4 and IPv6 from all blocklist sources
- Filter IPv6 private/reserved ranges
- Support CIDR notation for IPv6
- Update statistics to show IPv4/IPv6 breakdown

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
| v3.6.0 | 2026-03-07 | CONSOLIDATE_ALERTS, Sentinel Turris, MAX_DECISIONS, CI/CD, pip-installable |
| v3.5.0 | 2026-02-23 | Daemon mode, webhooks, AbuseIPDB API, per-source metrics |
| v3.4.0 | 2026-02-20 | CIDR allowlists, ALLOWLIST_GITHUB provider, Prometheus push gateway |
| v3.3.2 | 2026-02-17 | Allowlist parsing fix |
| v3.3.1 | 2026-02-17 | CrowdSec credential file fix |
| v3.3.0 | 2026-02-16 | Docker secrets, allowlists, CLI enhancements, Prometheus metrics, env validation |
| v3.1.0 | 2026-02-12 | Dead sources cleanup, allowlists |
| v3.0.0 | 2026-02-12 | Python Edition — complete rewrite with LAPI mode, streaming, per-feed control |
