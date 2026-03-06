# Changelog

All notable changes to crowdsec-blocklist-import are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

---

## [Unreleased]

### Removed

- **Spamhaus EDROP Blocklist** — Removed deprecated EDROP source. Spamhaus has merged EDROP into the main DROP list, so the EDROP URL now returns no IPs. The DROP source already includes all former EDROP entries. Fixes [#56](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/56)

---

## [3.5.0] — 2026-02-23

### Added

- **Built-in Scheduler/Daemon Mode** — Added `INTERVAL` environment variable. Run as a long-lived daemon instead of managing cron/systemd timers. Set `INTERVAL=3600` to repeat every hour. Graceful SIGTERM/SIGINT handling with current-run completion. Closes [#5](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/5)
- **Webhook Notifications** — Added `WEBHOOK_URL` and `WEBHOOK_TYPE` environment variables. Get import results pushed to Discord, Slack, or any generic JSON webhook endpoint after each run. Closes [#7](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/7)
- **AbuseIPDB Direct API Integration** — Added `ABUSEIPDB_API_KEY` environment variable. Query AbuseIPDB's blacklist API directly with configurable confidence threshold (`ABUSEIPDB_MIN_CONFIDENCE`, `ABUSEIPDB_LIMIT`). Provides higher-quality results than the community mirror. Closes [#15](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/15)
- **Spamhaus EDROP Blocklist** — Added EDROP (Extended DROP) source alongside the existing DROP feed for more aggressive reputation-based blocking
- **Per-Source Prometheus Metrics** — Enhanced metrics with proper label cardinality controls, per-source status tracking, error message sanitization, and improved Grafana dashboard

### Fixed

- **IPv4-Mapped IPv6 Filtering** — Add `::ffff:0:0/96` to private networks list. Correctly filters IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`). Closes [#8](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/8)
- **Dangerous .0 Auto-Expansion** — Removed automatic expansion of `.0` addresses to `/24` CIDR blocks. This could inadvertently block 256 addresses when a single `.0` IP appeared in a blocklist
- **Type Hints** — Fixed `parse_ip_or_network()` return type hint (was `Optional[str]`, correctly returns `tuple`)
- **Type Hints** — Fixed `flush_batch()` return type hint (was `None`, correctly returns `tuple`)
- **Docker Release Tags** — Fixed Docker image version tags by triggering builds on release:published events instead of push:tags. Ensures Docker images match code versions. Closes [#41](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/41)

### Changed

- **Deprecated Legacy Bash Script** — `import.sh` is now deprecated. The Python version provides superior performance, memory efficiency, and feature parity. Existing bash users should migrate to the Python implementation
- **Prometheus Push Gateway** — Changed from listening mode to push mode (Prometheus Pushgateway integration)

### Contributors

- Claude Opus 4.6
- gaelj

---

## [3.4.0] — 2026-02-22

### Added

- **CIDR-Aware Allowlist Matching** — Enhanced allowlist system now correctly handles CIDR ranges in addition to individual IPs. Allowlist entries can now be a mix: `192.168.1.0/24,10.0.0.1,172.16.0.0/12`
- **GitHub IP Ranges Provider** — New `ALLOWLIST_GITHUB=true` environment variable. Automatically fetches GitHub's official IP ranges (git, web, api, hooks, actions) and adds them to the allowlist. Perfect for protecting GitHub Actions and webhook endpoints
- **Complete Documentation Rewrite** — Major README rewrite with accurate environment variables, corrected source lists, and proper GHCR image references. Added `docs/` directory with four comprehensive guides:
  - `config-reference.md` — Complete environment variable reference
  - `troubleshooting.md` — Common issues and solutions
  - `faq.md` — Frequently asked questions
  - `examples.md` — Deployment examples (Docker, Kubernetes, Synology, bare metal)

### Fixed

- **Documentation Accuracy** — Fixed ~25 critical inaccuracies from initial draft (wrong env var names, fabricated features, incorrect Python version requirements)

### Changed

- **Security Policy** — Added security advisory warning about malicious clones. Users are urged to verify they're using the official source at [wolffcatskyy/crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)

### Contributors

- Claude Opus 4.6

---

## [3.3.2] — 2026-02-18

### Fixed

- **Allowlist Parsing** — Fixed filtering of empty strings when parsing `ALLOWLIST` and `CUSTOM_BLOCKLISTS` environment variables
- **Credential File Support** — Restored CrowdSec credential file support in `read_secret_file()` function

### Changed

- **Documentation** — Cleaned up allowlist documentation. Noted that `ALLOWLIST_URL` and `ALLOWLIST_FILE` are planned for future releases (not yet implemented in Python version)

---

## [3.3.1] — 2026-02-17

### Fixed

- **Prometheus Metrics** — Fixed Prometheus Pushgateway integration to use push mode correctly

### Added

- **Grafana Dashboard** — Added built-in Grafana dashboard for Prometheus metrics visualization

---

## [3.3.0] — 2026-02-16

### Added

- **ENABLE_* Variable Validation** — Added startup validation for all `ENABLE_*` environment variables. Invalid values cause the importer to fail with clear error messages. Prevents silent misconfiguration
- **CLI Flags** — Added `--version`, `--help`, and `--list-sources` flags to `import.sh` (bash version)
- **Docker Secrets Support** — Improved Docker secrets support with `_FILE` environment variable suffix. Set `CROWDSEC_MACHINE_PASSWORD_FILE=/run/secrets/password` to read from mounted secrets

### Fixed

- **Prometheus Metrics** — Changed from Counter to Gauge for `errors_total` metric (more accurate for monitoring)

### Changed

- **NixOS** — Added NixOS packaging information to README for users on NixOS/NixOS-unstable

---

## [3.2.0] — 2026-02-16

### Added

- **Prometheus Metrics Endpoint** — Added Prometheus metrics endpoint. Tracks total IPs imported, deduplication rate, failed imports per source, and import duration. Closes [#34](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/34)

### Fixed

- **Allowlist Parsing** — Fixed parsing of empty strings in `ALLOWLIST` variable
- **Block-list Cleanup** — Improved cleanup of blocklist entries
- **Credential File Support** — Improved Docker secrets support for `_FILE` environment variable variants

### Changed

- **Logging** — Improved log messages and source identification

---

## [3.0.0] — 2026-02-11

### Added

- **Complete Python Rewrite** — Rewrote the entire tool in Python 3.11+ with major performance and efficiency improvements:
  - Memory-efficient streaming (handles 500k+ IPs without loading entire file into RAM)
  - 28+ blocklist sources (feature parity with bash version)
  - LAPI mode only (no Docker socket dependency)
  - Full IPv4/IPv6 support via Python's `ipaddress` module
  - Full type hints for better IDE support and error detection
  - Structured logging with configurable levels
  - Retry logic with exponential backoff
  - Docker-ready with `python:3.11-slim` image
  - `--dry-run`, `--help`, `--version` CLI flags

### Changed

- **Performance** — Improved import speed and memory usage compared to bash version
- **Architecture** — Removed Docker socket dependency; uses direct LAPI HTTP API

### Technical Details

- Single file implementation (~650 lines of production code)
- Dependencies: `requests`, `python-dotenv`, `prometheus-client`
- Memory usage: ~50-100MB for streaming 300k+ IPs
- Speed: 500-1000 IPs/second depending on network

---

## [2.1.0] — 2026-02-04

### Added

- **Device Memory Query** — Added `BOUNCER_SSH` environment variable to query bouncer device(s) before importing. Checks available memory and ipset headroom. Deploys lightweight memory agent script on first run
- **MAX_DECISIONS Guardrail** — Added `MAX_DECISIONS` environment variable. If set, the importer stops adding IPs once the total decision count in CrowdSec reaches this limit. Prevents overloading embedded devices like UniFi. Works as source-side layer of two-layer protection (device-side memory agent is layer 2)
- **Device Memory Floor** — Added `DEVICE_MEM_FLOOR` environment variable (default 300MB). Minimum MemAvailable to preserve on bouncer device(s)

### Fixed

- **MAX_DECISIONS Default** — Fixed default `MAX_DECISIONS=40000` to prevent UniFi Network app crashes. 120K+ decisions crash the app on all tested UniFi devices when bouncer pushes them into ipset. The 40K default works safely on all devices. Closes [#21](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/21)

---

## [2.0.0] — 2026-02-03

### Added

- **Direct LAPI Mode** — Added direct CrowdSec LAPI integration without Docker socket dependency. Set `CROWDSEC_LAPI_URL`, `CROWDSEC_MACHINE_ID`, and `CROWDSEC_MACHINE_PASSWORD` for direct LAPI connection
- **8 New Threat Feeds** — Added AbuseIPDB (99% confidence), Cybercrime Tracker C2, Monty Security C2, DShield Top Attackers, VXVault Malware, IPsum Level 4+, Firehol Level 3, and Maltrail Mass Scanners
- **One-Line Installer** — Added auto-detection installer script (`install.sh`) that detects CrowdSec environment (Pangolin, Docker Compose, standalone, native) and configures LAPI credentials automatically
- **Companion Projects** — Added crowdsec-unifi-parser to Related Projects

### Fixed

- **sudo PATH Issue** — Fixed PATH issues when running `sudo ./import.sh`. Commands like `docker` and `cscli` are now found regardless of how the script is invoked (added explicit PATH export at startup)

### Changed

- **Docker Removal** — Eliminated Docker socket requirement entirely. LAPI mode is now primary (closes [#9](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/9), [#10](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/10), and resolves core issue behind [#12](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/12))
- **IP Coverage** — Increased from 60k to 95k unique IPs after deduplication with 8 new feeds

---

## [1.1.0] — 2026-01-31

### Added

- **Selective Blocklists** — Added `ENABLE_<SOURCE>` environment variables to disable individual blocklist sources. Closes [#1](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/1)
- **Custom Blocklists** — Added `CUSTOM_BLOCKLISTS` environment variable to import custom threat feed URLs. Closes [#2](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/2)
- **Dry-Run Mode** — Added `DRY_RUN=true` mode to preview imports without making changes. Closes [#3](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/3)
- **Per-Source Statistics** — Added per-source statistics summary table printed after each run. Closes [#4](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/4)
- **API Version Override** — Added `DOCKER_API_VERSION` environment variable for Docker/Engine version mismatches
- **AI-Ready Contributing** — Added structured YAML issue forms and comprehensive AI-friendly CONTRIBUTING.md based on Fedora's 2025 AI contribution policy

### Fixed

- **Private IP Regex** — Fixed private IP regex filter (extra closing parenthesis)

---

## [1.0.4] — 2026-01-26

### Added

- **Native CrowdSec Support** — Added support for native (non-Docker) CrowdSec installations via `MODE=native` environment variable

---

## [1.0.3] — 2026-01-26

### Added

- **Auto-Detection** — Automatically detects CrowdSec container (case-insensitive matching with helpful warning)
- **Better Error Messages** — Improved error messages when Docker socket is not accessible
- **Timeout Configuration** — Added `FETCH_TIMEOUT` environment variable (default 60s) for slow connections

---

## [1.0.2] — 2026-01-26

### Changed

- **User Experience** — Improved messaging: source counts displayed prominently, clearer error messages, better troubleshooting guidance

---

## [1.0.1] — 2026-01-25

### Added

- **Telemetry Support** — Added optional telemetry (opt-out via `TELEMETRY_ENABLED=false`)

---

## [1.0.0] — 2026-01-25

### Added

- **Initial Release** — First public release of crowdsec-blocklist-import
- **28+ Threat Feeds** — Support for 28+ blocklist sources including:
  - IPsum, Spamhaus DROP, Blocklist.de, Firehol, Abuse.ch
  - Emerging Threats, Binary Defense, Bruteforce Blocker
  - DShield, CI Army, Abuse IPDB, Cybercrime Tracker
  - Monty Security C2, VX Vault, Botvrij, GreenSnow
  - StopForumSpam, Tor Exit Nodes, Scanner IPs (Shodan, Censys, etc.)
- **Deduplication Engine** — Automatically detects IPs already in CrowdSec, eliminating redundant processing
- **Normalization Layer** — Strips comments, validates CIDR blocks, removes duplicates, enforces consistent formatting
- **Real-Time Sync** — Complete refresh with live threat data on every import
- **Per-Feed Control** — Enable/disable individual blocklists via environment variables
- **Allowlist Support** — Static IP and CIDR range allowlists
- **Docker Support** — Docker Compose example and Dockerfile included
- **Dry-Run Mode** — Preview imports without making changes
- **Documentation** — Comprehensive README with quickstart, configuration, and troubleshooting

---

## Versioning

This project follows [Semantic Versioning](https://semver.org):

- **MAJOR** — Breaking changes (incompatible API changes)
- **MINOR** — New features (backwards compatible)
- **PATCH** — Bug fixes (backwards compatible)

All releases are tagged on GitHub and published to [GitHub Container Registry](https://github.com/wolffcatskyy/crowdsec-blocklist-import/pkgs/container/crowdsec-blocklist-import-python).

---

**For more information, see:**

- [README.md](README.md) — Installation and quickstart
- [docs/config-reference.md](docs/config-reference.md) — Complete environment variable reference
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [GitHub Issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues) — Report bugs and request features
