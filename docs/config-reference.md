# CrowdSec Blocklist Import - Configuration Reference

**Version:** 3.4.0
**Configuration Method:** Environment Variables (no YAML config file)
**Last Updated:** 2026-02-22

---

## Overview

crowdsec-blocklist-import is configured entirely through environment variables. This document provides a complete reference for all available configuration options, including required settings, optional parameters, and advanced features.

---

## Required Variables

These variables must be set before the application can run. The application will not start without them.

| Variable | Description | Example |
|----------|-------------|---------|
| CROWDSEC_LAPI_URL | CrowdSec Local API URL | `http://localhost:8080` |
| CROWDSEC_LAPI_KEY or CROWDSEC_LAPI_KEY_FILE | Bouncer API key or path to Docker secret file | `key_abcd1234...` or `/run/secrets/lapi_key` |
| CROWDSEC_MACHINE_ID | Machine identifier for authentication | `blocklist-import` |
| CROWDSEC_MACHINE_PASSWORD or CROWDSEC_MACHINE_PASSWORD_FILE | Machine password or path to Docker secret file | `mypassword` or `/run/secrets/machine_password` |

### Notes on Required Variables

- **Docker Secrets:** Use the `_FILE` suffix to reference mounted secret files instead of passing credentials directly
- **LAPI_URL:** Must include protocol (http/https) and port. Default is `http://localhost:8080`
- **Key vs Key_FILE:** Provide either `CROWDSEC_LAPI_KEY` OR `CROWDSEC_LAPI_KEY_FILE`, not both
- **Password vs Password_FILE:** Provide either `CROWDSEC_MACHINE_PASSWORD` OR `CROWDSEC_MACHINE_PASSWORD_FILE`, not both

---

## Decision Configuration

Controls how blocklist decisions are created and managed in CrowdSec.

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| DECISION_DURATION | `24h` | How long decisions remain active | `48h`, `168h`, `1h` |
| DECISION_REASON | `external_blocklist` | Visible in `cscli decisions list` output | `blocklist-import` |
| DECISION_TYPE | `ban` | Decision action type | `ban`, `captcha`, `throttle` |
| DECISION_ORIGIN | `blocklist-import` | Origin label for filtering and auditing | `external-threat-feed` |
| DECISION_SCENARIO | `external/blocklist` | Scenario name for classification | `external/malware` |

### Notes on Decision Configuration

- **Duration Format:** Supports Go duration format: `h` (hours), `m` (minutes), `s` (seconds). CrowdSec may accept extended formats, but `h`, `m`, `s` are the verified standard units.
- **DECISION_TYPE:** Valid values are `ban` (block), `captcha` (challenge), or `throttle` (rate limit)
- **DECISION_ORIGIN:** Used to group and filter decisions; recommended to match service name
- **DECISION_SCENARIO:** Helps with alert routing and severity classification

---

## Allowlists

Configure IP addresses and networks to exclude from blocklist imports.

| Variable | Description | Example |
|----------|-------------|---------|
| ALLOWLIST | Comma-separated IPv4/IPv6 addresses and CIDR ranges | `140.82.112.0/20,8.8.8.8,2001:4860:4860::8888` |
| ALLOWLIST_GITHUB | Automatically fetch and apply GitHub IP ranges | `true`, `false` |

### Notes on Allowlists

- **Multiple Formats:** Supports individual IPs, CIDR notation, and IPv6 addresses
- **Comma Separation:** Use commas without spaces between entries
- **GitHub IPs:** When enabled, the application automatically fetches current GitHub IP ranges from the official API
- **Precedence:** Allowlisted IPs will never be imported as decisions, regardless of blocklist source

---

## Processing Configuration

Controls import behavior, performance, and output formatting.

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| BATCH_SIZE | `1000` | Number of IPs to process per API batch | `500`, `2000`, `5000` |
| FETCH_TIMEOUT | `60` | HTTP fetch timeout in seconds | `30`, `120` |
| MAX_RETRIES | `3` | Retry count on failed imports | `1`, `5`, `10` |
| LOG_LEVEL | `INFO` | Logging verbosity level | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| DRY_RUN | `false` | Preview import without applying decisions | `true`, `false` |

### Notes on Processing Configuration

- **BATCH_SIZE:** Larger batches improve throughput but consume more memory; adjust based on available resources
- **FETCH_TIMEOUT:** Increase for slow or unreliable network connections; decrease for fast-fail behavior
- **MAX_RETRIES:** Number of times to retry failed imports before skipping the blocklist
- **LOG_LEVEL:** `DEBUG` produces verbose output useful for troubleshooting; `WARN` and `ERROR` minimize output
- **DRY_RUN:** Validates configuration and shows what would be imported without modifying decisions

---

## Metrics Configuration

Controls Prometheus metrics and telemetry collection.

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| METRICS_ENABLED | `true` | Enable Prometheus metrics collection | `true`, `false` |
| METRICS_PUSHGATEWAY_URL | `localhost:9091` | Prometheus Push Gateway endpoint | `pushgateway:9091`, `http://10.0.0.5:9091` |
| TELEMETRY_ENABLED | `true` | Enable anonymous usage telemetry | `true`, `false` |

### Notes on Metrics Configuration

- **METRICS_ENABLED:** When disabled, no metrics are collected or pushed
- **METRICS_PUSHGATEWAY_URL:** Must be accessible from the application container; include hostname/IP and port
- **TELEMETRY_ENABLED:** Anonymous telemetry helps improve the application; disable if required by policy
- **Metrics Included:** IPs imported, decisions created, blocklists processed, fetch failures, batch performance

---

## Blocklist Toggle Switches

Each blocklist source can be individually enabled or disabled. All blocklists default to `true` (enabled).

| Variable | Description | Default |
|----------|-------------|---------|
| ENABLE_IPSUM | IPsum aggregated threat intelligence (IPs appearing on 3+ blocklists) | `true` |
| ENABLE_SPAMHAUS | Spamhaus DROP/EDROP lists | `true` |
| ENABLE_BLOCKLIST_DE | Blocklist.de abuse IP database | `true` |
| ENABLE_FIREHOL | FireHOL threat intelligence lists | `true` |
| ENABLE_ABUSE_CH | Abuse.ch malware IP lists | `true` |
| ENABLE_EMERGING_THREATS | Emerging Threats ETopen IP reputation | `true` |
| ENABLE_BINARY_DEFENSE | Binary Defense Systems threat feed | `true` |
| ENABLE_BRUTEFORCE_BLOCKER | Bruteforce Blocker SSH/FTP attackers | `true` |
| ENABLE_DSHIELD | DShield Internet Storm Center list | `true` |
| ENABLE_CI_ARMY | CI Army malicious IP list | `true` |
| ENABLE_BOTVRIJ | Botvrij.eu bot C&C IP list | `true` |
| ENABLE_GREENSNOW | Greensnow cybersecurity threat list | `true` |
| ENABLE_STOPFORUMSPAM | Stop Forum Spam IP blacklist | `true` |
| ENABLE_TOR | Tor exit node IP addresses | `true` |
| ENABLE_SCANNERS | Shodan/Censys scanner IPs | `true` |
| ENABLE_ABUSE_IPDB | AbuseIPDB malicious IP database | `true` |
| ENABLE_CYBERCRIME_TRACKER | Abuse.ch Cybercrime Tracker C&C IPs | `true` |
| ENABLE_MONTY_SECURITY_C2 | Monty Security C&C server tracker | `true` |
| ENABLE_VXVAULT | VXvault malware sample repository IPs | `true` |

### Notes on Blocklist Toggles

- **Format:** Set to `false` (case-insensitive) to disable; any other value enables the blocklist
- **Partial Ingestion:** Can enable/disable individual blocklists without affecting others
- **Selective Import:** Useful for testing, reducing import volume, or excluding sources with false positives
- **Update Frequency:** Each blocklist has its own update schedule; check individual source websites for refresh rates

---

## Docker Secrets Support

For secure credential management in Docker/Kubernetes environments, use the `_FILE` suffix pattern.

### Usage Pattern

Instead of passing secrets as plain environment variables:
```
CROWDSEC_LAPI_KEY=my_secret_key
```

Mount a Docker secret and reference it:
```
CROWDSEC_LAPI_KEY_FILE=/run/secrets/lapi_key
```

### Supported Variables

The following variables support the `_FILE` pattern:
- `CROWDSEC_LAPI_KEY_FILE` (instead of `CROWDSEC_LAPI_KEY`)
- `CROWDSEC_MACHINE_PASSWORD_FILE` (instead of `CROWDSEC_MACHINE_PASSWORD`)

### Docker Compose Example

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_LAPI_KEY_FILE: /run/secrets/lapi_key
      CROWDSEC_MACHINE_PASSWORD_FILE: /run/secrets/machine_password
    secrets:
      - lapi_key
      - machine_password

secrets:
  lapi_key:
    external: true
  machine_password:
    external: true
```

---

## Environment File Support

The application supports loading environment variables from a `.env` file using python-dotenv.

### .env File Example

```
# CrowdSec API Configuration
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=bouncer_key_abc123xyz
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=machine_password_123

# Decision Configuration
DECISION_DURATION=48h
DECISION_TYPE=ban
DECISION_ORIGIN=external-blocklist
DECISION_SCENARIO=external/malware

# Allowlists
ALLOWLIST=140.82.112.0/20,8.8.8.8,1.1.1.1
ALLOWLIST_GITHUB=true

# Processing
BATCH_SIZE=2000
FETCH_TIMEOUT=45
MAX_RETRIES=5
LOG_LEVEL=INFO
DRY_RUN=false

# Metrics
METRICS_ENABLED=true
METRICS_PUSHGATEWAY_URL=pushgateway:9091
TELEMETRY_ENABLED=true

# Blocklist Toggles
ENABLE_IPSUM=true
ENABLE_SPAMHAUS=true
ENABLE_ABUSE_CH=true
ENABLE_TOR=false
```

### Loading Behavior

- `.env` file is loaded automatically if present in the working directory
- Environment variables override values from `.env` file
- `_FILE` variables are resolved after `.env` loading

---

## Environment Validation

The application includes built-in validation for environment variables.

### Validation Features

- **Required Variable Checking:** Confirms all required variables are set before startup
- **Typo Detection:** Suggests corrections for common misspellings (e.g., `CROWDESC_LAPI_URL` vs correct `CROWDSEC_LAPI_URL`)
- **Format Validation:** Validates URLs, durations, numeric ranges, and boolean values
- **Credentials Verification:** Tests connectivity to CrowdSec LAPI before starting imports

### Error Messages

When validation fails, the application provides clear error messages:
```
ERROR: Missing required variable: CROWDSEC_LAPI_KEY
       Use CROWDSEC_LAPI_KEY_FILE instead to reference a Docker secret
```

```
ERROR: Invalid duration format for DECISION_DURATION: xyz
       Expected format: 24h, 48h, 168h, 1h, 30m, etc.
```

---

## Command-Line Interface (CLI)

All environment variables can be overridden via command-line flags. Flags take precedence over environment variables.

### Global Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--help` | `-h` | Boolean | Display help message and exit |
| `--version` | `-v` | Boolean | Display application version and exit |

### Configuration Flags

| Flag | Short | Type | Description | Overrides |
|------|-------|------|-------------|-----------|
| `--lapi-url` | | String | CrowdSec LAPI URL | CROWDSEC_LAPI_URL |
| `--lapi-key` | | String | Bouncer API key | CROWDSEC_LAPI_KEY |
| `--duration` | | String | Decision duration | DECISION_DURATION |
| `--batch-size` | | Integer | IPs per batch | BATCH_SIZE |

### Execution Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--dry-run` | `-n` | Boolean | Preview without importing |
| `--debug` | `-d` | Boolean | Enable debug logging |
| `--validate` | | Boolean | Validate config and exit |
| `--list-sources` | | Boolean | List all blocklist sources and exit |

### Metrics Flags

| Flag | Type | Description | Overrides |
|------|------|-------------|-----------|
| `--pushgateway-url` | String | Prometheus Push Gateway URL | METRICS_PUSHGATEWAY_URL |
| `--no-metrics` | Boolean | Disable metrics collection | METRICS_ENABLED=false |

### CLI Examples

```bash
# Display version
python blocklist_import.py -v

# Preview import without applying decisions
python blocklist_import.py --dry-run

# Override LAPI URL
python blocklist_import.py --lapi-url http://10.0.0.5:8080

# Set duration and batch size
python blocklist_import.py --duration 168h --batch-size 5000

# Validate configuration
python blocklist_import.py --validate

# List available blocklists
python blocklist_import.py --list-sources

# Enable debug logging
python blocklist_import.py --debug

# Disable metrics
python blocklist_import.py --no-metrics

# Combine multiple flags
python blocklist_import.py --dry-run --debug --batch-size 3000
```

---

## Configuration Examples

### Minimal Configuration

Required environment variables only:

```bash
CROWDSEC_LAPI_URL=http://localhost:8080
CROWDSEC_LAPI_KEY=my_bouncer_key
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=my_password
```

### Production Configuration

Recommended settings for production deployments:

```bash
# API Configuration
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY_FILE=/run/secrets/lapi_key
CROWDSEC_MACHINE_ID=blocklist-import-prod
CROWDSEC_MACHINE_PASSWORD_FILE=/run/secrets/machine_password

# Decision Configuration
DECISION_DURATION=48h
DECISION_TYPE=ban
DECISION_ORIGIN=external-blocklist
DECISION_REASON=malicious_ip_detected
DECISION_SCENARIO=external/malware

# Allowlists
ALLOWLIST=140.82.112.0/20,8.8.8.8,1.1.1.1,208.67.222.222
ALLOWLIST_GITHUB=true

# Processing
BATCH_SIZE=2000
FETCH_TIMEOUT=60
MAX_RETRIES=3
LOG_LEVEL=INFO
DRY_RUN=false

# Metrics
METRICS_ENABLED=true
METRICS_PUSHGATEWAY_URL=prometheus-pushgateway:9091
TELEMETRY_ENABLED=false

# Selective Blocklists
ENABLE_SPAMHAUS=true
ENABLE_ABUSE_CH=true
ENABLE_BLOCKLIST_DE=true
ENABLE_EMERGING_THREATS=true
ENABLE_TOR=true
ENABLE_SCANNERS=false
```

### Testing Configuration

Development/testing setup with dry-run and debug logging:

```bash
CROWDSEC_LAPI_URL=http://localhost:8080
CROWDSEC_LAPI_KEY=test_key_123
CROWDSEC_MACHINE_ID=blocklist-import-test
CROWDSEC_MACHINE_PASSWORD=test_password

DECISION_DURATION=1h
BATCH_SIZE=500
FETCH_TIMEOUT=30
LOG_LEVEL=DEBUG
DRY_RUN=true

METRICS_ENABLED=false
TELEMETRY_ENABLED=false
```

---

## Precedence Order

Configuration values are loaded in the following order (later sources override earlier ones):

1. **Default values** in the application code
2. **`.env` file** in the working directory
3. **Environment variables** in the shell/container
4. **`_FILE` variables** (Docker secrets, read and override parent variable)
5. **Command-line flags** (highest priority, always override)

Example:
```bash
# 1. Code default: LOG_LEVEL=INFO
# 2. .env file: LOG_LEVEL=WARN
# 3. Environment: LOG_LEVEL=DEBUG
# Result: DEBUG (environment variable wins)
```

---

## Common Configuration Scenarios

### Scenario 1: Import Only Critical Blocklists

Reduce false positives by importing only trusted sources:

```bash
ENABLE_IPSUM=true
ENABLE_SPAMHAUS=true
ENABLE_ABUSE_CH=true
ENABLE_EMERGING_THREATS=true
ENABLE_BLOCKLIST_DE=true

# Disable less reliable or specialized sources
ENABLE_TOR=false
ENABLE_STOPFORUMSPAM=false
ENABLE_CI_ARMY=false
ENABLE_BOTVRIJ=false
ENABLE_GREENSNOW=false
```

### Scenario 2: Aggressive Blocking (All Blocklists)

Enable all available threat intelligence sources:

```bash
# Leave all ENABLE_* variables unset or set to true (default)
# All 19 blocklists will be imported
```

### Scenario 3: Content Distribution Network (CDN) Safe Configuration

Prevent blocking of CDN and cloud provider IP ranges:

```bash
ALLOWLIST=13.32.0.0/11,13.33.0.0/16,13.34.0.0/16,13.35.0.0/16,13.36.0.0/14,13.39.0.0/17,13.40.0.0/16,13.41.0.0/16,143.204.0.0/16,144.220.0.0/16,150.222.0.0/16,52.0.0.0/8,54.0.0.0/8,99.77.0.0/16

# Additional: Auto-allow GitHub, Cloudflare, AWS, Google, Microsoft
ALLOWLIST_GITHUB=true
```

### Scenario 4: Short-Duration Temporary Blocks

Test mode with auto-expiring decisions:

```bash
DECISION_DURATION=1h
DRY_RUN=false
LOG_LEVEL=DEBUG
FETCH_TIMEOUT=30
MAX_RETRIES=1
```

### Scenario 5: High-Volume Enterprise Import

Optimize for performance with large IP lists:

```bash
BATCH_SIZE=5000
FETCH_TIMEOUT=120
MAX_RETRIES=5
LOG_LEVEL=WARN
METRICS_ENABLED=true
TELEMETRY_ENABLED=true
```

---

## Troubleshooting Configuration

### Issue: "Missing Required Variable"

**Cause:** One or more required variables are not set.

**Solution:** Ensure all required variables are set:
```bash
echo $CROWDSEC_LAPI_URL
echo $CROWDSEC_LAPI_KEY
echo $CROWDSEC_MACHINE_ID
echo $CROWDSEC_MACHINE_PASSWORD
```

### Issue: "Connection Refused" to LAPI

**Cause:** LAPI URL is incorrect or CrowdSec is not accessible.

**Solution:** Verify connectivity:
```bash
curl http://localhost:8080/health
# Or with custom URL
curl http://your-crowdsec-host:8080/health
```

### Issue: "Invalid Duration Format"

**Cause:** DECISION_DURATION uses wrong format.

**Solution:** Use Go duration format:
```bash
# CORRECT:
DECISION_DURATION=24h    # 24 hours
DECISION_DURATION=48h    # 48 hours
DECISION_DURATION=168h   # 7 days (168 hours)
DECISION_DURATION=1h30m  # 1 hour 30 minutes

# INCORRECT:
DECISION_DURATION=24     # Missing unit
DECISION_DURATION=1 day  # Space and long form not supported
```

### Issue: Credentials Not Being Read from Docker Secrets

**Cause:** `_FILE` path is incorrect or file doesn't exist.

**Solution:** Verify the secret file exists and is readable:
```bash
# Inside the container
ls -la /run/secrets/lapi_key
cat /run/secrets/lapi_key
```

### Issue: Metrics Not Appearing in Prometheus

**Cause:** Push Gateway URL is unreachable or metrics are disabled.

**Solution:** Check configuration:
```bash
echo $METRICS_ENABLED
echo $METRICS_PUSHGATEWAY_URL
# Test connectivity from container
curl http://localhost:9091/metrics
```

---

## Best Practices

1. **Use Docker Secrets:** Never pass credentials as plain environment variables in production. Use `_FILE` suffix pattern with mounted secrets.

2. **Enable Metrics:** Leave `METRICS_ENABLED=true` in production for monitoring and alerting on import failures.

3. **Set Appropriate Allowlists:** Configure `ALLOWLIST` to prevent blocking trusted IP ranges (CDN, cloud providers, internal services).

4. **Test with Dry-Run:** Always test configuration changes with `DRY_RUN=true` or `--dry-run` flag before applying to production.

5. **Log Level in Production:** Use `LOG_LEVEL=INFO` or `LOG_LEVEL=WARN` to avoid excessive disk usage from debug logs.

6. **Reasonable Batch Size:** Start with `BATCH_SIZE=1000` and adjust based on available memory and API response times.

7. **Selective Blocklists:** Disable blocklists that generate false positives in your environment (e.g., `ENABLE_TOR=false` if Tor access is needed).

8. **Monitor Decision Duration:** Choose `DECISION_DURATION` based on your threat model; shorter durations reduce impact of false positives.

9. **Use .env Files:** For local development, use a `.env` file to avoid setting environment variables manually.

10. **Regular Validation:** Run `--validate` flag periodically to catch configuration drift or typos.

---

## Related Documentation

- **Configuration Reference:** See config-reference.md (this document) for all environment variables and CLI flags
- **Troubleshooting:** See troubleshooting.md for common issues and solutions
- **CrowdSec Documentation:** https://docs.crowdsec.net
- **FAQ:** See faq.md for frequently asked questions
- **Examples:** See examples.md for deployment and configuration examples

---

## Support

For issues or questions:
- Check the Troubleshooting Configuration section above
- Run `python blocklist_import.py --validate` to verify configuration
- Enable `LOG_LEVEL=DEBUG` for detailed error information
- Review CrowdSec LAPI logs for connection issues
