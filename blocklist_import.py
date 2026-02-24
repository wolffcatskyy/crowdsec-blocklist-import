#!/usr/bin/env python3
"""
CrowdSec Blocklist Import - Python Edition

A memory-efficient implementation that imports 28+ public threat feeds
directly into CrowdSec via the LAPI HTTP API.

Features:
- Streaming downloads (no full file in memory)
- Batch processing (configurable batch size)
- IPv4 and IPv6 support
- Automatic deduplication
- Retry logic with exponential backoff
- Full type hints
- Per-source Prometheus metrics (status, IPs, duration, errors with message)

Authors:

- Claude AI (wolffcatskyy/crowdsec-blocklist-import)
- gaelj

License: MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Generator, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Optional Prometheus metrics support
try:
    from prometheus_client import CollectorRegistry, Gauge, Histogram, push_to_gateway, delete_from_gateway
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Optional dotenv support - not required if env vars are set directly
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        """Stub if python-dotenv is not installed."""
        pass

__version__ = "3.5.0"

# =============================================================================
# Environment Variable Validation
# =============================================================================

# All valid ENABLE_* environment variable names (canonical list)
VALID_ENABLE_VARS: set[str] = {
    "ENABLE_IPSUM",
    "ENABLE_SPAMHAUS",
    "ENABLE_BLOCKLIST_DE",
    "ENABLE_FIREHOL",
    "ENABLE_ABUSE_CH",
    "ENABLE_EMERGING_THREATS",
    "ENABLE_BINARY_DEFENSE",
    "ENABLE_BRUTEFORCE_BLOCKER",
    "ENABLE_DSHIELD",
    "ENABLE_CI_ARMY",
    "ENABLE_BOTVRIJ",
    "ENABLE_GREENSNOW",
    "ENABLE_STOPFORUMSPAM",
    "ENABLE_TOR",
    "ENABLE_SCANNERS",
    "ENABLE_ABUSE_IPDB",
    "ENABLE_CYBERCRIME_TRACKER",
    "ENABLE_MONTY_SECURITY_C2",
    "ENABLE_VXVAULT",
}

# Valid boolean string values (case-insensitive)
VALID_BOOL_VALUES: set[str] = {"true", "false", "1", "0", "yes", "no", "on", "off"}


class EnvValidationError(Exception):
    """Raised when environment variable validation fails."""
    pass


def validate_bool_value(var_name: str, value: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a value is a valid boolean string.

    Returns (is_valid, error_message).
    """
    if value.lower() in VALID_BOOL_VALUES:
        return True, None

    return False, (
        f"Invalid value for {var_name}: '{value}'\n"
        f"  Expected one of: true, false, 1, 0, yes, no, on, off (case-insensitive)"
    )


def find_similar_vars(unknown_var: str, valid_vars: set[str]) -> list[str]:
    """
    Find similar variable names for typo suggestions.

    Uses simple substring matching and edit distance approximation.
    """
    suggestions = []
    unknown_lower = unknown_var.lower()

    for valid in valid_vars:
        valid_lower = valid.lower()

        # Exact substring match (missing/extra characters)
        if unknown_lower in valid_lower or valid_lower in unknown_lower:
            suggestions.append(valid)
            continue

        # Check for common typos (swapped characters, missing underscore, etc.)
        # Remove underscores and compare
        unknown_compact = unknown_lower.replace("_", "")
        valid_compact = valid_lower.replace("_", "")

        if unknown_compact == valid_compact:
            suggestions.append(valid)
            continue

        # Check if most characters match (simple similarity)
        common = sum(1 for c in unknown_compact if c in valid_compact)
        if common >= len(valid_compact) * 0.7:
            suggestions.append(valid)

    return suggestions


def validate_enable_env_vars(logger: Optional[logging.Logger] = None) -> tuple[bool, list[str]]:
    """
    Validate all ENABLE_* environment variables.

    Checks:
    1. All ENABLE_* vars have valid boolean values
    2. Warns about unknown ENABLE_* vars (possible typos)

    Returns (is_valid, list_of_errors).
    """
    errors: list[str] = []
    warnings: list[str] = []

    for var_name, value in os.environ.items():
        if not var_name.startswith("ENABLE_"):
            continue

        # Check if it's a known variable
        if var_name not in VALID_ENABLE_VARS:
            suggestions = find_similar_vars(var_name, VALID_ENABLE_VARS)

            if suggestions:
                suggestion_text = ", ".join(suggestions[:3])
                warnings.append(
                    f"Unknown environment variable: {var_name}={value}\n"
                    f"  Did you mean: {suggestion_text}?"
                )
            else:
                warnings.append(
                    f"Unknown environment variable: {var_name}={value}\n"
                    f"  This variable will be ignored. Check spelling or see available options below."
                )
        else:
            # Validate the boolean value
            is_valid, error = validate_bool_value(var_name, value)
            if not is_valid:
                errors.append(error)

    # Log warnings (don't fail, just warn)
    if logger and warnings:
        for warning in warnings:
            logger.warning(warning)

    return len(errors) == 0, errors


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Configuration loaded from environment variables."""

    # CrowdSec LAPI settings
    lapi_url: str = "http://localhost:8080"
    lapi_key: str = ""  # Bouncer API key (for reading decisions)
    lapi_key_file: str = ""  # Bouncer API key file (for reading decisions)

    # Machine credentials (for writing decisions via /alerts endpoint)
    # These are alternative to lapi_key for write operations
    machine_id: str = ""
    machine_password: str = ""
    machine_password_file: str = ""

    # Decision settings
    decision_duration: str = "24h"
    decision_reason: str = "external_blocklist"
    decision_type: str = "ban"
    decision_origin: str = "blocklist-import"
    decision_scenario: str = "external/blocklist"

    # Processing settings
    allow_list: list[str] = None
    custom_block_lists: list[str] = None
    batch_size: int = 1000
    fetch_timeout: int = 60
    max_retries: int = 3
    log_timestamps: bool = True

    # Logging
    log_level: str = "INFO"

    # Dry run mode
    dry_run: bool = False

    # Telemetry
    telemetry_enabled: bool = True
    telemetry_url: str = "https://bouncer-telemetry.ms2738.workers.dev/ping"

    # Prometheus metrics
    metrics_enabled: bool = True
    pushgateway_url: str = "localhost:9091"

    # Daemon mode (built-in scheduler)
    interval: int = 0  # 0 = run once (default), >0 = repeat every N seconds
    run_on_start: bool = True  # Run immediately on start, then wait for interval

    # Webhook notifications
    webhook_url: str = ""
    webhook_type: str = "generic"  # generic, discord, slack

    # AbuseIPDB direct API
    abuseipdb_api_key: str = ""
    abuseipdb_min_confidence: int = 90
    abuseipdb_limit: int = 10000

    # Provider allowlists
    allowlist_github: bool = False

    # Blocklist enables (all enabled by default)
    enable_ipsum: bool = True
    enable_spamhaus: bool = True
    enable_blocklist_de: bool = True
    enable_firehol: bool = True
    enable_abuse_ch: bool = True
    enable_emerging_threats: bool = True
    enable_binary_defense: bool = True
    enable_bruteforce_blocker: bool = True
    enable_dshield: bool = True
    enable_ci_army: bool = True
    enable_botvrij: bool = True
    enable_greensnow: bool = True
    enable_stopforumspam: bool = True
    enable_tor: bool = True
    enable_scanners: bool = True
    enable_abuseipdb: bool = True
    enable_cybercrime_tracker: bool = True
    enable_monty_security_c2: bool = True
    enable_vxvault: bool = True

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        load_dotenv()

        def get_bool(key: str, default: bool = True) -> bool:
            val = os.getenv(key, str(default)).lower()
            return val in ("true", "1", "yes", "on")

        return cls(
            lapi_url=os.getenv("CROWDSEC_LAPI_URL", "http://localhost:8080").rstrip("/"),
            lapi_key=os.getenv("CROWDSEC_LAPI_KEY", ""),
            lapi_key_file=os.getenv("CROWDSEC_LAPI_KEY_FILE", ""),
            machine_id=os.getenv("CROWDSEC_MACHINE_ID", ""),
            machine_password=os.getenv("CROWDSEC_MACHINE_PASSWORD", ""),
            machine_password_file=os.getenv("CROWDSEC_MACHINE_PASSWORD_FILE", ""),
            decision_duration=os.getenv("DECISION_DURATION", "24h"),
            decision_reason=os.getenv("DECISION_REASON", "external_blocklist"),
            decision_type=os.getenv("DECISION_TYPE", "ban"),
            decision_origin=os.getenv("DECISION_ORIGIN", "blocklist-import"),
            decision_scenario=os.getenv("DECISION_SCENARIO", "external/blocklist"),
            allow_list=[ l.strip() for l in os.getenv("ALLOWLIST", "").split(",") if l.strip() ],
            allowlist_github=get_bool("ALLOWLIST_GITHUB", False),
            custom_block_lists=[ l.strip() for l in os.getenv("CUSTOM_BLOCKLISTS", "").split(",") if l.strip() ],
            batch_size=int(os.getenv("BATCH_SIZE", "1000")),
            fetch_timeout=int(os.getenv("FETCH_TIMEOUT", "60")),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_timestamps=get_bool("LOG_TIMESTAMPS"),
            dry_run=get_bool("DRY_RUN", False),
            telemetry_enabled=get_bool("TELEMETRY_ENABLED", True),
            telemetry_url=os.getenv("TELEMETRY_URL", "https://bouncer-telemetry.ms2738.workers.dev/ping"),
            metrics_enabled=get_bool("METRICS_ENABLED", True),
            pushgateway_url=os.getenv("METRICS_PUSHGATEWAY_URL", "localhost:9091"),
            interval=int(os.getenv("INTERVAL", "0")),
            run_on_start=get_bool("RUN_ON_START", True),
            webhook_url=os.getenv("WEBHOOK_URL", ""),
            webhook_type=os.getenv("WEBHOOK_TYPE", "generic").lower(),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            abuseipdb_min_confidence=int(os.getenv("ABUSEIPDB_MIN_CONFIDENCE", "90")),
            abuseipdb_limit=int(os.getenv("ABUSEIPDB_LIMIT", "10000")),
            enable_ipsum=get_bool("ENABLE_IPSUM"),
            enable_spamhaus=get_bool("ENABLE_SPAMHAUS"),
            enable_blocklist_de=get_bool("ENABLE_BLOCKLIST_DE"),
            enable_firehol=get_bool("ENABLE_FIREHOL"),
            enable_abuse_ch=get_bool("ENABLE_ABUSE_CH"),
            enable_emerging_threats=get_bool("ENABLE_EMERGING_THREATS"),
            enable_binary_defense=get_bool("ENABLE_BINARY_DEFENSE"),
            enable_bruteforce_blocker=get_bool("ENABLE_BRUTEFORCE_BLOCKER"),
            enable_dshield=get_bool("ENABLE_DSHIELD"),
            enable_ci_army=get_bool("ENABLE_CI_ARMY"),
            enable_botvrij=get_bool("ENABLE_BOTVRIJ"),
            enable_greensnow=get_bool("ENABLE_GREENSNOW"),
            enable_stopforumspam=get_bool("ENABLE_STOPFORUMSPAM"),
            enable_tor=get_bool("ENABLE_TOR"),
            enable_scanners=get_bool("ENABLE_SCANNERS"),
            enable_abuseipdb=get_bool("ENABLE_ABUSE_IPDB"),
            enable_cybercrime_tracker=get_bool("ENABLE_CYBERCRIME_TRACKER"),
            enable_monty_security_c2=get_bool("ENABLE_MONTY_SECURITY_C2"),
            enable_vxvault=get_bool("ENABLE_VXVAULT"),
        )


# =============================================================================
# Blocklist Sources
# =============================================================================

@dataclass
class BlocklistSource:
    """Represents a blocklist source."""
    name: str
    url: str
    enabled_key: str
    comment_char: str = "#"
    extract_field: Optional[int] = None  # Field index (0-based) to extract from lines

# Define all blocklist sources
BLOCKLIST_SOURCES: list[BlocklistSource] = [
    # IPsum - aggregated threat intel (level 3+ = on 3+ lists)
    BlocklistSource(
        name="IPsum",
        url="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        enabled_key="enable_ipsum",
    ),
    # Spamhaus DROP
    BlocklistSource(
        name="Spamhaus DROP",
        url="https://www.spamhaus.org/drop/drop.txt",
        enabled_key="enable_spamhaus",
        comment_char=";",
        extract_field=0,
    ),
    # Blocklist.de
    BlocklistSource(
        name="Blocklist.de all",
        url="https://lists.blocklist.de/lists/all.txt",
        enabled_key="enable_blocklist_de",
    ),
    BlocklistSource(
        name="Blocklist.de SSH",
        url="https://lists.blocklist.de/lists/ssh.txt",
        enabled_key="enable_blocklist_de",
    ),
    BlocklistSource(
        name="Blocklist.de Apache",
        url="https://lists.blocklist.de/lists/apache.txt",
        enabled_key="enable_blocklist_de",
    ),
    BlocklistSource(
        name="Blocklist.de mail",
        url="https://lists.blocklist.de/lists/mail.txt",
        enabled_key="enable_blocklist_de",
    ),
    # Firehol
    BlocklistSource(
        name="Firehol level1",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        enabled_key="enable_firehol",
    ),
    BlocklistSource(
        name="Firehol level2",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        enabled_key="enable_firehol",
    ),
    # Abuse.ch
    BlocklistSource(
        name="Feodo Tracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        enabled_key="enable_abuse_ch",
    ),
    BlocklistSource(
        name="URLhaus",
        url="https://urlhaus.abuse.ch/downloads/text_online/",
        enabled_key="enable_abuse_ch",
    ),
    # Other sources
    BlocklistSource(
        name="Emerging Threats",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        enabled_key="enable_emerging_threats",
    ),
    BlocklistSource(
        name="Binary Defense",
        url="https://www.binarydefense.com/banlist.txt",
        enabled_key="enable_binary_defense",
    ),
    BlocklistSource(
        name="Bruteforce Blocker",
        url="https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        enabled_key="enable_bruteforce_blocker",
    ),
    BlocklistSource(
        name="DShield",
        url="https://www.dshield.org/block.txt",
        enabled_key="enable_dshield",
        extract_field=0,
    ),
    BlocklistSource(
        name="CI Army",
        url="https://cinsscore.com/list/ci-badguys.txt",
        enabled_key="enable_ci_army",
    ),
    BlocklistSource(
        name="Botvrij",
        url="https://www.botvrij.eu/data/ioclist.ip-dst.raw",
        enabled_key="enable_botvrij",
    ),
    BlocklistSource(
        name="GreenSnow",
        url="https://blocklist.greensnow.co/greensnow.txt",
        enabled_key="enable_greensnow",
    ),
    BlocklistSource(
        name="StopForumSpam",
        url="https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt",
        enabled_key="enable_stopforumspam",
    ),
    # Tor exit nodes
    BlocklistSource(
        name="Tor exit nodes",
        url="https://check.torproject.org/torbulkexitlist",
        enabled_key="enable_tor",
    ),
    BlocklistSource(
        name="Tor (dan.me.uk)",
        url="https://www.dan.me.uk/torlist/?exit",
        enabled_key="enable_tor",
    ),
    # Scanners
    BlocklistSource(
        name="Shodan scanners",
        url="https://gist.githubusercontent.com/jfqd/4ff7fa70950626a11832a4bc39451c1c/raw",
        enabled_key="enable_scanners",
    ),
    # AbuseIPDB 99% confidence (via borestad mirror)
    BlocklistSource(
        name="AbuseIPDB",
        url="https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-1d.ipv4",
        enabled_key="enable_abuseipdb",
    ),
    # Cybercrime Tracker C2 (FireHOL mirror)
    BlocklistSource(
        name="Cybercrime Tracker",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset",
        enabled_key="enable_cybercrime_tracker",
    ),
    # Monty Security C2 Tracker
    BlocklistSource(
        name="Monty Security C2",
        url="https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
        enabled_key="enable_monty_security_c2",
    ),
    # DShield Top Attackers
    BlocklistSource(
        name="DShield Top Attackers",
        url="https://feeds.dshield.org/top10-2.txt",
        enabled_key="enable_dshield",
        extract_field=0,
    ),
    # VXVault Malware (FireHOL mirror)
    BlocklistSource(
        name="VXVault",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/vxvault.ipset",
        enabled_key="enable_vxvault",
    ),
    # --- Tier 2 Extended Coverage Blocklists ---
    # IPsum Level 4+ (higher confidence than existing level 3)
    BlocklistSource(
        name="IPsum level4",
        url="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
        enabled_key="enable_ipsum",
    ),
    # Firehol Level 3 (extended 30-day coverage)
    BlocklistSource(
        name="Firehol level3",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        enabled_key="enable_firehol",
    ),
    # Maltrail mass scanners
    BlocklistSource(
        name="Maltrail scanners",
        url="https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt",
        enabled_key="enable_scanners",
    )
]

# Static scanner IPs (Censys)
STATIC_SCANNER_IPS: list[str] = [
    "192.35.168.0/23",
    "162.142.125.0/24",
    "74.120.14.0/24",
    "167.248.133.0/24",
]


def list_blocklist_sources(logger: logging.Logger) -> None:
    """Print a formatted list of all available blocklist sources."""
    logger.info("Available blocklist sources:")
    logger.info("")

    # Group sources by their enable key
    sources_by_key: dict[str, list[str]] = {}
    for source in BLOCKLIST_SOURCES:
        env_var = source.enabled_key.upper()
        if env_var not in sources_by_key:
            sources_by_key[env_var] = []
        sources_by_key[env_var].append(source.name)

    # Print each group
    for env_var in sorted(sources_by_key.keys()):
        sources = sources_by_key[env_var]
        current_value = os.getenv(env_var, "true").lower()
        status = "enabled" if current_value in ("true", "1", "yes", "on") else "disabled"

        logger.info(f"  {env_var} ({status}):")
        for source in sources:
            logger.info(f"    - {source}")

    logger.info("")


# =============================================================================
# Prometheus Metrics — error message sanitization
# =============================================================================

# Fixed-category error message labels to bound Prometheus label cardinality.
# Raw exception strings (containing hostnames, ports, retry counts, etc.)
# must NEVER be used directly as label values — doing so creates a new time
# series per unique string and causes storage bloat in the Pushgateway (issue #3).
#
# Every call-site that records an error MUST pass the exception through
# sanitize_error_message() before using it as a label value.

_ERROR_PATTERNS: list[tuple[str, str]] = [
    # requests / urllib3 transport errors — checked against class name first
    ("ConnectionError",         "connection_error"),
    ("ConnectTimeout",          "connect_timeout"),
    ("ReadTimeout",             "read_timeout"),
    ("Timeout",                 "timeout"),
    ("SSLError",                "ssl_error"),
    ("TooManyRedirects",        "too_many_redirects"),
    ("ChunkedEncodingError",    "chunked_encoding_error"),
    ("ContentDecodingError",    "content_decoding_error"),
    # HTTP status codes embedded in HTTPError messages
    ("404",                     "http_404"),
    ("403",                     "http_403"),
    ("429",                     "http_429"),
    ("500",                     "http_500"),
    ("502",                     "http_502"),
    ("503",                     "http_503"),
    ("504",                     "http_504"),
    ("HTTPError",               "http_error"),
    # Misc
    ("UnicodeDecodeError",      "unicode_decode_error"),
    ("JSONDecodeError",         "json_decode_error"),
    ("ValueError",              "value_error"),
]


def sanitize_error_message(exc: Exception) -> str:
    """
    Convert an exception into a fixed-category string safe for use as a
    Prometheus label value.

    Iterates through a priority-ordered list of known patterns (class name
    substrings and HTTP status codes). Returns the first match, or the
    exception *class name* as a stable fallback.

    Never returns the raw str(exc), which may contain hostnames, ports,
    retry counts, or other unbounded content that would create a new
    Prometheus time series on every run (issue #3).
    """
    exc_type = type(exc).__name__
    exc_str = str(exc)

    for pattern, category in _ERROR_PATTERNS:
        if pattern in exc_type or pattern in exc_str:
            return category

    # Fallback: exception class name — finite and stable across runs
    return exc_type[:64]


# =============================================================================
# Prometheus Metrics
# =============================================================================

class MetricsCollector:
    """
    Prometheus metrics collector for blocklist import.

    Per-source granularity:
      - blocklist_import_source_status{source}
            Gauge: 1 = success, 0 = failed.
            Success/failure is encoded as the *value*, not a label (issue #4).
      - blocklist_import_source_ips{source}               IPs fetched per source
      - blocklist_import_source_duration_seconds{source}  fetch time per source
      - blocklist_import_errors_total{error_type, source, message}
            error_type: "fetch" | "parse" | "import" | "encoding"  (issue #5)
            message: sanitized fixed-category string — never raw exception text,
            to keep label cardinality bounded (issue #3).

    Aggregate gauges (for stat panels / success-rate):
      - blocklist_import_total_ips
      - blocklist_import_new_ips
      - blocklist_import_existing_decisions
      - blocklist_import_encoding_errors_total            (issue #5)
      - blocklist_import_sources_enabled / _successful / _failed
      - blocklist_import_last_run_timestamp
      - blocklist_import_duration_seconds (histogram)

    Stale-gauge strategy (issue #6):
      The CollectorRegistry is re-created fresh for every run, and
      delete_from_gateway() is called before push_to_gateway(). This ensures
      that error/source metrics from a prior run that do not recur are
      removed from the Pushgateway rather than persisting indefinitely.
    """

    def __init__(self, pushgateway_url: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.pushgateway_url = pushgateway_url  # e.g., "localhost:9091"
        self.logger = logger or logging.getLogger("blocklist-import")
        # Fresh registry per run — prevents stale label combinations from
        # lingering in the Pushgateway across runs (issue #6).
        self.registry = CollectorRegistry()

        if not PROMETHEUS_AVAILABLE:
            self.logger.warning(
                "prometheus-client not installed. Metrics disabled. "
                "Install with: pip install prometheus-client"
            )
            return

        # Gauge: Total IPs currently imported
        self.total_ips = Gauge(
            "blocklist_import_total_ips",
            "Total number of IPs imported in the last run",
            registry=self.registry,
        )

        # Gauge: Unix timestamp of last successful run
        self.last_run_timestamp = Gauge(
            "blocklist_import_last_run_timestamp",
            "Unix timestamp of the last import run",
            registry=self.registry,
        )

        # Gauge: Number of enabled blocklist sources
        self.sources_enabled = Gauge(
            "blocklist_import_sources_enabled",
            "Number of enabled blocklist sources",
            registry=self.registry,
        )

        # Per-error detail.
        # error_type = "fetch" | "parse" | "import" | "encoding"
        # source      = BlocklistSource.name  (stable, human-readable)
        # message     = sanitized fixed-category string — never raw exception text.
        #               See sanitize_error_message() for the full category list.
        self.errors_total = Gauge(
            "blocklist_import_errors_total",
            "Import errors labelled by type, source, and sanitized message category. "
            "message values are fixed categories (not raw exception strings) to bound cardinality.",
            ["error_type", "source", "message"],
            registry=self.registry,
        )

        self.duration_seconds = Histogram(
            "blocklist_import_duration_seconds",
            "Duration of full import run in seconds",
            buckets=[1, 5, 10, 30, 60, 120, 300, 600],
            registry=self.registry,
        )

        self.sources_successful = Gauge(
            "blocklist_import_sources_successful",
            "Number of sources successfully fetched in the last run",
            registry=self.registry,
        )

        self.sources_failed = Gauge(
            "blocklist_import_sources_failed",
            "Number of sources that failed to fetch in the last run",
            registry=self.registry,
        )

        self.existing_decisions = Gauge(
            "blocklist_import_existing_decisions",
            "Number of existing CrowdSec decisions found",
            registry=self.registry,
        )

        self.new_ips = Gauge(
            "blocklist_import_new_ips",
            "Number of new unique IPs added in the last run",
            registry=self.registry,
        )

        # Encoding errors were tracked in stats but previously invisible in
        # Prometheus. Now exposed as a top-level gauge
        self.encoding_errors_total = Gauge(
            "blocklist_import_encoding_errors_total",
            "Total number of lines skipped due to encoding errors across all sources",
            registry=self.registry,
        )

        # Per-source granular metrics.
        # source_status value: 1 = success, 0 = failed.
        # There is intentionally NO 'status' label — value encodes the state
        self.source_status = Gauge(
            "blocklist_import_source_status",
            "Per-source fetch status: 1=success, 0=failed",
            ["source"],
            registry=self.registry,
        )

        self.source_ips = Gauge(
            "blocklist_import_source_ips",
            "Number of unique new IPs fetched from each source in the last run",
            ["source"],
            registry=self.registry,
            )

        self.source_duration_seconds = Gauge(
            "blocklist_import_source_duration_seconds",
            "Time taken to fetch and parse each source (seconds)",
            ["source"],
            registry=self.registry,
        )

    # ------------------------------------------------------------------
    # Per-source helpers — called directly from fetch_blocklist / run_import
    # ------------------------------------------------------------------

    def record_source_success(self, source_name: str, ip_count: int, duration: float) -> None:
        """Record a successful source fetch."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.source_status.labels(source=source_name).set(1)
        self.source_ips.labels(source=source_name).set(ip_count)
        self.source_duration_seconds.labels(source=source_name).set(duration)

    def record_source_failure(self, source_name: str, error_type: str,
                               exc: Optional[Exception], duration: float) -> None:
        """
        Record a failed source fetch.

        exc is sanitized to a fixed category string before being stored as a
        label value — never use str(exc) directly (issue #3).
        """
        if not PROMETHEUS_AVAILABLE:
            return
        self.source_status.labels(source=source_name).set(0)
        self.source_ips.labels(source=source_name).set(0)
        self.source_duration_seconds.labels(source=source_name).set(duration)
        short_msg = sanitize_error_message(exc) if isinstance(exc, Exception) else (str(exc)[:64] if exc else "unknown")
        self.errors_total.labels(
            error_type=error_type,
            source=source_name,
            message=short_msg,
        ).set(1)

    def record_parse_errors(self, source_name: str, errors: dict[str, int]) -> None:
        """
        Record per-source parse errors.

        Bad token strings are truncated to 64 chars. Unlike exception
        messages, parse tokens are naturally bounded per source.
        """
        if not PROMETHEUS_AVAILABLE or not errors:
            return
        for bad_token, count in errors.items():
            short_token = bad_token[:120]
            self.errors_total.labels(
                error_type="parse",
                source=source_name,
                message=short_token,
            ).set(count)

    def record_encoding_errors(self, count: int) -> None:
        """
        Record the aggregate encoding error count (issue #5).

        Previously these were tracked in ImportStats and logged but never
        surfaced in Prometheus. Now visible as blocklist_import_encoding_errors_total.
        """
        if not PROMETHEUS_AVAILABLE or count == 0:
            return
        self.encoding_errors_total.set(count)

    # ------------------------------------------------------------------
    # End-of-run aggregate update
    # ------------------------------------------------------------------

    def update_aggregates(self, stats: "ImportStats", enabled_count: int) -> None:
        """Update scalar/aggregate gauges at end of run."""
        if not PROMETHEUS_AVAILABLE:
            return
        self.total_ips.set(stats.imported_ok)
        self.new_ips.set(stats.new_ips)
        self.last_run_timestamp.set(time.time())
        self.sources_enabled.set(enabled_count)
        self.sources_successful.set(stats.sources_ok)
        self.sources_failed.set(stats.sources_failed)
        self.existing_decisions.set(stats.existing_skipped)
        self.duration_seconds.observe(stats.duration_seconds)
        self.record_encoding_errors(stats.encoding_errors)

    def push(self) -> bool:
        """
        Push all metrics to the Pushgateway.

        Calls delete_from_gateway() first to remove any label combinations
        from previous runs that are not present in the current run. Without
        this, resolved errors and disabled sources would persist in the
        Pushgateway indefinitely (issue #6).
        """
        if not PROMETHEUS_AVAILABLE or not self.pushgateway_url:
            return False
        try:
            # Remove stale time series from the previous run.
            # Non-fatal: if deletion fails we warn but still push, which will
            # overwrite any series present in both runs.
            try:
                delete_from_gateway(
                    self.pushgateway_url,
                    job="crowdsec-blocklist-import",
                )
            except Exception as del_exc:
                self.logger.warning(
                    f"Could not delete stale metrics from Pushgateway "
                    f"({self.pushgateway_url}): {del_exc}"
                )

            push_to_gateway(
                self.pushgateway_url,
                job="crowdsec-blocklist-import",
                registry=self.registry,
            )
            self.logger.info(f"Metrics pushed to Pushgateway at {self.pushgateway_url}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to push metrics to {self.pushgateway_url}: {e}")
            return False


# Global metrics instance (initialized in main)
_metrics: Optional[MetricsCollector] = None


def get_metrics() -> Optional[MetricsCollector]:
    """Get the global metrics collector instance."""
    return _metrics


def init_metrics(pushgateway_url: str, logger: logging.Logger) -> MetricsCollector:
    """Initialize the global metrics collector."""
    global _metrics
    _metrics = MetricsCollector(pushgateway_url=pushgateway_url, logger=logger)
    return _metrics


# =============================================================================
# IP Validation
# =============================================================================

# Private/reserved IP ranges to exclude
PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    # IPv6 private ranges
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("fc00::/7"),  # Unique local
    ipaddress.ip_network("fe80::/10"),  # Link-local
    ipaddress.ip_network("ff00::/8"),  # Multicast
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]

# Well-known IPs to exclude (DNS resolvers, etc.)
EXCLUDED_IPS: Set[str] = {
    "1.0.0.1", "1.1.1.1",  # Cloudflare
    "8.8.8.8", "8.8.4.4",  # Google
    "9.9.9.9",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}


# =============================================================================
# Allowlist with CIDR Support
# =============================================================================

# GitHub meta API URL for fetching their IP ranges
GITHUB_META_URL = "https://api.github.com/meta"
GITHUB_META_SECTIONS = ["git", "web", "api", "hooks", "actions"]

# Fallback GitHub ranges if the API is unreachable
GITHUB_FALLBACK_RANGES = [
    "140.82.112.0/20",
    "185.199.108.0/22",
    "192.30.252.0/22",
    "143.55.64.0/20",
]


class Allowlist:
    """
    CIDR-aware allowlist for filtering IPs.

    Supports both individual IPs and CIDR ranges. Uses Python's ipaddress
    module for proper containment checks. Individual IPs are stored in a set
    for O(1) lookup; CIDR networks are checked via containment.

    To keep performance reasonable, CIDR networks are stored in a sorted list
    and checked sequentially. For typical allowlist sizes (dozens to hundreds
    of entries), this is fast enough. The individual IPs set provides a fast
    path for the common case.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self._exact_ips: Set[str] = set()
        self._networks_v4: list[ipaddress.IPv4Network] = []
        self._networks_v6: list[ipaddress.IPv6Network] = []
        self._logger = logger or logging.getLogger("blocklist-import")

    @property
    def entry_count(self) -> int:
        """Total number of allowlist entries (IPs + networks)."""
        return len(self._exact_ips) + len(self._networks_v4) + len(self._networks_v6)

    def add_entry(self, entry: str) -> None:
        """
        Add an IP or CIDR range to the allowlist.

        Args:
            entry: An IP address (e.g., "1.2.3.4") or CIDR range (e.g., "140.82.112.0/20")
        """
        entry = entry.strip()
        if not entry:
            return

        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    self._networks_v4.append(network)
                else:
                    self._networks_v6.append(network)
            else:
                # Validate it's a real IP, then store as string for fast lookup
                ipaddress.ip_address(entry)
                self._exact_ips.add(entry)
        except (ValueError, TypeError) as e:
            self._logger.warning(f"Invalid allowlist entry '{entry}': {e}")

    def add_entries(self, entries: list[str]) -> None:
        """Add multiple entries to the allowlist."""
        for entry in entries:
            self.add_entry(entry)

    def contains(self, ip_str: str) -> bool:
        """
        Check if an IP address or CIDR is in the allowlist.

        For individual IPs: checks exact match and CIDR containment.
        For CIDR ranges from blocklists: checks if the range overlaps with
        any allowlisted network.

        Args:
            ip_str: An IP address or CIDR string to check.

        Returns:
            True if the IP/CIDR should be allowlisted (skipped).
        """
        # Fast path: exact string match
        if ip_str in self._exact_ips:
            return True

        try:
            if "/" in ip_str:
                # It's a CIDR from a blocklist - check overlap with allowlisted networks
                network = ipaddress.ip_network(ip_str, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    for allowed_net in self._networks_v4:
                        if network.overlaps(allowed_net):
                            return True
                else:
                    for allowed_net in self._networks_v6:
                        if network.overlaps(allowed_net):
                            return True
            else:
                # It's a single IP - check containment in allowlisted networks
                ip = ipaddress.ip_address(ip_str)
                if isinstance(ip, ipaddress.IPv4Address):
                    for network in self._networks_v4:
                        if ip in network:
                            return True
                else:
                    for network in self._networks_v6:
                        if ip in network:
                            return True
        except (ValueError, TypeError):
            pass

        return False

    def fetch_github_ranges(self, session: Optional[requests.Session] = None) -> int:
        """
        Fetch GitHub's published IP ranges from their meta API and add to allowlist.

        Falls back to hardcoded ranges if the API is unreachable.

        Args:
            session: Optional requests session to use. Creates a new one if not provided.

        Returns:
            Number of ranges added.
        """
        if session is None:
            session = requests.Session()

        ranges_added = 0
        try:
            self._logger.info("Fetching GitHub IP ranges from meta API...")
            response = session.get(
                GITHUB_META_URL,
                timeout=10,
                headers={"User-Agent": f"crowdsec-blocklist-import/{__version__}"},
            )
            response.raise_for_status()
            data = response.json()

            seen = set()
            for section in GITHUB_META_SECTIONS:
                for cidr in data.get(section, []):
                    if cidr not in seen:
                        seen.add(cidr)
                        self.add_entry(cidr)
                        ranges_added += 1

            self._logger.info(f"Added {ranges_added} GitHub IP ranges to allowlist")

        except Exception as e:
            self._logger.warning(f"Could not fetch GitHub meta API ({e}), using fallback ranges")
            for cidr in GITHUB_FALLBACK_RANGES:
                self.add_entry(cidr)
                ranges_added += 1
            self._logger.info(f"Added {ranges_added} fallback GitHub IP ranges to allowlist")

        return ranges_added


def build_allowlist(config: "Config", session: Optional[requests.Session] = None,
                    logger: Optional[logging.Logger] = None) -> Allowlist:
    """
    Build an Allowlist from the configuration.

    Processes the ALLOWLIST env var entries and fetches provider ranges
    (e.g., GitHub) if enabled.

    Args:
        config: The application configuration.
        session: Optional requests session for fetching remote allowlists.
        logger: Optional logger instance.

    Returns:
        A populated Allowlist instance.
    """
    allowlist = Allowlist(logger=logger)

    # Add user-defined allowlist entries (supports both IPs and CIDRs)
    if config.allow_list:
        allowlist.add_entries(config.allow_list)
        if allowlist.entry_count > 0:
            if logger:
                logger.info(f"Allowlist: {allowlist.entry_count} user-defined entries loaded")

    # Fetch provider allowlists
    if config.allowlist_github:
        allowlist.fetch_github_ranges(session=session)

    if allowlist.entry_count > 0 and logger:
        logger.info(
            f"Allowlist total: {len(allowlist._exact_ips)} IPs, "
            f"{len(allowlist._networks_v4)} IPv4 networks, "
            f"{len(allowlist._networks_v6)} IPv6 networks"
        )

    return allowlist


def is_private_or_reserved(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP is in a private or reserved range."""
    for network in PRIVATE_NETWORKS:
        try:
            if ip in network:
                return True
        except TypeError:
            # IPv4 in IPv6 network or vice versa
            continue
    return False


def parse_ip_or_network(value: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse and validate an IP address or CIDR network.

    Returns the normalized IP/CIDR string if valid, None otherwise.
    Excludes private/reserved ranges and well-known IPs.
    """
    value = value.strip()
    if not value:
        return (None, None)

    try:
        if value.startswith("http"):
            # Extract IP from URL
            value = value.replace("https://", "") \
                .replace("http://", "") \
                .split("/")[0] \
                .split(":")[0]

        # Workaround typos in Maltrail: example C91.196.152.28
        if value.startswith("C"):
            value = value[1:]

        if "/" not in value:
            # Parse as single IP
            ip = ipaddress.ip_address(value)
            if is_private_or_reserved(ip):
                return (None, None)
            if str(ip) in EXCLUDED_IPS:
                return (None, None)
            return (str(ip), None)

        if "/" in value:
            # Try parsing as network (CIDR)
            network = ipaddress.ip_network(value, strict=False)
            # Check if network overlaps with private ranges
            for private in PRIVATE_NETWORKS:
                try:
                    if network.overlaps(private):
                        return (None, None)
                except TypeError:
                    continue
            return (str(network), None)
    except (ValueError, TypeError):
        return (None, value)


def extract_ips_from_line(line: str, errors: dict[str], source: BlocklistSource) -> Generator[str, None, None]:
    """
    Extract IP addresses/networks from a line of text.

    Handles various formats:
    - Plain IP: 1.2.3.4
    - CIDR: 1.2.3.0/24
    - Tabular: 1.2.3.4<tab>other_data
    - URLs: http://177.70.102.228:8070/TmpFTP/01/Consulta/2019-03-13/info.zip
    - Commented: # comment
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith(source.comment_char):
        return

    # Remove inline comments
    if source.comment_char in line:
        line = line.split(source.comment_char)[0].strip()

    # Extract specific field if configured
    if source.extract_field is not None:
        parts = line.split()
        if len(parts) > source.extract_field:
            line = parts[source.extract_field]

    # Try to extract IP/CIDR patterns
    # Handle various separators
    for part in line.replace(",", " ").replace("\t", " ").split():
        (parsed, error) = parse_ip_or_network(part)
        if parsed:
            yield parsed
        if error:
            if error not in errors.keys():
                errors[error] = 1
            else:
                errors[error] += 1


# =============================================================================
# HTTP Client with Retry
# =============================================================================

def create_http_session(max_retries: int = 3) -> requests.Session:
    """Create an HTTP session with retry logic."""
    session = requests.Session()

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,  # 1s, 2s, 4s...
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "DELETE"],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


# =============================================================================
# Blocklist Fetcher
# =============================================================================

@dataclass
class FetchResult:
    """Result of fetching a blocklist."""
    source: BlocklistSource
    success: bool
    ip_count: int = 0
    duration: float = 0.0
    error_type: str = ""                    # "fetch" | "parse" | "import" | "encoding"
    error_exc: Optional[Exception] = None   # original exception (sanitized before use as label)
    parse_errors: dict[str, int] = field(default_factory=dict)


def log_separator(logger):
    logger.debug("-" * 10)


def fetch_blocklist(
    session: requests.Session,
    source: BlocklistSource,
    timeout: int,
    seen_ips: Set[str],
    allowlist: Allowlist,
    stats: "ImportStats",
    logger: logging.Logger,
) -> tuple[list[str], FetchResult]:
    """
    Fetch and parse a single blocklist source.

    Returns (new_unique_ips, FetchResult).
    FetchResult now carries duration, error_type, error_message and
    per-token parse_errors so MetricsCollector can record full detail.
    """
    new_ips: list[str] = []
    t0 = time.time()

    try:
        logger.debug(f"Fetching {source.name} from {source.url}")

        response = session.get(
            source.url,
            timeout=timeout,
            stream=True,
            headers={"User-Agent": f"crowdsec-blocklist-import/{__version__}"},
        )
        response.raise_for_status()

        # Process line by line (streaming)
        # Use iter_lines without decode_unicode to handle encoding ourselves
        total_ip_cnt = 0
        ignored_ip_cnt = 0
        parse_errors: dict[str, int] = {}

        for raw_line in response.iter_lines():
            if raw_line:
                # Decode bytes to string, handling various encodings
                if isinstance(raw_line, bytes):
                    try:
                        line = raw_line.decode("utf-8")
                    except UnicodeDecodeError:
                        try:
                            line = raw_line.decode("latin-1")
                        except UnicodeDecodeError:
                            stats.encoding_errors += 1
                            continue  # Skip unparseable lines
                else:
                    line = raw_line

                for ip in extract_ips_from_line(line, parse_errors, source):
                    total_ip_cnt += 1
                    if ip not in seen_ips:
                        if allowlist.contains(ip):
                            ignored_ip_cnt += 1
                        else:
                            seen_ips.add(ip)
                            new_ips.append(ip)

        # Log parse errors (capped)
        max_cnt = 20
        for error in parse_errors:
            logger.debug(f'{source.name}: error parsing IP from "{error}" (×{parse_errors[error]})')
            max_cnt -= 1
            if max_cnt == 0:
                break

        nb_errors = sum(parse_errors.values())
        stats.parse_errors += nb_errors

        ignored_ips = f"{ignored_ip_cnt} ignored IPs (allow-list), " if ignored_ip_cnt > 0 else ""
        error_cnt = f", {nb_errors} parse errors" if nb_errors > 0 else ""
        logger.debug(
            f"{source.name}: {total_ip_cnt} total IPs{error_cnt}, "
            f"{ignored_ips}{len(new_ips)} unique new IPs"
        )

        duration = time.time() - t0
        return new_ips, FetchResult(
            source=source,
            success=True,
            ip_count=len(new_ips),
            duration=duration,
            parse_errors=parse_errors,
        )

    except requests.RequestException as e:
        duration = time.time() - t0
        logger.warning(f"{source.name}: unavailable ({e})")
        return new_ips, FetchResult(
            source=source,
            success=False,
            duration=duration,
            error_type="fetch",
            error_exc=e,
        )
    except Exception as e:
        duration = time.time() - t0
        logger.error(f"{source.name}: unexpected error ({e})")
        return new_ips, FetchResult(
            source=source,
            success=False,
            duration=duration,
            error_type="fetch",
            error_exc=e,
        )


# =============================================================================
# CrowdSec LAPI Client
# =============================================================================

class CrowdSecLAPI:
    """CrowdSec Local API client.

    Supports two authentication modes:
    1. Bouncer API key (X-Api-Key header) - read-only access to decisions
    2. Machine credentials (JWT token) - full access including writing alerts/decisions

    For writing decisions, machine credentials are required.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        machine_id: str,
        machine_password: str,
        session: requests.Session,
        logger: logging.Logger,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.machine_id = machine_id
        self.machine_password = machine_password
        self.session = session
        self.logger = logger
        self.jwt_token: Optional[str] = None
        self.jwt_expires: Optional[float] = None

        # Headers for bouncer API (read operations)
        self.bouncer_headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": f"crowdsec-blocklist-import/{__version__}",
        }

    def _get_machine_token(self) -> Optional[str]:
        """Get JWT token for machine authentication."""
        # Check if we have a valid cached token
        if self.jwt_token and self.jwt_expires and time.time() < self.jwt_expires - 60:
            return self.jwt_token

        if not self.machine_id or not self.machine_password:
            return None

        try:
            response = self.session.post(
                f"{self.base_url}/v1/watchers/login",
                json={
                    "machine_id": self.machine_id,
                    "password": self.machine_password,
                    "scenarios": ["external/blocklist"],
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"crowdsec-blocklist-import/{__version__}",
                },
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                self.jwt_token = data.get("token")
                # Parse expiration or default to 1 hour
                expire_str = data.get("expire", "")
                if expire_str:
                    from datetime import datetime
                    try:
                        expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
                        self.jwt_expires = expire_dt.timestamp()
                    except (ValueError, AttributeError):
                        self.jwt_expires = time.time() + 3600
                else:
                    self.jwt_expires = time.time() + 3600
                self.logger.debug("Obtained machine JWT token")
                return self.jwt_token
            else:
                self.logger.warning(
                    f"Machine login failed: {response.status_code} {response.text[:200]}"
                )
                return None

        except requests.RequestException as e:
            self.logger.error(f"Machine login request failed: {e}")
            return None

    def _get_machine_headers(self) -> Optional[dict]:
        """Get headers for machine-authenticated requests."""
        token = self._get_machine_token()
        if not token:
            return None
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"crowdsec-blocklist-import/{__version__}",
        }

    def health_check(self) -> bool:
        """Check if LAPI is accessible."""
        try:
            response = self.session.get(
                f"{self.base_url}/v1/decisions",
                headers=self.bouncer_headers,
                timeout=10,
                params={"limit": 1},
            )
            # 200 = OK, 403 = unauthorized but reachable
            return response.status_code in (200, 403)
        except requests.RequestException as e:
            self.logger.error(f"LAPI health check failed: {e}")
            return False

    def can_write(self) -> bool:
        """Check if we have credentials for write operations."""
        return bool(self.machine_id and self.machine_password)

    def get_existing_ips(self) -> Set[str]:
        """
        Get all existing decision IPs from CrowdSec.

        Returns a set of IP addresses/CIDRs that already have decisions.
        Uses bouncer API key for read access.
        """
        existing: Set[str] = set()

        try:
            # Paginate through all decisions
            # CrowdSec default limit is 100, we can increase
            response = self.session.get(
                f"{self.base_url}/v1/decisions",
                headers=self.bouncer_headers,
                timeout=60,
            )

            if response.status_code == 200:
                decisions = response.json()
                if decisions:
                    for decision in decisions:
                        value = decision.get("value", "")
                        if value:
                            existing.add(value)
            else:
                self.logger.error(f"Error calling {self.base_url}/v1/decisions")
                self.logger.error(f"Response: {response}")

        except requests.RequestException as e:
            self.logger.warning(f"Failed to fetch existing decisions: {e}")
        except (ValueError, KeyError) as e:
            self.logger.warning(f"Failed to parse existing decisions: {e}")

        return existing

    def add_decisions(
        self,
        ips: list[str],
        duration: str,
        reason: str,
        decision_type: str,
        origin: str,
        scenario: str,
    ) -> tuple[int, int]:
        """
        Add decisions to CrowdSec via LAPI.

        CrowdSec LAPI creates decisions through the /alerts endpoint.
        Each alert can contain multiple decisions.

        Returns (success_count, error_count).
        """
        if not ips:
            return 0, 0

        from datetime import datetime, timezone

        # Build decisions for this alert
        decisions = []
        for ip in ips:
            # Determine if it's a network or single IP
            scope = "Ip"
            if "/" in ip:
                scope = "Range"

            decisions.append({
                "duration": duration,
                "origin": origin,
                "scenario": scenario,
                "scope": scope,
                "type": decision_type,
                "value": ip,
            })

        # Build alert payload (CrowdSec creates decisions via alerts)
        # See: https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        alert = {
            "capacity": 0,
            "decisions": decisions,
            "events": [],
            "events_count": 1,
            "labels": None,
            "leakspeed": "0",
            "message": reason,
            "scenario": scenario,
            "scenario_hash": "",
            "scenario_version": "",
            "simulated": False,
            "source": {
                "scope": "Ip",
                "value": "0.0.0.0",
            },
            "start_at": now,
            "stop_at": now,
        }

        # Get machine authentication headers (required for /alerts endpoint)
        headers = self._get_machine_headers()
        if not headers:
            self.logger.error(
                "Machine credentials required for writing decisions. "
                "Set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD or CROWDSEC_MACHINE_PASSWORD_FILE"
            )
            return 0, len(ips)

        try:
            response = self.session.post(
                f"{self.base_url}/v1/alerts",
                headers=headers,
                json=[alert],  # API expects array of alerts
                timeout=60,
            )

            if response.status_code in (200, 201):
                return len(ips), 0
            else:
                self.logger.warning(
                    f"LAPI returned {response.status_code}: {response.text[:200]}"
                )
                return 0, len(ips)

        except requests.RequestException as e:
            self.logger.error(f"Failed to add decisions: {e}")
            return 0, len(ips)


# =============================================================================
# Main Importer
# =============================================================================

@dataclass
class ImportStats:
    """Statistics from the import run."""
    sources_ok: int = 0
    sources_failed: int = 0
    total_ips_fetched: int = 0
    encoding_errors: int = 0
    parse_errors: int = 0
    new_ips: int = 0
    imported_ok: int = 0
    imported_failed: int = 0
    existing_skipped: int = 0
    duration_seconds: float = 0.0


def read_secret_file(file_path: str) -> str:
    """Read a secret from a file, supporting multiple formats.

    Supports:
    - Docker secrets pattern: single line with just the password
    - CrowdSec credentials: YAML with 'password: <value>' line
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()
        # Single line = plain password (Docker secrets style)
        if len(lines) == 1:
            return lines[0].strip()
        # Multi-line = look for 'password: ' prefix (CrowdSec YAML style)
        for line in lines:
            if line.strip().startswith('password:'):
                return line.replace('password:', '', 1).strip()
        # Fallback: return entire content stripped
        return ''.join(lines).strip()


def run_import(config: Config, logger: logging.Logger) -> ImportStats:
    """
    Run the blocklist import.

    Memory efficient implementation using generators and batching.
    """
    stats = ImportStats()
    start_time = time.time()

    logger.info(f"CrowdSec Blocklist Import v{__version__}")
    logger.info(f"Decision duration: {config.decision_duration}")
    logger.info(f"LAPI URL: {config.lapi_url}")
    logger.info(f"Machine ID: {config.machine_id}")

    if config.dry_run:
        logger.info("DRY RUN MODE - no changes will be made")

    # Create HTTP session with retry logic
    session = create_http_session(config.max_retries)

    # Build CIDR-aware allowlist
    allowlist = build_allowlist(config, session=session, logger=logger)
    metrics = get_metrics()

    # Read secrets from files if _FILE env vars are set (Docker secrets pattern)
    # _FILE takes precedence over direct value
    lapi_key = config.lapi_key
    if config.lapi_key_file:
        lapi_key = read_secret_file(config.lapi_key_file)
        logger.debug(f"Read LAPI key from {config.lapi_key_file}")

    machine_password = config.machine_password
    if config.machine_password_file:
        machine_password = read_secret_file(config.machine_password_file)
        logger.debug(f"Read machine password from {config.machine_password_file}")

    # Initialize LAPI client
    lapi = CrowdSecLAPI(
        base_url=config.lapi_url,
        api_key=lapi_key,
        machine_id=config.machine_id,
        machine_password=machine_password,
        session=session,
        logger=logger,
    )

    # Check LAPI connectivity (unless dry run)
    if not config.dry_run:
        # Need either bouncer key (for reading) or machine creds (for writing)
        if not lapi_key and not (config.machine_id and machine_password):
            logger.error(
                "Authentication required. Set either:\n"
                "  - CROWDSEC_LAPI_KEY or CROWDSEC_LAPI_KEY_FILE (bouncer key for read-only)\n"
                "  - CROWDSEC_MACHINE_ID + CROWDSEC_MACHINE_PASSWORD or CROWDSEC_MACHINE_PASSWORD_FILE (for full access)"
            )
            return stats

        # Check if we have write capability
        if not lapi.can_write():
            logger.error(
                "Machine credentials required for writing decisions.\n"
                "Set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD or CROWDSEC_MACHINE_PASSWORD_FILE.\n"
                "Get these from: cscli machines list (or register a new machine)"
            )
            return stats

        if not lapi.health_check():
            logger.error("Cannot connect to CrowdSec LAPI")
            return stats

        logger.info("Connected to CrowdSec LAPI")

    # Get existing decisions to avoid duplicates
    existing_ips: Set[str] = set()
    if not config.dry_run:
        logger.info("Checking existing CrowdSec decisions...")
        existing_ips = lapi.get_existing_ips()
        stats.existing_skipped = len(existing_ips)
        logger.info(f"Found {len(existing_ips)} existing decisions")

    # Track seen IPs for deduplication (includes existing)
    seen_ips: Set[str] = existing_ips.copy()

    # Collect enabled sources
    enabled_sources: list[BlocklistSource] = []
    for source in BLOCKLIST_SOURCES:
        if getattr(config, source.enabled_key, True):
            enabled_sources.append(source)
    if config.custom_block_lists:
        for i, url in enumerate(config.custom_block_lists):
            if url:
                enabled_sources.append(BlocklistSource(f"custom_blocklist_{i}", url, "custom_blocklists"))

    logger.info(f"Fetching from {len(enabled_sources)} enabled blocklist sources...")

    # Process blocklists and batch import
    batch: list[str] = []

    def log_batch_stats(ok: int, failed: int, batch_cnt: int):
        if ok > 0:
            logger.debug(f"Imported {ok} IPs in {batch_cnt} batches")
        if failed > 0:
            logger.warning(f"Failed to import {failed} IPs")

    def flush_batch(source_name: str) -> tuple[int, int]:
        """Import the current batch to CrowdSec."""
        nonlocal batch
        if not batch:
            return 0, 0

        if config.dry_run:
            logger.debug(f"DRY RUN: Would import {len(batch)} IPs")
            stats.imported_ok += len(batch)
            ok, failed = len(batch), 0
        else:
            ok, failed = lapi.add_decisions(
                ips=batch,
                duration=config.decision_duration,
                reason=f"{config.decision_reason} ({source_name})",
                decision_type=config.decision_type,
                origin=config.decision_origin,
                scenario=f"{config.decision_scenario} ({source_name})",
            )
            stats.imported_ok += ok
            stats.imported_failed += failed

            # Record import errors in metrics
            if failed > 0 and metrics:
                metrics.errors_total.labels(
                    error_type="import",
                    source=source_name,
                    message="lapi_write_failure",
                ).set(failed)

        batch = []
        return ok, failed

    # Process each blocklist source
    for source in enabled_sources:
        source_ok = 0
        source_failed = 0
        batch_cnt = 1
        log_separator(logger)
        # Fetch blocklist and get results
        new_ips, result = fetch_blocklist(
            session=session,
            source=source,
            timeout=config.fetch_timeout,
            seen_ips=seen_ips,
            allowlist=allowlist,
            stats=stats,
            logger=logger,
        )

        # --- Update per-source metrics immediately after fetch ---
        if metrics:
            if result.success:
                metrics.record_source_success(
                    source_name=source.name,
                    ip_count=result.ip_count,
                    duration=result.duration,
                )
                if result.parse_errors:
                    metrics.record_parse_errors(source.name, result.parse_errors)
            else:
                metrics.record_source_failure(
                    source_name=source.name,
                    error_type=result.error_type or "fetch",
                    message=result.error_message,
                    duration=result.duration,
                )

        if result.success:
            stats.sources_ok += 1
        else:
            stats.sources_failed += 1

        # Add IPs to batch
        stats.total_ips_fetched += len(new_ips)
        stats.new_ips += len(new_ips)

        for ip in new_ips:
            batch.append(ip)
            # Flush batch when full
            if len(batch) >= config.batch_size:
                batch_cnt += 1
                ok, failed = flush_batch(source.name)
                source_ok += ok
                source_failed += failed

        # Flush any remaining IPs
        ok, failed = flush_batch(source.name)
        source_ok += ok
        source_failed += failed
        log_batch_stats(source_ok, source_failed, batch_cnt)

    # Static scanner IPs (Censys)
    log_separator(logger)
    if config.enable_scanners:
        logger.debug("Adding static scanner IPs (Censys)")
        t0 = time.time()
        added = 0
        for cidr in STATIC_SCANNER_IPS:
            if cidr not in seen_ips:
                seen_ips.add(cidr)
                batch.append(cidr)
                stats.new_ips += 1
                stats.total_ips_fetched += 1
                added += 1
        stats.sources_ok += 1
        ok, failed = flush_batch("Censys")
        log_batch_stats(ok, failed, 1)
        if metrics:
            metrics.record_source_success("Censys", added, time.time() - t0)

    # Fetch AbuseIPDB direct API (if API key is configured)
    if config.abuseipdb_api_key and config.enable_abuseipdb:
        log_separator(logger)
        abuseipdb_ips, abuseipdb_result = fetch_abuseipdb_api(
            config=config,
            session=session,
            seen_ips=seen_ips,
            allowlist=allowlist,
            stats=stats,
            logger=logger,
        )
        if abuseipdb_result.success:
            stats.sources_ok += 1
        else:
            stats.sources_failed += 1

        stats.total_ips_fetched += len(abuseipdb_ips)
        stats.new_ips += len(abuseipdb_ips)

        for ip in abuseipdb_ips:
            batch.append(ip)
            if len(batch) >= config.batch_size:
                ok, failed = flush_batch("AbuseIPDB API")
                log_batch_stats(ok, failed, 1)
        ok, failed = flush_batch("AbuseIPDB API")
        log_batch_stats(ok, failed, 1)

    stats.duration_seconds = time.time() - start_time

    # Send telemetry
    if config.telemetry_enabled and not config.dry_run:
        send_telemetry(
            session=session,
            url=config.telemetry_url,
            ip_count=stats.imported_ok,
            logger=logger,
        )

    # Send webhook notification
    if config.webhook_url:
        send_webhook(config, stats, logger)

    # Push aggregate metrics and push to gateway
    if metrics:
        metrics.update_aggregates(stats, len(enabled_sources))
        metrics.push()

    # Log summary
    log_separator(logger)
    logger.info(
        f"Sources: {stats.sources_ok} successful, "
        f"{stats.sources_failed} unavailable"
    )

    if stats.new_ips == 0:
        logger.info(
            f"No new IPs to import (all IPs already in CrowdSec)"
        )
    else:
        logger.info(
            f"Imported {stats.imported_ok} new IPs into CrowdSec"
        )
        if stats.imported_failed > 0:
            logger.warning(f"Failed to import {stats.imported_failed} IPs")
    if stats.parse_errors:
        logger.warning(f"{stats.parse_errors} parsing errors")
    if stats.encoding_errors:
        logger.warning(f"{stats.encoding_errors} encoding errors")

    logger.info(f"Completed in {stats.duration_seconds:.1f}s")

    return stats


def send_telemetry(
    session: requests.Session,
    url: str,
    ip_count: int,
    logger: logging.Logger,
) -> None:
    """Send anonymous telemetry."""
    try:
        session.post(
            url,
            json={
                "tool": "blocklist-import-python",
                "version": __version__,
                "ip_count": ip_count,
            },
            timeout=5,
        )
        logger.debug("Telemetry sent")
    except Exception:
        pass  # Telemetry failure is not critical


# =============================================================================
# Webhook Notifications
# =============================================================================

def send_webhook(config: Config, stats: "ImportStats", logger: logging.Logger) -> None:
    """Send import results to a webhook (Discord, Slack, or generic)."""
    if not config.webhook_url:
        return

    try:
        if config.webhook_type == "discord":
            payload = _format_discord_webhook(stats)
        elif config.webhook_type == "slack":
            payload = _format_slack_webhook(stats)
        else:
            payload = _format_generic_webhook(stats)

        response = requests.post(
            config.webhook_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code < 300:
            logger.debug(f"Webhook sent ({config.webhook_type})")
        else:
            logger.warning(f"Webhook returned {response.status_code}: {response.text[:200]}")

    except Exception as e:
        logger.warning(f"Webhook failed: {e}")


def _format_discord_webhook(stats: "ImportStats") -> dict:
    """Format stats as a Discord embed."""
    color = 0x2ECC71 if stats.imported_failed == 0 else 0xE74C3C
    fields = [
        {"name": "Sources", "value": f"{stats.sources_ok} ok / {stats.sources_failed} failed", "inline": True},
        {"name": "New IPs", "value": str(stats.new_ips), "inline": True},
        {"name": "Imported", "value": str(stats.imported_ok), "inline": True},
        {"name": "Duration", "value": f"{stats.duration_seconds:.1f}s", "inline": True},
    ]
    if stats.imported_failed > 0:
        fields.append({"name": "Failed", "value": str(stats.imported_failed), "inline": True})

    return {
        "embeds": [{
            "title": "CrowdSec Blocklist Import",
            "color": color,
            "fields": fields,
            "footer": {"text": f"v{__version__}"},
        }]
    }


def _format_slack_webhook(stats: "ImportStats") -> dict:
    """Format stats as a Slack message."""
    emoji = ":white_check_mark:" if stats.imported_failed == 0 else ":warning:"
    text = (
        f"{emoji} *CrowdSec Blocklist Import*\n"
        f"Sources: {stats.sources_ok} ok / {stats.sources_failed} failed\n"
        f"New IPs: {stats.new_ips} | Imported: {stats.imported_ok}\n"
        f"Duration: {stats.duration_seconds:.1f}s"
    )
    if stats.imported_failed > 0:
        text += f"\nFailed: {stats.imported_failed}"
    return {"text": text}


def _format_generic_webhook(stats: "ImportStats") -> dict:
    """Format stats as a generic JSON payload."""
    return {
        "event": "blocklist_import_complete",
        "version": __version__,
        "sources_ok": stats.sources_ok,
        "sources_failed": stats.sources_failed,
        "new_ips": stats.new_ips,
        "imported_ok": stats.imported_ok,
        "imported_failed": stats.imported_failed,
        "duration_seconds": round(stats.duration_seconds, 1),
    }


# =============================================================================
# AbuseIPDB Direct API
# =============================================================================

def fetch_abuseipdb_api(
    config: Config,
    session: requests.Session,
    seen_ips: Set[str],
    allowlist: "Allowlist",
    stats: "ImportStats",
    logger: logging.Logger,
) -> tuple[list[str], "FetchResult"]:
    """
    Fetch IPs directly from AbuseIPDB's blacklist API endpoint.

    Requires an API key (free tier: 1000 reports/day, 5 checks/day).
    Returns IPs with confidence >= abuseipdb_min_confidence.
    """
    source = BlocklistSource(
        name="AbuseIPDB API",
        url="https://api.abuseipdb.com/api/v2/blacklist",
        enabled_key="enable_abuseipdb",
    )

    new_ips: list[str] = []

    if not config.abuseipdb_api_key:
        return new_ips, FetchResult(source=source, success=True, ip_count=0)

    try:
        logger.debug(f"Fetching AbuseIPDB blacklist (confidence >= {config.abuseipdb_min_confidence}%)")

        response = session.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={
                "Key": config.abuseipdb_api_key,
                "Accept": "text/plain",
            },
            params={
                "confidenceMinimum": config.abuseipdb_min_confidence,
                "limit": config.abuseipdb_limit,
            },
            timeout=config.fetch_timeout,
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            ip_str = line.strip()
            if not ip_str or ip_str.startswith("#"):
                continue

            try:
                ip = ipaddress.ip_address(ip_str)
                if is_private_or_reserved(ip):
                    continue
                if str(ip) in EXCLUDED_IPS:
                    continue
                normalized = str(ip)
                if normalized not in seen_ips:
                    if not allowlist.contains(normalized):
                        seen_ips.add(normalized)
                        new_ips.append(normalized)
            except (ValueError, TypeError):
                stats.parse_errors += 1

        logger.debug(f"AbuseIPDB API: {len(new_ips)} unique new IPs")
        return new_ips, FetchResult(source=source, success=True, ip_count=len(new_ips))

    except requests.RequestException as e:
        logger.warning(f"AbuseIPDB API: unavailable ({e})")
        return new_ips, FetchResult(source=source, success=False, error=str(e))
    except Exception as e:
        logger.error(f"AbuseIPDB API: unexpected error ({e})")
        return new_ips, FetchResult(source=source, success=False, error=str(e))


# =============================================================================
# CLI
# =============================================================================

def setup_logging(config: Config) -> logging.Logger:
    """Configure logging with structured output."""
    logger = logging.getLogger("blocklist-import")
    logger.setLevel(getattr(logging, config.log_level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)

    format = "[%(asctime)s] [%(levelname)s] %(message)s" if config.log_timestamps else "[%(levelname)s] %(message)s"
    formatter = logging.Formatter(
        format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Import public threat blocklists into CrowdSec via LAPI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  CROWDSEC_LAPI_URL        CrowdSec LAPI URL (default: http://localhost:8080)
  CROWDSEC_LAPI_KEY[_FILE] CrowdSec LAPI key / key file (required)
  DECISION_DURATION        How long decisions last (default: 24h)
  BATCH_SIZE               IPs per batch (default: 1000)
  LOG_LEVEL                DEBUG, INFO, WARN, ERROR (default: INFO)
  DRY_RUN                  Set to true for dry run mode
  TELEMETRY_ENABLED        Set to false to disable telemetry
  METRICS_ENABLED          Set to false to disable Prometheus metrics (default: true)
  METRICS_PUSHGATEWAY_URL  Push URL for Prometheus metrics (default: localhost:9091)
  INTERVAL                 Daemon mode: seconds between runs (0=once, default: 0)
  RUN_ON_START             In daemon mode, run immediately on start (default: true)
  WEBHOOK_URL              Webhook URL for notifications (Discord/Slack/generic)
  WEBHOOK_TYPE             Webhook format: generic, discord, slack (default: generic)
  ABUSEIPDB_API_KEY        AbuseIPDB API key for direct blacklist queries
  ABUSEIPDB_MIN_CONFIDENCE Minimum confidence score 1-100 (default: 90)

  ENABLE_IPSUM             Enable IPsum blocklist (default: true)
  ENABLE_SPAMHAUS          Enable Spamhaus DROP (default: true)
  ENABLE_BLOCKLIST_DE      Enable Blocklist.de feeds (default: true)
  ENABLE_FIREHOL           Enable Firehol levels 1/2/3 (default: true)
  ENABLE_ABUSE_CH          Enable Abuse.ch feeds (default: true)
  ... and more (see README.md)

Examples:
  # Basic usage with LAPI key
  CROWDSEC_LAPI_KEY=mykey ./blocklist_import.py

  # Dry run to see what would be imported
  ./blocklist_import.py --dry-run

  # Validate configuration without running
  ./blocklist_import.py --validate

  # List all available blocklist sources
  ./blocklist_import.py --list-sources

  # Debug mode with custom duration
  LOG_LEVEL=DEBUG DECISION_DURATION=48h ./blocklist_import.py

Note: ENABLE_* variables are validated at startup. Invalid values will
cause the program to exit with an error. Unknown ENABLE_* variables
(possible typos) will generate warnings with suggestions.
""",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "-n", "--dry-run",
        action="store_true",
        help="Don't actually import, just show what would be done",
    )

    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "--lapi-url",
        help="CrowdSec LAPI URL (overrides CROWDSEC_LAPI_URL)",
    )

    parser.add_argument(
        "--lapi-key",
        help="CrowdSec LAPI key (overrides CROWDSEC_LAPI_KEY)",
    )

    parser.add_argument(
        "--duration",
        help="Decision duration (overrides DECISION_DURATION)",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        help="Batch size for imports (overrides BATCH_SIZE)",
    )

    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit without running import",
    )

    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="List all available blocklist sources and exit",
    )

    parser.add_argument(
        "--pushgateway-url",
        help="Push URL for Prometheus (overrides METRICS_PUSHGATEWAY_URL, default: localhost:9091)",
    )

    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="Disable Prometheus metrics endpoint",
    )

    parser.add_argument(
        "--interval",
        type=int,
        metavar="SECONDS",
        help="Run in daemon mode: repeat every N seconds (overrides INTERVAL)",
    )

    parser.add_argument(
        "--webhook-url",
        help="Webhook URL for notifications (overrides WEBHOOK_URL)",
    )

    parser.add_argument(
        "--webhook-type",
        choices=["generic", "discord", "slack"],
        help="Webhook format (overrides WEBHOOK_TYPE)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Load config from environment
    config = Config.from_env()

    # Override with CLI args
    if args.dry_run:
        config.dry_run = True
    if args.debug:
        config.log_level = "DEBUG"
    if args.lapi_url:
        config.lapi_url = args.lapi_url
    if args.lapi_key:
        config.lapi_key = args.lapi_key
    if args.duration:
        config.decision_duration = args.duration
    if args.batch_size:
        config.batch_size = args.batch_size
    if args.pushgateway_url:
        config.pushgateway_url = args.pushgateway_url
    if args.no_metrics:
        config.metrics_enabled = False
    if args.interval is not None:
        config.interval = args.interval
    if args.webhook_url:
        config.webhook_url = args.webhook_url
    if args.webhook_type:
        config.webhook_type = args.webhook_type

    # Setup logging
    logger = setup_logging(config)

    # Handle --list-sources flag
    if args.list_sources:
        logger.info(f"CrowdSec Blocklist Import v{__version__}")
        list_blocklist_sources(logger)
        return 0

    # Validate ENABLE_* environment variables
    is_valid, errors = validate_enable_env_vars(logger)

    if not is_valid:
        logger.error("Configuration validation failed:")
        logger.error("")
        for error in errors:
            for line in error.split("\n"):
                logger.error(f"  {line}")
        logger.error("")
        logger.error("Fix the above errors and try again.")
        logger.error("Use --list-sources to see all valid ENABLE_* variables.")
        return 1

    # Handle --validate flag
    if args.validate:
        logger.info(f"CrowdSec Blocklist Import v{__version__}")
        logger.info("Configuration validation passed!")
        logger.info("")
        list_blocklist_sources(logger)
        return 0

    # Initialize and start Prometheus metrics server
    if config.metrics_enabled and PROMETHEUS_AVAILABLE:
        init_metrics(config.pushgateway_url, logger)

    elif config.metrics_enabled and not PROMETHEUS_AVAILABLE:
        logger.warning(
            "Prometheus metrics requested but prometheus-client not installed. "
            "Install with: pip install prometheus-client"
        )

    # Daemon mode: repeat on interval
    if config.interval > 0:
        return _run_daemon(config, logger)

    # Single run mode
    return _run_once(config, logger)


def _run_once(config: Config, logger: logging.Logger) -> int:
    """Execute a single import run."""
    try:
        stats = run_import(config, logger)

        # Exit with error if import failed
        if stats.sources_ok == 0:
            return 1
        if stats.imported_failed > 0 and stats.imported_ok == 0:
            return 1
        return 0

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if config.log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        return 1


def _run_daemon(config: Config, logger: logging.Logger) -> int:
    """Run in daemon mode: repeat imports on a fixed interval."""
    shutdown = False

    def _signal_handler(signum, frame):
        nonlocal shutdown
        logger.info(f"Received signal {signum}, shutting down after current run...")
        shutdown = True

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger.info(f"Daemon mode: running every {config.interval}s (Ctrl+C to stop)")

    run_number = 0
    while not shutdown:
        run_number += 1

        if run_number == 1 and not config.run_on_start:
            logger.info(f"Skipping initial run (RUN_ON_START=false), waiting {config.interval}s...")
        else:
            logger.info(f"Starting import run #{run_number}")
            try:
                stats = run_import(config, logger)
                if stats.sources_ok == 0:
                    logger.warning("No sources succeeded — will retry next interval")
            except Exception as e:
                logger.error(f"Import run #{run_number} failed: {e}")
                if config.log_level == "DEBUG":
                    import traceback
                    traceback.print_exc()

        # Sleep in small increments so we can respond to signals quickly
        logger.info(f"Next run in {config.interval}s...")
        elapsed = 0
        while elapsed < config.interval and not shutdown:
            time.sleep(min(5, config.interval - elapsed))
            elapsed += 5

    logger.info("Daemon stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
