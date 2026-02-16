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

Authors:

- Claude AI (wolffcatskyy/crowdsec-blocklist-import)
- gaelj

License: MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Generator, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Optional dotenv support - not required if env vars are set directly
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        """Stub if python-dotenv is not installed."""
        pass

__version__ = "3.3.0"

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
            allow_list=[ l.strip() for l in os.getenv("ALLOWLIST", "").split(",") ],
            custom_block_lists=[ l.strip() for l in os.getenv("CUSTOM_BLOCKLISTS", "").split(",") ],
            batch_size=int(os.getenv("BATCH_SIZE", "1000")),
            fetch_timeout=int(os.getenv("FETCH_TIMEOUT", "60")),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_timestamps=get_bool("LOG_TIMESTAMPS"),
            dry_run=get_bool("DRY_RUN", False),
            telemetry_enabled=get_bool("TELEMETRY_ENABLED", True),
            telemetry_url=os.getenv("TELEMETRY_URL", "https://bouncer-telemetry.ms2738.workers.dev/ping"),
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
    # Spamhaus DROP/EDROP
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
]

# Well-known IPs to exclude (DNS resolvers, etc.)
EXCLUDED_IPS: Set[str] = {
    "1.0.0.1", "1.1.1.1",  # Cloudflare
    "8.8.8.8", "8.8.4.4",  # Google
    "9.9.9.9",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}


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


def parse_ip_or_network(value: str) -> Optional[str]:
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
            ret = str(ip)
            if ret.endswith(".0"):
                value = f"{ret}/24"
            else:
                return (ret, None)

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


def extract_ips_from_line(line: str, errors: dict[str], source: BlocklistSource, logger: logging.Logger) -> Generator[str, None, None]:
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
    error: Optional[str] = None


def log_separator(logger):
    logger.debug("-" * 10)


def fetch_blocklist(
    session: requests.Session,
    source: BlocklistSource,
    timeout: int,
    seen_ips: Set[str],
    allow_list: list[str],
    stats: ImportStats,
    logger: logging.Logger,
) -> tuple[list[str], FetchResult]:
    """
    Fetch and process a blocklist, returning new unique IPs.

    Memory efficient: processes line by line without loading entire file.
    Returns a tuple of (new_ips_list, fetch_result).
    """
    new_ips: list[str] = []

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
        errors = dict()
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

                for ip in extract_ips_from_line(line, errors, source, logger):
                    total_ip_cnt += 1
                    if ip not in seen_ips:
                        if ip in allow_list:
                            ignored_ip_cnt += 1
                        else:
                            seen_ips.add(ip)
                            new_ips.append(ip)
        max_cnt = 20
        for error in errors:
            logger.debug(f'{source.name}: error parsing IP from "{error}" (×{errors[error]})')
            max_cnt -= 1
            if max_cnt == 0:
                break
        nb_errors = sum([errors[e] for e in errors.keys()])
        stats.parse_errors += nb_errors

        ignored_ips = f"{ignored_ip_cnt} ignored IPs (allow-list), " if ignored_ip_cnt > 0 else ""
        error_cnt = f", {nb_errors} parse errors" if len(errors) > 0 else ""
        logger.debug(f"{source.name}: {total_ip_cnt} total IPs{error_cnt}, {ignored_ips}{len(new_ips)} unique new IPs")
        return new_ips, FetchResult(source=source, success=True, ip_count=len(new_ips))

    except requests.RequestException as e:
        logger.warning(f"{source.name}: unavailable ({e})")
        return new_ips, FetchResult(source=source, success=False, error=str(e))
    except Exception as e:
        logger.error(f"{source.name}: unexpected error ({e})")
        return new_ips, FetchResult(source=source, success=False, error=str(e))


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


def read_password_file(password_file: str) -> str:
    with open(password_file, 'r') as f:
        lines = f.readlines()
        return [l.replace("password: ", "").strip() for l in lines if len(lines) == 1 or l.startswith("password: ")][0]


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

    lapi_key = config.lapi_key
    if not lapi_key and config.lapi_key_file:
        lapi_key = read_password_file(config.lapi_key_file)
        logger.debug(f"Read lapi_key from {config.lapi_key_file}")

    machine_password = config.machine_password
    if not machine_password and config.machine_password_file:
        machine_password = read_password_file(config.machine_password_file)
        logger.debug(f"Read machine_password from {config.machine_password_file}")

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
    if config.custom_block_lists is not None:
        i = 0
        for c in config.custom_block_lists:
            if c:
                enabled_sources.append(BlocklistSource(f"custom_blocklist_{i}", c, "custom_blocklists"))
                i += 1

    logger.info(f"Fetching from {len(enabled_sources)} enabled blocklist sources...")

    # Process blocklists and batch import
    batch: list[str] = []

    def log_batch_stats(ok: int, failed: int, batch_cnt: int):
        if ok > 0:
            logger.debug(f"Imported {ok} IPs in {batch_cnt} batches")
        if failed > 0:
            logger.warning(f"Failed to import {failed} IPs")

    def flush_batch(sourceName: str) -> None:
        """Import the current batch to CrowdSec."""
        nonlocal batch
        if not batch:
            return (0, 0)

        if config.dry_run:
            logger.debug(f"DRY RUN: Would import {len(batch)} IPs")
            stats.imported_ok += len(batch)
            ok = len(batch)
            failed = 0
        else:
            ok, failed = lapi.add_decisions(
                ips=batch,
                duration=config.decision_duration,
                reason=f"{config.decision_reason} ({sourceName})",
                decision_type=config.decision_type,
                origin=config.decision_origin,
                scenario=f"{config.decision_scenario} ({sourceName})",
            )
            stats.imported_ok += ok
            stats.imported_failed += failed
            # if ok > 0:
            #     logger.debug(f"Imported batch of {ok} IPs")
            # if failed > 0:
            #     logger.warning(f"Failed to import {failed} IPs")

        batch = []
        return (ok, failed)

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
            allow_list=config.allow_list,
            stats=stats,
            logger=logger,
        )

        # Track statistics
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

    # Add static scanner IPs
    log_separator(logger)
    if config.enable_scanners:
        logger.debug("Adding static scanner IPs (Censys)")
        for cidr in STATIC_SCANNER_IPS:
            if cidr not in seen_ips:
                seen_ips.add(cidr)
                batch.append(cidr)
                stats.new_ips += 1
                stats.total_ips_fetched += 1
        stats.sources_ok += 1

        source_ok, source_failed = flush_batch("Censys")
        log_batch_stats(source_ok, source_failed, 1)

    stats.duration_seconds = time.time() - start_time

    # Send telemetry
    if config.telemetry_enabled and not config.dry_run:
        send_telemetry(
            session=session,
            url=config.telemetry_url,
            ip_count=stats.imported_ok,
            logger=logger,
        )

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

  ENABLE_IPSUM             Enable IPsum blocklist (default: true)
  ENABLE_SPAMHAUS          Enable Spamhaus DROP/EDROP (default: true)
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

    # Run import
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


if __name__ == "__main__":
    sys.exit(main())
