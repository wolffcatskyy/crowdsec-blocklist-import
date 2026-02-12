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

Author: Claude AI (wolffcatskyy/crowdsec-blocklist-import)
License: MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Generator, Iterator, Optional, Set

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

__version__ = "3.1.0"

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Configuration loaded from environment variables."""

    # CrowdSec LAPI settings
    lapi_url: str = "http://localhost:8080"
    lapi_key: str = ""  # Bouncer API key (for reading decisions)

    # Machine credentials (for writing decisions via /alerts endpoint)
    # These are alternative to lapi_key for write operations
    machine_id: str = ""
    machine_password: str = ""

    # Decision settings
    decision_duration: str = "24h"
    decision_reason: str = "external_blocklist"
    decision_type: str = "ban"
    decision_origin: str = "blocklist-import"
    decision_scenario: str = "external/blocklist"

    # Processing settings
    batch_size: int = 1000
    fetch_timeout: int = 60
    max_retries: int = 3

    # Logging
    log_level: str = "INFO"

    # Dry run mode
    dry_run: bool = False

    # Telemetry
    telemetry_enabled: bool = True
    telemetry_url: str = "https://bouncer-telemetry.ms2738.workers.dev/ping"

    # Allowlist settings (IPs to exclude from blocklists)
    allowlist_url: str = ""      # URL to fetch allowlist from
    allowlist_file: str = ""     # Local file path for allowlist
    allowlist_inline: str = ""   # Comma-separated list of IPs/CIDRs

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
            machine_id=os.getenv("CROWDSEC_MACHINE_ID", ""),
            machine_password=os.getenv("CROWDSEC_MACHINE_PASSWORD", ""),
            decision_duration=os.getenv("DECISION_DURATION", "24h"),
            decision_reason=os.getenv("DECISION_REASON", "external_blocklist"),
            decision_type=os.getenv("DECISION_TYPE", "ban"),
            decision_origin=os.getenv("DECISION_ORIGIN", "blocklist-import"),
            decision_scenario=os.getenv("DECISION_SCENARIO", "external/blocklist"),
            batch_size=int(os.getenv("BATCH_SIZE", "1000")),
            fetch_timeout=int(os.getenv("FETCH_TIMEOUT", "60")),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            dry_run=get_bool("DRY_RUN", False),
            telemetry_enabled=get_bool("TELEMETRY_ENABLED", True),
            telemetry_url=os.getenv("TELEMETRY_URL", "https://bouncer-telemetry.ms2738.workers.dev/ping"),
            allowlist_url=os.getenv("ALLOWLIST_URL", ""),
            allowlist_file=os.getenv("ALLOWLIST_FILE", ""),
            allowlist_inline=os.getenv("ALLOWLIST", ""),
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
        extract_field=0,
    ),
    # Spamhaus DROP (EDROP deprecated)
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
    # SSL Blacklist removed - deprecated by abuse.ch
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
    # Removed dead sources: Darklist (empty), Talos (404), Charles Haley (404)
    BlocklistSource(
        name="Botvrij",
        url="https://www.botvrij.eu/data/ioclist.ip-dst.raw",
        enabled_key="enable_botvrij",
    ),
    # myip.ms removed - 404
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
]

# Static scanner IPs (Censys)
STATIC_SCANNER_IPS: list[str] = [
    "192.35.168.0/23",
    "162.142.125.0/24",
    "74.120.14.0/24",
    "167.248.133.0/24",
]


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
        return None

    try:
        # Try parsing as network (CIDR)
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            # Check if network overlaps with private ranges
            for private in PRIVATE_NETWORKS:
                try:
                    if network.overlaps(private):
                        return None
                except TypeError:
                    continue
            return str(network)
        else:
            # Parse as single IP
            ip = ipaddress.ip_address(value)
            if is_private_or_reserved(ip):
                return None
            if str(ip) in EXCLUDED_IPS:
                return None
            return str(ip)
    except (ValueError, TypeError):
        return None


def load_allowlist(
    config: "Config",
    session: requests.Session,
    logger: logging.Logger,
) -> Set[str]:
    """
    Load allowlist from URL, file, and/or inline config.

    Returns a set of IP addresses/CIDRs to exclude from blocklists.
    Supports same formats as blocklists (one IP/CIDR per line, # comments).
    """
    allowlist: Set[str] = set()

    # Load from URL
    if config.allowlist_url:
        try:
            logger.debug(f"Loading allowlist from URL: {config.allowlist_url}")
            response = session.get(
                config.allowlist_url,
                timeout=config.fetch_timeout,
                headers={"User-Agent": f"crowdsec-blocklist-import/{__version__}"},
            )
            response.raise_for_status()
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parsed = parse_ip_or_network(line)
                    if parsed:
                        allowlist.add(parsed)
            logger.debug(f"Loaded {len(allowlist)} entries from ALLOWLIST_URL")
        except Exception as e:
            logger.warning(f"Failed to load allowlist from URL: {e}")

    # Load from file
    if config.allowlist_file:
        try:
            logger.debug(f"Loading allowlist from file: {config.allowlist_file}")
            with open(config.allowlist_file, "r") as f:
                count_before = len(allowlist)
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parsed = parse_ip_or_network(line)
                        if parsed:
                            allowlist.add(parsed)
                logger.debug(f"Loaded {len(allowlist) - count_before} entries from ALLOWLIST_FILE")
        except Exception as e:
            logger.warning(f"Failed to load allowlist from file: {e}")

    # Load from inline config (comma-separated)
    if config.allowlist_inline:
        logger.debug("Loading allowlist from ALLOWLIST variable")
        count_before = len(allowlist)
        for entry in config.allowlist_inline.split(","):
            entry = entry.strip()
            if entry:
                parsed = parse_ip_or_network(entry)
                if parsed:
                    allowlist.add(parsed)
        logger.debug(f"Loaded {len(allowlist) - count_before} entries from ALLOWLIST")

    if allowlist:
        logger.info(f"Allowlist loaded: {len(allowlist)} unique entries")

    return allowlist


def is_allowlisted(ip: str, allowlist: Set[str]) -> bool:
    """
    Check if an IP or CIDR should be excluded based on allowlist.

    Uses exact string matching for efficiency.
    For CIDR-aware filtering, the allowlist should contain
    the same notation used in blocklists.
    """
    return ip in allowlist


def extract_ips_from_line(line: str, source: BlocklistSource) -> Generator[str, None, None]:
    """
    Extract IP addresses/networks from a line of text.

    Handles various formats:
    - Plain IP: 1.2.3.4
    - CIDR: 1.2.3.0/24
    - Tabular: 1.2.3.4<tab>other_data
    - Commented: # comment
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith(source.comment_char):
        return

    # Remove inline comments (both ; and #)
    if ";" in line:
        line = line.split(";")[0].strip()
    if "#" in line and source.comment_char != "#":
        line = line.split("#")[0].strip()

    # Extract specific field if configured
    if source.extract_field is not None:
        parts = line.split()
        if len(parts) > source.extract_field:
            line = parts[source.extract_field]

    # Try to extract IP/CIDR patterns
    # Handle various separators
    for part in line.replace(",", " ").replace("\t", " ").split():
        parsed = parse_ip_or_network(part)
        if parsed:
            yield parsed


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


def fetch_blocklist(
    session: requests.Session,
    source: BlocklistSource,
    timeout: int,
    seen_ips: Set[str],
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
                            continue  # Skip unparseable lines
                else:
                    line = raw_line

                for ip in extract_ips_from_line(line, source):
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        new_ips.append(ip)

        logger.debug(f"{source.name}: {len(new_ips)} unique IPs")
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

            self.logger.debug(f"Found {len(existing)} existing decisions")

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

        import socket
        from datetime import datetime, timezone

        # Get machine name for alert source
        machine_id = socket.gethostname()

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
                "Set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD"
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
    new_ips: int = 0
    imported_ok: int = 0
    imported_failed: int = 0
    existing_skipped: int = 0
    allowlist_filtered: int = 0
    duration_seconds: float = 0.0


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

    if config.dry_run:
        logger.info("DRY RUN MODE - no changes will be made")

    # Create HTTP session with retry logic
    session = create_http_session(config.max_retries)

    # Initialize LAPI client
    lapi = CrowdSecLAPI(
        base_url=config.lapi_url,
        api_key=config.lapi_key,
        machine_id=config.machine_id,
        machine_password=config.machine_password,
        session=session,
        logger=logger,
    )

    # Check LAPI connectivity (unless dry run)
    if not config.dry_run:
        # Need either bouncer key (for reading) or machine creds (for writing)
        if not config.lapi_key and not (config.machine_id and config.machine_password):
            logger.error(
                "Authentication required. Set either:\n"
                "  - CROWDSEC_LAPI_KEY (bouncer key for read-only)\n"
                "  - CROWDSEC_MACHINE_ID + CROWDSEC_MACHINE_PASSWORD (for full access)"
            )
            return stats

        # Check if we have write capability
        if not lapi.can_write():
            logger.error(
                "Machine credentials required for writing decisions.\n"
                "Set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD.\n"
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

    # Load allowlist
    allowlist: Set[str] = set()
    if config.allowlist_url or config.allowlist_file or config.allowlist_inline:
        allowlist = load_allowlist(config, session, logger)

    # Collect enabled sources
    enabled_sources: list[BlocklistSource] = []
    for source in BLOCKLIST_SOURCES:
        if getattr(config, source.enabled_key, True):
            enabled_sources.append(source)

    logger.info(f"Fetching from {len(enabled_sources)} enabled blocklist sources...")

    # Process blocklists and batch import
    batch: list[str] = []

    def flush_batch() -> None:
        """Import the current batch to CrowdSec."""
        nonlocal batch
        if not batch:
            return

        if config.dry_run:
            logger.debug(f"DRY RUN: Would import {len(batch)} IPs")
            stats.imported_ok += len(batch)
        else:
            ok, failed = lapi.add_decisions(
                ips=batch,
                duration=config.decision_duration,
                reason=config.decision_reason,
                decision_type=config.decision_type,
                origin=config.decision_origin,
                scenario=config.decision_scenario,
            )
            stats.imported_ok += ok
            stats.imported_failed += failed
            if ok > 0:
                logger.debug(f"Imported batch of {ok} IPs")
            if failed > 0:
                logger.warning(f"Failed to import {failed} IPs")

        batch = []

    # Process each blocklist source
    for source in enabled_sources:
        # Fetch blocklist and get results
        new_ips, result = fetch_blocklist(
            session=session,
            source=source,
            timeout=config.fetch_timeout,
            seen_ips=seen_ips,
            logger=logger,
        )

        # Track statistics
        if result.success:
            stats.sources_ok += 1
        else:
            stats.sources_failed += 1

        # Add IPs to batch (filtering allowlisted entries)
        stats.total_ips_fetched += len(new_ips)

        for ip in new_ips:
            if allowlist and is_allowlisted(ip, allowlist):
                stats.allowlist_filtered += 1
                continue
            stats.new_ips += 1
            batch.append(ip)
            # Flush batch when full
            if len(batch) >= config.batch_size:
                flush_batch()

    # Add static scanner IPs
    if config.enable_scanners:
        logger.debug("Adding static scanner IPs (Censys)")
        for cidr in STATIC_SCANNER_IPS:
            if cidr not in seen_ips:
                seen_ips.add(cidr)
                if allowlist and is_allowlisted(cidr, allowlist):
                    stats.allowlist_filtered += 1
                    continue
                batch.append(cidr)
                stats.new_ips += 1
                stats.total_ips_fetched += 1
        stats.sources_ok += 1

    # Log allowlist stats
    if stats.allowlist_filtered > 0:
        logger.info(f"Allowlist filtered {stats.allowlist_filtered} IPs")

    # Flush any remaining IPs
    flush_batch()

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

def setup_logging(level: str) -> logging.Logger:
    """Configure logging with structured output."""
    logger = logging.getLogger("blocklist-import")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
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
  CROWDSEC_LAPI_URL      CrowdSec LAPI URL (default: http://localhost:8080)
  CROWDSEC_LAPI_KEY      CrowdSec LAPI key (required)
  DECISION_DURATION      How long decisions last (default: 24h)
  BATCH_SIZE             IPs per batch (default: 1000)
  LOG_LEVEL              DEBUG, INFO, WARN, ERROR (default: INFO)
  DRY_RUN                Set to true for dry run mode
  TELEMETRY_ENABLED      Set to false to disable telemetry

  ENABLE_IPSUM           Enable IPsum blocklist (default: true)
  ENABLE_SPAMHAUS        Enable Spamhaus DROP/EDROP (default: true)
  ENABLE_BLOCKLIST_DE    Enable Blocklist.de feeds (default: true)
  ENABLE_FIREHOL         Enable Firehol level1/2 (default: true)
  ENABLE_ABUSE_CH        Enable Abuse.ch feeds (default: true)
  ... and more (see README.md)

Examples:
  # Basic usage with LAPI key
  CROWDSEC_LAPI_KEY=mykey ./blocklist_import.py

  # Dry run to see what would be imported
  ./blocklist_import.py --dry-run

  # Debug mode with custom duration
  LOG_LEVEL=DEBUG DECISION_DURATION=48h ./blocklist_import.py
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
    logger = setup_logging(config.log_level)

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
