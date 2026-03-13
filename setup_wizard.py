#!/usr/bin/env python3
"""Interactive setup wizard for CrowdSec Blocklist Import."""

import os
import sys
import getpass
import subprocess
import tempfile
from pathlib import Path

from blocklist_import import BLOCKLIST_SOURCES, VALID_ENABLE_VARS, __version__

# ---------------------------------------------------------------------------
# Group metadata: maps ENABLE_* key -> (display name, description)
# ---------------------------------------------------------------------------
GROUP_META = {
    "ENABLE_IPSUM":             ("IPsum",              "Aggregated threat intel (IPs on 3+ blocklists)"),
    "ENABLE_SPAMHAUS":          ("Spamhaus",           "Known spam / hijacked netblocks (DROP)"),
    "ENABLE_BLOCKLIST_DE":      ("Blocklist.de",       "All/SSH/Apache/Mail attacker IPs"),
    "ENABLE_FIREHOL":           ("Firehol",            "Firehol level1-3 netsets"),
    "ENABLE_ABUSE_CH":          ("Abuse.ch",           "Feodo Tracker + URLhaus malware feeds"),
    "ENABLE_EMERGING_THREATS":  ("Emerging Threats",   "Compromised IP list"),
    "ENABLE_BINARY_DEFENSE":    ("Binary Defense",     "Binary Defense ban list"),
    "ENABLE_BRUTEFORCE_BLOCKER":("Bruteforce Blocker", "Brute-force attacker IPs"),
    "ENABLE_DSHIELD":           ("DShield",            "DShield top attackers + block list"),
    "ENABLE_CI_ARMY":           ("CI Army",            "Bad-reputation IPs (CINSscore)"),
    "ENABLE_BOTVRIJ":           ("Botvrij",            "Botnet C2 IP/IOC list"),
    "ENABLE_GREENSNOW":         ("GreenSnow",          "Known attacker IPs"),
    "ENABLE_STOPFORUMSPAM":     ("StopForumSpam",      "Toxic IPs from forum spam network"),
    "ENABLE_TOR":               ("Tor",                "Tor exit nodes (may cause false positives)"),
    "ENABLE_SCANNERS":          ("Scanners",           "Shodan, Censys, Maltrail scanner IPs"),
    "ENABLE_ABUSE_IPDB":        ("AbuseIPDB",          "99%+ confidence IPs (borestad mirror)"),
    "ENABLE_CYBERCRIME_TRACKER":("Cybercrime Tracker", "C2 IPs from cybercrime tracker"),
    "ENABLE_MONTY_SECURITY_C2": ("Monty Security C2",  "Monty Security C2 tracker feed"),
    "ENABLE_VXVAULT":           ("VXVault",            "Malware hosting IPs"),
    "ENABLE_SENTINEL":          ("Sentinel",           "Turris Sentinel greylist"),
}

# Ordered list used for display (matches VALID_ENABLE_VARS ordering)
ORDERED_ENABLE_KEYS = [
    "ENABLE_IPSUM", "ENABLE_SPAMHAUS", "ENABLE_BLOCKLIST_DE", "ENABLE_FIREHOL",
    "ENABLE_ABUSE_CH", "ENABLE_EMERGING_THREATS", "ENABLE_BINARY_DEFENSE",
    "ENABLE_BRUTEFORCE_BLOCKER", "ENABLE_DSHIELD", "ENABLE_CI_ARMY", "ENABLE_BOTVRIJ",
    "ENABLE_GREENSNOW", "ENABLE_STOPFORUMSPAM", "ENABLE_TOR", "ENABLE_SCANNERS",
    "ENABLE_ABUSE_IPDB", "ENABLE_CYBERCRIME_TRACKER", "ENABLE_MONTY_SECURITY_C2",
    "ENABLE_VXVAULT", "ENABLE_SENTINEL",
]

# Presets
PRESET_MINIMAL = {"ENABLE_IPSUM", "ENABLE_SPAMHAUS", "ENABLE_FIREHOL",
                  "ENABLE_EMERGING_THREATS", "ENABLE_DSHIELD"}
PRESET_PRIVACY = VALID_ENABLE_VARS - {"ENABLE_TOR", "ENABLE_SCANNERS"}

# Default values used when generating .env (omit keys that match these)
DEFAULTS = {
    "CROWDSEC_LAPI_URL":    "http://localhost:8080",
    "DECISION_DURATION":    "24h",
    "DECISION_REASON":      "external_blocklist",
    "DECISION_TYPE":        "ban",
    "DECISION_ORIGIN":      "blocklist-import",
    "DECISION_SCENARIO":    "external/blocklist",
    "BATCH_SIZE":           "1000",
    "FETCH_TIMEOUT":        "60",
    "MAX_RETRIES":          "3",
    "LOG_LEVEL":            "INFO",
    "INTERVAL":             "0",
    "MAX_DECISIONS":        "0",
    "WEBHOOK_TYPE":         "generic",
    "ABUSEIPDB_MIN_CONFIDENCE": "90",
    "ABUSEIPDB_LIMIT":      "10000",
}


# ---------------------------------------------------------------------------
# Helper: count sources per enable key
# ---------------------------------------------------------------------------
def _source_counts():
    counts = {}
    for src in BLOCKLIST_SOURCES:
        key = src.enabled_key.upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


SOURCE_COUNTS = _source_counts()


# ---------------------------------------------------------------------------
# UI primitives
# ---------------------------------------------------------------------------

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_header(title):
    print()
    print(f"=== {title} ===")
    print()


def print_status(label, value, good=True):
    marker = "[+]" if good else "[x]"
    print(f"  {marker} {label}: {value}")


def prompt_choice(prompt, max_val, default=0):
    """Prompt for an integer choice in [0, max_val]. Returns int."""
    while True:
        try:
            raw = input(f"{prompt} [{default}]: ").strip()
            if raw == "":
                return default
            val = int(raw)
            if 0 <= val <= max_val:
                return val
            print(f"  Please enter a number between 0 and {max_val}.")
        except ValueError:
            print("  Invalid input — enter a number.")
        except (KeyboardInterrupt, EOFError):
            print()
            raise KeyboardInterrupt


def prompt_yn(prompt, default=True):
    """Yes/no prompt. Returns bool."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            raw = input(f"{prompt} {hint}: ").strip().lower()
            if raw == "":
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            print("  Please enter y or n.")
        except (KeyboardInterrupt, EOFError):
            print()
            raise KeyboardInterrupt


def prompt_input(prompt, default="", secret=False):
    """Prompt for string input. Uses getpass when secret=True."""
    display_default = "****" if (secret and default) else default
    hint = f" [{display_default}]" if display_default else ""
    try:
        if secret:
            val = getpass.getpass(f"{prompt}{hint}: ")
        else:
            val = input(f"{prompt}{hint}: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        print()
        raise KeyboardInterrupt


def _is_enabled(state, key):
    """Return True if the ENABLE_* key is on (default True)."""
    val = state.get(key, "true").lower()
    return val in ("true", "1", "yes", "on")


# ---------------------------------------------------------------------------
# Menu: CrowdSec connection
# ---------------------------------------------------------------------------

def menu_crowdsec_connection(state):
    clear_screen()
    print_header("CrowdSec Connection")

    print("  Configure how blocklist-import connects to your CrowdSec LAPI.")
    print()

    state["CROWDSEC_LAPI_URL"] = prompt_input(
        "  LAPI URL",
        default=state.get("CROWDSEC_LAPI_URL", "http://localhost:8080"),
    )

    print()
    print("  Bouncer API key — used to read existing decisions.")
    print("  Generate with:  cscli bouncers add blocklist-import -o raw")
    state["CROWDSEC_LAPI_KEY"] = prompt_input(
        "  CROWDSEC_LAPI_KEY",
        default=state.get("CROWDSEC_LAPI_KEY", ""),
        secret=True,
    )

    print()
    print("  Machine credentials — required for writing (importing) decisions.")
    print("  Create with:  cscli machines add blocklist-import --password 'YourPassword'")
    state["CROWDSEC_MACHINE_ID"] = prompt_input(
        "  CROWDSEC_MACHINE_ID",
        default=state.get("CROWDSEC_MACHINE_ID", "blocklist-import"),
    )
    state["CROWDSEC_MACHINE_PASSWORD"] = prompt_input(
        "  CROWDSEC_MACHINE_PASSWORD",
        default=state.get("CROWDSEC_MACHINE_PASSWORD", ""),
        secret=True,
    )

    print()
    if state.get("CROWDSEC_LAPI_URL") and prompt_yn("  Test connection now?", default=False):
        url = state["CROWDSEC_LAPI_URL"].rstrip("/")
        try:
            import requests
            resp = requests.get(f"{url}/health", timeout=5)
            if resp.status_code == 200:
                print_status("Health check", "OK (200)", good=True)
            else:
                print_status("Health check", f"HTTP {resp.status_code}", good=False)
        except Exception as exc:
            print_status("Connection failed", str(exc), good=False)
        print()
        input("  Press Enter to continue...")


# ---------------------------------------------------------------------------
# Menu: Select blocklists
# ---------------------------------------------------------------------------

def menu_select_blocklists(state):
    while True:
        clear_screen()
        print_header("Select Blocklists")

        print(f"  {'#':>2}  {'Status':<6}  {'Group':<24}  {'Src':>3}  Description")
        print(f"  {'-'*2}  {'-'*6}  {'-'*24}  {'-'*3}  {'-'*36}")

        for idx, key in enumerate(ORDERED_ENABLE_KEYS, start=1):
            name, desc = GROUP_META.get(key, (key, ""))
            on = _is_enabled(state, key)
            status = " ON " if on else " OFF"
            count = SOURCE_COUNTS.get(key, 0)
            print(f"  {idx:>2}) [{status}]  {name:<24}  {count:>3}  {desc}")

        total_enabled = sum(1 for k in ORDERED_ENABLE_KEYS if _is_enabled(state, k))
        total_sources = sum(
            SOURCE_COUNTS.get(k, 0) for k in ORDERED_ENABLE_KEYS if _is_enabled(state, k)
        )
        print()
        print(f"  {total_enabled}/{len(ORDERED_ENABLE_KEYS)} groups enabled  ({total_sources} sources active)")
        print()
        print("  a) All ON    m) Minimal (top 5)    p) Privacy (no Tor/Scanners)")
        print("  t) Toggle by number    b) Back to main menu")
        print()

        try:
            raw = input("  Choice: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if raw == "b" or raw == "":
            break
        elif raw == "a":
            for k in ORDERED_ENABLE_KEYS:
                state[k] = "true"
            print("  All blocklists enabled.")
        elif raw == "m":
            for k in ORDERED_ENABLE_KEYS:
                state[k] = "true" if k in PRESET_MINIMAL else "false"
            print("  Minimal preset applied (top 5 feeds).")
        elif raw == "p":
            for k in ORDERED_ENABLE_KEYS:
                state[k] = "true" if k in PRESET_PRIVACY else "false"
            print("  Privacy preset applied (Tor + Scanners disabled).")
        elif raw == "t":
            try:
                num_raw = input("  Toggle number(s), comma-separated: ").strip()
                for part in num_raw.split(","):
                    n = int(part.strip())
                    if 1 <= n <= len(ORDERED_ENABLE_KEYS):
                        key = ORDERED_ENABLE_KEYS[n - 1]
                        state[key] = "false" if _is_enabled(state, key) else "true"
                    else:
                        print(f"  Skipping out-of-range: {n}")
            except ValueError:
                print("  Invalid input.")
        else:
            print("  Unknown option.")


# ---------------------------------------------------------------------------
# Menu: Advanced settings
# ---------------------------------------------------------------------------

def menu_advanced_settings(state):
    while True:
        clear_screen()
        print_header("Advanced Settings")

        settings = [
            ("DECISION_DURATION",       "Decision duration (e.g. 24h, 7d)",    "24h"),
            ("BATCH_SIZE",              "Batch size (IPs per API call)",         "1000"),
            ("LOG_LEVEL",               "Log level (DEBUG/INFO/WARNING/ERROR)",  "INFO"),
            ("INTERVAL",                "Daemon interval in seconds (0=one-shot)","0"),
            ("MAX_DECISIONS",           "Max decisions to import (0=unlimited)", "0"),
            ("ABUSEIPDB_API_KEY",       "AbuseIPDB direct API key (optional)",   ""),
            ("WEBHOOK_URL",             "Webhook URL for notifications",          ""),
            ("WEBHOOK_TYPE",            "Webhook type (generic/discord/slack)",   "generic"),
            ("ALLOWLIST",               "Allowlist IPs/CIDRs (comma-separated)", ""),
            ("PUSHGATEWAY_URL",         "Prometheus Pushgateway URL",             ""),
        ]

        for idx, (key, label, default) in enumerate(settings, start=1):
            val = state.get(key, default)
            display = "****" if (key == "ABUSEIPDB_API_KEY" and val) else (val or "(not set)")
            print(f"  {idx:>2}) {label}")
            print(f"      Current: {display}")
            print()

        print("  Enter number to change, or 0 to go back.")
        print()

        choice = prompt_choice("  Choice", len(settings))
        if choice == 0:
            break

        key, label, default = settings[choice - 1]
        print()

        if key == "LOG_LEVEL":
            print("  Options: 1) DEBUG  2) INFO  3) WARNING  4) ERROR")
            level_map = {1: "DEBUG", 2: "INFO", 3: "WARNING", 4: "ERROR"}
            current_idx = {v: k for k, v in level_map.items()}.get(state.get(key, "INFO"), 2)
            sel = prompt_choice("  Select", 4, default=current_idx)
            if sel in level_map:
                state[key] = level_map[sel]
        elif key == "WEBHOOK_TYPE":
            print("  Options: 1) generic  2) discord  3) slack")
            type_map = {1: "generic", 2: "discord", 3: "slack"}
            current_idx = {v: k for k, v in type_map.items()}.get(state.get(key, "generic"), 1)
            sel = prompt_choice("  Select", 3, default=current_idx)
            if sel in type_map:
                state[key] = type_map[sel]
        elif key == "ABUSEIPDB_API_KEY":
            print("  Leave blank to use the free public mirror by @borestad (no key needed).")
            print("  Provide a direct API key for higher rate limits and fresher data.")
            print()
            state[key] = prompt_input(f"  {label}", default=state.get(key, default), secret=True)
        else:
            state[key] = prompt_input(f"  {label}", default=state.get(key, default))

        # Remove key if reset to empty/default to keep .env clean
        if state.get(key) == default and key in DEFAULTS and DEFAULTS[key] == default:
            state.pop(key, None)


# ---------------------------------------------------------------------------
# Menu: Generate .env
# ---------------------------------------------------------------------------

def _build_env_lines(state):
    """Return a list of strings representing the .env file content."""
    lines = [
        f"# CrowdSec Blocklist Import Configuration",
        f"# Generated by setup wizard v{__version__}",
        "",
        "# === CrowdSec Connection ===",
    ]

    for key in ("CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_KEY", "CROWDSEC_LAPI_KEY_FILE",
                "CROWDSEC_MACHINE_ID", "CROWDSEC_MACHINE_PASSWORD",
                "CROWDSEC_MACHINE_PASSWORD_FILE"):
        if state.get(key):
            lines.append(f"{key}={state[key]}")

    lines += [
        "",
        "# === Decision Settings ===",
    ]
    for key in ("DECISION_DURATION", "DECISION_REASON", "DECISION_TYPE",
                "DECISION_ORIGIN", "DECISION_SCENARIO", "ALLOWLIST"):
        val = state.get(key)
        if val and val != DEFAULTS.get(key, ""):
            lines.append(f"{key}={val}")

    lines += [
        "",
        "# === Processing Settings ===",
    ]
    for key in ("BATCH_SIZE", "FETCH_TIMEOUT", "MAX_RETRIES", "MAX_DECISIONS"):
        val = state.get(key)
        if val and val != DEFAULTS.get(key, ""):
            lines.append(f"{key}={val}")

    lines += [
        "",
        "# === Logging & Daemon ===",
    ]
    for key in ("LOG_LEVEL", "LOG_TIMESTAMPS", "INTERVAL"):
        val = state.get(key)
        if val and val != DEFAULTS.get(key, ""):
            lines.append(f"{key}={val}")

    lines += [
        "",
        "# === Notifications & Metrics ===",
    ]
    for key in ("WEBHOOK_URL", "WEBHOOK_TYPE", "PUSHGATEWAY_URL"):
        val = state.get(key)
        if val and val != DEFAULTS.get(key, ""):
            lines.append(f"{key}={val}")

    lines += [
        "",
        "# === AbuseIPDB (optional direct API key) ===",
    ]
    for key in ("ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY_FILE",
                "ABUSEIPDB_MIN_CONFIDENCE", "ABUSEIPDB_LIMIT"):
        val = state.get(key)
        if val and val != DEFAULTS.get(key, ""):
            lines.append(f"{key}={val}")

    lines += [
        "",
        "# === Blocklist Selection ===",
        "# All groups are enabled by default; uncomment/set to 'false' to disable.",
    ]
    for key in ORDERED_ENABLE_KEYS:
        val = state.get(key, "true").lower()
        # Write every ENABLE_ key explicitly so the file is self-documenting
        name, desc = GROUP_META.get(key, (key, ""))
        lines.append(f"# {desc}")
        lines.append(f"{key}={val}")

    lines.append("")
    return lines


def menu_generate_env(state):
    clear_screen()
    print_header("Generate .env File")

    lines = _build_env_lines(state)

    print("  Preview of .env to be written:")
    print()
    for line in lines[:40]:
        print(f"  {line}")
    if len(lines) > 40:
        print(f"  ... ({len(lines) - 40} more lines)")
    print()

    out_path = prompt_input("  Output path", default=".env")
    out = Path(out_path)

    if out.exists():
        print()
        if not prompt_yn(f"  '{out}' already exists. Overwrite?", default=False):
            print("  Aborted — file not written.")
            input("  Press Enter to continue...")
            return

    out.write_text("\n".join(lines))
    print()
    print_status("Written", str(out.resolve()), good=True)
    print()
    input("  Press Enter to continue...")


# ---------------------------------------------------------------------------
# Menu: Test connection & dry run
# ---------------------------------------------------------------------------

def menu_test_connection(state):
    clear_screen()
    print_header("Test Connection & Dry Run")

    if not state.get("CROWDSEC_LAPI_URL"):
        print("  No LAPI URL configured. Set it in 'Configure CrowdSec connection' first.")
        input("  Press Enter to continue...")
        return

    print("  Writing temporary .env for test...")
    lines = _build_env_lines(state)

    tmp_env = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("\n".join(lines))
            tmp_env = f.name

        script = Path(__file__).parent / "blocklist_import.py"
        if not script.exists():
            print(f"  Cannot find {script}")
            return

        print()
        print("  Running --validate ...")
        print()
        result = subprocess.run(
            [sys.executable, str(script), "--validate"],
            env={**os.environ, "DOTENV_PATH": tmp_env},
            capture_output=False,
            timeout=30,
        )
        print()

        if prompt_yn("  Run --dry-run (downloads + parses all enabled feeds, no writes)?",
                     default=False):
            print()
            subprocess.run(
                [sys.executable, str(script), "--dry-run"],
                env={**os.environ, "DOTENV_PATH": tmp_env},
                capture_output=False,
                timeout=300,
            )
            print()

    except subprocess.TimeoutExpired:
        print("  Timed out waiting for process.")
    except Exception as exc:
        print(f"  Error: {exc}")
    finally:
        if tmp_env and os.path.exists(tmp_env):
            os.unlink(tmp_env)

    print()
    input("  Press Enter to continue...")


# ---------------------------------------------------------------------------
# Menu: View current configuration
# ---------------------------------------------------------------------------

def menu_view_config(state):
    clear_screen()
    print_header("Current Configuration")

    sections = {
        "CrowdSec Connection": [
            "CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_KEY", "CROWDSEC_MACHINE_ID",
            "CROWDSEC_MACHINE_PASSWORD",
        ],
        "Decision Settings": [
            "DECISION_DURATION", "DECISION_REASON", "DECISION_TYPE",
            "ALLOWLIST", "MAX_DECISIONS",
        ],
        "Processing": ["BATCH_SIZE", "FETCH_TIMEOUT", "LOG_LEVEL", "INTERVAL"],
        "Notifications": ["WEBHOOK_URL", "WEBHOOK_TYPE", "PUSHGATEWAY_URL"],
        "AbuseIPDB": ["ABUSEIPDB_API_KEY"],
    }

    secret_keys = {"CROWDSEC_LAPI_KEY", "CROWDSEC_MACHINE_PASSWORD", "ABUSEIPDB_API_KEY"}

    for section, keys in sections.items():
        print(f"  --- {section} ---")
        for key in keys:
            val = state.get(key, "(default)")
            if key in secret_keys and val and val != "(default)":
                val = "****"
            print(f"    {key:<36} = {val}")
        print()

    print("  --- Blocklist Groups ---")
    enabled_groups = []
    disabled_groups = []
    for key in ORDERED_ENABLE_KEYS:
        name, _ = GROUP_META.get(key, (key, ""))
        count = SOURCE_COUNTS.get(key, 0)
        if _is_enabled(state, key):
            enabled_groups.append(f"{name} ({count})")
        else:
            disabled_groups.append(f"{name} ({count})")

    total_sources = sum(
        SOURCE_COUNTS.get(k, 0) for k in ORDERED_ENABLE_KEYS if _is_enabled(state, k)
    )
    print(f"    Enabled  ({len(enabled_groups)} groups, {total_sources} sources):")
    for g in enabled_groups:
        print(f"      [+] {g}")
    if disabled_groups:
        print(f"    Disabled ({len(disabled_groups)} groups):")
        for g in disabled_groups:
            print(f"      [x] {g}")
    print()
    input("  Press Enter to continue...")


# ---------------------------------------------------------------------------
# Main menu loop
# ---------------------------------------------------------------------------

def main_menu(state):
    while True:
        clear_screen()
        print_header(f"CrowdSec Blocklist Import v{__version__} Setup")

        connected = bool(state.get("CROWDSEC_LAPI_URL") and state.get("CROWDSEC_LAPI_KEY"))
        enabled_count = sum(1 for k in ORDERED_ENABLE_KEYS if _is_enabled(state, k))
        total_sources = sum(
            SOURCE_COUNTS.get(k, 0) for k in ORDERED_ENABLE_KEYS if _is_enabled(state, k)
        )

        print(f"  Connection : {'configured' if connected else 'not configured'}")
        print(f"  Blocklists : {enabled_count}/{len(ORDERED_ENABLE_KEYS)} groups enabled"
              f"  ({total_sources} sources)")
        print()
        print("  1) Configure CrowdSec connection")
        print("  2) Select blocklists")
        print("  3) Advanced settings")
        print("  4) Generate .env file")
        print("  5) Test connection & dry run")
        print("  6) View current configuration")
        print("  0) Exit")
        print()

        choice = prompt_choice("  Choice", 6)

        if choice == 0:
            print()
            print("  Exiting setup wizard.")
            print()
            break
        elif choice == 1:
            menu_crowdsec_connection(state)
        elif choice == 2:
            menu_select_blocklists(state)
        elif choice == 3:
            menu_advanced_settings(state)
        elif choice == 4:
            menu_generate_env(state)
        elif choice == 5:
            menu_test_connection(state)
        elif choice == 6:
            menu_view_config(state)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_setup():
    """Main entry point called from blocklist_import.py --setup."""
    state = {}

    env_path = Path(".env")
    if env_path.exists():
        try:
            from dotenv import dotenv_values
            loaded = {k: v for k, v in dotenv_values(env_path).items() if v is not None}
            state.update(loaded)
            print(f"Loaded existing configuration from {env_path.resolve()}")
        except ImportError:
            pass

    try:
        main_menu(state)
    except KeyboardInterrupt:
        print()
        print("Setup wizard interrupted.")

    return 0


if __name__ == "__main__":
    sys.exit(run_setup())
