# Contributing to CrowdSec Blocklist Import

Contributions welcome — from humans, AIs, or both working together.

This guide is structured so you can paste it (or a section of it) directly into your AI assistant (Claude, ChatGPT, Copilot, etc.) along with an issue, and get a useful PR out of it.

## Quick Start

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

# Run directly (requires cscli in PATH)
MODE=native ./import.sh

# Or run via Docker (requires Docker socket access)
MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh

# Or use Docker Compose
docker compose up
```

## Architecture Overview (for AI context)

**Single-file Bash script** — everything is in `import.sh` (~200 lines).

```
import.sh
├── Configuration (env vars: MODE, CROWDSEC_CONTAINER, DECISION_DURATION, etc.)
├── Logging helpers (log, debug, info, warn, error)
├── send_telemetry() — anonymous usage ping
├── run_cscli() / run_cscli_stdin() — abstraction over Docker vs native mode
├── find_crowdsec_container() — auto-detect CrowdSec container by name
├── setup_crowdsec() — detect and configure access mode (native/docker/auto)
├── show_docker_help() — troubleshooting output for Docker issues
├── fetch_list() — download a single blocklist with filtering
└── main() — orchestration:
    1. Setup CrowdSec access mode
    2. Fetch from 28 blocklist sources (IPsum, Spamhaus, Firehol, Abuse.ch, etc.)
    3. Combine all IPs, extract valid IPv4 addresses
    4. Filter out private/reserved ranges (RFC1918, loopback, etc.)
    5. Query existing CrowdSec decisions to avoid duplicates
    6. Bulk import new IPs via `cscli decisions import`
    7. Send telemetry, cleanup temp files
```

**Two access modes:**
- **Docker mode** — runs `docker exec $CONTAINER cscli ...` (needs Docker socket)
- **Native mode** — runs `cscli` directly (CrowdSec installed on host)
- **Auto mode** (default) — tries native first, falls back to Docker

**Key design principles:**
- **Run once and exit** — not a daemon; designed for cron scheduling
- **Idempotent** — checks existing decisions before importing, skips duplicates
- **Graceful failure** — individual blocklist fetches can fail without stopping the import
- **Minimal dependencies** — bash, curl, coreutils only (no Python, no pip)
- **Docker image** — based on `docker:24-cli` for Docker socket access

**Blocklist pipeline:**
```
28 sources → curl + filter → deduplicate → remove private IPs → diff vs existing → cscli decisions import
```

## How to Contribute with AI

### Step 1: Pick an issue

Browse [open issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues). There are currently **12 open issues** (1 bug, 11 enhancements) — great starting points for contributors.

### Step 2: Give your AI context

Copy this into your AI assistant:

```
I want to contribute to crowdsec-blocklist-import. Here's the project context:

- Single Bash script: import.sh (~200 lines)
- Dependencies: bash, curl, coreutils (no Python)
- Docker image: docker:24-cli base
- Config: all environment variables (MODE, CROWDSEC_CONTAINER, DECISION_DURATION, LOG_LEVEL, FETCH_TIMEOUT, TELEMETRY_ENABLED)
- Two modes: Docker (docker exec cscli) and Native (cscli directly)
- Auto-detection picks native first, then Docker
- Fetches 28 public blocklists, deduplicates, filters private IPs, imports via cscli decisions import
- Run-once design — meant for cron, not a long-running daemon
- Idempotent — queries existing decisions and only imports new IPs

The issue I want to work on is: [paste issue title and body here]
```

Then paste the contents of `import.sh` and ask your AI to implement the fix/feature.

### Step 3: Submit a PR

- Fork the repo
- Create a branch (`feat/your-feature` or `fix/your-fix`)
- Make your changes
- Test against a real CrowdSec instance (Docker or native)
- Open a PR with a clear description of what changed and why

## Writing Good Issues (for maintainers)

When creating issues, structure them for AI consumption:

```markdown
## What
[One sentence describing the desired outcome]

## Why
[Context on why this matters]

## Where in the code
[File, function, or line range in import.sh]

## Acceptance criteria
- [ ] Specific, testable requirement 1
- [ ] Specific, testable requirement 2

## Constraints
- Must not break existing env var config
- Must work in both Docker and native modes
- Script should remain a single file (import.sh)
- No new dependencies beyond bash/curl/coreutils
```

## Code Style

- **Bash** with `set -e` — script exits on error
- **Environment variables** for all config — with sensible defaults via `${VAR:-default}`
- **Logging** via `log()`, `info()`, `warn()`, `error()`, `debug()` helpers (not raw `echo`)
- **Log levels** controlled by `LOG_LEVEL` env var (DEBUG, INFO, WARN, ERROR)
- **Error handling**: individual fetch failures are logged and counted, not fatal
- **Functions** for reusable logic — `fetch_list()`, `run_cscli()`, etc.
- **Comments** for non-obvious behavior (regex filters, awk pipelines)
- Keep it in **one file** — `import.sh` should remain self-contained
- **No new dependencies** — bash, curl, and coreutils only
- **Both modes** — changes must work in Docker mode and native mode

## Testing

There's no test suite yet (good first contribution!). For now:

1. Run with `LOG_LEVEL=DEBUG` and verify log output
2. Test in both Docker mode (`MODE=docker`) and native mode (`MODE=native`)
3. Verify idempotency — running twice should import 0 IPs the second time
4. Check that private/reserved IPs are filtered correctly
5. Test with unreachable blocklist URLs to verify graceful failure

## Open Issues — Great Starting Points

There are **12 open issues** — a mix of 1 bug and 11 enhancement requests. Browse them at:
https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues

Notable enhancements include per-feed enable/disable, direct LAPI mode (no Docker socket), custom feed URLs, and Prometheus metrics.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
