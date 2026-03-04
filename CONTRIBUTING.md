# Contributing to crowdsec-blocklist-import

We've reinvented open source contributing. Every issue in this repo is **AI-Ready** — structured so that you (or your AI tool) can pick one up and start coding immediately.

## AI-Ready Issues — How It Works

Every issue follows a structured format:

| Section | Purpose |
|---------|---------|
| **Context** | What the project does, architecture overview |
| **Current Behavior** | What happens now (with code snippets) |
| **Desired Behavior** | What should happen after the change |
| **Implementation Guide** | Exact files, functions, and approach |
| **Acceptance Criteria** | Checkbox list of "done" conditions |
| **Constraints** | What NOT to do (guardrails) |
| **AI Prompt** | Ready-to-paste prompt for AI coding tools |

### Contribute in 3 Steps

1. **Pick an issue** — Browse [`ai-ready`](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready) issues
2. **Copy the AI Prompt** — Each issue has a fenced code block at the bottom
3. **Paste into your AI tool** — Claude Code, Cursor, GitHub Copilot, ChatGPT, etc.

Then review the output, test it, and submit a PR. That's it.

### Why This Works

- **No codebase knowledge required** — the issue provides all the context
- **No onboarding docs to read** — file paths and function names are in the issue
- **No guessing what "done" means** — acceptance criteria are explicit checkboxes
- **AI tools produce better code** — structured prompts with constraints beat vague descriptions

---

## Use This Format In Your Own Projects

Want to adopt AI-Ready Issues for your repos? Here's the template:

```markdown
## Context
[What the project does, 2-3 sentences. Architecture: single file? Multi-service?]

## Current Behavior
[What happens now, with code snippets showing the relevant section]

## Desired Behavior
[What should happen, with example output/behavior]

## Implementation Guide
### File: `path/to/file.ext`
[Step-by-step: what to add, where to add it, example code]

## Acceptance Criteria
- [ ] [Specific, testable condition]
- [ ] [Another condition]

## Constraints
- **[Rule]** — [Why this constraint exists]

## AI Prompt
\```
[Single paragraph prompt that an AI tool can execute. Reference specific files,
functions, and patterns. Include what NOT to do.]
\```
```

The key insight: **write issues for machines, not just humans.** Be explicit about file paths, function names, and constraints. Ambiguity is the enemy of good AI-generated code.

---

## Development Setup

### Prerequisites

```bash
docker --version  # Should be 20.10+
docker ps | grep crowdsec  # CrowdSec must be running
```

### Local Testing

```bash
# Build the container
docker build -t crowdsec-blocklist-import:dev .

# Run with debug output
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CROWDSEC_CONTAINER=crowdsec \
  -e LOG_LEVEL=DEBUG \
  -e DRY_RUN=true \
  crowdsec-blocklist-import:dev
```

### Testing Directly

```bash
# Install dependencies
pip install -r requirements.txt

# Run with debug output
LOG_LEVEL=DEBUG DRY_RUN=true python3 blocklist_import.py
```

---

## Project Architecture

This is a **single-file Python tool** (`blocklist_import.py`):

- **Config**: Environment variables and `.env` file support
- **Logging**: Structured logging with configurable `LOG_LEVEL`
- **Source control**: `BlocklistSource` dataclass, `ENABLE_*` env var toggles per source
- **Statistics**: Per-source metrics via `FetchResult` dataclass, Prometheus push support
- **CrowdSec access**: LAPI client with machine and bouncer authentication
- **Fetching**: `fetch_blocklist()`, `fetch_abuseipdb_api()` — download, parse, and filter
- **Pipeline**: Fetch → deduplicate → allowlist filter → batch import via LAPI
- **Daemon mode**: Built-in scheduler (`INTERVAL` env var) with graceful signal handling
- **Webhooks**: Discord, Slack, or generic JSON POST notifications after each run

**Runtime**: Docker image based on `python:3.11-slim`. Dependencies: `requests`, `python-dotenv`, `prometheus-client`.

**Key constraint**: Single file, works in both Docker and native mode.

---

## Submitting Pull Requests

### Branch Naming

- `fix/` — bug fixes (`fix/container-detection`)
- `feature/` — new features (`feature/ipv6-support`)
- `docs/` — documentation (`docs/daemon-mode`)

### Commit Messages

- `Fix:` for bug fixes
- `Feature:` for new features
- `Docs:` for documentation

### PR Template

```markdown
## Description
Brief summary of what this PR does.

## Issue
Closes #XX

## How Was This Tested?
- Environment: [Docker/native, OS, CrowdSec version]
- Scenarios verified: [list]

## Checklist
- [ ] Tested locally with DRY_RUN=true
- [ ] Works in both Docker and native modes
- [ ] No new dependencies added
- [ ] Documentation updated if needed

## AI Assistance (if applicable)
**Tool:** [Claude / Cursor / Copilot / etc.]
**Prompt used:** [paste or summarize]
**Manual changes:** [what you adjusted after AI generation]
```

### Review Process

1. We review within a few days
2. We might request changes — this is collaborative
3. Once approved, we merge and credit you as a contributor

---

## Code Style

```python
# Clear variable names
CROWDSEC_LAPI_URL = os.getenv("CROWDSEC_LAPI_URL", "")

# Use the project's logging
logger.error("Critical issue")       # Always shown
logger.warning("Non-critical issue") # Warning, continue
logger.info("Informational")         # Normal logging
logger.debug("Detailed info")        # LOG_LEVEL=DEBUG only
```

### Key Rules

- **Single file** — `blocklist_import.py` must remain self-contained
- **Minimal dependencies** — `requests`, `python-dotenv`, `prometheus-client` only
- **Both modes** — changes must work in Docker and native mode
- **Idempotent** — running twice should import 0 IPs the second time
- **Graceful failure** — individual blocklist failures are logged, not fatal

---

## Getting Help

**Can I use AI tools?** Yes — that's the whole point. Just review and test everything before submitting.

**What if my PR is rejected?** We'll explain why and suggest improvements.

**How do I add a new blocklist source?** Add a new `BlocklistSource` entry to the `SOURCES` list in `blocklist_import.py` following the existing pattern.

---

**Ready? [Browse AI-Ready Issues →](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready)**
