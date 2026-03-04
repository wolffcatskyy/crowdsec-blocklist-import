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

## Development Setup

### Prerequisites

Python 3.11+ is required.

```bash
python3 --version  # Should be 3.11+
```

### Install Dependencies

```bash
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

pip install -r requirements.txt
```

### Environment Configuration

```bash
cp .env.example .env
# Edit .env with your CrowdSec LAPI URL and credentials
```

See `.env.example` for all available configuration options.

### Running Locally

```bash
# Single run
python blocklist_import.py

# With debug logging
LOG_LEVEL=DEBUG python blocklist_import.py

# Dry run (validates config without modifying CrowdSec)
DRY_RUN=true python blocklist_import.py

# List all available blocklist sources
python blocklist_import.py --list-sources
```

### Testing with Docker

```bash
# Build the development image
docker build -t crowdsec-blocklist-import:dev .

# Run with debug output
docker run --rm \
  --network crowdsec \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=your_key \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=your_password \
  -e LOG_LEVEL=DEBUG \
  crowdsec-blocklist-import:dev
```

---

## Project Architecture

This is a **Python 3.11+ application** (`blocklist_import.py`, ~2000 lines):

### Structure

- **Configuration** (`Config` dataclass, lines 194–340)
  - LAPI settings (URL, credentials, decision duration)
  - Feature flags (webhook, Prometheus metrics, allowlist)
  - Customizable batch sizes, timeouts, retry logic

- **Blocklist Sources** (`BlocklistSource` dataclass, `BLOCKLIST_SOURCES` list)
  - 28+ public threat feeds (IPsum, Spamhaus, Firehol, etc.)
  - Per-source configuration (URL, comment format, field extraction)
  - Environment variable control (`ENABLE_*` flags)

- **Data Validation** (lines 64–188)
  - Environment variable validation with helpful error messages
  - Typo detection for unknown `ENABLE_*` variables
  - Boolean value validation

- **IP Processing** (`stream_filter_ips()`, `validate_ip()`)
  - Streaming downloads (memory-efficient)
  - IPv4 and IPv6 support
  - CIDR normalization and validation
  - Automatic deduplication

- **CrowdSec API Integration** (`import_decisions()`, `fetch_existing_decisions()`)
  - Batch processing to minimize API calls
  - Retry logic with exponential backoff
  - Automatic deduplication against existing decisions

- **Webhook Notifications** (`send_webhook()`, lines 1987+)
  - Discord, Slack, and generic JSON webhook formats
  - Per-source statistics in messages

- **Prometheus Metrics** (lines 564–650)
  - Per-source import statistics
  - Error categorization (connection errors, HTTP status codes, etc.)
  - Push to Prometheus Pushgateway

### Code Style

Use type hints and dataclasses throughout:

```python
from dataclasses import dataclass
from typing import Optional, Generator

@dataclass
class MyData:
    field1: str
    field2: int = 0
    field3: Optional[str] = None

def process_items(items: list[str]) -> Generator[str, None, None]:
    """Process items and yield results."""
    for item in items:
        if validate(item):
            yield item
```

### Key Patterns

- **Streaming** — Use generators for large lists (not lists)
- **Type hints** — All function signatures must have type hints
- **Error handling** — Log errors, don't crash on individual blocklist failures
- **Idempotency** — Running twice should import 0 new IPs the second time
- **Configuration** — Use environment variables, never hardcode values
- **Logging** — Use the `logger` instance, set log level via `LOG_LEVEL` env var

---

## Running Tests

Tests are not yet included in the repository. If you add tests, follow this pattern:

```bash
# Install test dependencies (add to requirements.txt if needed)
pip install pytest pytest-cov pytest-mock

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=. --cov-report=html
```

For now, testing is manual:

```bash
# Dry run against live CrowdSec
DRY_RUN=true python blocklist_import.py

# Check logs for errors
LOG_LEVEL=DEBUG python blocklist_import.py 2>&1 | less
```

---

## How to Add a New Blocklist Source

1. **Find the blocklist URL** (should be a plain-text IP/CIDR list)
2. **Determine the format**:
   - Comment character (usually `#` or `;`)
   - Does it have prefixes/suffixes to strip? (e.g., Spamhaus uses `192.0.2.0/24 ; comment`)
   - Set `extract_field=0` to extract the first field

3. **Create an `ENABLE_*` variable** for your source (e.g., `ENABLE_MYLIST`)
4. **Add to `BLOCKLIST_SOURCES`** list (line 352):

```python
BlocklistSource(
    name="My Custom List",
    url="https://example.com/list.txt",
    enabled_key="enable_mylist",  # Matches ENABLE_MYLIST env var
    comment_char="#",              # Change if needed
    extract_field=None,            # Set to 0 if first field only
),
```

5. **Add to `VALID_ENABLE_VARS`** (line 64):

```python
VALID_ENABLE_VARS: set[str] = {
    # ... existing sources ...
    "ENABLE_MYLIST",
}
```

6. **Test it**:

```bash
ENABLE_IPSUM=false ENABLE_MYLIST=true LOG_LEVEL=DEBUG python blocklist_import.py
```

7. **Update `.env.example`** with the new variable:

```env
# My Custom List
ENABLE_MYLIST=true
```

---

## How to Add a New Webhook Format

1. **Create a formatter function** (add after line 1987):

```python
def _format_myservice_webhook(stats: ImportStats) -> dict[str, Any]:
    """Format import results for MyService webhook."""
    return {
        "text": f"Imported {stats.total_new_ips} IPs from {stats.total_sources} sources",
        # Add MyService-specific fields here
    }
```

2. **Update `send_webhook()`** (line 1990) to call your formatter:

```python
if config.webhook_type == "myservice":
    payload = _format_myservice_webhook(stats)
elif config.webhook_type == "discord":
    payload = _format_discord_webhook(stats)
# ... etc
```

3. **Test it**:

```bash
WEBHOOK_URL=http://localhost:9999 \
WEBHOOK_TYPE=myservice \
python blocklist_import.py
```

4. **Document in README.md** under "Webhook Notifications"

---

## Submitting Pull Requests

### AI Disclosure

**Always disclose if AI assisted you.** Include this in your PR:

```
🤖 *This PR was assisted by Claude AI.*
```

### Branch Naming

- `fix/` — bug fixes (`fix/prometheus-label-overflow`)
- `feature/` — new features (`feature/abuseipdb-api`)
- `docs/` — documentation (`docs/webhook-setup`)

### Commit Messages

Start with an action verb:

- `Fix:` for bug fixes
- `Feature:` for new features
- `Docs:` for documentation
- `Refactor:` for code reorganization
- `Test:` for test additions

Example:
```
Feature: Add OPNsense webhook format

- Add _format_opnsense_webhook() formatter
- Update send_webhook() to support 'opnsense' type
- Add WEBHOOK_TYPE=opnsense to .env.example
- Test with dry run
```

### PR Template

```markdown
## Description
Brief summary of what this PR does.

## Motivation
Why was this change needed? Link to issue if applicable (Closes #123)

## Testing
- [ ] Tested with `DRY_RUN=true python blocklist_import.py`
- [ ] Verified against live CrowdSec instance
- [ ] Checked logs with `LOG_LEVEL=DEBUG`

## Checklist
- [ ] Code follows project style (type hints, dataclasses)
- [ ] No new production dependencies added
- [ ] `.env.example` updated if adding new config options
- [ ] README updated if adding new features

## AI Assistance
- **Tool:** Claude / Cursor / etc. (if used)
- **Disclosure:** 🤖 *This PR was assisted by Claude AI.*
```

### Review Process

1. We review within a few days
2. We might request changes — this is collaborative
3. Once approved, we merge and credit you as a contributor

---

## Code Review Guidelines

When reviewing PRs or testing locally, check for:

1. **Type hints** — All functions must have parameter and return type hints
2. **Error handling** — Individual blocklist failures should be logged, not fatal
3. **Logging** — Use `logger.info()`, `logger.warning()`, `logger.error()`, `logger.debug()`
4. **Idempotency** — Running twice should not create duplicates
5. **Configuration** — All magic numbers and strings should be in `Config` or top-level constants
6. **Documentation** — Code comments for complex logic, docstrings for functions

---

## Getting Help

**Can I use AI tools?** Yes — that's the whole point. Just review and test everything before submitting.

**What if my PR is rejected?** We'll explain why and suggest improvements. We appreciate all contributions.

**How do I report a bug?** Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Logs with `LOG_LEVEL=DEBUG`
- CrowdSec version and OS

**How do I request a feature?** Open an issue with:
- Use case (why you need it)
- Proposed solution
- Alternative approaches considered

---

**Ready? [Browse AI-Ready Issues →](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready)**
