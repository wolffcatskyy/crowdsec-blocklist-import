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
chmod +x import.sh
LOG_LEVEL=DEBUG DRY_RUN=true MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh
```

---

## Project Architecture

This is a **single-file bash tool** (`import.sh`, ~620 lines):

- **Config**: Environment variables at the top (lines 10-35)
- **Logging**: `log()`, `debug()`, `info()`, `warn()`, `error()` functions
- **Source control**: `normalize_source_name()`, `is_source_enabled()`, `show_source_overrides()`
- **Statistics**: `record_stat()`, `show_stats()` — per-source IP count tracking
- **CrowdSec access**: `run_cscli()`, `run_cscli_stdin()` — Docker exec / native abstraction
- **Auto-detection**: `find_crowdsec_container()`, `setup_crowdsec()` — mode selection
- **Fetching**: `fetch_list()` — download and filter individual blocklists
- **Pipeline**: `main()` — orchestrates fetch → combine → dedup → filter → import

**Runtime**: Docker image based on `docker:24-cli` (Alpine). Dependencies: `bash`, `curl`, `coreutils`.

**Key constraint**: Single file, no new dependencies, works in both Docker and native mode.

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

```bash
# Clear variable names
CROWDSEC_CONTAINER_NAME="crowdsec"

# Use the project's log helpers
error "Critical issue"       # Always shown
warn  "Non-critical issue"   # Warning, continue
info  "Informational"        # Normal logging
debug "Detailed info"        # LOG_LEVEL=DEBUG only

# Always check for errors
if ! command; then
    error "Descriptive message"
    return 1
fi
```

### Key Rules

- **Single file** — `import.sh` must remain self-contained
- **No new dependencies** — bash, curl, and coreutils only
- **Both modes** — changes must work in Docker and native mode
- **Idempotent** — running twice should import 0 IPs the second time
- **Graceful failure** — individual blocklist failures are logged, not fatal

---

## Getting Help

**Can I use AI tools?** Yes — that's the whole point. Just review and test everything before submitting.

**What if my PR is rejected?** We'll explain why and suggest improvements.

**How do I add a new blocklist source?** Add a `fetch_list` call in `main()` following the existing pattern.

---

**Ready? [Browse AI-Ready Issues →](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues?q=is%3Aopen+label%3Aai-ready)**
