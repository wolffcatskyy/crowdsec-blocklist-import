# Contributing to crowdsec-blocklist-import

Welcome! We're thrilled you're interested in contributing. This guide is designed for **everyone** — whether you're contributing your first line of code, using AI tools to help, or simply reporting ideas. No prior open source experience required.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [First-Time Contributors](#first-time-contributors)
- [Using AI to Contribute](#using-ai-to-contribute)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Code of Conduct](#code-of-conduct)
- [Getting Help](#getting-help)

---

## Ways to Contribute

Contributions aren't limited to code. Here are ways you can help:

### Bug Reports & Issues
- Found something broken? [Open an issue](../../issues)
- Unexpected behavior in Docker deployment? Let us know
- Container detection not working? We want to fix it

### Documentation
- Improved installation instructions
- Clearer explanations of Docker Compose setup
- Troubleshooting guides based on your experience
- Examples for different CrowdSec configurations

### Features & Enhancements
- New blocklist source integrations
- Better error messages
- Performance improvements
- Support for additional container runtimes

### Testing & Quality
- Test the tool on your setup
- Report edge cases or compatibility issues
- Suggest security improvements
- Help improve automated tests

### Community
- Answer questions from other users
- Share your deployment stories
- Help improve this documentation

---

## First-Time Contributors

Never contributed to open source before? Perfect. This project is a great place to start.

### Step 1: Fork the Repository

Click the **Fork** button at the top of the [repository page](../../). You now have your own copy to experiment with safely.

### Step 2: Clone Your Fork

```bash
git clone https://github.com/YOUR-USERNAME/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import
```

### Step 3: Create a Branch

```bash
git checkout -b fix/my-fix-name
# or for features:
git checkout -b feature/my-feature-name
```

**Branch naming conventions:**
- `fix/` — bug fixes (`fix/container-detection`)
- `feature/` — new features (`feature/ipv6-support`)
- `docs/` — documentation (`docs/kubernetes-guide`)
- `test/` — testing improvements (`test/docker-compose-validation`)

### Step 4: Make Your Changes

See [Making Changes](#making-changes) below.

### Step 5: Commit and Push

```bash
git add .
git commit -m "Fix: container detection with custom names"
git push origin fix/my-fix-name
```

**Commit message format:**
- `Fix:` for bug fixes
- `Feature:` for new features
- `Docs:` for documentation
- `Test:` for test additions

### Step 6: Open a Pull Request

1. Go to the original repository
2. Click **Pull Requests** → **New Pull Request**
3. Select your branch
4. Fill out the PR template
5. Submit!

---

## Using AI to Contribute

We **welcome and encourage** AI-assisted contributions. AI tools (Claude, ChatGPT, GitHub Copilot, etc.) can help you generate code, write tests, improve documentation, and debug issues.

### Architecture Context for AI

Paste this into your AI assistant along with the issue you want to work on:

```
I want to contribute to crowdsec-blocklist-import. Here's the project context:

- Single Bash script: import.sh (~200 lines)
- Docker image based on docker:24-cli
- Two access modes: Docker exec (runs cscli inside CrowdSec container) and LAPI (direct HTTP API calls)
- Config via environment variables (MODE, CROWDSEC_CONTAINER, DECISION_DURATION, LOG_LEVEL, FETCH_TIMEOUT, TELEMETRY_ENABLED)
- Auto-detection picks native first, then Docker
- Functions: log helpers, run_cscli/run_cscli_stdin (Docker/native abstraction), find_crowdsec_container (auto-detection), fetch_list (download + import individual blocklists), main pipeline
- Dependencies: bash, curl, coreutils, docker CLI (for Docker mode)
- The script downloads 28 IP blocklists, converts them to CrowdSec decision format, deduplicates, filters private IPs, and imports via cscli or LAPI
- Run-once design — meant for cron, not a long-running daemon
- Idempotent — queries existing decisions and only imports new IPs

The issue I want to work on is: [paste issue title and body here]
```

Then paste the contents of `import.sh` and ask your AI to implement the fix/feature.

### Guidelines for AI-Assisted Work

**You are always responsible for your contribution.**

#### Required

1. **Review everything before submitting** — read every line, understand what it does
2. **Disclose AI assistance in your PR:**
   ```
   **AI Assistance:** Generated using [tool] with prompts focusing on [specific area]
   **Validation:** Tested in [your setup], verified [specific test cases]
   **Changes Made:** Manually reviewed and adjusted [list specific changes]
   ```
3. **Test thoroughly** — run the code locally, test error conditions
4. **Validate against project standards** — follows our code style, works with Docker setup

#### What We Won't Accept

- Unreviewed or untested AI output ("AI slop")
- Code you don't understand
- Changes that don't address a specific issue
- Low-quality generic "improvements"

### AI-Friendly Issue Template

When opening an issue, provide context that both AI tools and humans can work with:

```markdown
## Issue Title
[Clear, specific description]

## Current Behavior
[What happens now]

## Expected Behavior
[What should happen]

## Environment
- Docker version: [e.g., 24.0.2]
- OS: [e.g., Ubuntu 22.04, Synology DSM 7.3]
- CrowdSec version: [e.g., 1.6.x]
- Access mode: [Docker exec / LAPI / Native]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Result]

## Logs
[Relevant error messages or logs]

## Suggested Solution (optional)
[Your idea for fixing this]
```

---

## Development Setup

### Prerequisites

```bash
# Check Docker version
docker --version  # Should be 20.10+

# Verify CrowdSec is running
docker ps | grep crowdsec
```

### Local Testing with Docker

```bash
# Build the container
docker build -t crowdsec-blocklist-import:dev .

# Run with test environment
docker run -e CROWDSEC_CONTAINER=your_container_name \
  -v /var/run/docker.sock:/var/run/docker.sock \
  crowdsec-blocklist-import:dev
```

### Testing the Script Directly

```bash
chmod +x import.sh

# Run with debug output
LOG_LEVEL=DEBUG MODE=docker CROWDSEC_CONTAINER=crowdsec ./import.sh

# Or native mode
LOG_LEVEL=DEBUG MODE=native ./import.sh
```

---

## Making Changes

### Code Style

```bash
# Use clear variable names
CROWDSEC_CONTAINER_NAME="crowdsec"

# Use functions for repeated logic
detect_container() {
    # Implementation
}

# Add comments for complex logic
# Check if container has cscli by attempting a test command
if docker exec "$container" cscli --help &>/dev/null; then
```

### Error Handling

```bash
# Always check for errors
if ! command; then
    error "Descriptive message about what failed"
    return 1
fi

# Use the project's log level helpers
error "Critical issue"       # Always shown — stop execution
warn  "Non-critical issue"   # Warning — continue but inform
info  "Informational"        # Normal logging
debug "Detailed info"        # Only shown with LOG_LEVEL=DEBUG
```

### Key Constraints

- **Single file** — `import.sh` should remain self-contained
- **No new dependencies** — bash, curl, and coreutils only
- **Both modes** — changes must work in Docker mode and native mode
- **Idempotent** — running twice should import 0 IPs the second time
- **Graceful failure** — individual blocklist fetch failures are logged, not fatal

### Pre-Submission Checklist

- [ ] Changes work locally
- [ ] Tested in both Docker and native modes
- [ ] Error messages are clear
- [ ] No debug code left in commits
- [ ] Documentation updated if needed

---

## Submitting Pull Requests

### PR Template

```markdown
## Description
Brief summary of what this PR does.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Problem It Solves
Which issue does this address? (Link: #123)

## How Was This Tested?
- Environment: [Docker/native, OS, CrowdSec version]
- Scenarios verified: [list]

## Checklist
- [ ] I've tested this locally
- [ ] Works in both Docker and native modes
- [ ] I've updated documentation if needed
- [ ] My code follows the project style
- [ ] No debug code or secrets in commits

## AI Assistance (if applicable)
**Tools Used:** Claude / ChatGPT / GitHub Copilot
**Scope:** Generated [specific part], reviewed and validated [changes made]
**Validation:** Tested in [environment], verified [specific test cases]
```

### Review Process

1. We'll review within a few days
2. We might request changes — this is normal and collaborative
3. Once approved, we'll merge and you'll be credited as a contributor

---

## Code of Conduct

- **Be respectful** to all contributors
- **Welcome diverse perspectives** and experiences
- **Ask questions** rather than make assumptions
- **Assume good intent** in interactions

---

## Getting Help

**"I'm not a programmer, can I still contribute?"**
Absolutely! Documentation, testing, and reporting issues are huge helps.

**"Can I use AI tools?"**
Yes! See [Using AI to Contribute](#using-ai-to-contribute). Just review and test everything.

**"How long until my PR is reviewed?"**
We aim for a few days. If it's been a week, ping us politely.

**"What if my PR is rejected?"**
That's okay! We'll explain why and suggest improvements. You can revise and resubmit.

---

## Open Issues — Great Starting Points

There are **12 open issues** — 1 bug and 11 enhancement requests. Browse them at:
https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues

Notable enhancements include per-feed enable/disable, direct LAPI mode (no Docker socket), custom feed URLs, and Prometheus metrics. Pick one, comment that you're working on it, and get started!

---

## Recognition

Contributors are listed on the GitHub contributors page and mentioned in release notes for significant contributions.

---

**Ready to contribute? Pick an issue from the [issues page](../../issues) and get started!**
