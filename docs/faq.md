# Frequently Asked Questions

Quick answers to common questions about crowdsec-blocklist-import.

## General Usage

### How often should I run the import?

**Recommended: Every 4-24 hours**, depending on your threat model and resource availability.

**Factors to consider:**

- **Threat environment:** High-risk networks (public-facing) benefit from more frequent updates (every 4-6 hours)
- **Resource availability:** System resources (CPU, network, memory) may limit frequency
- **Blocklist freshness:** Most lists update daily; importing more than daily sees minimal returns
- **False positives:** More frequent imports mean more opportunities for bad data; daily is usually a good balance

**Typical configurations:**
- **Conservative:** Every 24 hours (daily)
- **Standard:** Every 12 hours (twice daily)
- **Aggressive:** Every 4-6 hours (multiple times daily)

Set this in your scheduler (cron, Task Scheduler, systemd timer):
```bash
# Twice daily at 12:00 and 18:00
0 12,18 * * * /path/to/blocklist_import.py
```

---

### Will this slow down my CrowdSec instance?

**No.** Imports do not negatively impact CrowdSec performance.

**Why:**
- LAPI is designed to handle batch imports efficiently
- Decisions are inserted in batches, not one-at-a-time
- Import process is separate from decision-making/enforcement
- Bouncers query decisions, not import operations

**Performance considerations:**
- Large imports (100K+ IPs) may momentarily use CPU
- First import is slower; subsequent runs are faster due to deduplication
- Once imported, decisions are cached in memory by bouncers
- No noticeable query performance degradation

**If you're concerned:**
- Use `--batch-size=500` to reduce memory footprint
- Run imports during off-peak hours
- Monitor with: `docker stats crowdsec`

---

### Can I use this without Docker?

**Yes, absolutely.** Docker is optional.

**Standalone installation:**
```bash
# Clone or download
git clone https://github.com/wolffcatskyy/crowdsec-blocklist-import.git
cd crowdsec-blocklist-import

# Install dependencies
pip install -r requirements.txt

# Run directly
python3 blocklist_import.py
```

**Requirements:**
- Python 3.11+
- pip (Python package manager)
- Network access to blocklist sources and CrowdSec LAPI

**Configuration:**
- Set environment variables (see `.env.example` for all options)
- No Docker or Docker Compose needed
- Works on any system with Python

**Scheduling:**
- **Linux:** Use cron
  ```bash
  0 */6 * * * /usr/bin/python3 /path/to/blocklist_import.py >> /var/log/blocklist-import.log 2>&1
  ```
- **Windows:** Use Task Scheduler
- **macOS:** Use launchd or cron

---

### What happens if a blocklist source goes down?

**The import continues with other sources.**

**Error handling:**
- Individual source failures don't stop the entire import
- Failed sources are logged with details
- Other blocklists are imported normally
- Script completes with a summary of successes and failures

**Example output:**
```
Importing from sources:
- source1: OK (1,234 IPs)
- source2: TIMEOUT (skipped)
- source3: OK (5,678 IPs)
- source4: 404 NOT FOUND (skipped)

Total: 6,912 new IPs imported
```

**What you should do:**
- Review logs for failed sources
- Consider removing consistently failing sources
- Check if the source is permanently down or temporarily unavailable
- Wait a few hours and retry if it was a temporary issue

---

### How does deduplication work?

**Automatic duplicate prevention** ensures the same IP isn't banned twice.

**Process:**
1. Script queries CrowdSec LAPI for existing decisions
2. For each IP from blocklist sources, checks if already present
3. Only new IPs are added to CrowdSec
4. Already-banned IPs are skipped (deduplication)

**Key points:**
- Deduplication happens at the LAPI level
- Each decision has an `origin` tag (e.g., "blocklist-import")
- Same IP from different sources = one decision
- Removes unnecessary duplicate records
- Makes database efficient and prevents bloat

**Example:**
```
Blocklist A contains: 1.1.1.1, 2.2.2.2, 3.3.3.3
Blocklist B contains: 2.2.2.2, 3.3.3.3, 4.4.4.4
Existing decisions: 3.3.3.3

Result: Add 1.1.1.1, 2.2.2.2, 4.4.4.4 (skip 3.3.3.3, already present)
```

**To reset deduplication:**
```bash
# Clear all blocklist-import decisions
cscli decisions delete --origin blocklist-import

# Then re-import
python3 blocklist_import.py
```

---

## Configuration & Customization

### Can I add custom blocklist sources?

**Not yet natively**, but workarounds exist.

**Current limitation:**
- Sources are hardcoded in the application
- Per-feed control via `ENABLE_*` environment variables (added in v3.0)

**Workarounds:**

1. **Modify source list in code:**
   Edit `blocklist_import.py` and add your source to the `SOURCES` list, then run directly.

2. **Pre-process custom blocklist:**
   Download your blocklist separately, then feed it to CrowdSec:
   ```bash
   # Download your custom blocklist
   curl https://yoursite.com/custom-blocklist.txt > /tmp/custom.txt

   # Add to CrowdSec
   while read ip; do
     cscli decisions add --ip "$ip" --origin custom-blocklist
   done < /tmp/custom.txt
   ```

3. **Use custom wrapper script:**
   Create a script that combines blocklist-import with your custom sources.

4. **Future releases:**
   Config file support (YAML/TOML) for custom sources is under consideration.

---

### Is IPv6 supported?

**Partial support** with full support planned for v4.0.0.

**Current status (v3.4.0):**
- IPv6 addresses are imported if present in blocklists
- IPv6 CIDR blocks are supported
- Limited testing on IPv6 edge cases

**Known limitations:**
- Not all sources include IPv6 addresses
- IPv6 deduplication may not work perfectly
- IPv6 isn't a primary focus for most blocklists

**Full IPv6 support (v4.0.0):**
- Planned for future release
- Will include dedicated IPv6 sources
- Better IPv6 deduplication
- IPv6-specific validation

**For now:**
- Mixed IPv4/IPv6 imports work fine
- If you need IPv6 focus, wait for v4.0.0 or use workaround above

---

### What's the difference between the bash and Python versions?

**Python is the current, maintained version. Bash is deprecated.**

| Feature | Bash (Legacy) | Python (Current) |
|---------|---------------|------------------|
| Status | Deprecated, EOL | Active development |
| Maintenance | No | Yes |
| Performance | Slower | Faster |
| Memory usage | Higher | Optimized |
| Error handling | Basic | Comprehensive |
| Dry-run | No | Yes |
| Debug mode | No | Yes |
| Deduplication | Basic | Advanced |
| Configuration | Limited | Full |
| Extensibility | Difficult | Easy |

**Why Python was better:**
- Faster IP validation and batch processing
- Proper error handling and recovery
- Memory-efficient streaming
- Better logging and debugging

**Migration path:**
```bash
# Old way (don't use)
bash import.sh

# New way (use this)
python3 blocklist_import.py
```

Strongly recommend switching if you're still on bash.

---

## Decision Management

### How do I remove all imported decisions?

**Use `cscli` command-line tool:**

```bash
cscli decisions delete --origin blocklist-import
```

**This will:**
- Remove all decisions created by blocklist-import
- Keep other decisions (manual bans, alert-generated, etc.)
- Take effect immediately in bouncers

**Selective removal:**
```bash
# Remove decisions for specific IP
cscli decisions delete --ip 1.2.3.4

# Remove decisions with specific scope
cscli decisions delete --scope ip --origin blocklist-import

# Remove decisions older than X days
cscli decisions delete --until "2024-01-01"
```

**Before bulk deletion:**
1. Backup current decisions: `cscli decisions list > backup.json`
2. Test removal on non-critical system first
3. Verify bouncers don't depend on these decisions

---

### Does this work with CrowdSec Cloud/Console?

**Yes, it works with any LAPI endpoint.**

**Configuration:**

For CrowdSec Cloud (managed service):
```bash
CROWDSEC_LAPI_URL=https://api.crowdsec.net
CROWDSEC_LAPI_KEY=YOUR_CLOUD_BOUNCER_KEY
```

For self-hosted:
```bash
CROWDSEC_LAPI_URL=http://crowdsec.example.com:8080
CROWDSEC_LAPI_KEY=YOUR_LOCAL_BOUNCER_KEY
```

**Important:**
- Cloud API uses HTTPS (secure)
- Self-hosted typically uses HTTP
- Bouncer key must be generated from your Cloud/local instance
- Authentication works the same way (API key in headers)

**Cloud advantages:**
- No local infrastructure needed
- Automatic updates and maintenance
- Central dashboard across multiple sites

---

## Data Quality & Accuracy

### What about false positives?

**Manage false positives with allowlists and source selection.**

**Strategies:**

1. **Use allowlists:**
   Create an allowlist of IPs that should never be blocked:
   ```
   # allowlist.txt
   192.168.1.0/24    # Home network
   10.0.0.0/8        # Office network
   ```
   Configure: `ALLOWLIST=192.168.1.0/24,10.0.0.0/8`

2. **Disable aggressive sources:**
   Some sources are overly aggressive (Tor, proxy lists):
   ```bash
   # Disable Tor list if you use Tor for anything
   # Disable proxy lists if you have legitimate proxy users
   ```

3. **Review source reputation:**
   Use reputable, established sources:
   - AlienVault OTX
   - Spamhaus
   - PhishTank
   - URLhaus
   - Avoid: Generic "all bad IPs" lists

4. **Monitor false positives:**
   - Review CrowdSec alerts for legitimate traffic being blocked
   - Check access logs for false blocks
   - Adjust allowlist as needed

5. **Use decision expiry:**
   Set time limits on imported decisions:
   ```bash
   # Decisions expire after 30 days (example)
   DECISION_DURATION=30d
   ```

6. **Community feedback:**
   Report false positives to blocklist maintainers.

---

### How much bandwidth does it use?

**Minimal.** Most blocklists are small text files.

**Typical bandwidth usage:**
- Single import run: 5-50 MB (depends on number of sources)
- Most sources: Under 1 MB each
- Largest sources: 5-10 MB
- Frequency impact: Daily import = 5-50 MB/day

**Comparison:**
- Single Netflix stream: 500+ MB/hour
- Slack messaging: 5-20 MB/day
- CrowdSec updates: 50-100 MB/week

**Optimization:**
- If bandwidth is constrained, reduce import frequency
- Select only essential sources
- Avoid extremely large lists (10+ MB)

**Network efficiency:**
- Uses streaming downloads (doesn't load entire file into memory)
- Compressed transfers when available
- Minimal LAPI communication overhead

---

## Deployment & Operations

### What are the system requirements?

**Minimal:**

| Component | Requirement |
|-----------|-------------|
| CPU | 1 core (shared is fine) |
| Memory | 256 MB minimum (512 MB recommended) |
| Disk | 100 MB for application |
| Network | Outbound access to blocklist sources and LAPI |
| Python | 3.11+ (if not using Docker) |

**For Docker:**
- Docker Engine 20.10+ (any OS with Docker)
- Memory limit: 512 MB - 1 GB
- CPU: No specific requirement (shares host)

**Network:**
- Outbound HTTPS to blocklist sources (443)
- Outbound HTTP or HTTPS to CrowdSec LAPI
- No inbound requirements

---

### How do I monitor the import?

**Multiple options:**

1. **View logs:**
   ```bash
   docker logs blocklist-import  # Docker
   tail -f /var/log/blocklist-import.log  # Standalone
   ```

2. **Check decision counts:**
   ```bash
   cscli decisions list --origin blocklist-import | wc -l
   ```

3. **Monitor with Prometheus:**
   If Push Gateway configured, check metrics:
   - `blocklist_import_new_ips`
   - `blocklist_import_total_ips`
   - `blocklist_import_sources_failed`

4. **Watch Grafana dashboard:**
   Import the provided dashboard JSON to visualize trends.

5. **Check recent decisions:**
   ```bash
   cscli decisions list -l 10 --origin blocklist-import
   ```

6. **CrowdSec dashboard:**
   View "Decisions" tab for recent imports.

---

### Can I run multiple instances?

**Yes, but not recommended** without deduplication.

**Considerations:**
- Multiple instances import same sources = duplicate decisions
- Deduplication at LAPI level prevents duplicates
- Each instance should use a unique `DECISION_ORIGIN` to distinguish metrics
- Different scheduling recommended (stagger imports)

**Recommended approach:**
- Single instance per CrowdSec deployment
- Load balance by distributing sources if needed
- Use scheduling to avoid simultaneous runs

**If you must run multiple:**
```yaml
# Instance 1
DECISION_ORIGIN: blocklist-import-1
CROWDSEC_LAPI_URL: http://crowdsec:8080

# Instance 2
DECISION_ORIGIN: blocklist-import-2
CROWDSEC_LAPI_URL: http://crowdsec:8080
```

---

## Troubleshooting Quick Links

For issues not covered here, see the full [Troubleshooting Guide](troubleshooting.md) which includes:

- Authentication failures and credential issues
- No IPs being imported (deduplication and connectivity)
- Blocklist source timeouts and failures
- Docker networking problems
- Memory issues with large imports
- Metrics and monitoring problems
- Permission and access control issues
- Legacy script migration

---

## Community & Support

**Need help?**
- GitHub Issues: [crowdsec-blocklist-import/issues](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues)
- CrowdSec Community: [discourse.crowdsec.net](https://discourse.crowdsec.net)
- Include logs, configuration (without secrets), and environment details

**Want to contribute?**
- Fork the repository
- Submit pull requests for features or fixes
- Report bugs with detailed information

---

## Version Information

- **Current stable:** v3.4.0
- **Upcoming:** v3.5.0 (notifications + scheduling), v4.0.0 (IPv6 + AbuseIPDB)
- **Deprecated:** bash (import.sh)

Check [Releases](https://github.com/wolffcatskyy/crowdsec-blocklist-import/releases) for latest version.
