# Troubleshooting

This guide covers common issues encountered when using crowdsec-blocklist-import and how to resolve them.

## Authentication Failures (401/403 from LAPI)

### Symptoms
- Script exits with "401 Unauthorized" or "403 Forbidden" errors
- LAPI connection fails during initial handshake
- Error messages mention invalid credentials or unauthenticated requests

### Causes
- Bouncer key is incorrect or expired
- Machine credentials are wrong
- Machine is not registered with CrowdSec
- LAPI is rejecting the authentication method

### Solutions

1. **Verify bouncer key registration:**
   ```bash
   cscli bouncers list
   ```
   Ensure your bouncer appears in the list and is not disabled.

2. **Re-register the bouncer:**
   ```bash
   cscli bouncers delete blocklist-import
   cscli bouncers add blocklist-import -o raw
   ```
   Copy the generated API key to your configuration.

3. **Check machine credentials:**
   ```bash
   cscli machines list
   ```
   Verify the machine is registered. If missing:
   ```bash
   cscli machines add blocklist-import --password 'YourSecurePassword'
   ```

4. **Validate LAPI connectivity:**
   ```bash
   curl -H "X-API-Key: YOUR_KEY" http://localhost:8080/v1/decisions
   ```
   Should return a 200 response with JSON data.

5. **Check configuration:**
   - Ensure `CROWDSEC_LAPI_URL` points to the correct CrowdSec instance
   - Verify `CROWDSEC_LAPI_KEY` is set correctly
   - Check that credentials are not expired

---

## No IPs Imported (0 New Additions)

### Symptoms
- Script completes successfully with "0 new IPs added"
- No decisions appear in CrowdSec
- All blocklist sources report "0 items processed"

### Causes
- All IPs from sources already exist in CrowdSec (deduplication working correctly)
- Blocklist sources are offline or unreachable
- Network connectivity issues preventing source downloads
- LAPI is not accepting decisions for some reason

### Solutions

1. **Run with dry-run and debug logging:**
   ```bash
   python3 blocklist_import.py --dry-run --debug
   ```
   This shows what would be imported without actually writing to CrowdSec.

2. **Check LAPI connectivity:**
   ```bash
   curl -v http://localhost:8080/v1/decisions
   ```
   Verify the endpoint responds and authentication succeeds.

3. **Verify blocklist sources are accessible:**
   ```bash
   python3 -c "import requests; print(requests.get('https://reputation.alienvault.com/reputation.snort').text[:100])"
   ```
   Test connectivity to one or more sources manually.

4. **Check for pre-existing decisions:**
   ```bash
   cscli decisions list | grep "blocklist-import" | wc -l
   ```
   If this returns a large number, previous imports are in the database.

5. **Inspect logs:**
   - Docker: `docker logs crowdsec-blocklist-import`
   - Standalone: Check application logs for detailed error messages
   - Look for per-source error messages indicating why sources failed

6. **Force reimport by clearing old decisions:**
   ```bash
   cscli decisions delete --origin blocklist-import
   ```
   Then run the import again. (Use carefully - this removes all previous blocklist decisions.)

---

## Blocklist Source Timeouts

### Symptoms
- Individual sources fail with timeout errors
- Some blocklists import, others fail
- Error messages indicate connection took too long
- Intermittent failures on certain sources

### Causes
- Upstream blocklist source is slow or overloaded
- `FETCH_TIMEOUT` is too low for slow sources
- DNS resolution delays
- Network latency or geographic distance from source
- Source is temporarily unavailable

### Solutions

1. **Increase fetch timeout:**
   - Environment variable: `FETCH_TIMEOUT=120` (default is 60 seconds)
   - Config file: Set in `.env` or compose.yaml
   - Command line: Add to your import call if supported

2. **Test source connectivity:**
   ```bash
   curl -w "Time: %{time_total}s\n" -o /dev/null -s https://reputation.alienvault.com/reputation.snort
   ```
   Identify which sources are slowest.

3. **Disable problematic sources:**
   Individual blocklist sources are controlled via `ENABLE_*` environment variables (all default to `true`).
   Set the corresponding variable to `false` to disable a problematic source:
   ```bash
   # In compose.yaml or .env — disable individual sources
   ENABLE_TOR=false
   ENABLE_FIREHOL_L3=false
   ENABLE_GREENSNOW=false
   ```
   Run `python3 blocklist_import.py --list-sources` to see all available source toggles.

4. **Check DNS resolution:**
   ```bash
   nslookup reputation.alienvault.com
   ```
   If slow, consider using a different DNS resolver (8.8.8.8, 1.1.1.1).

5. **Verify network connectivity:**
   ```bash
   ping -c 3 reputation.alienvault.com
   ```
   Check for packet loss or high latency.

6. **Monitor source status:**
   Keep track of which sources frequently timeout and consider removing unreliable ones.

---

## Docker Networking Issues

### Symptoms
- Container cannot reach CrowdSec LAPI
- "Connection refused" or "No such host" errors
- Works on standalone but fails in Docker
- Error mentions "localhost" not found

### Causes
- Container is on different Docker network than CrowdSec
- Using `localhost` or `127.0.0.1` instead of service name
- Network connectivity between containers broken
- Firewall rules blocking container communication

### Solutions

1. **Use service name instead of localhost:**
   - Wrong: `http://localhost:8080` or `http://127.0.0.1:8080`
   - Right: `http://crowdsec:8080`

   Update `CROWDSEC_LAPI_URL` in configuration:
   ```bash
   CROWDSEC_LAPI_URL=http://crowdsec:8080
   ```

2. **Verify both containers are on same network:**
   ```bash
   docker network ls
   docker inspect NETWORK_NAME | grep -A 20 '"Containers"'
   ```
   Both CrowdSec and blocklist-import should appear.

3. **Add container to CrowdSec network if missing:**
   ```bash
   docker compose down
   # Edit compose.yaml to use same network as CrowdSec
   docker compose up -d
   ```

4. **Check network communication:**
   ```bash
   docker exec blocklist-import curl -v http://crowdsec:8080/v1/decisions
   ```
   Should return 200 (or 403 if auth fails, but at least network works).

5. **Review compose.yaml networking:**
   ```yaml
   services:
     blocklist-import:
       networks:
         - crowdsec-net  # Same network as CrowdSec
     crowdsec:
       networks:
         - crowdsec-net

   networks:
     crowdsec-net:
       driver: bridge
   ```

---

## Memory Issues (Out of Memory)

### Symptoms
- Container killed with "OOMKilled" status
- Process crashes with "Segmentation fault"
- Import stops halfway through
- "MemoryError" in Python stack traces

### Causes
- `BATCH_SIZE` is too large for available memory
- Too many blocklist sources loaded simultaneously
- Large blocklist sources not being streamed properly
- Container memory limit too low

### Solutions

1. **Reduce batch size:**
   - Default: `BATCH_SIZE=1000`
   - Try: `BATCH_SIZE=500` or lower
   - Edit in `.env` or compose.yaml

2. **Limit blocklist sources:**
   - Use fewer, smaller sources
   - Remove extremely large lists or ones with many duplicate IPs
   - Stagger imports across multiple runs

3. **Increase container memory:**
   ```yaml
   services:
     blocklist-import:
       deploy:
         resources:
           limits:
             memory: 1G  # or higher
   ```

4. **Enable streaming mode (default):**
   Ensure you're not loading entire blocklists into memory:
   ```bash
   # Verify in code/logs that streaming is enabled
   python3 blocklist_import.py --debug | grep -i stream
   ```

5. **Monitor memory usage during import:**
   ```bash
   docker stats blocklist-import
   ```
   Watch memory growth to identify the problem source.

6. **Test with dry-run:**
   ```bash
   python3 blocklist_import.py --dry-run
   ```
   Dry-run uses less memory; if it works, memory management is the issue.

---

## Metrics Not Appearing in Prometheus

### Symptoms
- Prometheus Push Gateway shows no metrics from blocklist-import
- Grafana dashboards show no data
- PUSH_GATEWAY logs don't mention blocklist-import
- Metrics are null or missing

### Causes
- `METRICS_PUSHGATEWAY_URL` is incorrect or malformed
- Prometheus Push Gateway is not running
- Push request is being blocked by firewall
- Metrics are disabled in configuration
- Network connectivity issue

### Solutions

1. **Verify Push Gateway URL:**
   ```bash
   # Should be accessible
   curl http://METRICS_PUSHGATEWAY_URL/metrics | head -20
   ```
   URL format: `http://pushgateway.example.com:9091` (no trailing slash)

2. **Check Push Gateway status:**
   ```bash
   docker ps | grep pushgateway
   docker logs pushgateway
   ```
   Ensure it's running and has no errors.

3. **Test metric push manually:**
   ```bash
   curl -X POST http://localhost:9091/metrics/job/blocklist-import -d "test_metric 1"
   ```
   Then check: `curl http://localhost:9091/metrics | grep blocklist`

4. **Verify metrics are enabled:**
   Check code/environment that metrics push is not disabled:
   ```bash
   # Should not be false or empty
   echo $METRICS_PUSHGATEWAY_URL
   ```

5. **Check firewall/network:**
   ```bash
   telnet PUSH_GATEWAY_HOST 9091
   ```
   Should connect without error.

6. **Check container network (Docker):**
   Ensure blocklist-import container can reach Push Gateway:
   ```bash
   docker exec blocklist-import curl -v http://pushgateway:9091/metrics
   ```

7. **Inspect logs:**
   ```bash
   docker logs blocklist-import | grep -i "push\|metric"
   ```
   Look for push errors or disabled metrics messages.

---

## Docker Image Tag Mismatch (Issue #41)

### Symptoms
- Downloaded image version doesn't match expected version
- `--version` flag shows different version than tag
- Confusion about which version is running

### Causes
- Using `:latest` tag which changes with releases
- Image built locally doesn't match tagged releases
- Version bump not reflected in image metadata

### Solutions

1. **Use specific version tags instead of `:latest`:**
   ```yaml
   # Wrong
   image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest

   # Right
   image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:v3.4.0
   ```

2. **Verify image version:**
   ```bash
   docker run --rm ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:v3.4.0 --version
   ```
   Should output the exact version matching the tag.

3. **Rebuild with correct version:**
   ```bash
   docker build -t ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:v3.4.0 .
   ```

4. **Check image metadata:**
   ```bash
   docker inspect ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:v3.4.0 | grep -i version
   ```

5. **Use release tags from GitHub:**
   Check the [releases page](https://github.com/wolffcatskyy/crowdsec-blocklist-import/releases) for available tagged versions.

---

## Allowlist Not Working

### Symptoms
- IPs in allowlist are still being imported
- Decisions are created for allowlisted IPs
- Allowlist appears to be ignored

### Causes
- `ALLOWLIST` environment variable not set or formatted incorrectly
- CIDR notation not used (single IPs may require /32)
- Allowlist not configured in environment
- Typo in the comma-separated list
- Provider allowlist (`ALLOWLIST_GITHUB`) not enabled

### Solutions

1. **Verify allowlist format:**
   `ALLOWLIST` is a comma-separated environment variable of IPs and/or CIDR ranges:
   ```bash
   # Individual IPs
   ALLOWLIST="140.82.121.3,8.8.8.8"

   # CIDR ranges (v3.4.0+)
   ALLOWLIST="140.82.112.0/20,185.199.108.0/22"

   # Mixed
   ALLOWLIST="1.2.3.4,140.82.112.0/20,8.8.8.8"
   ```

2. **Check allowlist configuration:**
   ```bash
   echo $ALLOWLIST
   # Should show comma-separated IPs/CIDRs

   # Also check provider allowlists
   echo $ALLOWLIST_GITHUB
   # Should be "true" to auto-fetch GitHub IP ranges
   ```

3. **Test with debug mode:**
   ```bash
   python3 blocklist_import.py --debug | grep -i allow
   ```
   Should show allowlist being loaded and applied.

4. **Enable provider allowlists (v3.4.0+):**
   ```bash
   # Auto-fetch GitHub IP ranges from https://api.github.com/meta
   ALLOWLIST_GITHUB=true
   ```
   This covers git, web, api, hooks, and actions endpoints.

5. **Test allowlist functionality:**
   ```bash
   # Add a test IP to your ALLOWLIST
   # Run import with --dry-run
   python3 blocklist_import.py --dry-run --debug
   # Verify test IP is filtered out
   ```

6. **Check for IPv4/IPv6 mismatch:**
   Ensure you're allowlisting the right IP version:
   ```bash
   # IPv4
   ALLOWLIST="192.168.1.0/24"

   # IPv6
   ALLOWLIST="2001:db8::/32"
   ```

---

## Permission Denied Errors

### Symptoms
- Script fails with "Permission denied" on Docker secret files
- Cannot read configuration or secret files
- Errors running as non-root user

### Causes
- Secret file permissions too restrictive
- Wrong file ownership
- Running as non-root user without proper permissions
- Docker secret mounted with wrong permissions

### Solutions

1. **Check file permissions:**
   ```bash
   ls -la /run/secrets/
   # Should be readable
   ```

2. **Fix file permissions:**
   ```bash
   chmod 644 /path/to/secret/file
   chmod 755 /path/to/secret/directory
   ```

3. **Check file ownership:**
   ```bash
   ls -l /etc/crowdsec-blocklist-import/
   # Should be owned by the user running the script
   ```

4. **Fix ownership (if needed):**
   ```bash
   chown appuser:appgroup /path/to/config
   ```

5. **In Docker, use proper secret handling:**
   ```yaml
   services:
     blocklist-import:
       secrets:
         - crowdsec_lapi_key
       environment:
         CROWDSEC_LAPI_KEY_FILE: /run/secrets/crowdsec_lapi_key

   secrets:
     crowdsec_lapi_key:
       file: ./secrets/crowdsec_lapi_key.txt
   ```

6. **Verify read access:**
   ```bash
   # As the user running the app
   su - appuser -c "cat /path/to/config"
   ```
   Should succeed without errors.

---

## Legacy Bash Script Issues

### Symptoms
- Using old `import.sh` script
- Script is deprecated or no longer maintained
- Missing features or functionality

### Causes
- Using legacy bash version instead of modern Python implementation
- Bash script is EOL and no longer supported

### Solutions

1. **Migrate to Python version:**
   The Python implementation (`blocklist_import.py`) is the current, maintained version.
   ```bash
   # Old (deprecated)
   bash import.sh

   # New (current)
   python3 blocklist_import.py
   ```

2. **Why migrate:**
   - Better performance and reliability
   - Active maintenance and bug fixes
   - More features (dry-run, debug, deduplication)
   - Easier to extend and configure
   - Better error handling

3. **Installation:**
   ```bash
   pip install -r requirements.txt
   python3 blocklist_import.py
   ```

4. **Configuration:**
   Update your cron/scheduler to use the new script.

---

## Still Having Issues?

If your problem isn't covered here:

1. **Enable debug mode:**
   ```bash
   python3 blocklist_import.py --debug
   ```
   This provides detailed logging of all operations.

2. **Check logs:**
   - Docker: `docker logs blocklist-import`
   - Standalone: Check application log files
   - CrowdSec: `cscli metrics` for decision counts

3. **Verify basic connectivity:**
   ```bash
   cscli machines list           # Machine registered?
   cscli bouncers list           # Bouncer registered?
   cscli decisions list --limit 5  # LAPI working?
   ```

4. **Report the issue:**
   Create a GitHub issue with:
   - Full error messages and logs
   - Configuration (without secrets)
   - Steps to reproduce
   - Environment (OS, Docker version, CrowdSec version)
