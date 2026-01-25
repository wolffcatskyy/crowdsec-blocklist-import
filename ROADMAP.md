# Roadmap

## v1.0.0 (Current)
- [x] 28+ public blocklists
- [x] Smart deduplication (skips existing CrowdSec decisions)
- [x] Private IP filtering
- [x] Docker container with multi-arch support (amd64/arm64)
- [x] Configurable decision duration

## v1.1.0 (Planned)
- [ ] **Selective blocklists**: Enable/disable individual sources via env vars
- [ ] **Custom blocklist URLs**: Add your own blocklist URLs
- [ ] **Dry-run mode**: Show what would be imported without making changes
- [ ] **Import statistics**: Better logging of import results per source
- [ ] **Health check endpoint**: For orchestration/monitoring

## v1.2.0 (Future)
- [ ] **Scheduled mode**: Built-in cron support (run as daemon)
- [ ] **Prometheus metrics**: Export import stats for monitoring
- [ ] **Webhook notifications**: Discord/Slack notifications on import
- [ ] **Blocklist caching**: Skip unchanged lists to reduce bandwidth
- [ ] **IPv6 support**: Currently IPv4 only

## v2.0.0 (Ideas)
- [ ] **CrowdSec API direct**: Connect to LAPI directly instead of via Docker socket
- [ ] **Web UI**: Simple dashboard showing imported IPs and sources
- [ ] **Blocklist quality scores**: Weight sources by false positive rates
- [ ] **Whitelist management**: Built-in whitelist for false positive prevention

## Contributing

Have an idea? [Open an issue](https://github.com/wolffcatskyy/crowdsec-blocklist-import/issues/new) or submit a PR\!
