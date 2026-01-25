# CrowdSec Blocklist Import

**Get premium-level threat protection for FREE.** Import 60,000+ IPs from 28 public threat feeds directly into CrowdSec - no subscription required.

## Why Use This?

| | CrowdSec Free | CrowdSec Pro | **Free + This Tool** |
|---|:---:|:---:|:---:|
| Community Intel (CAPI) | ~22k IPs | ~22k IPs | ~22k IPs |
| Premium Blocklists | ❌ | ✅ | ✅ **60k+ IPs** |
| Tor Exit Nodes | ❌ | ✅ | ✅ |
| Scanner Blocking | ❌ | ✅ | ✅ |
| All Your Bouncers | ✅ | ✅ | ✅ |
| **Monthly Cost** | **$0** | **$50+** | **$0** |

**How it works:** Import blocklists once into CrowdSec → All your bouncers automatically enforce them. One import, network-wide protection.

> **Have a UniFi router?** Use our companion tool **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** to sync these bans directly to your router's firewall - block threats at the network edge!

## Features

- **28+ Free Blocklists**: IPsum, Spamhaus, Firehol, Abuse.ch, Emerging Threats, and more
- **Smart Deduplication**: Skips IPs already in CrowdSec (CAPI, Console lists, local detections)
- **Private IP Filtering**: Automatically excludes RFC1918 and reserved ranges
- **Docker Ready**: Run as a container with Docker socket access
- **Cron Friendly**: Designed for daily runs with 24h decision expiration

## Included Blocklists

| Source | Description |
|--------|-------------|
| IPsum (level 3+) | Aggregated threat intel (on 3+ blocklists) |
| Spamhaus DROP/EDROP | Known hijacked/malicious netblocks |
| Blocklist.de | IPs reported for attacks (all/ssh/apache/mail) |
| Firehol level1 + level2 | High confidence bad IPs |
| Feodo Tracker | Banking trojan C2 servers |
| SSL Blacklist | Malicious SSL certificate IPs |
| Emerging Threats | Compromised IPs |
| Binary Defense | Ban list |
| Bruteforce Blocker | SSH/FTP brute force sources |
| DShield | SANS Internet Storm Center top attackers |
| CI Army | Cinsscore bad reputation |
| Darklist | SSH brute force |
| URLhaus | Malware distribution IPs |
| Talos Intelligence | Cisco threat intel |
| Charles Haley | SSH dictionary attacks |
| Botvrij | Botnet C2 IPs |
| myip.ms | Blacklist database |
| GreenSnow | Attacker IPs |
| StopForumSpam | Toxic spam IPs |
| **Tor exit nodes** | Official Tor Project + dan.me.uk |
| **Shodan scanners** | Known Shodan scanner IPs |
| **Censys scanners** | Censys scanner IP ranges |

## Quick Start

### Docker Compose (Recommended)

```yaml
version: "3.8"

services:
  crowdsec-blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
    container_name: crowdsec-blocklist-import
    restart: "no"
    environment:
      - CROWDSEC_CONTAINER=crowdsec
      - DECISION_DURATION=24h
      - TZ=America/New_York
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

Run once: `docker compose up`

### Scheduled via Cron (Host)

```bash
# Run daily at 4am to refresh blocklists
0 4 * * * docker compose -f /path/to/docker-compose.yml up --abort-on-container-exit
```

### Standalone Docker Run

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CROWDSEC_CONTAINER=crowdsec \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import:latest
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CROWDSEC_CONTAINER` | `crowdsec` | Name of your CrowdSec container |
| `DECISION_DURATION` | `24h` | How long decisions last (refresh daily) |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARN, ERROR) |
| `TZ` | `UTC` | Timezone for logs |

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    ONE IMPORT = ALL BOUNCERS                    │
└─────────────────────────────────────────────────────────────────┘

     28 Free Blocklists ──► crowdsec-blocklist-import ──► CrowdSec
                                                              │
                    ┌─────────────────────────────────────────┤
                    │                    │                    │
                    ▼                    ▼                    ▼
              UniFi Firewall      NPM/Nginx WAF      Cloudflare Worker
              (router-level)      (reverse proxy)    (edge blocking)
                    │                    │                    │
                    └────────────────────┴────────────────────┘
                              Network-Wide Protection
```

1. **Fetch**: Downloads 28+ blocklists from public sources
2. **Combine**: Merges all IPs and removes duplicates  
3. **Filter**: Excludes private ranges (10.x, 192.168.x, etc.)
4. **Dedupe**: Queries CrowdSec for existing decisions to avoid duplicates
5. **Import**: Bulk imports new IPs via `cscli decisions import`

## Viewing Imported Decisions

```bash
# Count imported decisions
docker exec crowdsec cscli decisions list | grep external_blocklist | wc -l

# List recent decisions
docker exec crowdsec cscli decisions list -l 20

# Remove all imported decisions (if needed)
docker exec crowdsec cscli decisions delete --all --reason external_blocklist
```

## Related Projects

| Project | Description |
|---------|-------------|
| **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer)** | Sync CrowdSec decisions to UniFi firewall groups |

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
