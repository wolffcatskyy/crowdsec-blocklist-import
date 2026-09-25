# Scenario name format

Every decision this tool writes carries a CrowdSec scenario name. It can be written in two formats, picked with `SCENARIO_FORMAT`.

## Legacy (default)

```
<DECISION_SCENARIO> (<Feed Name>)
external/blocklist (Spamhaus DROP)
external/blocklist (all sources)        # CONSOLIDATE_ALERTS=true
```

Unchanged from earlier releases. Existing `cscli decisions list --scenario ...` filters, Grafana panels and alert routes keep working.

## Structured (`SCENARIO_FORMAT=structured`)

```
<SCENARIO_PREFIX>/<feed-slug>/c<confidence>
external/blocklist-import/spamhaus-drop/c95
external/blocklist-import/tor-exit-nodes/c40
external/blocklist-import/all-sources   # CONSOLIDATE_ALERTS=true (mixed feeds, no confidence)
```

Grammar (what consumers should parse):

```
scenario   = prefix "/" feed-slug [ "/c" confidence ]
feed-slug  = 1*( a-z / 0-9 ) *( "-" 1*( a-z / 0-9 ) )
confidence = integer 0-100
```

Regex: `^<prefix>/([a-z0-9]+(?:-[a-z0-9]+)*)(?:/c([0-9]{1,3}))?$`

- **feed-slug** is the feed name lowercased with every run of other characters replaced by `-` (`Tor (dan.me.uk)` -> `tor-dan-me-uk`, `custom_blocklist_0` -> `custom-blocklist-0`).
- **confidence** is how likely an entry from that feed is a real, current threat. Lower means more false-positive risk, not "less dangerous".
- The prefix still starts with `external/blocklist`, so a prefix match such as `external/blocklist.*` catches both formats. Exact-name filters on the legacy format need updating when you switch.

## Default confidence

Starting points based on how each list is built. Override any of them with `FEED_CONFIDENCE="slug=NN,..."`. Feeds not listed (for example `CUSTOM_BLOCKLISTS`) default to 50.

| Confidence | Feeds |
|-----------|-------|
| 95 | spamhaus-drop, feodo-tracker |
| 90 | firehol-level1, abuseipdb, abuseipdb-api |
| 85 | ipsum-level4, emerging-threats, dshield |
| 80 | cybercrime-tracker, monty-security-c2, dshield-top-attackers |
| 75 | urlhaus, ipsum, firehol-level2, blocklist-de-ssh, binary-defense, bruteforce-blocker, ci-army |
| 70 | blocklist-de-all, botvrij, greensnow, vxvault |
| 65 | blocklist-de-apache, blocklist-de-mail, sentinel |
| 60 | firehol-level3 |
| 55 | stopforumspam |
| 50 | shodan-scanners, maltrail-scanners, static-scanner-ips-censys |
| 40 | tor-exit-nodes, tor-dan-me-uk |

## Consumers

- **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) sidecar** (v2.6.0+): reads feed and confidence and applies a penalty-only scoring factor, so when the device's ipset is full the lowest-confidence imports are dropped first. It never ranks imports above local detections, manual bans or CAPI.

## Notes

- `CONSOLIDATE_ALERTS=true` sends one mixed alert per run, so there is no per-feed confidence to carry. Leave consolidation off if you want feed-ranked decisions.
- When the same IP is on several feeds, only the first feed that imports it gets a decision (deduplication), so its scenario names that feed.
