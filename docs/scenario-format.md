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
external/blocklist-import/tor-exit-nodes/c25
```
`CONSOLIDATE_ALERTS=true` consolidates **per feed** in structured mode (one
alert per feed, each carrying its own confidence), so consolidation no longer
turns feed ranking off. The mixed `all-sources` scenario only exists in the
legacy format.

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

These numbers are **judgment calls, not measurements**. They are starting
points based on how each list is built, arranged in tiers:

- **90-95** - curated, few false positives: Spamhaus DROP, Feodo and other
  abuse.ch lists.
- **70-85** - high-signal attack/C2 reports: Emerging Threats compromised,
  FireHOL level 1, CINS Army, DShield (top attackers), plus consensus lists
  like IPsum level 4+.
- **50-65** - broad automated reports (Blocklist.de, IPsum at lower levels)
  and non-malicious scanner lists (Shodan, Censys, Maltrail).
- **20-40** - noisier aggregated lists (FireHOL level 3/4, StopForumSpam,
  VXVault) and anonymity networks. Tor exits get 25: traffic from an exit
  node is not malicious per se.

Tune them for your own risk appetite with `FEED_CONFIDENCE="slug=NN,..."`
(e.g. `FEED_CONFIDENCE="tor-exit-nodes=20,stopforumspam=40"`). Feeds not
listed (for example `CUSTOM_BLOCKLISTS`) default to 50. The bouncer sidecar
can also override per feed in its own config (`feed_scoring.feeds`).

| Confidence | Feeds |
|-----------|-------|
| 95 | spamhaus-drop, feodo-tracker |
| 90 | abuseipdb, abuseipdb-api, urlhaus |
| 85 | firehol-level1, ipsum-level4, emerging-threats, dshield |
| 80 | cybercrime-tracker, monty-security-c2, dshield-top-attackers |
| 75 | binary-defense, ci-army, firehol-level2 |
| 70 | botvrij |
| 65 | blocklist-de-ssh, ipsum, greensnow, sentinel, bruteforce-blocker |
| 60 | blocklist-de-all |
| 55 | blocklist-de-apache, blocklist-de-mail |
| 50 | shodan-scanners, maltrail-scanners, static-scanner-ips-censys |
| 35 | vxvault, firehol-level3, stopforumspam |
| 25 | tor-exit-nodes, tor-dan-me-uk |

## Consumers

- **[crowdsec-unifi-bouncer](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer) sidecar** (v2.6.0+): reads feed and confidence and applies a penalty-only scoring factor, so when the device's ipset is full the lowest-confidence imports are dropped first. It never ranks imports above local detections, manual bans or CAPI.

## Deduplication across feeds

When the same IP is listed by several feeds, only one decision is written. In
structured mode, feeds are processed highest-confidence first, so the IP
always gets the **highest confidence among the feeds listing it** - an IP on
both Spamhaus DROP and a Tor exit list is scored `c95`, never `c25`. (Static
sort order: the feature has no per-IP signal to pick a feed by, only
per-feed.) In legacy mode the processing order is unchanged from earlier
releases.

## Upstream sharing

Imported alerts are **not** sent upstream as CrowdSec community signals.
Signal sharing requires console enrollment (`cscli console enroll`) with
sharing enabled, and applies to detections from hub scenarios - not to
decisions pushed through the LAPI `/alerts` endpoint with this tool's own
origin (`blocklist-import`). The live CI test (`.github/workflows/ci.yml`,
`live-lapi` job) verifies on every run that the LAPI the importer writes to
is not enrolled and has no online API credentials, so nothing can leak
upstream.

## Release plan

- **v3.9 (this repo) / v2.6 (crowdsec-unifi-bouncer):** structured format is
  opt-in via `SCENARIO_FORMAT=structured`. Legacy stays the default.
- **v4.0:** structured becomes the default, staged through the `PRESET`
  mechanism so existing installs opt in deliberately.
- No public claims about the combined feed-scoring feature until it has run
  against a live LAPI (covered by CI) **and** on real UniFi hardware.
