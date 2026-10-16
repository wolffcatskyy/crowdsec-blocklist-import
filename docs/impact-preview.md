# Impact Preview (Report Only)

The impact preview answers one question before you enable anything: **what
would these feeds have caught in my own traffic?** It compares the current
blocklist feed contents against IP addresses observed in your own log files
and reports the overlap - per feed and per preset - without touching
CrowdSec, your firewall, or any configuration.

```bash
python blocklist_import.py --impact-preview /var/log/nginx/access.log \
    --impact-preview-html preview.html
```

## Inputs

`--impact-preview` takes one or more plain-text files. Anything that prints
IP addresses works:

- web server logs (`/var/log/nginx/access.log`, Apache access logs)
- firewall logs (UniFi, pfSense, iptables)
- CrowdSec's own view: `cscli alerts list -o json | jq -c '.[]' > alerts.txt`
- a saved list of addresses, one per line or mixed with other text

Every candidate token is validated as an IPv4 or IPv6 address; duplicates
count once. Private/reserved addresses in your logs are kept as observations
(they simply will not match public threat feeds). **Log contents never
leave your machine** - only aggregate counts appear in the output.

By default the preview analyzes the feeds your current configuration
enables. Add `--impact-preview-all-feeds` to score every fetchable source
instead, which is how you compare presets or candidate feeds you have not
enabled yet.

## Output

The text summary lists, per feed:

- **Entries** - addresses/ranges the feed currently publishes
- **Hits** - observed log addresses the feed would have covered
- **Unique** - hits no other analyzed feed covers (the feed's marginal value)
- **Shared** - hits at least one other feed also covers (overlap)

A preset ladder follows: for `embedded`, `server`, and `max`, the total
feed set, total entries, total hits, and **marginal hits** - what each step
adds over the smaller preset before it.

`--impact-preview-html PATH` writes a self-contained graphical report
(inline SVG charts, no JavaScript, no external assets - it opens offline):

- stacked bar chart of unique vs shared hits per feed
- feed size chart
- the preset ladder
- a per-feed table and a capped drilldown sample of matched addresses

Feeds that fail to fetch are flagged in the report instead of aborting the
preview. Feeds that are not importable in your configuration (for example,
AbuseIPDB without an API key) are marked as skipped.

## Report sensitivity

The text summary prints aggregate counts only. The HTML report also carries
a capped drilldown sample of the matched addresses themselves. Reports are
generated locally and are never uploaded anywhere by the tool, but a report
built from real logs reveals parts of your traffic: **treat it as sensitive
and do not publish or share it**.

## Guarantees and limits

- **Report only.** No feeds are enabled, no decisions are added, no live
  blocking rules are changed. The preview never builds a LAPI client and
  does not need `CROWDSEC_LAPI_KEY`.
- **Snapshot semantics.** Feed contents are whatever the feed published at
  the moment you run the preview. A hit means the observed address is on
  the feed *now*; it says nothing about whether the address was listed when
  the traffic actually happened.
- **No allowlists.** Import-time allowlists are not applied, so the counts
  shown here are an upper bound.
- **Not AUTOPILOT.** The preview scores feeds against a log file you point
  at. AUTOPILOT (v3.9.0) plans from live per-feed hit telemetry. The two
  compose: preview before you opt in, AUTOPILOT after feeds are running.
