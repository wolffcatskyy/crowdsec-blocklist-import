# crowdsec-blocklist-import Helm chart

Imports [28+ public threat-intelligence blocklists](https://github.com/wolffcatskyy/crowdsec-blocklist-import) into CrowdSec via LAPI, with deduplication, normalization, and automatic refreshes.

Two run modes:

| Mode | Kind | Use when |
| ---- | ---- | -------- |
| `cronjob` (default) | `batch/v1` CronJob | Scheduled one-shot imports - how most users run the container today |
| `deployment` | `apps/v1` Deployment | Long-lived daemon repeating every `config.interval` seconds, no CronJob needed |

## Install

```sh
helm install blocklists ./charts/crowdsec-blocklist-import \
  --namespace crowdsec --create-namespace \
  --set config.crowdsecLapiUrl=http://crowdsec-service.crowdsec.svc:8080 \
  --set secrets.crowdsecLapiKey=<bouncer-api-key>
```

Get a bouncer key from your CrowdSec instance with `cscli bouncers add <name>`.

### CronJob mode (default)

```sh
helm install blocklists ./charts/crowdsec-blocklist-import \
  --set secrets.crowdsecLapiKey=<key> \
  --set cronjob.schedule="*/30 * * * *"
```

### Daemon mode

```sh
helm install blocklists ./charts/crowdsec-blocklist-import \
  --set mode=deployment \
  --set config.interval=3600 \
  --set secrets.crowdsecLapiKey=<key>
```

`config.interval` must be greater than 0 in deployment mode; the chart fails to render otherwise. In cronjob mode `INTERVAL` is forced to `0` so every job is a single run.

### Bring your own Secret

```sh
kubectl create secret generic blocklist-import \
  --from-literal=CROWDSEC_LAPI_KEY=<key>
helm install blocklists ./charts/crowdsec-blocklist-import \
  --set existingSecret=blocklist-import
```

Expected keys: `CROWDSEC_LAPI_KEY` (required), `ABUSEIPDB_API_KEY` and `WEBHOOK_URL` (optional).

## Feeds

Every feed has an `ENABLE_*` switch (all default to true upstream). Set
`feedFlags.BLOCKLISTS_OPT_IN=true` to flip the default to opt-in, then enable
feeds individually:

```yaml
feedFlags:
  BLOCKLISTS_OPT_IN: "true"
  ENABLE_IPSUM: "true"
  ENABLE_SPAMHAUS: "true"
```

Run `python blocklist_import.py --list-blocklists` (or `helm template` against a
one-off job) to see every switch.

## Values

| Key | Default | Description |
| --- | ------- | ----------- |
| `mode` | `cronjob` | `cronjob` or `deployment` |
| `image.repository` | `ghcr.io/wolffcatskyy/crowdsec-blocklist-import` | Image |
| `image.tag` | chart appVersion | Image tag |
| `cronjob.schedule` | `0 * * * *` | Cron schedule (hourly) |
| `cronjob.concurrencyPolicy` | `Forbid` | Skip overlapping runs |
| `config.crowdsecLapiUrl` | `http://crowdsec:8080` | CrowdSec LAPI URL |
| `config.interval` | `3600` | Daemon repeat seconds (deployment mode) |
| `config.decisionDuration` | `24h` | Ban duration per imported IP |
| `config.batchSize` | `1000` | Decisions per LAPI batch |
| `config.maxDecisions` | `0` | Cap on decisions per run (0 = unlimited) |
| `config.allowlist` | `""` | Comma-separated IPs/CIDRs never banned |
| `config.customBlocklists` | `""` | Comma-separated extra feed URLs |
| `config.telemetryEnabled` | `"true"` | Anonymous usage ping |
| `config.metricsPushgatewayUrl` | `""` | Prometheus pushgateway `host:port` |
| `feedFlags` | `BLOCKLISTS_OPT_IN: "false"` | Feed on/off switches |
| `secrets.crowdsecLapiKey` | `""` | Bouncer API key (required) |
| `existingSecret` | `""` | Use your own Secret instead |
| `extraEnv` | `[]` | Additional env vars |

See `values.yaml` for the full list (TLS client-cert paths, webhook settings,
AbuseIPDB tuning, refresh periods, scheduling controls).
