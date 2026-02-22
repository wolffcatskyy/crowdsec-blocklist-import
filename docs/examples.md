# crowdsec-blocklist-import Examples

Real-world deployment examples for crowdsec-blocklist-import v3.4.0.

> **Important:** This tool runs once and exits. It does not have a built-in scheduler
> or daemon mode. Use cron, Kubernetes CronJob, or Synology Task Scheduler to run it
> on a recurring basis.

---

## Basic Docker Run

One-liner to import blocklists into CrowdSec. The container runs once and exits.

```bash
docker run --rm \
  --network crowdsec-net \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=your-bouncer-api-key \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=your-machine-password \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
```

With additional options:

```bash
docker run --rm \
  --network crowdsec-net \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=your-bouncer-api-key \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=your-machine-password \
  -e DECISION_DURATION=24h \
  -e BATCH_SIZE=1000 \
  -e LOG_LEVEL=INFO \
  -e ENABLE_TOR=false \
  -e ALLOWLIST_GITHUB=true \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
```

---

## Basic Docker Compose

Standard setup with CrowdSec on the same Docker network. The blocklist-import
container runs once, imports IPs, and exits.

```yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/linux"
    networks:
      - crowdsec-net
    volumes:
      - crowdsec_data:/var/lib/crowdsec/
      - crowdsec_config:/etc/crowdsec/
      - /var/log:/var/log:ro

  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    depends_on:
      - crowdsec
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge

volumes:
  crowdsec_data:
  crowdsec_config:
```

Run the import:

```bash
docker compose up --abort-on-container-exit
```

---

## Docker with Secrets

Secure setup using Docker secrets for sensitive credentials. Only
`CROWDSEC_LAPI_KEY_FILE` and `CROWDSEC_MACHINE_PASSWORD_FILE` are supported as
`_FILE` variants.

**Directory structure:**

```
./compose.yaml
./secrets/
  ├── lapi_key.txt
  └── machine_password.txt
```

**secrets/lapi_key.txt:**

```
your-actual-bouncer-api-key
```

**secrets/machine_password.txt:**

```
your-actual-machine-password
```

**compose.yaml:**

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    depends_on:
      - crowdsec
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY_FILE: /run/secrets/crowdsec_lapi_key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD_FILE: /run/secrets/crowdsec_machine_password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO
    secrets:
      - crowdsec_lapi_key
      - crowdsec_machine_password
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge

secrets:
  crowdsec_lapi_key:
    file: ./secrets/lapi_key.txt
  crowdsec_machine_password:
    file: ./secrets/machine_password.txt
```

Run the import:

```bash
docker compose up --abort-on-container-exit
```

---

## Minimal Python Setup

Direct Python installation without Docker. Useful for development or lightweight deployments.

**Install dependencies:**

```bash
pip install -r requirements.txt
```

The dependencies are: `requests`, `python-dotenv`, `prometheus-client`.

**Create a .env file:**

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```
CROWDSEC_LAPI_URL=http://192.168.1.100:8080
CROWDSEC_LAPI_KEY=your-bouncer-api-key
CROWDSEC_MACHINE_ID=blocklist-import
CROWDSEC_MACHINE_PASSWORD=your-machine-password
DECISION_DURATION=24h
LOG_LEVEL=INFO
```

**Run the importer:**

```bash
python blocklist_import.py
```

The tool logs to stdout/stderr. To save output to a file:

```bash
python blocklist_import.py 2>&1 | tee import-output.log
```

---

## Cron Scheduling

The tool runs once and exits, so use cron (or equivalent) for recurring imports.

### Docker Version

Create `/usr/local/bin/run-blocklist-import.sh`:

```bash
#!/bin/bash
# Run blocklist-import container once and remove it
docker compose -f /path/to/compose.yaml up --abort-on-container-exit --remove-orphans
```

Make executable and schedule:

```bash
chmod +x /usr/local/bin/run-blocklist-import.sh
```

Add to crontab (runs daily at 4 AM):

```bash
0 4 * * * /usr/local/bin/run-blocklist-import.sh >> /var/log/blocklist-import-cron.log 2>&1
```

### Direct Python Version

Create `/usr/local/bin/blocklist-import.sh`:

```bash
#!/bin/bash
cd /path/to/blocklist-import
source .env
python blocklist_import.py
```

Make executable and schedule:

```bash
chmod +x /usr/local/bin/blocklist-import.sh
0 4 * * * /usr/local/bin/blocklist-import.sh >> /var/log/blocklist-import-cron.log 2>&1
```

View crontab:

```bash
crontab -l
```

---

## Kubernetes CronJob

Deploy blocklist-import as a scheduled Kubernetes CronJob. This is the natural
fit for Kubernetes since the tool runs once and exits.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: crowdsec

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: blocklist-config
  namespace: crowdsec
data:
  CROWDSEC_LAPI_URL: "http://crowdsec.crowdsec.svc.cluster.local:8080"
  CROWDSEC_MACHINE_ID: "blocklist-import-k8s"
  DECISION_DURATION: "24h"
  LOG_LEVEL: "INFO"
  ALLOWLIST_GITHUB: "true"

---
apiVersion: v1
kind: Secret
metadata:
  name: blocklist-secrets
  namespace: crowdsec
type: Opaque
stringData:
  lapi_key: "your-bouncer-api-key"
  machine_password: "your-machine-password"

---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: blocklist-import
  namespace: crowdsec
spec:
  schedule: "0 4 * * *"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 3
      template:
        spec:
          containers:
          - name: blocklist-import
            image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
            imagePullPolicy: IfNotPresent
            envFrom:
            - configMapRef:
                name: blocklist-config
            env:
            - name: CROWDSEC_LAPI_KEY
              valueFrom:
                secretKeyRef:
                  name: blocklist-secrets
                  key: lapi_key
            - name: CROWDSEC_MACHINE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: blocklist-secrets
                  key: machine_password
            resources:
              requests:
                memory: "128Mi"
                cpu: "100m"
              limits:
                memory: "512Mi"
                cpu: "500m"
          restartPolicy: OnFailure
```

Deploy to cluster:

```bash
kubectl apply -f blocklist-cronjob.yaml
```

Check CronJob status:

```bash
kubectl get cronjob -n crowdsec
kubectl get jobs -n crowdsec
kubectl logs -n crowdsec -l job-name=blocklist-import-<job-id>
```

Trigger a manual run:

```bash
kubectl create job --from=cronjob/blocklist-import blocklist-import-manual -n crowdsec
```

---

## Synology NAS Task Scheduler

Deploy on Synology DSM using Docker Compose and Task Scheduler. Synology does not
have cron, so Task Scheduler is the correct approach.

**Setup directory:**

```bash
sudo mkdir -p /volume2/docker/blocklist-import
cd /volume2/docker/blocklist-import
```

**compose.yaml:**

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    environment:
      CROWDSEC_LAPI_URL: http://192.168.18.10:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import-nas
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO
      ALLOWLIST_GITHUB: "true"
```

**Create Task Scheduler task in DSM:**

1. Open DSM > Control Panel > Task Scheduler
2. Create > Triggered Task > User-defined Script
3. General: Task name `Security: Blocklist Import`, User `root`
4. Schedule: Daily at 04:00 (or your preferred time)
5. Task Settings > Run command:

```bash
/usr/local/bin/docker compose -f /volume2/docker/blocklist-import/compose.yaml up --abort-on-container-exit --remove-orphans
```

**Manually test the task:**

```bash
sudo /usr/local/bin/docker compose -f /volume2/docker/blocklist-import/compose.yaml up --abort-on-container-exit --remove-orphans
```

**Check container logs:**

```bash
sudo /usr/local/bin/docker logs blocklist-import
```

---

## Selective Sources

Enable or disable specific blocklist sources. All sources default to enabled.
Use `ENABLE_<SOURCE>=false` to disable individual feeds.

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO

      # Disable sources that may cause false positives
      ENABLE_TOR: "false"
      ENABLE_SCANNERS: "false"

      # All other sources remain enabled by default
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge
```

**Available source toggles (all default to `true`):**

| Variable | Source |
|----------|--------|
| `ENABLE_TOR` | Tor exit nodes |
| `ENABLE_SCANNERS` | Shodan/Censys/Maltrail scanners |
| `ENABLE_IPSUM` | IPsum aggregated threat intel |
| `ENABLE_SPAMHAUS_DROP` | Spamhaus DROP |
| `ENABLE_SPAMHAUS_EDROP` | Spamhaus EDROP |
| `ENABLE_FIREHOL_L1` | Firehol Level 1 |
| `ENABLE_FIREHOL_L2` | Firehol Level 2 |
| `ENABLE_FIREHOL_L3` | Firehol Level 3 |
| `ENABLE_DSHIELD` | DShield top attackers |
| `ENABLE_BLOCKLIST_DE` | Blocklist.de |
| `ENABLE_GREENSNOW` | GreenSnow attacker IPs |
| `ENABLE_BRUTEFORCE_BLOCKER` | Bruteforce Blocker |
| `ENABLE_STAMPARM_IPSUM` | Stamparm IPsum |
| `ENABLE_ABUSE_IPDB` | Abuse IPDB |
| `ENABLE_CYBERCRIME_TRACKER` | Cybercrime Tracker |
| `ENABLE_MONTY_SECURITY_C2` | Monty Security C2 |
| `ENABLE_VXVAULT` | VX Vault |
| `ENABLE_COINBLOCKER` | CoinBlocker |
| `ENABLE_EMERGINGTHREATS` | Emerging Threats |

List all sources and their current status:

```bash
python blocklist_import.py --list-sources
```

---

## Allowlists

Prevent specific IPs or ranges from being imported.

### Static Allowlist

Use the `ALLOWLIST` environment variable with comma-separated IPs or CIDR ranges:

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO

      # Static allowlist: individual IPs and CIDR ranges
      ALLOWLIST: "1.2.3.4,10.0.0.0/8,192.168.0.0/16,203.0.113.0/24"
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge
```

### GitHub Provider Allowlist

Setting `ALLOWLIST_GITHUB=true` auto-fetches GitHub's IP ranges from
`https://api.github.com/meta`. This covers git, web, API, hooks, and actions
endpoints. No token is required -- it uses GitHub's public API.

```yaml
services:
  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO

      # Auto-fetch GitHub IP ranges (public API, no token needed)
      ALLOWLIST_GITHUB: "true"

      # Can combine with static allowlist
      ALLOWLIST: "1.2.3.4,10.0.0.0/8"
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge
```

---

## Prometheus Monitoring Stack

Monitor blocklist imports with Prometheus and Grafana. Metrics are pushed to a
Pushgateway after each run (since the container exits after import, Prometheus
cannot scrape it directly).

```yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/linux"
    networks:
      - monitoring
    volumes:
      - crowdsec_data:/var/lib/crowdsec/
      - crowdsec_config:/etc/crowdsec/
      - /var/log:/var/log:ro

  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    depends_on:
      - crowdsec
      - pushgateway
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password
      DECISION_DURATION: 24h
      LOG_LEVEL: INFO

      # Prometheus Push Gateway
      METRICS_ENABLED: "true"
      METRICS_PUSHGATEWAY_URL: "http://pushgateway:9091"
    networks:
      - monitoring

  pushgateway:
    image: prom/pushgateway:latest
    container_name: pushgateway
    ports:
      - "9091:9091"
    networks:
      - monitoring
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    ports:
      - "9090:9090"
    networks:
      - monitoring
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_USERS_ALLOW_SIGN_UP: "false"
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - monitoring
    restart: unless-stopped

networks:
  monitoring:
    driver: bridge

volumes:
  crowdsec_data:
  crowdsec_config:
  prometheus_data:
  grafana_data:
```

**prometheus.yml:**

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['pushgateway:9091']
```

**Available metrics pushed to Pushgateway:**

| Metric | Type | Description |
|--------|------|-------------|
| `blocklist_import_total_ips` | Gauge | Total IPs imported in last run |
| `blocklist_import_last_run_timestamp` | Gauge | Unix timestamp of last run |
| `blocklist_import_sources_enabled` | Gauge | Number of enabled sources |
| `blocklist_import_sources_successful` | Gauge | Sources fetched successfully |
| `blocklist_import_sources_failed` | Gauge | Sources that failed |
| `blocklist_import_new_ips` | Gauge | New unique IPs added |
| `blocklist_import_duration_seconds` | Histogram | Import duration |

A pre-built Grafana dashboard is available in the repository: `grafana-dashboard.json`.

**Access Grafana:**

- URL: http://localhost:3000
- Username: admin / Password: admin
- Add Prometheus data source: http://prometheus:9090
- Import `grafana-dashboard.json` for a ready-made dashboard

---

## Dry Run Testing

Test blocklist import without applying changes to CrowdSec. Useful for verifying
configuration, network connectivity, and source availability.

**Docker dry run with debug logging:**

```bash
docker run --rm \
  --network crowdsec-net \
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 \
  -e CROWDSEC_LAPI_KEY=your-bouncer-api-key \
  -e CROWDSEC_MACHINE_ID=blocklist-import \
  -e CROWDSEC_MACHINE_PASSWORD=your-machine-password \
  -e DRY_RUN=true \
  -e LOG_LEVEL=DEBUG \
  ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
```

**Python dry run:**

```bash
python blocklist_import.py --dry-run --debug
```

**List available sources and their enable status:**

```bash
python blocklist_import.py --list-sources
```

**Validate configuration without running:**

```bash
python blocklist_import.py --validate
```

Expected output shows:

- Available blocklist sources and their enabled/disabled status
- Fetch attempts per source
- IP count per source
- Allowlist filtering results
- IPs that would be added (not actually added in dry-run mode)
- Timing and performance summary

---

## High-Volume Setup

Tuning for large deployments importing many sources with high IP counts.

```yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/linux"
    networks:
      - crowdsec-net
    volumes:
      - crowdsec_data:/var/lib/crowdsec/
      - crowdsec_config:/etc/crowdsec/
      - /var/log:/var/log:ro
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G

  blocklist-import:
    image: ghcr.io/wolffcatskyy/crowdsec-blocklist-import-python:latest
    container_name: blocklist-import
    restart: "no"
    depends_on:
      - crowdsec
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY: your-bouncer-api-key
      CROWDSEC_MACHINE_ID: blocklist-import
      CROWDSEC_MACHINE_PASSWORD: your-machine-password

      # Performance tuning
      BATCH_SIZE: "5000"
      FETCH_TIMEOUT: "120"
      MAX_RETRIES: "5"
      DECISION_DURATION: 48h

      # Enable all sources
      LOG_LEVEL: INFO

      # Metrics for monitoring import performance
      METRICS_ENABLED: "true"
      METRICS_PUSHGATEWAY_URL: "http://pushgateway:9091"

    deploy:
      resources:
        limits:
          cpus: '1.5'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M

    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    driver: bridge

volumes:
  crowdsec_data:
  crowdsec_config:
```

**Performance tuning guidelines:**

| Variable | Default | Guidance |
|----------|---------|----------|
| `BATCH_SIZE` | `1000` | Increase to 5000-10000 for 100K+ IPs; reduces API calls |
| `FETCH_TIMEOUT` | `60` | Increase to 120s for slow or distant sources |
| `MAX_RETRIES` | `3` | Increase to 5 for production; handles transient failures |

**Monitor performance (the tool logs to stdout):**

```bash
docker logs blocklist-import 2>&1 | grep -E "(Imported|Added|Skipped|Duration)"
```

**Memory efficiency:**

- Handles 500k+ IPs without issues
- Typical usage: 50-100MB
- Streaming downloads (files are never fully loaded into memory)
- Set-based deduplication with O(1) lookup

---

## Summary

Use these examples as starting points for your deployment:

| Use Case | Example |
|----------|---------|
| Quick test | Basic Docker Run or Dry Run Testing |
| Development | Minimal Python Setup |
| Single server | Basic Docker Compose |
| Secure credentials | Docker with Secrets |
| Recurring imports | Cron Scheduling |
| Kubernetes | Kubernetes CronJob |
| Synology NAS | Synology NAS Task Scheduler |
| Source control | Selective Sources |
| IP exclusions | Allowlists |
| Observability | Prometheus Monitoring Stack |
| Large scale | High-Volume Setup |

For questions or issues, visit the [GitHub repository](https://github.com/wolffcatskyy/crowdsec-blocklist-import).
