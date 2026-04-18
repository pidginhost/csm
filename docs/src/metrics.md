# Metrics (Prometheus)

CSM exposes a `/metrics` endpoint on its HTTPS web UI port
(default 9443). The endpoint serves the Prometheus text exposition
format (`Content-Type: text/plain; version=0.0.4`) and is safe to
scrape every 15 seconds.

This is ROADMAP item 4. The initial release covers the metrics
listed under "Available metrics" below. More call sites are
instrumented in ongoing releases; track progress in
`CHANGELOG.md` under `## [Unreleased]`.

## Enabling

Metrics are on whenever `webui.enabled: true` is set in `csm.yaml`.
The endpoint has its own auth knob:

```yaml
webui:
  enabled: true
  auth_token: "<UI login token>"
  metrics_token: "<long random string for Prometheus scraper>"
```

`metrics_token` is optional. When set, a Bearer header containing
this exact value unlocks `/metrics`. The UI `auth_token` or a valid
UI session cookie is also accepted so the dashboard can self-scrape,
but keeping the two tokens separate is recommended: rotating
`auth_token` does not then break Prometheus scraping, and giving
your monitoring stack the scrape token does not also give it UI
access.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: csm
    scheme: https
    tls_config:
      # CSM serves a self-signed cert by default; either skip
      # verification here or pin the CA you chose.
      insecure_skip_verify: true
    authorization:
      type: Bearer
      credentials: "<metrics_token from csm.yaml>"
    static_configs:
      - targets:
          - csm-host-1.example.internal:9443
          - csm-host-2.example.internal:9443
```

This file passes `promtool check config`.

## Quick check

```bash
curl -sk -H "Authorization: Bearer $METRICS_TOKEN" \
    https://localhost:9443/metrics | head
```

## Available metrics

### Build / process

- `csm_build_info{version}` (gauge, always 1): build metadata.
  Scrape once to discover the running version. Join on it in
  queries via `group_left(version)`.

### YARA-X worker (when `signatures.yara_worker_enabled: true`)

- `csm_yara_worker_restarts_total` (counter): cumulative number of
  times the supervisor has restarted the `csm yara-worker` child.
  Alert on sustained growth: a single restart is routine (rule
  deploys), a steady climb means the worker is crash-looping and
  real-time YARA scans are degraded.

### Findings

- `csm_findings_total{severity}` (counter): every finding CSM
  records is counted here. Severities are `CRITICAL`, `HIGH`, and
  `WARNING` (matching the `alert.Severity` enum). Use `rate(...)`
  for arrival velocity; watch for sudden CRITICAL spikes.

### State

- `csm_store_size_bytes` (gauge): on-disk size of the bbolt state
  database (`/opt/csm/state/csm.db` by default). ROADMAP item 6
  will add a retention policy that compacts this file; for now use
  this metric to spot runaway growth.

## Caveats

- Scrape the web UI's HTTPS port, not a separate listener.
- `curl -k` / `insecure_skip_verify` is appropriate only when the
  cert is self-signed and the network path is trusted. Pin a CA for
  anything else.
- Prometheus label cardinality: per-account and per-IP labels are
  deliberately not exposed. Shared-hosting deployments with 1000+
  cPanel users would otherwise overwhelm a Prometheus server.

## Planned additions

Tracked in `CHANGELOG.md` under `## [Unreleased]`. In rough priority
order:

- `csm_fanotify_queue_depth`, `csm_fanotify_events_dropped_total`,
  `csm_fanotify_reconcile_latency_seconds`: real-time file-monitor
  health.
- `csm_check_duration_seconds{name,tier}`: how long each of the 62
  checks takes per cycle.
- `csm_firewall_rules_total`, `csm_blocked_ips_total`: firewall
  state gauges.
- `csm_auto_response_actions_total{action}`: block / quarantine /
  clean action counts.

When these land, they follow the naming and label conventions
established above (lowercase `snake_case`, `csm_` prefix, `_total`
suffix on counters).
