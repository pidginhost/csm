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

### Fanotify realtime monitor

- `csm_fanotify_queue_depth` (gauge): current number of queued
  events waiting for the analyzer pool. The queue capacity is 4000;
  sustained values near that cap mean drops are imminent. Alert
  target: `max_over_time(csm_fanotify_queue_depth[5m]) > 3500`.
- `csm_fanotify_events_dropped_total` (counter): cumulative events
  dropped because the analyzer queue was full. The reconcile pass
  still rescans drop-affected directories 60 s later, so dropped
  events do not disappear from detection -- they arrive delayed.
  Alert target: `rate(csm_fanotify_events_dropped_total[5m]) > 0`
  paired with a short for-clause.
- `csm_fanotify_reconcile_latency_seconds` (histogram): how long
  the post-overflow reconcile pass takes to walk drop-affected
  directories and rescan recent files. Buckets: 0.01 s .. 60 s.
  Watch p95: reconcile stealing tens of seconds means bulk events
  are piling up faster than the walker can keep up.

### Periodic check runner

- `csm_check_duration_seconds{name,tier}` (histogram): wall-clock
  time each check takes to complete. Label `name` is one of the 62
  checks (`fake_kernel_threads`, `webshells`, ...); label `tier` is
  `critical`, `deep`, or `all`. Buckets: 0.01 s .. 300 s (300 s is
  the per-check timeout ceiling). Useful aggregations:

  ```
  # p95 of the slowest check in the critical tier:
  histogram_quantile(0.95,
    sum by (le, name) (
      rate(csm_check_duration_seconds_bucket{tier="critical"}[10m])
    )
  )

  # total time each cycle spends in deep-tier checks:
  sum by (tier) (rate(csm_check_duration_seconds_sum{tier="deep"}[1h]))
  ```

### Firewall

- `csm_blocked_ips_total` (gauge): number of IPs currently on the
  firewall block list. Excludes expired temp bans -- the store's
  `LoadFirewallState` filters those before the gauge reads.
- `csm_firewall_rules_total` (gauge): total firewall rules across
  all four categories (blocked IPs, allowed IPs, blocked subnets,
  port-specific allows). Sudden drops are worth investigating; the
  firewall engine does not prune rules without operator or
  auto-response action.

### Auto-response

- `csm_auto_response_actions_total{action}` (counter): every
  auto-response action fired, by class. Labels: `action` is
  `kill`, `quarantine`, or `block`. Incremented once per finding
  the corresponding `Auto*` helper produces, so a batch blocking
  four IPs in one cycle adds 4 to `action=block`. Useful for
  detecting response storms:
  `rate(csm_auto_response_actions_total[5m])`.

## Caveats

- Scrape the web UI's HTTPS port, not a separate listener.
- `curl -k` / `insecure_skip_verify` is appropriate only when the
  cert is self-signed and the network path is trusted. Pin a CA for
  anything else.
- Prometheus label cardinality: per-account and per-IP labels are
  deliberately not exposed. Shared-hosting deployments with 1000+
  cPanel users would otherwise overwhelm a Prometheus server.

## Not instrumented (yet)

- Per-account labels on any metric. Deliberately off: shared-hosting
  deployments with 1000+ cPanel users would blow out Prometheus
  cardinality.
- Fanotify inline auto-response actions (the quarantine-while-
  seeing-the-write path in `fanotify.go`). The periodic
  `csm_auto_response_actions_total` does not count those; a follow-
  up may split the metric or add a `source` label.
- bbolt per-bucket size breakdown. Ships with ROADMAP item 6 (the
  retention + compaction work).
