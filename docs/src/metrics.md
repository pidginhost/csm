# Metrics (Prometheus)

CSM exposes a `/metrics` endpoint on its HTTPS web UI port
(default 9443). The endpoint serves the Prometheus text exposition
format (`Content-Type: text/plain; version=0.0.4`) and is safe to
scrape every 15 seconds.

"Available metrics" below is the shipped set. New call sites are
instrumented in ongoing releases; check `CHANGELOG.md` under
`## [Unreleased]` for the latest additions.

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

A complete, validated version of this snippet (with `global:` block)
ships as `docs/src/examples/prometheus-scrape.yml`. The CI pipeline
runs `promtool check config` against that file in the `promtool-check`
job; if the example ever stops validating, the pipeline fails.

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

### YARA-X worker (default-on; off only if `signatures.yara_worker_enabled: false`)

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
  database (`/opt/csm/state/csm.db` by default). Enable the
  `retention:` block to bound logical growth and run `csm store
  compact` during maintenance to reclaim freelisted pages; without
  either, this gauge only climbs.

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

### Config reloads

- `csm_config_reloads_total{result}` (counter): SIGHUP reload
  attempts, by outcome. Labels: `result` is one of:
  - `success` -- safe fields swapped in place, integrity hash
    re-signed, live config updated.
  - `restart_required` -- one or more fields that need a full
    restart changed; live config unchanged.
  - `error` -- YAML parse failure, validation failure, or re-sign
    failure; live config unchanged.
  - `noop` -- file edit produced no semantic change (identical
    values, whitespace edit, etc.).
  Alert target: `rate(csm_config_reloads_total{result="error"}[5m]) > 0`
  paired with a short for-clause.

### Auto-response

- `csm_auto_response_actions_total{action}` (counter): every
  auto-response action fired, by class. Labels: `action` is
  `kill`, `quarantine`, or `block`. Incremented once per finding
  the corresponding `Auto*` helper produces, so a batch blocking
  four IPs in one cycle adds 4 to `action=block`. Useful for
  detecting response storms:
  `rate(csm_auto_response_actions_total[5m])`.

### Retention (when `retention.enabled: true`)

- `csm_retention_sweeps_total` (counter): number of retention
  sweep cycles completed since daemon start. A flatline after a
  restart means the sweep goroutine is not scheduling; a healthy
  daemon increments this on every `sweep_interval` tick.
- `csm_retention_deleted_total` (counter): cumulative entries
  deleted across the `history`, `attacks:events`, and `reputation`
  buckets. Spikes on the first sweep after enabling retention
  (initial backlog), then settles to the steady-state churn. Useful
  for estimating when the file might benefit from a
  `csm store compact` maintenance window.

### PHP-relay (email abuse, cPanel only)

All series are prefixed `csm_php_relay_`. Registered when `email_protection.php_relay.enabled: true` and the host is cPanel; otherwise zero across the board. See [Real-time detection](detection-realtime.md#php-relay-mail-abuse-cpanel-only).

- `csm_php_relay_findings_total{path}` (counter): findings emitted per detection path. Labels: `path` is one of `header`, `volume`, `volume_account`, `fanout` (and later `baseline`, `reputation` for Stages 2-3). Use `rate(...)` to spot detection storms; a sudden rate jump on `header` typically means a contact-form vulnerability is being exploited, on `volume_account` typically means an account password was leaked.
- `csm_php_relay_actions_total{action,result}` (counter): auto-freeze invocations attempted. Labels: `action` is currently `freeze`; `result` is `ok` or `fail`. Pair with `csm_php_relay_findings_total` to confirm freeze keeps up with detection.
- `csm_php_relay_action_gone_total` (counter): messages already absent from the spool by the time `exim -Mf` ran. Normal queue churn; not a failure. Sustained growth means the spool is moving fast and the freezer is racing the queue runner.
- `csm_php_relay_path_skipped_total{path,reason}` (counter): path evaluation that bailed before producing a finding. Labels: `path` matches the finding labels above; `reason` enumerates the gate that fired (e.g. ignore-list match, missing scriptKey).
- `csm_php_relay_spool_scan_fallbacks_total{reason}` (counter): AutoFreeze fell back to a full spool walk to find msgIDs. Labels: `reason` is `capped` (the in-memory `activeMsgs` per script hit its cap, so a fresh disk walk was needed) or `reputation` (a late reputation finding arrived for a script with no live `activeMsgs`). Sustained growth on `capped` means a single script is firing faster than the in-memory window keeps state for; consider raising `header_score_volume_min` or adding an ignore.
- `csm_php_relay_active_msgs_capped_total` (counter): per-script `activeMsgs` set hit its cap and dropped the oldest entry. Counts the eviction event itself; the next freeze for that script will land in `csm_php_relay_spool_scan_fallbacks_total{reason="capped"}`.
- `csm_php_relay_windows_active{kind}` (gauge): retained per-script / per-IP / per-account window state. Labels: `kind` is `script`, `ip`, or `account`. Sized by Flow E sweep cadence (5 min for windows, 24 h retention for accounts); flat values across hours are normal.
- `csm_php_relay_msgid_index_size{layer}` (gauge): msgID dedup index size by storage layer. Labels: `layer` is `memory` (in-process map) or `bbolt` (persisted batch writer). Memory ceiling is 200k entries; bbolt grows freely until the 25 h Flow E sweep prunes it.
- `csm_php_relay_msgindex_persist_dropped_total` (counter): bbolt persist queue overflow drops (the 4096-deep buffered channel was full when the watcher tried to enqueue). Should be zero in steady state; a non-zero value means the bbolt writer is blocked on disk and the in-memory dedup is the only thing protecting against double-fire on a queue-runner re-write.
- `csm_php_relay_msgindex_persist_errors_total` (counter): bbolt commit failures from the async batch writer. Each bump also emits a Critical `email_php_relay_msgindex_persist_failed` finding. Disk-full or permissions issue on `/opt/csm/state/csm.db`.
- `csm_php_relay_inotify_overflows_total` (counter): kernel `IN_Q_OVERFLOW` events on the spool watcher. Each one triggers a bounded recovery scan (default cap 1000 files); if the cap fires, also emits `email_php_relay_overflow_scan_truncated` Critical. Sustained growth means the spool is churning faster than inotify can keep up — usually a backup restore or a real attack.
- `csm_php_relay_spool_read_errors_total` (counter): `emailspool.ParseHeaders` errors on `-H` files the watcher tried to consume. Usually transient (file disappeared between inotify event and open) and self-correcting; sustained growth points at a permissions or filesystem problem.
- `csm_php_relay_userdata_errors_total` (counter): `cpanelUserDomains` resolver errors reading `/var/cpanel/userdata/`. Used by the Path 1 `From` mismatch check; errors here mean Path 1 is potentially undercounting until the read recovers.

### Signature retroactive rescans

- `csm_signature_rescans_total` (counter): full deep-tier sweeps
  completed because a signature file's mtime advanced. Steady-state
  zero on hosts that don't auto-update rules; ticks once per
  `update-rules` invocation otherwise.

## Counter reset semantics

Prometheus counters in CSM live in process memory. They reset to zero
whenever the daemon restarts (config change, binary upgrade, crash
recovery). This is the standard behaviour for every
Prometheus-instrumented daemon; Prometheus's scrape pipeline detects
counter resets on its own and `rate()`, `increase()`, and
`rate_over_time()` all handle them correctly.

Operators should not alert on "counter decreased across a scrape" as
a failure condition. Alert on `rate()` or `increase()` of a counter
over a window long enough to absorb expected restarts.

Persisting counters across restarts would require writing to bbolt on
every increment, which would not pay for itself. If a specific metric
needs restart-stable behaviour later, a gauge-over-the-bbolt-counter
pattern can be added for that one case without affecting the rest.

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
- bbolt per-bucket size breakdown, `csm_store_used_bytes`, and
  `csm_store_last_compact_ts`. Deferred to the online-compaction
  follow-up of the retention work (see `ROADMAP.md`).
