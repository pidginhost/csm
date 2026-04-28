# CSM Engineering Roadmap

Forward-looking engineering decisions that are committed to but not yet
implemented. Items move from here into commits + `CHANGELOG.md` entries
as they land, then settle into "Related work already landed" so the
numbered list stays a to-do, not an archive.

This file is for contributors. End-user documentation lives in `docs/`.

**Stable cross-references.** Older commits, CHANGELOG entries, and a few
code comments reference `ROADMAP item N` by the number that item had
when the commit was written. Those numbers are frozen in time. The
topics they point to are listed by name in the next section; any `item
N` mention in git history maps to the matching bullet there.

## Related work already landed (do not duplicate)

- **Daemon control socket + thin-client CLI (phase 1).** The daemon
  serves a Unix socket at `/var/run/csm/control.sock` (0600, root-only).
  CLI commands `run`, `run-critical`, `run-deep`, and `status` route
  through it instead of opening their own bbolt handle; `update-rules`
  and `update-geoip` run locally and emit a best-effort reload ping
  afterward. Shared wire protocol in `internal/control`. Phase 2
  (remaining CLI migrations) is item 1 below.

- **glibc-dynamic builder** (historical item 1). Builder base moved from
  Alpine + musl-static to AlmaLinux 8 + glibc 2.28, on both amd64 and
  arm64 (arm64 via docker buildx + QEMU in `build/Dockerfile.build`).
  Every supported target distro (CloudLinux 8 / AlmaLinux 8-9 / Ubuntu
  22.04-24.04) ships glibc ≥ 2.28, so one build runs everywhere.
  Resolves the YARA-X 1.15.0 runtime regressions that motivated the
  switch. `CSM_BUILDER_TAG` gates the CI builder image.

- **YARA-X process isolation** (historical item 2). `csm yara-worker`
  subcommand, length-prefixed JSON over a Unix socket, exponential
  backoff supervisor, `yara_worker_crashed` Critical finding, and
  `csm_yara_worker_restarts_total` counter. Default-on via a *bool
  tri-state: omitting `signatures.yara_worker_enabled` (or setting it
  to `true`) runs the supervised child; explicit `false` keeps the
  in-process scanner. Any future cgo-heavy component can adopt the
  same supervisor wrapper.

- **Prometheus `/metrics` endpoint** (historical item 4). OpenMetrics
  text exposition on the existing HTTPS web UI port. Bearer auth via
  `webui.metrics_token` (falls back to UI AuthToken / session cookie).
  Twelve metrics documented in `docs/src/metrics.md` including
  `csm_findings_total{severity}`, `csm_fanotify_*` series,
  `csm_check_duration_seconds{name,tier}`, firewall gauges, and
  `csm_auto_response_actions_total{action}`.

- **SIGHUP config hot-reload** (historical item 7). `systemctl reload
  csm` re-reads `csm.yaml`, diffs against the running config via the
  `hotreload` struct tag, and swaps safe-tagged fields in place;
  `thresholds`, `alerts`, `suppressions`, `auto_response`,
  `reputation`, and `email_protection` are tagged safe today. Unsafe
  edits abort the reload with a Warning `config_reload_restart_required`
  finding naming the offending fields. Reload re-signs
  `integrity.config_hash` in place. Known open corners: no dry-run
  diff endpoint yet; `reputation.whitelist` and
  `email_protection.known_forwarders` still capture their lists at
  startup so edits to those sub-keys need a restart to propagate.

- **bbolt retention + manual compaction** (historical item 6). Opt-in
  `retention:` block drives a daily sweep over `history`,
  `attacks:events`, and `reputation`; `csm_retention_sweeps_total` and
  `csm_retention_deleted_total` track activity; `csm store compact
  [--preview]` reclaims on-disk space when the daemon is stopped.
  "Compact without restarting the daemon" is deferred until a real
  operator reports pressure — it needs coordinated write quiescence
  bigger than the rest of this work. `csm_store_last_compact_ts` and
  `csm_store_used_bytes` metrics are likewise deferred to that pass.

- **Daemon control socket phase 2** (historical item 1). `csm baseline`,
  `csm firewall *`, and `csm check*` migrated off direct bbolt onto the
  existing control socket. New wire commands: `baseline`, the
  `firewall.*` family (block/unblock/allow/allow_port/remove_port/
  tempban/tempallow/deny_subnet/remove_subnet/remove_allow/deny_file/
  allow_file/flush/restart/apply_confirmed/confirm/status/ports/grep/
  audit), and `tier.run` with `Alerts=false` + inline `FindingList` for
  `csm check*`. Socket I/O buffer raised to 16 MiB (root-only 0600).
  `csm-critical.timer` and `csm-deep.timer` systemd units deleted in
  favour of the daemon's internal scanners, eliminating the
  per-interval double-run. `stopTimers` / `startTimers` shell-outs
  removed from the CLI. Known corner: `csm firewall restart` and
  `csm firewall apply-confirmed` now require a live engine; a dead
  engine means `systemctl restart csm` rather than CLI-side recovery.

- **Backup / restore for state** (historical item 2). `csm store export
  <path>` writes a tar+zstd archive containing a bbolt snapshot, the
  state directory, and the signature-rules cache, plus a sibling
  `<path>.sha256` companion file. Export routes through the control
  socket; the daemon owns the source of truth for paths. `csm store
  import <path>` is direct-to-disk and refuses with a live daemon.
  `--only=baseline` restores only state JSON files (file hashes);
  `--only=firewall` merges only the `fw:*` buckets into an existing
  bbolt; `--force-platform-mismatch` is required for cross-platform
  restores. Manifest carries a `schema_version` int; imports refuse
  archives newer than the running binary.

---

## 1. Structured audit log export

**Status:** planned
**Drives / unblocks:** SIEM integration; retention beyond the bbolt
window

### Why

Findings live in bbolt. Hosts shipping to Splunk, Loki, or Elastic
screen-scrape the web UI today. The alert package emits email and
webhook per-finding but does not format a stable, replayable stream.
Bulk reconciliation ("give me everything that happened between
yesterday 08:00 and now") is also missing.

### Decision

New sink types alongside the existing email and webhook sinks:
append-only JSONL at `/var/log/csm/audit.jsonl` and syslog RFC 5424
over UDS, TCP, or TLS. Configurable in `csm.yaml`. Stable schema
with a `v` field so downstream parsers can pin.

### Scope sketch

- `internal/alert/audit_sink.go` with a `Sink` interface retrofitted
  over the existing two sinks (no new code path for email or
  webhook; only the file and syslog sinks add functionality).
- Schema:
  `{"v":1,"ts":"...","finding_id":"...","severity":"...",
  "check":"...","details":{...}}`. Frozen on first release.
- logrotate fragment in packaging for the JSONL target.
- Backfill: `csm export --since <ts>` dumps historical findings
  from bbolt in the same format for initial SIEM onboarding.

### Acceptance criteria

- Tailing the JSONL while running `csm run` produces one line per
  finding with parseable JSON on every line.
- Syslog target tested against `rsyslog` and `syslog-ng` receivers
  in integration.
- Backfill export of 10,000 findings is byte-identical to a fresh
  replay.

### Out of scope

- CEF or LEEF formats.
- Filtering/routing logic per finding type at the sink layer.
  Downstream SIEM handles that.

### Estimated size

2-3 engineering days.

