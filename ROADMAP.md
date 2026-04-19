# CSM Engineering Roadmap

Forward-looking engineering decisions that are committed to but not yet
implemented. Items move from here into commits + `CHANGELOG.md` entries
as they land.

This file is for contributors. End-user documentation lives in
`docs/`.

## Related work already landed (do not duplicate)

- **Daemon control socket + thin-client CLI (phase 1).** The daemon
  now serves a Unix socket at `/var/run/csm/control.sock` (0600,
  root-only). CLI commands `run`, `run-critical`, `run-deep`, `status`,
  `update-rules`, and `update-geoip` route through it instead of
  opening their own bbolt handle. Shared wire protocol lives in
  `internal/control`. Any new IPC work (see item 2) should reuse the
  `/var/run/csm/` path convention, permission model, and line-framed
  JSON request/response pattern rather than inventing a parallel
  stack. Phase 2 (remaining CLI migrations) is tracked as item 3
  below.

---

## 1. Move build from musl-static to glibc-dynamic

**Status:** done — phase A (amd64, glibc-dynamic) landed and verified
in production; phase B (arm64 via docker buildx + QEMU) shipped via
`build/Dockerfile.build` and `build-builder-image-arm64`. Both arches
now target the same `GLIBC_2.28` floor.
**Drives / unblocks:** safe future YARA-X upgrades; any other cgo
dependency upgrade

### Why

The YARA-X 1.15.0 upgrade attempt on 2026-04-16 put a production
host into a deterministic SIGSEGV restart loop inside
`yrx_compiler_build`. The
crash was never root-caused in the production-pressure window; the
only reliable fix was to revert to v1.14.0 (commit `a98e257`). The
failure mode — SEGV_ACCERR in Rust-compiled-to-C-ABI code called via
cgo, inside a binary linked statically against musl with a
source-built libunwind and stub libgcc_s.a — strongly suggests a
Rust/musl/unwinder ABI interaction that upstream YARA-X does not
test.

Corroborating evidence: the 2.4.3 release required **8 consecutive
builder-image iterations** just to get YARA-X 1.15.0 to link at all,
including a source-built libunwind with `--disable-minidebuginfo` to
dodge undefined `lzma_*` symbols from Alpine's packaged libunwind.
Each round shipped through CI without reproducing the runtime
crash, because we had no local 1.15.0 reproduction harness. Upstream
YARA-X's CI matrix targets glibc. We are fighting a
combination they do not exercise.

### Decision

Switch the builder base from `alpine` + musl-static to
`debian:bookworm-slim` + glibc-dynamic. Build `csm` as a
glibc-dynamic binary whose glibc floor matches the oldest supported
cPanel host (CloudLinux / Alma / RHEL 8, glibc 2.28). Accept the
trade-off that the binary becomes distro-floor-specific instead of
"runs anywhere with a Linux kernel".

### Expected outcome

- Future YARA-X (and other cgo) upgrades stop fighting the
  toolchain. Upstream test config = our runtime config.
- Debug tooling (gdb, perf, lldb, proper stack unwinding, symbolic
  traces) works as documented instead of silently producing garbage
  on musl-static.
- The `Dockerfile.builder` work that landed with the 2.4.3 attempt
  (source libunwind, `--disable-minidebuginfo`, libgcc_s stub,
  musl-gcc shim, linker override via `CARGO_TARGET_*_LINKER`) all
  disappears — none of it is needed on glibc.

### Work items

1. Fork `build/Dockerfile.builder` to target `debian:bookworm-slim`
   on a glibc-2.28 or glibc-2.31 floor (build on a CloudLinux 8 or
   Debian 11 image that has glibc 2.28/2.31). Keep only: Go
   toolchain, Rust toolchain, `cargo-c` for YARA-X build.
2. Cross-compile for aarch64 against a matched glibc-floor arm64
   base (e.g. `debian:bookworm-slim/arm64`). Drop the
   `musl.cc` cross-toolchain.
3. Bump `.gitlab-ci.yml` `CSM_BUILDER_TAG` to something like
   `glibc-2.28-r1`. The CI job that rebuilds the builder image runs
   automatically on tag change.
4. Verify on every target distro we deploy to: CloudLinux 8,
   AlmaLinux 8, AlmaLinux 9, Ubuntu 22.04, Ubuntu 24.04. Use the
   existing `integration` stage, extended.
5. Review `scripts/deploy.sh`, `scripts/install.sh`, and
   `/root/deploy-csm.sh` for any binary-naming or SHA-pinning
   assumptions; update if needed.
6. Once green on all targets, re-attempt the YARA-X upgrade (to the
   latest stable at the time, which may be 1.15.x patch, 1.16, or
   later) **with local reproduction coverage** before it ships to
   main. The re-attempt is a separate commit; this roadmap item
   is complete when the glibc build is shipping and stable.

### Out of scope

- Running CSM on Alpine, BusyBox, or other musl-libc distros. Not
  a real deployment target.
- Statically linking all dependencies into the glibc binary. Dynamic
  glibc with a pinned floor is sufficient.
- Re-attempting the YARA-X upgrade in this work item. That happens
  after the build change has been stable for a release cycle.

### Rollback plan

The current 2.4.2 musl-static build is proven stable. If the glibc
switch causes regressions, revert the Dockerfile + CSM_BUILDER_TAG
commits and the next CI run produces the old binary.

---

## 2. Process-isolate YARA-X (and other cgo dependencies)

**Status:** done for YARA-X (opt-in behind
`signatures.yara_worker_enabled`). Default-on flip remains; tracked
as a follow-up below.
**Drives / unblocks:** resilience against any future cgo
dependency bug

### Why

A bug in any cgo dependency currently takes the entire `csm` daemon
down. The 2026-04-16 incident demonstrated the cost: 17 systemd
restart attempts over 4 minutes, real-time monitoring offline for
the whole window, manual rollback required. Glibc (item 1 above)
reduces the probability of such a bug; it does not eliminate it. The
next cgo dependency crash — in YARA-X, in a future
`github.com/google/nftables` bug, in a libc symbol that drifts
between distros — will have the same blast radius unless we
architect around it.

### Decision

Run the YARA rule compiler + scan loop in a supervised child
process (`csm yara-worker`). The daemon supervises the worker over a
Unix-domain socket. If the worker crashes the daemon restarts it
with exponential backoff and emits a clear finding
(`yara_worker_crashed` or similar); real-time monitoring stays up
throughout.

The pattern generalises: any future cgo-heavy component can be
moved behind the same supervisor wrapper.

### Scope sketch

- New subcommand: `csm yara-worker` (runs the YARA-X compile + scan
  loop; reads requests and writes responses on a Unix socket).
- IPC: length-prefixed frames on a Unix-domain socket. Socket path
  `/run/csm/yara-worker.sock` (mode `0600`, owned by root).
  Configurable.
- Daemon side: supervisor goroutine that forks the worker, monitors
  it, restarts on exit with exponential backoff up to a ceiling,
  and surfaces an alert after N consecutive restarts.
- Rule-reload: worker re-execs on `SIGHUP` to pick up new rules
  without a daemon restart.
- Graceful degradation: if the worker has been unavailable for
  longer than a threshold, YARA-backed checks return "no result"
  rather than blocking or escalating.

### Acceptance criteria

- An induced `SIGSEGV` in the worker leaves the daemon running and
  the real-time file monitor uninterrupted. A finding is emitted
  identifying the worker crash.
- Scan latency adds no more than ~5 ms over the in-process baseline
  (budget: one socket round-trip + serialisation).
- The integration stage covers: normal scan, worker crash during a
  scan, worker crash during rule rebuild, worker unreachable
  (socket gone), and worker restart-loop ceiling.

### Out of scope

- Process-isolating anything other than YARA-X in the first pass.
  Other cgo dependencies can adopt the same pattern in follow-up
  work.
- Multi-worker / worker-pool scaling. One worker per daemon is
  sufficient for current load.

### Estimated size

3–5 engineering days including integration tests.

### Follow-ups (not yet shipped)

- Flip `signatures.yara_worker_enabled` default to true once the
  opt-in window has been stable for one release cycle.
- Apply the same supervisor pattern to any future cgo dependency
  whose crash would otherwise take the daemon down.

---

## 3. Daemon control socket phase 2 — remaining CLI migrations

**Status:** planned, after phase 1 has been stable for one release
**Drives / unblocks:** eliminates the last bbolt-contention paths;
lets the admin run any CLI command while the daemon is live.

### Why

Phase 1 (already landed) covered the commands that routinely raced
for the bbolt lock from systemd timers (`run-critical`, `run-deep`,
`status`, the rule/GeoIP reloads). A smaller set of commands still
opens bbolt directly and therefore still fails with
`store: opening bbolt: timeout` when the daemon holds the lock:

- `csm baseline` — currently works around the lock by calling
  `systemctl stop csm-critical.timer` + `csm-deep.timer` before
  touching state. The stop/start dance is fragile and does nothing
  about the daemon itself; `baseline` has historically required the
  operator to stop the daemon first. Move into the socket via a
  `baseline` command so the daemon coordinates the wipe + rescan.
- `csm firewall ...` — the whole firewall subcommand surface
  (allow, deny, status, ports, subnets) reads and mutates firewall
  state that the daemon also manages. Route through the socket with a
  `firewall.<action>` command family so the daemon's in-memory engine
  is the single writer.
- `csm check`, `csm check-critical`, `csm check-deep` — dry-run
  variants of the tier runners. Phase 1 left them on the in-process
  path. Either migrate them to the socket with `alerts=false` (and
  stream findings back), or formalise them as "offline detection test"
  tools that require the daemon to be stopped.

### Decision

Migrate `baseline`, `firewall`, and the `check*` dry-run commands to
the existing control socket. Reuse the `internal/control` wire format
and `cmd/csm/client.go` helpers. No new socket, no new protocol
version.

### Scope sketch

- New command names on the protocol: `baseline`, `firewall.list`,
  `firewall.block`, `firewall.unblock`, `firewall.allow`,
  `firewall.ports`, `firewall.status`, and either `check.run`
  (returns the full finding list) or `tier.run` with `alerts=false`
  plus a follow-up `findings.latest` to stream results back.
- Client-side: replace the remaining `loadConfig` calls in
  `cmd/csm/main.go` and `cmd/csm/firewall.go` with `sendControl`
  calls. Delete the `stopTimers` / `startTimers` helpers once
  `baseline` moves inside the daemon.
- Decide whether the systemd timers and the daemon's internal
  `criticalScanner` / `deepScanner` goroutines should continue
  coexisting. Phase 1 left both alive; with the socket in place they
  now run the same code path twice per interval. Options are:
  1. Delete the systemd timers — the daemon already schedules the
     same work from its internal tickers.
  2. Keep timers but turn them into nudges that the daemon can
     coalesce (if another tier run is in progress, no-op).
  3. Keep both, accept the double-run. Least code change but wastes
     CPU.

### Acceptance criteria

- `csm baseline` works while the daemon is running, with no
  `stopTimers` / `startTimers` shell-out in the CLI.
- `csm firewall status` and all mutating firewall commands succeed
  against a live daemon, no state-file parsing in the CLI.
- The `store: opening bbolt: timeout` error is unreachable from any
  shipped CLI command.
- CHANGELOG entry and docs update ship in the same commit.

### Out of scope

- Changing the `check*` semantics (they currently write to history
  even in "dry-run" mode — a pre-existing quirk; fix in a separate
  commit if at all).
- Removing the `loadConfig` vs `loadConfigLite` split. Bootstrap
  commands (`install`, `validate`, `verify`, `rehash`) legitimately
  run before the daemon exists and stay on the in-process path.

### Estimated size

1–2 engineering days including tests and docs.

---

## 4. Prometheus/OpenMetrics endpoint

**Status:** shipped. `/metrics` on the web UI HTTPS port, Bearer
auth via `webui.metrics_token` (falls back to the UI AuthToken /
session cookie), Prometheus text exposition format, zero new
external dependencies. Eleven metrics live under `[Unreleased]`:
`csm_build_info{version}`, `csm_yara_worker_restarts_total`,
`csm_findings_total{severity}`, `csm_store_size_bytes`,
`csm_fanotify_queue_depth`, `csm_fanotify_events_dropped_total`,
`csm_fanotify_reconcile_latency_seconds`,
`csm_check_duration_seconds{name,tier}`,
`csm_blocked_ips_total`, `csm_firewall_rules_total`, and
`csm_auto_response_actions_total{action}`. Documented in
`docs/src/metrics.md` with scrape config that passes
`promtool check config`.
**Drives / unblocks:** fleet observability; alerting without log
scraping

### Why

One daemon per server and no `/metrics` handler today. The 2.5.0
reconcile pass hides fanotify drops from humans; operators running
CSM on 10+ hosts have no way to alert on "which server has a growing
finding queue" or "which watcher is dropping events" without
SSH-ing in and running `csm status`. Every production daemon of this
shape ships metrics; not doing so makes CSM look toy next to
competitors.

### Decision

Add a `/metrics` handler on the existing HTTPS web UI server (port
9443), OpenMetrics text format, no new listener, no new dependency.
Auth via either the UI session cookie or a static bearer token from
`csm.yaml`. Wire gauges and counters at existing choke points rather
than adding a new abstraction layer.

### Scope sketch

- Metrics: `findings_total{severity}`,
  `fanotify_queue_depth`, `fanotify_events_dropped_total`,
  `fanotify_reconcile_latency_seconds`,
  `check_duration_seconds{name,tier}`, `store_size_bytes`,
  `firewall_rules_total`, `blocked_ips_total`,
  `yara_worker_restarts_total` (cross-references item 2),
  `auto_response_actions_total{action}`, `build_info{version}`.
- Histogram buckets sized for the observed 10 ms -- 60 s range of
  check durations.
- `metrics_token` in `csm.yaml`, sent via `Authorization: Bearer`.
  UI session cookie also accepted so the dashboard can self-scrape.
- Docs: new `docs/src/metrics.md` with a scrape-config snippet that
  passes `promtool check config`.

### Acceptance criteria

- `curl -H "Authorization: Bearer $TOKEN" https://host:9443/metrics`
  returns Prometheus text exposition.
- `findings_total` is monotonically non-decreasing within a daemon
  lifetime. Counter resets on daemon restart are expected and are
  handled by Prometheus's built-in reset detection (`rate()`,
  `increase()`). See `docs/src/metrics.md` for the full policy.
- No new external dependency in `go.sum`.

### Out of scope

- Pushgateway integration. Pull only.
- Per-account labels. Cardinality risk on shared hosts with 1000+
  cPanel users.
- StatsD / InfluxDB line protocol.

### Estimated size

2 engineering days.

### Rollback plan

Revert the handler registration in `internal/webui/server.go`.
Metrics are read-only and additive; no state to migrate.

---

## 5. Structured audit log export

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

---

## 6. bbolt growth + retention policy

**Status:** planned
**Drives / unblocks:** predictable disk use on long-running
daemons

### Why

bbolt never shrinks the on-disk file once a page is written, only
freelists the space. `purge_correlation.go` trims one bucket; no
documented cap exists on `findings`, `history`, `blocked_ips`, or
the per-IP reputation buckets. Servers under sustained attack
accumulate millions of rows; the file can exceed 1 GB over months.
Recovery today is `systemctl stop` + `bbolt compact`. Needs to be
a first-class feature.

### Decision

Per-bucket retention config with a background compactor. Defaults:
findings 90 days, history 30 days, blocked IPs indefinite (already
pruned on unblock), reputation 180 days. Online compaction via
`bbolt.Tx.WriteTo` into a temp file + atomic rename during
low-activity windows. `csm store compact` CLI command routes
through the control socket for manual runs.

### Scope sketch

- New goroutine in the daemon: daily retention sweep per bucket,
  driven by a `retention:` block in `csm.yaml`.
- Compaction trigger: `used_bytes / file_size < 0.5` and file
  > 128 MiB schedules a compact at the next daily window.
- Control-socket command `store.compact` so operators can force it
  without touching bbolt.
- `/metrics` exposes `store_size_bytes`, `store_used_bytes`,
  `store_last_compact_ts`.

### Acceptance criteria

- A synthetic 10 M-finding run followed by a compact reduces file
  size by > 40% without restarting the daemon.
- Retention deletions are atomic per-key (no half-deleted finding
  visible to the UI mid-sweep).
- Compact never runs while a critical-tier or deep-tier scan is in
  flight.

### Out of scope

- Migrating off bbolt to SQLite/Badger. Separate decision; retention
  policy stands regardless.
- Per-account sharding.

### Estimated size

3 engineering days.

### Rollback plan

The retention goroutine and the compact command are additive.
Disabling the `retention:` block in `csm.yaml` turns the new
behaviour off.

---

## 7. Config hot-reload via SIGHUP

**Status:** shipped. `systemctl reload csm` (or `kill -HUP
$MAINPID`) re-reads `csm.yaml`, validates it, diffs against the
running config, and swaps in fields tagged `hotreload:"safe"`
without a restart. Tagged safe today: `thresholds`, `alerts`,
`suppressions`, `auto_response`, `reputation`,
`email_protection`. Fanotify marks survive the reload. Reload
re-signs `integrity.config_hash` on disk so scripted edits no
longer need a manual `csm rehash`. `ExecReload=` is wired into the
systemd unit. See "Follow-ups" below for the remaining top-level
fields (webui.metrics_token, signatures.rules_dir) and the four
startup-capture sub-keys that stay on restart within the
safe-tagged parents.
**Drives / unblocks:** live threshold tuning, live alert-sink
tuning, live suppression edits during an incident; all without
losing fanotify marks

### Why

Editing `csm.yaml` today requires `systemctl restart csm`. The
restart drops fanotify marks on every watched directory; during a
real incident the operator either tunes live (and loses 3-5 s of
real-time monitoring on re-mark) or leaves a noisy threshold in
place. Both are bad.

A second cost: the integrity check (`integrity.Verify` in
`cmd/csm/main.go`) refuses any config whose sha256 disagrees with
`cfg.Integrity.ConfigHash`, so every hand-edit must be followed by
`csm rehash` before the restart or the daemon crash-loops. The
workflow is documented in `docs/src/configuration.md` (section
"Editing csm.yaml by hand"); hot-reload should fold the rehash
into reload so the whole dance collapses to
`sudo kill -HUP $(pidof csm)` (or `systemctl reload csm` once
`ExecReload=` is wired).

### Decision

On SIGHUP, re-read `csm.yaml`, diff against the running config, and
apply only keys that are safe to apply live. Unsafe keys (bbolt
path, control-socket path, web UI port, fanotify watched roots)
require a restart; the reload logs a clear
"SIGHUP ignored for key X, restart required" line.

### Scope sketch

- Tag each config struct field with `hotreload:"safe"` or
  `hotreload:"restart"`.
- Single reload lock around the swap; readers use an
  `atomic.Pointer[Config]`.
- Applies cleanly to: thresholds, alert sinks, suppression rules,
  retention config (item 6), metrics token (item 4), rule paths
  for signatures and modsec.
- Restart required for: watched roots, web UI listener, bbolt path.
- Emit a finding on reload error (bad YAML, unsafe key touched).
- Wire `ExecReload=` into the systemd unit.

### Acceptance criteria

- `kill -HUP $(pidof csm)` after a threshold change emits a
  "reloaded" log line and the new value takes effect on the next
  check tick without fanotify drops.
- A deliberate bad YAML does not crash the daemon; the old config
  stays live and a finding is emitted.
- Reload re-signs `integrity.config_hash` in place. The manual
  `csm rehash` step for hand-edits becomes optional: a scripted
  edit + SIGHUP sequence must leave the daemon running and the
  on-disk file correctly signed.

### Out of scope

- Reloading compiled YARA rules. `update-rules` already does that
  through the control socket.
- Dynamic watched-root changes. Fanotify re-marking cost is not
  worth the complexity here.

### Follow-ups (not yet shipped)

- Dashboard surface for "what would a reload change?" -- a dry-run
  diff endpoint on the control socket that returns the classified
  field list without actually swapping. Useful for
  config-management tools. Tracked separately; not required to
  close item 7.
- `reputation.whitelist` runtime propagation. Today the initial
  whitelist is seeded into the threat DB at startup; runtime
  whitelist edits go through the Threat Intelligence UI/API and
  persist to disk. Editing `reputation.whitelist` in `csm.yaml`
  and reloading does not push additions into the running threat
  DB. An `UpdateConfigWhitelist([]string)` method on the threat
  DB wired into the reload path is the natural fix; skipped here
  because the operator path for adding whitelist entries already
  exists and works.
- `email_protection.known_forwarders` runtime propagation. Same
  shape as the whitelist case: the forwarder watcher captures the
  list at startup. Fix is an `UpdateForwarders([]string)` on the
  watcher. Low-value until anyone asks -- operators rarely edit
  this after install.

### Deliberately restart-required

- Every `signatures.*` field (including `rules_dir`,
  `auto_update`, `yara_forge.*`, `yara_worker_enabled`). Changing
  `rules_dir` is rare operator maintenance; for rule CONTENT
  updates in the SAME directory, use `csm update-rules` which
  already reloads without a daemon restart. YARA-X worker mode
  toggles need the full supervisor lifecycle.
- `webui` (except `metrics_token` which is field-level safe).
  Listener, TLS cert/key, auth token all need the HTTP server to
  restart.
- `firewall.*`, `geoip.*`, `email_av.*`, `challenge.*` -- each
  owns a long-lived goroutine / subsystem whose init consumes
  these fields; a mid-life swap would require careful restart
  machinery that is not worth the complexity for typical
  operator cadence.

### Estimated size

2 engineering days.

### Rollback plan

Revert the signal handler; the daemon falls back to restart-only
reload.

---

## 8. Backup / restore for baseline + state

**Status:** planned
**Drives / unblocks:** re-provisioning; disaster recovery; cluster
cloning; support-bundle artifacts

### Why

A fresh `csm baseline` on a 200k-file account tree takes 20+
minutes. Operators reinstalling the OS, migrating to a new box, or
cloning known-good state across a cluster currently pay that cost
every time. There is also no audited answer to "what did CSM know
at 09:00 this morning" after a later compromise -- bbolt is a black
box with no supported export.

### Decision

Two CLI commands, both through the control socket. `csm store
export <path>` writes a tagged tar+zstd archive of bbolt buckets +
baseline hashes + firewall state + suppressions + signature-rule
cache. `csm store import <path>` restores onto a stopped daemon
(refuses with a live daemon, because split-brain is worse than
downtime). Partial restore via `--only=baseline`.

### Scope sketch

- New `internal/store/archive.go`: read/write primitives over the
  existing bbolt handle.
- CLI integration in `cmd/csm/`.
- Manifest with `schema_version`, `source_hostname`,
  `source_platform`, `export_ts`, `bucket_list`.
- Import refuses to load an archive whose `schema_version` is
  newer than the running binary.
- Same export format doubles as a snapshot the support tooling can
  attach to a bug report.

### Acceptance criteria

- Export + import round-trip on a 100 MiB bbolt file produces a
  byte-for-byte identical bucket listing.
- A `--only=baseline` import skips findings/history and leaves the
  target daemon's existing findings intact.
- Archive is self-describing: `tar tf` lists the manifest and
  bucket files without a CSM binary present.

### Out of scope

- Encryption of the archive at rest. Operators can pipe through
  gpg; CSM does not manage key material.
- Cross-platform baseline transfer. A baseline captured on Apache
  is not meaningful on Nginx; the import refuses when
  `source_platform` differs.

### Estimated size

3 engineering days.

### Rollback plan

Export is read-only. Import only runs on a stopped daemon; if the
imported state is bad, the operator deletes bbolt and
re-baselines.

---

## 9. Challenge UX polish

**Status:** planned
**Drives / unblocks:** fewer false-positive bans; legitimate-visitor
experience

### Why

The proof-of-work challenge at `internal/challenge` is binary: the
visitor either completes the JS-based PoW or is blocked.
JS-disabled clients (older phones, accessibility tooling, text
browsers, scripted legitimate integrations) are false-positives by
construction. Authenticated WordPress admins, site owners, and
CSM's own webhook receivers can trip the challenge during normal
work; there is no "I am already trusted" path.

### Decision

Three independent improvements, all optional and configurable:

1. Cloudflare Turnstile / hCaptcha fallback page presented when the
   PoW page detects JS disabled. Operator supplies a site key; if
   unset, the feature is off and behaviour is unchanged.
2. Session-token bypass for authenticated WordPress admins: a
   signed cookie the admin-ajax flow (or a tiny WP plugin) can set
   so the challenge server sees "this visitor authenticated against
   the account's WP admin in the last N minutes". Signing key lives
   in bbolt, rotated on restart.
3. Verified-crawler allow-pass (Googlebot, Bingbot) via reverse-DNS
   + forward-confirm, opt-in in `csm.yaml`; default off.

### Scope sketch

- New `internal/challenge/fallback_captcha.go` with a pluggable
  provider (Turnstile first, hCaptcha as a strategy).
- New `internal/challenge/verified_session.go` for the signed-cookie
  path.
- Reverse-DNS verification integrated with the existing allow-list
  machinery rather than a new path.
- All three configurable independently in `csm.yaml`.

### Acceptance criteria

- A JS-disabled curl with a real browser User-Agent receives the
  CAPTCHA page, not a 403, when the provider is configured.
- A valid Turnstile token unlocks the visitor for the same
  duration PoW would.
- A spoofed `User-Agent: Googlebot` from a non-Google IP is still
  challenged -- reverse-DNS verification does not trust the UA
  alone.
- Authenticated-admin bypass only applies to visitors with a cookie
  signed by the current secret; an old signed cookie after a
  daemon restart fails verification.

### Out of scope

- Building our own CAPTCHA. Third-party providers only.
- Challenge for non-HTTP traffic.

### Estimated size

3-4 engineering days.

### Rollback plan

All three features are opt-in; removing their blocks from
`csm.yaml` reverts to current PoW-only behaviour.

---
