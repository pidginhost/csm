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

---

## 1. Daemon control socket phase 2 — remaining CLI migrations

**Status:** planned, after phase 1 has been stable for one release
**Drives / unblocks:** eliminates the last bbolt-contention paths;
lets the admin run any CLI command while the daemon is live.

### Why

Phase 1 covered the commands that routinely raced for the bbolt lock
from systemd timers (`run-critical`, `run-deep`, `status`, the
rule/GeoIP reload pings). A smaller set of commands still opens bbolt
directly and therefore still fails with `store: opening bbolt: timeout`
when the daemon holds the lock:

- `csm baseline` — currently works around the lock by calling
  `systemctl stop csm-critical.timer` + `csm-deep.timer` before
  touching state. The stop/start dance is fragile and does nothing
  about the daemon itself; `baseline` has historically required the
  operator to stop the daemon first. Move into the socket via a
  `baseline` command so the daemon coordinates the wipe + rescan.
- `csm firewall ...` — the whole firewall subcommand surface (allow,
  deny, status, ports, subnets) reads and mutates firewall state that
  the daemon also manages. Route through the socket with a
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

## 2. Structured audit log export

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

## 3. Backup / restore for baseline + state

**Status:** planned
**Drives / unblocks:** re-provisioning; disaster recovery; cluster
cloning; support-bundle artifacts

### Why

A fresh `csm baseline` on a 200k-file account tree takes 20+
minutes. Operators reinstalling the OS, migrating to a new box, or
cloning known-good state across a cluster currently pay that cost
every time. There is also no audited answer to "what did CSM know
at 09:00 this morning" after a later compromise — bbolt is a black
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

## 4. Challenge UX polish

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
  challenged — reverse-DNS verification does not trust the UA
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
