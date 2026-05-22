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
  afterward. Shared wire protocol in `internal/control`.

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

- **Challenge UX polish** (historical item 3). Three opt-in bypass
  paths replace the binary "solve PoW or 403" gate. CAPTCHA fallback
  embeds a Cloudflare Turnstile or hCaptcha widget for JS-disabled
  visitors (`POST /challenge/captcha-verify`). Verified-session bypass
  lets operators mint a signed cookie via `POST /challenge/admin-token`
  with a shared secret; the signing key is regenerated at every daemon
  start, so old cookies stop working after a restart. Verified-crawler
  allow-pass does reverse-DNS + forward-confirm for Googlebot and
  Bingbot, with positive/negative caching to keep DNS load bounded.
  All three default off.

- **Structured audit log export** (historical item 1). Every
  deduplicated finding routes through configurable audit sinks
  before the email/webhook rate limiter, so SIEMs see the complete
  picture even when operator-facing alerts are throttled. JSONL
  file at `/var/log/csm/audit.jsonl` with logrotate's
  `copytruncate` mode and RFC 5424 syslog over UDP, TCP, unix-stream,
  unix-datagram, or TLS. Schema frozen at `v=1`. `csm export --since
  <when>` backfills historical findings via a new `history.since`
  control-socket command for first-time SIEM onboarding.

- **Detection-cleaning rounding** (historical item 1). WordPress
  multisite scanning, Joomla, Drupal 8+, Magento 1/2, OpenCart,
  MySQL trigger/event/procedure/function scanning, manual DB-object
  drop with backup/restore APIs, hardened `.htaccess` detectors and
  cleaner, signature-update-driven retroactive rescans, cleanup-history
  UI, and supported-CMS policy docs have landed.

- **Copy Fail BPF LSM kernel block** (historical item 5). BPF-tagged
  builds now ship the AF_ALG LSM program, ringbuf event consumer, and
  daemon backend wrapper. On kernels with BPF LSM, the daemon can deny
  AF_ALG socket creation in-kernel and emit the same Critical finding
  path used by the audit fallback. Operator docs now describe the
  shipped BPF semantics and real-host validation path.

---

## 1. Signed YARA Forge mirror automation

**Status:** planned
**Drives / unblocks:** safe automatic YARA Forge updates without
turning off signature verification

### Why

CSM now correctly refuses `signatures.yara_forge.enabled: true` unless
`signatures.signing_key` and `signatures.yara_forge.download_url` point
at a ZIP plus detached CSM signature. Upstream YARA Forge GitHub
releases publish ZIPs, but not CSM `.sig` files, so operators cannot
enable automatic Forge updates directly against GitHub without weakening
the trust model.

### Decision

Build and document a small mirror job operated by us:

1. Query the latest `YARAHQ/yara-forge` release.
2. Download the selected Forge ZIP tiers (`core`, `extended`, `full`).
3. Sign the raw ZIP bytes with the CSM Ed25519 rule-signing key.
4. Publish each ZIP and `<zip>.sig` under a stable HTTPS path compatible
   with `signatures.yara_forge.download_url` and the `{tier}` /
   `{version}` placeholders.
5. Publish checksums and retain a bounded number of older releases for
   rollback.
6. Add an operator example that enables Forge through `/etc/csm/conf.d/`
   without editing the main `/opt/csm/csm.yaml`.

### Acceptance criteria

- A fresh mirror run publishes the latest Forge release ZIPs, `.sig`
  files, and checksums.
- A CSM instance configured with the mirror URL updates Forge rules
  successfully and records the installed Forge version.
- Missing, corrupt, or mismatched signatures fail closed.
- Operators who do not use the mirror can keep Forge disabled without
  disabling local YAML/YARA signatures.

### Out of scope

- Accepting unsigned upstream Forge ZIPs.
- Relaxing `signatures.signing_key` validation.
- Shipping the private signing key in this repository or in packages.

### Estimated size

0.5-1 engineering day.

---

## 2. `csm support-bundle` command

**Status:** planned
**Drives / unblocks:** support workflow for operators reporting bugs

### Why

Operators reporting issues currently grep journal logs, copy
`/opt/csm/state/state.json`, and try to reconstruct the daemon's
view by hand. The new `csm store export` covers the bbolt + state
side; this wraps that plus the rest of what a triage engineer
needs into a single artifact.

### Decision

New CLI command `csm support-bundle <path>` produces a tar+zstd
archive (same format as `store export`) containing:

- The output of `csm store export` (manifest, bbolt snapshot,
  state, signature cache).
- The last N journalctl lines for the `csm.service` unit (default
  N=2000), captured via `journalctl -u csm --no-pager`.
- The current `/etc/csm/csm.yaml` with secrets redacted (`smtp`,
  `webhook.url`, `abuseipdb_key`, `webui.auth_token`,
  `verified_session.admin_secret`, `captcha_fallback.secret_key`).
- A `system.txt` file with `uname -a`, `csm version`, distro info,
  and the daemon's startup integrity hashes.

Live daemon required (mirrors `store export`).

### Acceptance criteria

- `tar tf <bundle>` lists the manifest, bbolt snapshot, state,
  rules, journal log, redacted config, and system.txt.
- Redaction is whitelist-style: any unknown `*_key` / `*_token` /
  `*_secret` field is also blanked.

### Out of scope

- Automatic upload to a support endpoint.
- Encryption at rest -- operators pipe through gpg as today.

### Estimated size

1 engineering day. Most plumbing exists.

---

## 3. Scheduled backup exports

**Status:** planned
**Drives / unblocks:** out-of-the-box DR for operators who do not
want to manage cron jobs

### Why

`csm store export` requires a cron entry today. Operators forget,
or write the cron with an absolute path that drifts when the disk
layout changes. A daemon-side schedule keeps backups colocated with
the rest of CSM's hot-reloadable config.

### Decision

New top-level config block:

```yaml
backup:
  enabled: true
  schedule: "@daily"            # cron spec or @hourly | @daily | @weekly
  destination_dir: /var/backups/csm
  filename: "csm-{date}.csmbak"
  retention_days: 14            # delete older archives
```

Daemon ticks the schedule, calls the existing `store.Export` path,
and prunes archives older than `retention_days` from
`destination_dir`. Failures emit a `backup_export_failed` Warning
finding routed through the normal alert pipeline.

### Acceptance criteria

- A `@daily` schedule produces one archive per day at the
  configured time, retains the last 14, and removes older ones.
- Manual `csm store export <path>` continues to work alongside
  the scheduled exports.
- Disabling the block stops scheduled exports without restart
  (hotreload-safe).

### Out of scope

- Off-host destinations (S3, SFTP). Operators rsync the
  `destination_dir` themselves.
- Encryption.

### Estimated size

1-2 engineering days.

---

## 4. WordPress companion plugin for signed-cookie operator bypass

**Status:** planned
**Drives / unblocks:** real-world adoption of the
`/challenge/admin-token` endpoint

### Why

The signed-cookie bypass landed in roadmap item 3 (challenge UX
polish) requires the operator to POST `admin_secret` to
`/challenge/admin-token`. That works for CSM-aware tooling and
manual curls but not for a WordPress admin who just wants to log
into wp-admin without solving PoW. A companion plugin closes the
gap: a logged-in WP admin gets the cookie automatically.

### Decision

Lives in a separate repository (`pidginhost/csm-wp-bypass`), not
this one. CSM exposes the contract; the plugin consumes it.

The plugin:

- Reads the operator-provided `admin_secret` from a constant
  defined in `wp-config.php` (`CSM_ADMIN_SECRET`).
- On `wp_login` for users with `manage_options`, POSTs to
  `https://<host>:<challenge_port>/challenge/admin-token` with
  the secret.
- Stores the returned cookie via PHP `setcookie()` with the same
  Domain / Path / Secure / HttpOnly / SameSite attributes CSM
  uses.

### Acceptance criteria (this repo)

- The `/challenge/admin-token` endpoint is documented as a stable
  contract; breaking changes require a roadmap item.
- A short integration note in `docs/src/challenge.md` points
  operators at the plugin repo.

### Out of scope

- The plugin code itself (separate repo, separate release cycle).
- Joomla / Drupal / Magento equivalents (parallel work, not blocked
  by this).

### Estimated size

0.5 engineering days for the contract documentation in this repo;
the plugin itself is ~2 days in the separate repo.

---

## 5. Per-account scanner mtime fairness and scan-cap hygiene

**Status:** planned
**Drives / unblocks:** detection equity on busy multi-tenant hosts;
removes the same bug class the May 2026 `domlog_max_files` fix closed
for WP brute-force from the rest of the scanner surface.

### Why

The May 2026 `scanDomlogs` fix landed three commits (`b30b9a25`,
`e4150436`, `c0cda5e4`) closing a class of bug where
`filepath.Glob` returned lexical order, a downstream cap or
`check_timeout` cut the iteration short, and late-alphabet vhosts
escaped detection. Several other scanners in `internal/checks/` use
the same pattern (`/home/*/...` glob, no mtime ranking, no
explicit cap, sometimes no `ctx.Err()` gate inside the loop), so the
same primitive applies: pick an account name that sorts late, evade
the scanner under load.

Adjacent hygiene gaps surfaced during the audit are bundled here so
they ride the same release rather than landing one at a time.

### Decision

Six discrete sub-items, each a separate commit so a regression can
be reverted in isolation.

1. **Per-account scanner fairness (`5.1`).** Apply the `scanDomlogs`
   recipe (mtime-desc sort + `ctx.Err()` gate inside the per-match
   loop + explicit cap) to:
   - `internal/checks/auth.go` (SSH `authorized_keys` glob, cPanel
     API token glob).
   - `internal/checks/emailpasswd.go` (Dovecot shadow glob).
   - `internal/checks/dbscan_magento.go`,
     `dbscan_joomla.go`, `dbscan_drupal.go`,
     `dbscan_opencart.go` (CMS config globs).
   Bound iteration with a new `thresholds.account_scan_max_files`
   (default high enough that typical hosts hit no cap, capped at the
   same 100000 ceiling as `domlog_max_files`).
   Add late-alphabet equity tests that prove a late-sorted account
   under load still produces a finding.

2. **Consolidate `scanDomlogs` and `scanDomlogsStats` (`5.2`).** The
   two functions in `bruteforce.go` duplicate ~85 lines of
   discovery+dedup+stale-filter+mtime-sort+cap. Extract one
   `discoverFreshDomlogs(ctx, cfg)` helper; rebuild both callers as
   thin wrappers over it. Parity test pins identical file selection
   under fixed fixtures.

3. **Promote `domlogTailLines` to config (`5.3`).** Hardcoded `500`
   in `bruteforce.go:26`. Move to
   `thresholds.domlog_tail_lines` with the same plumbing pattern as
   `domlog_max_files` (default 500, validate range, default config,
   installer, production example, docs, webui schema).

4. **Webshell-scan truncation visibility (`5.4`).**
   `internal/daemon/webshell_content.go:26` silently truncates input
   at 64 KiB. Add `csm_webshell_truncated_total` counter and a
   Warning finding when truncation actually drops content the scanner
   would otherwise see. If real-world payloads cluster above 64 KiB,
   raise the cap; the visibility is the prerequisite for that data.

5. **Log `EvalSymlinks` silent drops (`5.5`).** `bruteforce.go:238`
   and `scanDomlogsStats` discard files whose `filepath.EvalSymlinks`
   fails. Same class as the original lex-order bug: silently dropped
   inputs hide detection gaps. Add a debug counter
   `csm_domlog_evalsymlinks_dropped_total{reason}` so operators can
   correlate a sudden drop in scanned-domlog count with an unrelated
   permissions or symlink-loop change.

6. **Audit `crontabBase64BlobMaxBytes` cap (`5.6`).** Current cap is
   8192 bytes in `crontabs.go:120`. Confirm by sampling production
   that no realistic suspicious crontab payload exceeds it, otherwise
   raise or make configurable. Low priority but cheap.

### Acceptance criteria

- For each sub-item: a TDD-style test demonstrating the bug pre-fix
  (late-alphabet account misses; truncation hides indicator;
  silent symlink drop unaccounted), then the code change, then the
  CHANGELOG entry and any operator docs in the same commit.
- No behaviour change for hosts under the bounds; only changes
  what happens at the boundary.
- `make ci` clean; no new `gosec` findings.

### Out of scope

- Rewriting any scanner to walk asynchronously per-account
  (would change the daemon's execution model; separate roadmap item
  if measurement shows it needed).
- Changing default cap values that already match production load.
- Backport to v3.6.x: ships in next minor only.

### Estimated size

2-3 engineering days for the six commits plus reviews.

---

## 6. Second-pass scanner audit follow-ups

**Status:** planned
**Drives / unblocks:** the same fairness, telemetry, and silent-error
hygiene roadmap item 5 closed, applied to the scanners item 5 did not
reach. A second audit pass against the same bug classes turned up nine
real-world instances.

### Why

The item 5 audit was scoped to the scanners that the May 2026
`scanDomlogs` fix made obvious peers. A follow-up grep against the
same bug-class patterns (lex-order globs, silent EvalSymlinks/Stat
drops, hardcoded scan windows, hardcoded byte caps inside content
checks) turned up more callers that share the same primitive. Closing
them is mechanical now that the helpers exist.

### Decision

Nine discrete sub-items. Each a separate commit so a regression can
be reverted in isolation.

1. **`CheckDatabaseObjects` mtime fairness (`6.1`).** `db_objects.go`
   iterates `/home/*/public_html/wp-config.php` in lex order. Already
   has `ctx.Err()` per iteration but no mtime rank. Same primitive
   as 5.1.

2. **`CheckForwarders` ctx + mtime fairness (`6.2`).** `forwarder.go`
   iterates `/etc/valiases/*` and `/etc/vfilters/*` per mail domain.
   No `ctx.Err()` inside either loop, no mtime rank. Hosts with many
   mail domains hit this on every scan cycle.

3. **`CheckFilesystem` mtime fairness (`6.3`).** `filesystem.go`
   iterates `/home/*/.config/*/*` for backdoor binaries with a
   per-pattern ctx check but no per-match one and no mtime rank.

4. **`CheckCrontabs` honour ctx + mtime fairness (`6.4`).**
   `crontabs.go` accepts `ctx` and ignores it. Per-user
   `/var/spool/cron/*` iter is unbounded. On hosts with many cron
   users a stuck `MatchCrontabPatternsDeep` could starve the cycle.

5. **`looksLikePHPWebshell` inner 64 KiB cap consistency (`6.5`).**
   The function still trims its own input to 64 KiB even after the
   upstream metering work in 5.4 covered the actual fd reads. If a
   future caller passes a larger buffer the inner trim silently
   truncates without any signal. Either remove the inner trim and
   let the caller own the cap, or wire the same
   `csm_realtime_content_scan_truncated_total` counter through it.

6. **`fanotify.go` other read sites get truncation metric (`6.6`).**
   `checkHtaccess` (16 KiB), `checkUserINI` (4 KiB), and
   `checkCrontab` (64 KiB) read from the event fd without
   `recordReadTruncation`. Files are usually small, but the same
   telemetry rationale that drove 5.4 applies.

7. **`validateReleaseSpoolDir` EvalSymlinks fallback hardening
   (`6.7`).** `emailav/quarantine.go` falls back to the cleaned
   (unresolved) path when `filepath.EvalSymlinks` errors on either
   the input or an allowed entry. Different shape from 5.5 but the
   same "silent error -> unsafe default" smell: a path containment
   check that does not verify the real on-disk identity is doing
   defence in name only. Decide: fail-closed on resolve errors, or
   document the operator-side preconditions.

8. **`domlogMaxAge` operator-tunable (`6.8`).** `bruteforce.go`
   hardcodes 30 min as the freshness cutoff. Same class as 5.3 (a
   scan window an operator might legitimately need to widen on
   low-traffic hosts so a slow-burn dictionary attack still falls
   inside the window).

9. **Targeted `tailFile` scan windows operator-tunable (`6.9`).**
   Most `tailFile(path, N)` sites in `internal/checks/` are
   one-shot polling helpers where the hardcoded N is fine. Two
   stand out as worth tuning: `mailrate.go`'s 500-line Exim window
   on busy mail hosts, and `bruteforce.go`'s 200-line
   `/var/log/messages` window on hosts that share that log with
   noisy services. Add config knobs only for those two.

### Acceptance criteria

- Each sub-item: TDD where applicable (the helper-style and
  metering work was test-driven in item 5; mirror the pattern).
- No behaviour change at the defaults; only changes what happens
  at the boundary or under load.
- `make ci` clean; no new `gosec` findings.

### Out of scope

- Reworking the global check-runner timeout model.
- Per-account asynchronous walks.
- Changing the upstream fd read sizes; the metering work proves
  whether that is needed first.

### Estimated size

2-3 engineering days for the nine commits plus reviews.

---

## 7. CSM CPU hot-spot cleanup

**Status:** planned
**Drives / unblocks:** the steady-state CPU footprint operators
observed on cluster6 (CSM at 70-80% of one core within a minute of
start, dominated by JSON round-trips and serial network queries).

### Why

A live audit of cluster6 turned up four concrete hot spots:

1. `internal/firewall/engine.go` `loadStateFile()` and `saveState()`
   read and rewrite the entire 325 KiB `state.json` (975+ entries) on
   every single-IP operation. `IsBlocked` also runs a linear scan on
   each call. `strace` recorded 725 opens of `firewall/state.json`
   over a 10-second window (~72 ops/s).
2. `CheckIPReputation` averages 3.6 s per run because the five
   AbuseIPDB lookups per cycle run serially.
3. Go runtime emits a tight loop of `epoll_ctl EPERM` (693 calls in
   5 seconds, all failing) -- some caller is handing the netpoller
   a non-pollable fd. Producer not yet pinpointed.
4. Many short-lived child processes (libc/libpthread/librt loads
   followed by exit) suggest repeated `os/exec.Command` for the same
   tool. Pooling or replacing one or two of the heaviest calls would
   help.

### Decision

Four discrete sub-items, each a separate commit.

1. **`7.1` Firewall in-memory cache + map-indexed reads.** Keep the
   parsed `FirewallState` in memory under `e.mu`, invalidate on
   mtime change, expose `IsBlocked` via a `map[string]struct{}` for
   O(1) lookup. Mutators still go through `saveState` synchronously
   so crash semantics are unchanged; the win comes from killing the
   per-call 325 KiB read + parse + linear scan.
2. **`7.2` Parallel AbuseIPDB queries.** Replace the sequential loop
   in `CheckIPReputation` with a small worker pool. Five queries fan
   out at once; per-cycle wall clock drops from ~3.6 s to
   ~max(single-call latency).
3. **`7.3` Trace and fix the `epoll_ctl EPERM` producer.**
   Investigate which code path passes a regular-file fd (or other
   non-pollable type) to a Go I/O primitive that registers it with
   the netpoller. Fix the producer; the EPERM stops.
4. **`7.4` Subprocess churn.** Identify the dominant short-lived
   subprocess and either cache its output for the typical cycle or
   replace the shell-out with an in-process equivalent.

### Acceptance criteria

- After each sub-item: re-measure on cluster6, confirm the targeted
  syscall pattern shrinks (state.json open rate, AbuseIPDB wall
  clock, EPERM rate, fork rate).
- No behaviour change: same blocked-IP set, same findings, same
  alerts. The fix targets cost, not semantics.
- `make ci` clean, including the race detector and `gosec`.

### Out of scope

- Replacing the JSON file with bbolt for firewall state (a separate
  larger migration; the cache + indexing closes the immediate CPU
  cost without rewriting the storage layer).
- Async batched persistence (defer until cache benchmarks show the
  synchronous write is the next bottleneck).

### Estimated size

2-3 engineering days for the four commits plus reviews.
