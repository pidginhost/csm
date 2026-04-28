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

---

## 1. Detection-cleaning rounding for non-WordPress workloads

**Status:** planned
**Drives / unblocks:** Imunify360 feature parity for hosts running
multi-CMS workloads
**Design:** `docs/superpowers/specs/2026-04-26-detection-cleaning-rounding-design.md`

### Why

CSM's database scanning and surgical cleaning are WordPress-only
today. `internal/checks/dbscan.go` is hardcoded to `wp-config.php`,
so Joomla / Drupal / Magento / OpenCart accounts get no DB-content
visibility. WordPress multisite (`wp_N_options`) is also invisible.
MySQL persistence vectors -- triggers, events, stored procedures,
stored functions -- are never inspected. `.htaccess` cleaning is
shallow. A signature update only catches files that change after
the update, not the existing fleet. And there is no operator-facing
cleanup history or one-click rollback even though backups are
already being written.

### Decision

Six gaps closed in one release:

1. Multi-CMS database scanning (Joomla, Drupal 7+8/9/10, Magento 1+2,
   OpenCart) via per-CMS adapters under `internal/checks/cms/`.
2. WordPress multisite (`wp_N_options`, `wp_N_posts` patterns).
3. MySQL persistence-mechanism scanning via INFORMATION_SCHEMA
   queries -- triggers, events, stored procedures, functions.
4. `.htaccess` hardened cleaning: registry of seven malicious
   directive patterns with surgical removal.
5. Signature-update-driven retroactive sweep -- when YAML or YARA
   rules update, sweep `/home/*/public_html` against the new rules.
6. Cleanup history UI and rollback in the web UI, backed by the
   existing per-action backup files.

### Out of scope

- JavaScript file cleaning (covered by detection but cleaning is
  a follow-up release).
- PostgreSQL / SQLite database support.
- Automatic dropping of malicious DB objects.

### Estimated size

5-7 engineering days (impl plan ready in the design doc).

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

