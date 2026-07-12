# CSM Engineering Roadmap

Forward-looking engineering decisions that are committed to but not yet
implemented. Items move from here into commits + `CHANGELOG.md` entries
as they land, then drop off this list (git history + CHANGELOG are the
archive).

This file is for contributors. End-user documentation lives in `docs/`.

**Stable cross-references.** Older commits, CHANGELOG entries, and a
few code comments reference `ROADMAP item N` by the number that item
had when the commit was written. Those numbers are frozen in time and
no longer map onto the current list. To resolve a historical
`ROADMAP item N`, search `git log` and `CHANGELOG.md` rather than this
file.

---

## Release readiness gates

These are release controls, not forward-looking feature work:

- [x] Tag builds require signed amd64 and arm64 binaries and packages.
- [x] Integration coverage must merge into the published coverage profile.
- [x] Tag integration requires a clean cPanel image, verifies cPanel is
  installed, installs the current pipeline package, and runs the integration
  binary.
- [x] Public release creation is blocked until assets, signatures, and coverage
  pass preflight validation.
- [ ] Provision and maintain the clean cPanel image referenced by the
  `INTEGRATION_CPANEL_IMAGE` CI variable.

---

## 2. `csm support-bundle` command

**Status:** planned. Triage workflow: operators today grep journal +
copy `state.json` by hand.

### Decision

New CLI `csm support-bundle <path>` produces a tar+zstd containing:
- `csm store export` output (manifest, bbolt snapshot, state, rules
  cache).
- Last N (default 2000) `journalctl -u csm` lines.
- `/etc/csm/csm.yaml` with secrets redacted (`smtp`, `webhook.url`,
  `abuseipdb_key`, `webui.auth_token`,
  `verified_session.admin_secret`, `captcha_fallback.secret_key`,
  plus whitelist-style redaction of any unknown `*_key` / `*_token`
  / `*_secret`).
- `system.txt` with `uname -a`, `csm version`, distro info, startup
  integrity hashes.

Live daemon required (mirrors `store export`).

### Out of scope

Auto-upload, encryption at rest (pipe through gpg).

### Size: 1 day.

---

## 3. Scheduled backup exports

**Status:** planned. `csm store export` needs an operator-managed
cron entry today.

### Decision

Top-level config block, hot-reloadable:

```yaml
backup:
  enabled: true
  schedule: "@daily"            # cron spec or @hourly|@daily|@weekly
  destination_dir: /var/backups/csm
  filename: "csm-{date}.csmbak"
  retention_days: 14
```

Daemon ticks schedule, calls `store.Export`, prunes archives older
than `retention_days`. Failures emit `backup_export_failed` Warning.

### Out of scope

Off-host destinations (S3 / SFTP). Encryption.

### Size: 1-2 days.

---

## 4. WordPress companion plugin for signed-cookie operator bypass

**Status:** planned. Closes UX gap on `/challenge/admin-token`: a
logged-in WP admin currently has no way to obtain the cookie without
manual curl.

### Decision

Plugin lives in separate repo (`pidginhost/csm-wp-bypass`). This
repo only:

- Documents `/challenge/admin-token` as a stable contract (breaking
  changes require a roadmap item).
- Adds a short integration note in `docs/src/challenge.md` linking
  the plugin repo.

Plugin behaviour (separate repo): reads `CSM_ADMIN_SECRET` from
`wp-config.php`, on `wp_login` for `manage_options` users POSTs to
the endpoint and sets the returned cookie.

### Size: 0.5 day (this repo); plugin itself ~2 days separately.

---

## 9. Firewall state migration to bbolt

**Status:** planned. Item 7.1 cache landed (commit 48cc718a) and
killed the per-call 325 KiB read + parse + linear scan. Next
bottleneck: every mutator still rewrites the full `state.json` on
disk (fsync amplification + crash window between mutators).

### Decision

Move firewall state out of `state.json` into bbolt:

- Bucket `fw:blocked` keyed by IP, value `{added, expires, reason,
  source}` JSON or msgpack.
- Bucket `fw:allow_*`, `fw:port_*` parallel.
- Mutators wrap `bolt.Update`; readers use `bolt.View`. The 7.1
  in-memory cache stays as the hot-path index, invalidated by the
  same mtime/sequence number scheme.
- `csm store export` already snapshots bbolt; firewall state rides
  along for free.

Migration: one-shot importer in `csm firewall migrate-state` reads
existing `state.json`, writes bbolt buckets, renames the JSON to
`state.json.migrated-<timestamp>` for rollback.

### Out of scope

Replacing the in-memory cache (item 7.1 result stands).

### Size: 2-3 days.

---

## 10. Security audit v5 feature backlog

**Status:** partially implemented. Completed items were removed after
landing; their commits and CHANGELOG entries are the archive. These three
larger detection and integration items remain:

- **Y11 -- spray ingests HTTP-flood / UA-spoof.** Add the HTTP checks to
  the spray default set plus a request-target identity dimension.
  `2026-05-29-y11-spray-http-signals-design.md`.
- **Y15 -- mail_logs source re-pick.** FileReader missing-file callback ->
  finding + unhealthy watcher (+ optional live journal re-pick).
  `2026-05-29-y15-maillog-source-repick-design.md`.
- **Y12 -- cross-server / fleet ingest.** DECISION: phpanel-side
  correlation vs peer-to-peer ingest endpoint + trust model.
  `2026-05-29-y12-fleet-ingest-design.md`.
