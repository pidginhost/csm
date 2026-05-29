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

## 1. Signed YARA Forge mirror automation

**Status:** planned. Detection lag risk: operators cannot enable
`signatures.yara_forge.enabled` without a CSM-signed `.sig` next to
each Forge ZIP, and YARAHQ does not publish `.sig` files.

### Decision

Operate a small mirror job. Pulls latest `YARAHQ/yara-forge` release,
downloads `core` / `extended` / `full` ZIPs, signs raw bytes with the
CSM Ed25519 rule-signing key, publishes ZIP + `<zip>.sig` + checksum
under a stable HTTPS path compatible with
`signatures.yara_forge.download_url` and the `{tier}` / `{version}`
placeholders. Retain N older releases for rollback. Operator example
enables Forge through `/etc/csm/conf.d/` without editing the main
`csm.yaml`.

### Acceptance

- Mirror run publishes latest Forge ZIPs, `.sig`, checksums.
- A CSM instance configured at the mirror URL records the installed
  Forge version.
- Missing / corrupt / mismatched signature fails closed.

### Size: 0.5-1 day.

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

**Status:** specced 2026-05-29. The v5 audit closed the immediate code
fixes; these eight are the remaining larger detection and integration
items, each with a design doc under `docs/superpowers/specs/`. Intended to
be implemented one per session. Items marked DECISION carry open
data-source / protocol / privacy / sequencing choices that must be
resolved before implementation (captured in each spec's "Open decisions").

Self-contained (no external dependency):

- **Y11 -- spray ingests HTTP-flood / UA-spoof.** Add the HTTP checks to
  the spray default set plus a request-target identity dimension.
  `2026-05-29-y11-spray-http-signals-design.md`.
- **Y15 -- mail_logs source re-pick.** FileReader missing-file callback ->
  finding + unhealthy watcher (+ optional live journal re-pick).
  `2026-05-29-y15-maillog-source-repick-design.md`.
- **Y16 -- OpenAPI spec for `/api/v1/*`.** Hand-authored spec + drift test.
  `2026-05-29-y16-openapi-spec-design.md`.

Decision required:

- **Y9 -- supply-chain CVE scanning.** DECISION: advisory data source
  (bundled/synced vs online OSV). `2026-05-29-y9-supply-chain-cve-design.md`.
- **Y10 -- credential-stuffing detection.** DECISION: behavioral
  (login-stream) vs at-rest hash reuse (system / WP). Privacy-sensitive.
  `2026-05-29-y10-credential-stuffing-design.md`.
- **Y12 -- cross-server / fleet ingest.** DECISION: phpanel-side
  correlation vs peer-to-peer ingest endpoint + trust model.
  `2026-05-29-y12-fleet-ingest-design.md`.
- **Y13 -- ASN/CIDR crawler-CDN whitelist.** DECISION: range data source
  (bundled table vs MaxMind ASN vs rDNS-only).
  `2026-05-29-y13-asn-crawler-whitelist-design.md`.
- **Y14 -- chained-attack correlator (uid0 + suid + bad_asn_outbound).**
  DECISION: bad-ASN model and chain threshold; blocked on Y13; needs a new
  `bad_asn_outbound` detector.
  `2026-05-29-y14-chained-attack-correlator-design.md`.
