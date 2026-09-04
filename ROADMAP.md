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

---

## 11. Coalesce firewall interval sets before apply

**Status:** planned. Highest-severity item currently open.

nftables interval sets reject overlapping elements. Blocked-subnet,
infra-IP and country sets are built straight from configured and
feed-supplied CIDRs, so a single pair where one range contains another
makes the whole set, and therefore the entire ruleset apply, fail.

The failure is silent in the worst way: the daemon continues without a
firewall engine, so automatic blocking stops and no finding is raised to
say the host is now unprotected.

### Decision

- Coalesce and de-overlap every CIDR list before building interval
  elements.
- A range that still cannot be represented is dropped individually, with
  a finding naming it, instead of failing the apply.
- An apply that fails for any reason raises a Critical finding. A host
  without a firewall engine must never look healthy.

### Prerequisite

Reproduce the kernel-side rejection in a container first: the coalescing
rules are only correct if they match what nftables actually refuses.

### Size: 3-4 hours, half of it the reproduction.

---

## 12. Rule corpus false-positive gates in CI

**Status:** planned. The gates exist and are skipped.

The signature and YARA false-positive gates need a corpus of known-clean
web application code. No such corpus is published with the repository, so
CI skips both gates and a rule change can only be measured locally.

### Decision

Publish a hash-pinned clean corpus as a CI artifact and make both gates
required. Pinning matters more than size: a corpus that drifts turns a
real regression into noise and a passing gate into a coin toss.

Open questions for whoever picks this up: where the corpus is hosted, how
its licence permits redistribution, and how often it is refreshed.

### Out of scope

Growing the corpus beyond what is needed to exercise the current rule
families.

### Size: 1 hour to write the proposal, half a day to implement once the
hosting decision is made.

---

## 13. Narrow the service unit's write scope

**Status:** planned.

The unit grants write access to the whole of `/etc` so that one mail
configuration fragment can be updated. Everything else the daemon writes
is already scoped.

### Decision

Write that one fragment through a transient unit with its own narrow
grant, and replace the blanket grant with the specific directories the
daemon genuinely writes.

### Size: 2-3 hours. Needs a Linux host to verify the transient unit
behaves under the packaged unit's sandbox.

---

## 14. Verify mailbox passwords without exposing material in argv

**Status:** planned.

The weak-password audit shells out to the mail server's password tool,
which places the hash and the candidate on the command line, where any
local process listing can read them while the check runs.

### Decision

Verify in-process. This means taking on a crypt implementation that
covers the hash formats the mail server emits, which is a new dependency
in a security product and should be reviewed as one: pinned, vendored
deliberately, and chosen for maintenance record over convenience.

### Size: 2-3 hours plus dependency review.

---

## 15. Realtime coverage for files renamed into a watched tree

**Status:** blocked on kernel support, not on design.

A file moved into a watched directory raises no content event, so it is
first examined by the next rolling content scan rather than on arrival.

Closing this needs rename events with directory-and-name reporting from
fanotify. Enterprise Linux 8 kernels backport the filesystem-scoped mark
but not the rename event or file-handle reporting, so the capability is
absent on the oldest platform CSM supports.

### Decision

Revisit when the supported platform floor rises. Until then the rolling
content scan is the documented coverage path, and any implementation must
probe for the capability at runtime and fall back rather than assume it.

### Size: unknown until the floor moves.

---

## 16. CMS discovery deeper than one directory below a document root

**Status:** planned, deliberately deferred once.

Discovery covers document roots the panel serves, addon directories in an
account home, and one directory below a document root. Installs nested
more deeply are found by neither the panel map nor the walk.

### Decision

Decide whether deeper nesting is worth the walk cost before implementing
it. The honest options are a bounded depth increase, or leaving it and
saying so in the documentation. What must not happen is the current
situation where the limit is real but undocumented.

### Size: 15 minutes to document the limit; a day to raise it safely.

---

## 17. Consolidate the Go toolchain pin and upgrade

**Status:** planned.

The Go version is pinned in four places -- the module file, the CI image,
the builder image, and the Alpine base -- and they have drifted apart.
Local development on a newer toolchain also produces formatting that the
CI linter does not expect.

### Decision

Reduce the four pins to a single source, then move that source forward.
Check first that the pinned linter release supports the target toolchain:
if it lags, the upgrade breaks CI on the first push.

### Size: 30 minutes for the compatibility check, 2-3 hours if it passes.

---

## 18. Lint timeout headroom in CI

**Status:** planned. Small, and it costs a release when it bites.

The lint job spends its whole budget loading packages before linting
anything, and now exceeds it when two pipelines run concurrently -- which
is exactly what pushing a branch and a tag together causes. The job fails
without having examined a single file, and every later stage is skipped.

### Decision

Raise the timeout enough to leave headroom on a cold cache under load.

### Size: 10 minutes.

