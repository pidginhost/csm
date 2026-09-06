# CSM Engineering Roadmap

Open engineering work and release acceptance checks. Implemented items below
retain a short status while their operational follow-up is still useful.
Commits and `CHANGELOG.md` remain the archive of completed changes.

This file is for contributors. End-user documentation lives in `docs/`.

**Stable cross-references.** Older commits, CHANGELOG entries, and a
few code comments reference `ROADMAP item N` by the number that item
had when the commit was written. Those numbers are frozen in time and
no longer map onto the current list. To resolve a historical
`ROADMAP item N`, search `git log` and `CHANGELOG.md` rather than this
file.

---

## Release readiness gates

The required dependencies are defined in [.gitlab-ci.yml](.gitlab-ci.yml).
A checked item means the control is implemented, not that a release pipeline
has passed it on the current infrastructure.

- [x] Version tags require signed amd64 and arm64 binaries and packages.
  The arm64 build and package jobs allow failure on branches, but not tags.
- [x] Publication requires the fixture privacy, pinned clean-application,
  production-tag and real-kernel jobs. Missing inputs or required kernel
  capabilities cannot be replaced by skipped tests.
- [x] Tag preflight requires a cPanel image before server allocation. Tag
  publication requires integration using the current pipeline packages,
  including cPanel installation, upgrade and service checks.
- [x] Public GitHub release creation requires merged integration coverage,
  assets and signature preflight validation.
- [ ] Provision and maintain a licensed clean cPanel image, set the protected
  `INTEGRATION_CPANEL_IMAGE` variable, and pass the live upgrade and forward
  guard checks. See [cPanel acceptance](docs/src/cpanel-release-tests.md).
- [ ] Provision the dedicated `csm-kernel` runner and pass every required
  attachment test, including BPF LSM, under the real service sandbox. See
  [kernel runner acceptance](docs/src/production-tests.md#kernel-runner).

As of 2026-09-06, local production-tag race tests and the four pinned corpus
gates passed. The EL8 production test image passed all 12 kernel tests on
LinuxKit 7.0.12, including BPF LSM attachment, and the strict systemd sandbox
checks. GitLab accepted the configuration and main/tag pipeline dry runs.
The licensed cPanel run and dedicated CI kernel runner remain operational gaps;
local evidence does not establish that the required CI jobs have executed.
Main-branch cloud integration is manual and is not a publication dependency;
it can run AlmaLinux/Ubuntu only when no cPanel image is configured.

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
landing; their commits and CHANGELOG entries are the archive. These two
larger detection and integration items remain:

- **Y11 -- spray ingests HTTP-flood / UA-spoof.** Add the HTTP checks to
  the spray default set plus a request-target identity dimension.
  `2026-05-29-y11-spray-http-signals-design.md`.
- **Y12 -- cross-server / fleet ingest.** DECISION: phpanel-side
  correlation vs peer-to-peer ingest endpoint + trust model.
  `2026-05-29-y12-fleet-ingest-design.md`.

Y15 mail source supervision is implemented in
[mail_reader.go](internal/daemon/mail_reader.go): initial attachment failures
retry, source loss and recovery update watcher health, and automatic selection
can switch from a missing file to journal input. Explicit modes stay fixed;
retries use current configuration and shutdown joins the readers. File and
real-systemd journal regressions cover recovery. The remaining release proof
is the live cPanel run above; copytruncate's polling limit is documented in
[mail monitoring](docs/src/detection-realtime.md#inotify-log-watchers-2-seconds).

---

## 11. Coalesce firewall interval sets before apply

**Status:** implemented.

Infrastructure, blocked subnet, country, Cloudflare, and DoS exemption sets
coalesce overlapping and adjacent IPv4/IPv6 intervals before applying them.
Full-space and upper-bound intervals keep their intended coverage. Subnet
removal and expiry rebuild the union from the remaining source entries in
one kernel transaction.

Constructor and apply failures get bounded startup retries, retained status
diagnostics, and degraded aggregate health. `csm doctor` reports the cause
and the restart needed after correcting the problem.

The `nftkernel` regression suite reproduces the original rejection in isolated
Linux network namespaces and verifies apply, reload, removal, expiry, and
failed-transaction recovery. See `docs/src/development.md` for the command.

---

## 12. Rule corpus false-positive gates in CI

**Status:** implemented. Every pipeline provisions checksum-pinned public
WordPress, WooCommerce and Elementor archives and runs all four engine gates
in the production YARA-X builder image. Missing inputs and regressions block
publication. Corpus inventories, versions and per-rule budgets are retained
as CI artifacts. See [the corpus gate documentation](docs/src/clean-corpus.md)
for measured coverage and known gaps.

Corpus growth and detector false-positive reductions remain ongoing work.

## 13. Narrow the service unit's write scope

**Status:** implemented; live cPanel acceptance remains open.

The packaged and installed units grant specific managed configuration
directories instead of all of `/etc`. Exim mutations run through a serialized
helper outside the daemon sandbox, including rebuild and rollback. Opted-in
module removal uses a separate transient service.

Real-systemd tests verify denied unrelated writes, permitted atomic updates,
helper rejection and rollback, account-root remediation, and restore.
The remaining check is the actual cPanel rebuild under the candidate package;
see [service write scope](docs/src/service-confinement.md) and the release
acceptance list above.

---

## 14. Verify mailbox passwords without exposing material in argv

**Status:** implemented.

[In-process verification](internal/checks/email_password_hash.go) replaces the
password-tool subprocess. Supported hash formats have explicit work limits,
concurrency is bounded, and unsupported or over-budget hashes leave the scan
incomplete and eligible for retry. Dependencies are pinned in `go.mod`.
Regression fixtures include upstream Dovecot vectors; a live Dovecot binary
was not part of local validation. Further interoperability coverage should
compare supported formats on the cPanel image without placing secrets in
process arguments.

---

## 15. Realtime coverage for files renamed into a watched tree

**Status:** atomic-save coverage implemented; rename-only arrivals remain open.

Creation and close-write events scan atomic-stage names and retain the event
file descriptor through analysis, including after rename, replacement or
unlink. The completed content reaches normal scanners without requiring a
rename event. See [realtime coverage](docs/src/detection-realtime.md).

A file moved into an eligible path without a usable create or close-write
event is a separate case. The current watcher does not subscribe to rename
notifications, so the rolling content scan remains its coverage path.

### Remaining acceptance

Probe directory/name event and file-handle support at runtime before adding
rename-only coverage. Test arrival from outside the watched scope, same-tree
moves, lost events, and unsupported kernels. Retain the rolling scan fallback
on enterprise kernels that lack the required notification support; raising
the supported platform floor is not required for the existing atomic-save fix.

---

## 16. CMS discovery deeper than one directory below a document root

**Status:** WordPress discovery limits documented; broader discovery planned.

WordPress merges the panel's document-root map with the account-home patterns
in [wpinstalls.go](internal/checks/wpinstalls.go). A deeply nested root declared
by the panel can be found; an undeclared installation outside those bounded
patterns can be missed. The supported layout is described in
[deep check platform support](docs/src/detection-deep.md#platform-support).
Other CMS adapters use their own configuration patterns in `cmsDiscover` and
do not inherit the WordPress panel-map traversal.

### Remaining acceptance

Decide the supported depth and cost budget for each CMS before expanding the
walk. Test nested mapped and unmapped installs, custom account roots, tenant
ownership, symlinks, cancellation and incomplete traversal. Document each
adapter's limits alongside the resulting coverage.

---

## 17. Consolidate bootstrap toolchain pins

**Status:** partially complete; image pin consolidation remains planned.

`go.mod` requires Go 1.26.7. CI sets `GOTOOLCHAIN=auto` so the Go command can
select that version even though the CI tools image starts with Go 1.26.3 and
the AlmaLinux YARA-X builder starts with Go 1.26.2. The Linux test wrapper
already derives its exact default image version from `go.mod`. The builder
uses AlmaLinux 8, not an Alpine Go base. Lint is pinned to golangci-lint 2.11.4;
formatting and canonical lint pass with Go 1.26.7.

### Remaining acceptance

Generate bootstrap version inputs from one maintained source and check them
for drift. Rebuild both architecture builders and the CI tools image, update
their tags, then record the selected Go and linter build versions in CI.
Verify both release architectures and formatter compatibility before changing
the module requirement. The current automatic toolchain selection requires
access to the toolchain download when it is absent from cache.

---

## 18. Measure lint timeout headroom

**Status:** five-minute limit configured; cold-runner measurement remains open.

`.golangci.yml`, `make lint`, the default CI lint job and production-tag lint
all use five minutes. Local canonical lint currently passes. Earlier package
loading timeouts are historical observations, not a current failing result.

### Remaining acceptance

Record package-loading and total lint time on cold caches with two concurrent
pipelines on the intended runner. Retain timings and exit statuses, then tune
runner resources or the timeout if the result leaves insufficient margin.
A timeout or typechecking failure cannot be reported as clean merely because
the tool also prints zero issues.
