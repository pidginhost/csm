# CSM Engineering Roadmap

Open engineering work and release acceptance checks, ordered so a contributor
can pick the top item and start. Completed work is removed from this file:
commits and `CHANGELOG.md` are the archive.

This file is for contributors. End-user documentation lives in `docs/`.

**Stable cross-references.** Older commits, CHANGELOG entries, and a few code
comments reference `ROADMAP item N` by the number that item had when the commit
was written. Those numbers are frozen in time and no longer map onto this list.
To resolve a historical `ROADMAP item N`, search `git log` and `CHANGELOG.md`
rather than this file. Items below are named, not numbered, for that reason.

---

## Release readiness gates

Required dependencies are defined in [.gitlab-ci.yml](.gitlab-ci.yml). A checked
item means the control is implemented and has passed on the current
infrastructure.

- [x] Version tags require signed amd64 and arm64 binaries and packages. The
  arm64 build and package jobs allow failure on branches, but not tags.
- [x] Publication requires the fixture privacy, pinned clean-application,
  production-tag and real-kernel jobs. Missing inputs or required kernel
  capabilities cannot be replaced by skipped tests.
- [x] Public GitHub release creation requires merged integration coverage,
  assets and signature preflight validation.
- [x] A dedicated kernel runner executes the required attachment tests,
  including BPF LSM, under the real service sandbox. See
  [kernel runner acceptance](docs/src/production-tests.md#kernel-runner).
- [x] Cloud integration installs the pipeline's own packages on freshly
  allocated servers and deletes them afterwards.
- [ ] Provision and maintain a licensed clean cPanel image, set the protected
  `INTEGRATION_CPANEL_IMAGE` variable, and pass the live upgrade and forward
  guard checks. See [cPanel acceptance](docs/src/cpanel-release-tests.md).
  **Blocked:** no cPanel licence is available for disposable CI clones, and the
  cloud image catalogue offers no cPanel image. Until then a tag must set
  `CSM_RELEASE_WITHOUT_CPANEL` with a stated reason, and its release evidence
  records `cpanel_coverage: "absent"`.

  Three shipped subsystems have completed every acceptance except this one, so
  closing the gate is all that remains for them: the narrowed service write
  scope (real-systemd tests cover denied writes, atomic updates, helper
  rejection and rollback, but not a live panel rebuild under the candidate
  package), mailbox password verification (upstream vectors are covered, a live
  Dovecot binary is not), and mail source supervision (file and journal
  recovery are covered).

### CI kernel coverage does not reach the deployed kernel

No available runner image reproduces the production kernel. Supported hosts run
CloudLinux 8 and EL8 on 4.18, while the cloud image catalogue offers AlmaLinux 9
and 10, Ubuntu and Debian only. A passing kernel job therefore establishes that
a feature works on a newer kernel, never that it works on the deployed one:
4.18 provides `pidfd_send_signal` but not `pidfd_open`, and a 5.14 or newer
runner cannot show that difference.

Capabilities the daemon depends on are consequently probed at runtime and
reported through `csm doctor` and the health status. **A kernel-capability
regression is expected to surface there, not in CI.** Treat any new dependency
on a kernel facility as requiring a runtime probe and a doctor check, not only
a kernel test.

Main-branch cloud integration is manual and is not a publication dependency.

---

# Priority 1 -- detection precision

These block growing the clean-application corpus, which is the only automated
evidence that a rule or analyzer does not fire on stock software. Each is a
real defect found by extending the corpus; none should be closed by raising a
threshold or excluding a path.

Verified pinned sources for Joomla, Drupal and OpenCart are ready to add to
`scripts/clean-corpus/manifest.json` (URL, SHA-256, exact file count and
in-archive licence path). Adding them today turns the gate red on the two
analyzer items below, so land the fixes first, then the sources and the
recalibrated status budgets in one commit.

## Taint laundering through value encoders

**Status:** open. One false positive on stock Joomla.

Every template-compiling CMS reads a file, writes generated PHP to a cache and
includes it. Joomla writes `"<?php ... return " . var_export($strings, true) . ";"`.
`var_export` emits an escaped PHP literal and cannot introduce executable
constructs, so it neutralises the flow, but the analyzer has no concept of a
laundering function. The `sanitize()` in `internal/phptaint/taint.go` is display
escaping and is unrelated.

**Decision needed:** which encoders neutralise a code-execution sink
(`var_export`, `json_encode`, `serialize`, integer casts) and where laundering
is applied, without blinding the engine to an `eval` of a decoded round-trip.

**Acceptance:** the Joomla language cache stops reporting; a laundered value
that is later decoded and executed still reports; the WordPress corpus stays at
zero.

## Local-path provenance through variables

**Status:** open. One false positive on stock OpenCart.

`argLocality` folds only literal and constant expressions, so a variable is
undecidable however it was built. OpenCart assigns `$file = DIR_TEMPLATE . $x`
before reading it, so a read from a known-local directory still seeds taint.
The constant table itself now covers every supported CMS.

**Acceptance:** a read through a variable assigned from a local path constant
is not a source; a read through a variable assigned from a parameter or an
unknown constant still is; reassignment between the two is handled.

## Content rules versus archive containers

**Status:** open. One false positive on a stock OpenCart developer tool.

A PHAR is an archive, so string rules match across bundled libraries that never
appear together in one source file. `network_socks_proxy` fired on a vendored
tool containing `socket_create(`, `socket_connect`, `socket_bind`,
`socket_listen`, `socket_accept` and the string `SOCKS` from unrelated packages.
No string-cooccurrence discriminator separates it from a real proxy.

This is a rule-class exposure, not one rule: every multi-string rule has it, and
the deep scan applies no extension gate.

**Decision needed:** require matches within a bounded offset window, or define
how content rules treat archive containers (`.phar`, `.zip`, `.jar`) that are
currently scanned as flat blobs.

**Acceptance:** the vendored tool stops matching; a real single-file proxy still
matches; the decision is applied consistently rather than rule by rule.

## Corpus growth

**Status:** ongoing.

After the three items above, add the pinned Joomla, Drupal and OpenCart sources
and recalibrate the engine status budgets, which scale with corpus size and were
set for a WordPress-only corpus: `phptaint partial_parse`, `jstaint oversize`
and `jstaint parse_error`. Recalibration is deliberate and belongs in the same
commit as the sources, with the measured numbers in the message.

Non-WordPress CMS adapters ship without any false-positive gate until this
lands. See [the corpus gate documentation](docs/src/clean-corpus.md).

---

# Priority 2 -- supply chain and operability

## Decide the trust model for internal CI builds

**Status:** open decision. Current behaviour is deliberate but narrow.

Release signing runs on tags only, so the internal package registry publishes
unsigned CI builds. The internal deploy script accepts those, states so, and
still requires a signature for any release version fetched through the same
path; `CSM_REQUIRE_SIGNATURES=1` refuses them outright. Their authenticity today
rests on the registry: TLS plus a token scoped to `read_package_registry`.

That is the path used to deploy main-branch builds to production, so it is the
least verified link in the chain.

**Options:** sign every published build with the release key, accepting wider
key exposure; sign CI builds with a separate lower-value key and embed both
public keys; or keep registry authentication as the boundary and document it as
the accepted limit.

**Acceptance:** whichever is chosen, the deploy scripts and
[release signing](docs/src/release-signing.md) state the same contract, and a
tampered artifact is refused on the path operators actually use.

## Operator-copied deploy scripts drift

**Status:** guard implemented; hardening open.

`csm doctor` now reports any deploy script on the host that still carries a path
able to install an unverified release. This came from a hand-maintained copy
that silently kept a superseded, weaker verification path.

**Remaining:** the check emits nothing when every script is current, unlike the
other checks which report `[OK]`. Make it report the clean result so an operator
can tell the check ran. Consider having the installer own the operator copy so
it is refreshed like the shipped one.

## Validate CageFS mount points

**Status:** open. Small, operator-facing.

`csm doctor` verifies that the PHP Shield event directory is a shared CageFS
mount and that live cages actually have it. It does not validate the rest of the
mount-point configuration, so entries pointing at directories that do not exist
cause every `cagefsctl` invocation to print errors, including CSM's own remount
guidance.

**Acceptance:** doctor reports configured mount points whose source is missing,
naming them; a correct configuration stays quiet or reports `[OK]`.

## `csm support-bundle`

**Status:** planned, unimplemented. Operators grep the journal and copy state
by hand today.

New CLI `csm support-bundle <path>` produces a tar+zstd containing:

- `csm store export` output (manifest, bbolt snapshot, state, rules cache).
- The last N (default 2000) service journal lines.
- The configuration file with secrets redacted: `smtp`, `webhook.url`,
  `abuseipdb_key`, `webui.auth_token`, `verified_session.admin_secret`,
  `captcha_fallback.secret_key`, plus whitelist-style redaction of any unknown
  `*_key`, `*_token` or `*_secret`.
- `system.txt` with `uname -a`, `csm version`, distro info and startup
  integrity hashes.

Requires a live daemon, mirroring `store export`. Auto-upload and encryption at
rest are out of scope; pipe through gpg.

**Size:** 1 day.

## Scheduled backup exports

**Status:** planned, unimplemented. `store export` needs an operator cron entry
today.

Hot-reloadable top-level config block:

```yaml
backup:
  enabled: true
  schedule: "@daily"            # cron spec or @hourly|@daily|@weekly
  destination_dir: /var/backups/csm
  filename: "csm-{date}.csmbak"
  retention_days: 14
```

The daemon ticks the schedule, calls `store.Export` and prunes archives older
than `retention_days`. Failures emit a `backup_export_failed` Warning.
Off-host destinations and encryption are out of scope.

**Size:** 1-2 days.

---

# Priority 3 -- detection coverage

## Realtime coverage for files renamed into a watched tree

**Status:** atomic-save coverage implemented; rename-only arrivals open.

Creation and close-write events scan atomic-stage names and retain the event
file descriptor through analysis, including after rename, replacement or unlink,
so completed content reaches the scanners without a rename event. See
[realtime coverage](docs/src/detection-realtime.md).

A file moved into an eligible path without a usable create or close-write event
is a separate case. The watcher does not subscribe to rename notifications, so
the rolling content scan remains its coverage path.

**Acceptance:** probe directory/name event and file-handle support at runtime
before adding rename-only coverage. Test arrival from outside the watched scope,
same-tree moves, lost events and unsupported kernels. Retain the rolling scan
fallback on enterprise kernels lacking the notification support; raising the
supported platform floor is not required.

## CMS discovery deeper than one directory below a document root

**Status:** WordPress limits documented; broader discovery open.

WordPress merges the panel's document-root map with account-home patterns in
[wpinstalls.go](internal/checks/wpinstalls.go), so a deeply nested declared root
is found while an undeclared installation outside those bounded patterns can be
missed. Other CMS adapters use their own patterns in `cmsDiscover` and do not
inherit the panel-map traversal. See
[deep check platform support](docs/src/detection-deep.md#platform-support).

**Acceptance:** decide the supported depth and cost budget per CMS before
expanding the walk. Test nested mapped and unmapped installs, custom account
roots, tenant ownership, symlinks, cancellation and incomplete traversal.
Document each adapter's limits alongside the resulting coverage.

## Spray correlation ingesting HTTP signals

**Status:** open. Formerly audit item Y11.

The HTTP abuse checks exist (`http_request_flood`, `http_scanner_profile`,
`http_ua_spoof`, `http_distributed_flood`, `http_asn_crawl`) and correlate under
the WordPress brute-force group. They do not feed the account-spray thresholds,
which remain mail-only.

**Acceptance:** add the HTTP checks to the spray signal set with a
request-target identity dimension, and show on recorded traffic that a
distributed low-rate campaign correlates without raising the existing per-source
detectors' false-positive rate.

## Cross-server fleet ingest

**Status:** open decision. Formerly audit item Y12.

Correlating activity seen by separate installations requires choosing between
panel-side correlation and a peer-to-peer ingest endpoint, and defining the
trust model between hosts before any protocol work. Nothing is implemented.

---

# Priority 4 -- infrastructure

## Firewall state migration to bbolt

**Status:** partially prepared. A `fw:blocked` bucket exists but is written only
during migration; `state.json` remains authoritative and every mutator rewrites
it in full, so fsync amplification and the crash window between mutators remain.

Move firewall state into bbolt: `fw:blocked` keyed by IP with
`{added, expires, reason, source}`, parallel `fw:allow_*` and `fw:port_*`
buckets, mutators wrapping `bolt.Update` and readers using `bolt.View`. The
existing in-memory cache stays as the hot-path index under the same invalidation
scheme. `csm store export` already snapshots bbolt, so firewall state rides
along. Provide a one-shot `csm firewall migrate-state` that reads the existing
JSON, writes the buckets and renames the file for rollback.

**Size:** 2-3 days.

## WordPress companion plugin for signed-cookie operator bypass

**Status:** planned. A logged-in administrator has no way to obtain the bypass
cookie without a manual request.

The plugin lives in a separate repository. This repository documents
`/challenge/admin-token` as a stable contract, with breaking changes requiring a
roadmap item, and adds a short integration note in `docs/src/challenge.md`.

**Size:** 0.5 day here; the plugin itself is separate.

## Consolidate bootstrap toolchain pins

**Status:** partially complete; image pin consolidation open.

`go.mod` requires Go 1.26.7 and CI sets `GOTOOLCHAIN=auto`, so the Go command
selects it even though the tools image and the YARA-X builder start older. The
Linux test wrapper derives its default image version from `go.mod`. Lint is
pinned to golangci-lint 2.11.4.

**Acceptance:** generate bootstrap version inputs from one maintained source and
check for drift; rebuild both architecture builders and the tools image, update
their tags, and record the selected Go and linter versions in CI. Automatic
toolchain selection still requires access to the toolchain download when it is
absent from cache.

## Lint timeout headroom

**Status:** measured and raised to ten minutes; runner capacity open.

This was measured the hard way: the v3.34.0 tag pipeline failed on
`context loading failed: ... context deadline exceeded` at 324s against the
five-minute cap, blocking a release. Package loading, not analysis, is what
approaches the limit, and it scales with runner concurrency -- main-branch
pipelines loaded in 172-201s while the tag pipeline runs every job at once.
All four invocations now allow ten minutes.

**Remaining:** the timeout hides a capacity problem rather than solving it.
Decide whether the shared runner should be given more headroom, and keep the
existing rule that a timeout or typechecking failure is never reported as clean
merely because the tool also prints zero issues.
