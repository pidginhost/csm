# CSM Engineering Roadmap

Open engineering work and release acceptance checks, ordered so a contributor
can pick the top item and start. Completed work is removed from this file:
commits and `CHANGELOG.md` are the archive.

This file is for contributors. End-user documentation lives in `docs/`.

## How this list is ordered

CSM runs as root on live shared-hosting servers and takes automatic action on
them. That shapes the ordering, which is by **harm to a protected server**, not
by effort or tidiness:

1. **Protection that fails silently.** A capability that stops working while
   everything still reports healthy is the worst outcome: there is no alert, no
   failing test, and no operator prompt. Nothing else on this list matters if
   the tool is quietly not protecting.
2. **Precision.** A false positive is not merely noise here. Findings drive
   automatic quarantine, and every past incident review found real compromises
   buried under false-positive floods. Precision failures cause missed
   detections indirectly and break customer sites directly.
3. **Supply chain and release integrity.** This project is open source and
   installs as root from a public repository. A compromised or unverifiable
   artifact is total, and the verification path is itself public.
4. **Correlation.** Turning many weak signals into few strong ones is the
   highest-leverage way to raise precision without losing coverage.
5. **Known coverage gaps.** Missed detections, mitigated somewhat by the
   overlapping realtime, deep-scan, signature and taint layers.
6. **Operability and debt.** Real work, but a server stays protected while it
   waits.

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

# Priority 1 -- protection that fails silently

## Curated tables go stale without failing anything

**Status:** open, and the highest-leverage item on this list.

Three separate subsystems narrow their behaviour through a hand-maintained
table. In each case the table was correct when written, fell behind as the
project grew, and **nothing failed** -- no test, no lint, no alert. Two were
found only by pointing a new corpus at the analyzer; the third by counting.

| Table | Scope when written | Actual scope needed |
| --- | --- | --- |
| `localPathConstants` in `internal/phptaint/sources.go` | WordPress only | every supported CMS |
| `scripts/clean-corpus/manifest.json` | WordPress only | every supported CMS |
| `securityEventChecks` in `internal/checks/correlation.go` | 22 checks | 221 finding names exist |

The taint table meant a stock Joomla or OpenCart install reported remote
execution on its own template cache. The corpus meant no non-WordPress CMS had
any false-positive gate at all. The third is measured in the next item.

This is a *class* of defect, not three bugs, and it is exactly the failure mode
this project can least afford: the tool keeps reporting healthy while covering
less than it claims.

**Decision:** each narrowing table gets a completeness test that fails when the
project grows past it. Every check that can emit Critical is either present in
`securityEventChecks` or listed in an explicit exclusion set with a stated
reason; every supported CMS appears in the corpus manifest and the path-constant
table. Adding a detector without updating the table must break CI, not degrade
detection quietly.

**Acceptance:** adding a new Critical-severity check to a fixture fails the
completeness test until it is classified. The exclusion set is readable and
each entry says why. No table in this class is left without such a test.

**Size:** about half a day, and it retires the whole class.

## Cross-account correlation sees a tenth of the detectors

**Status:** open. Measured, not estimated.

`CorrelateFindings` raises a coordinated-attack finding when three or more
accounts show Critical security events, but only for checks listed in
`securityEventChecks`:

```
finding names known to the runner : 221
checks in securityEventChecks     :  22
not eligible for correlation      : 209
```

Not eligible: `backdoor_port_outbound`, `bad_asn_outbound`,
`admin_cross_account_overlap`, `bulk_password_change`, and every database and
non-WordPress CMS detector. A database-level compromise replicated across
accounts -- a shape this project has repeatedly encountered -- cannot raise the
cross-account signal today.

The list is also Critical-only and count-based, so several corroborating
Warnings on one account never combine into anything.

**Acceptance:** classify all 221 finding names as security events or not, with
the completeness test above holding the classification. Re-derive the
coordinated-attack threshold against recorded finding streams rather than
assuming three accounts is still right at ten times the detector surface.

---

# Priority 2 -- detection precision

A false positive here is not cosmetic. Findings drive automatic quarantine on
customer sites, and every past incident review found real compromises buried
under false-positive floods. These block growing the clean-application corpus,
which is the only automated evidence that a rule or analyzer does not fire on
stock software.

Verified pinned sources for Joomla, Drupal and OpenCart are ready to add to
`scripts/clean-corpus/manifest.json` (URL, SHA-256, exact file count and
in-archive licence path). Adding them today turns the gate red on the two
analyzer items below, so land the fixes first, then the sources and the
recalibrated status budgets in one commit. None of these should be closed by
raising a threshold or excluding a path.

## Taint laundering through value encoders

**Status:** open. One false positive on stock Joomla.

Every template-compiling CMS reads a file, writes generated PHP to a cache and
includes it. Joomla writes
`"<?php ... return " . var_export($strings, true) . ";"`. `var_export` emits an
escaped PHP literal and cannot introduce executable constructs, so it
neutralises the flow, but the analyzer has no concept of a laundering function.
The `sanitize()` in `internal/phptaint/taint.go` is display escaping and is
unrelated.

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

**Status:** open. One false positive on a stock developer tool shipped inside a
supported CMS.

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

# Priority 3 -- supply chain and release integrity

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
that silently kept a superseded, weaker verification path -- the same
stale-copy failure mode as the tables in Priority 1, on the supply chain.

**Remaining:** the check emits nothing when every script is current, unlike the
other checks which report `[OK]`. Make it report the clean result so an operator
can tell the check ran. Consider having the installer own the operator copy so
it is refreshed like the shipped one.

## Runner capacity for the release pipeline

**Status:** timeout raised; capacity question open.

The v3.34.0 tag pipeline failed on
`context loading failed: ... context deadline exceeded` at 324s against a
five-minute lint cap, stopping the release before any artifact was built.
Package loading, not analysis, approaches that limit and scales with runner
concurrency: main-branch pipelines load in 172-201s while a tag pipeline runs
every job at once. All four invocations now allow ten minutes.

The gates behaved correctly -- nothing was signed, published or released -- but
the timeout hides a capacity problem rather than solving it.

**Remaining:** decide whether the shared runner should be given more headroom.
Keep the existing rule that a timeout or typechecking failure is never reported
as clean merely because the tool also prints zero issues.

---

# Priority 4 -- correlation

Turning many weak signals into few strong ones is the highest-leverage way to
raise precision without giving up coverage. The incident correlator in
`internal/incident` is already a real subsystem -- kinds, keys, groups, spray,
reclassification, auto-close with per-kind idle thresholds, safety caps and a
dry-run mode -- and should be extended rather than replaced. The findings-level
`CorrelateFindings` is the weak layer; see Priority 1.

**Build the evidence harness first.** Correlation logic is far harder to test
than detection logic, and there is no equivalent of the corpus gate for it.
Recorded finding streams in, expected incidents out. Without that, this section
adds a second layer that can be wrong in ways nothing catches, which given the
false-positive history here is a real risk rather than a theoretical one.

## Corroboration grading

**Status:** open. Highest value of this section.

A Warning corroborated by an independent signal on the same account, file or
address should escalate; an uncorroborated Warning in a family known to be noisy
should demote. This attacks false-positive volume directly instead of adding
detections, and it is the mechanism that would have kept past compromises
visible above their noise.

**Acceptance:** replayed streams from real incidents raise the compromise above
its surrounding noise; replayed clean streams do not manufacture incidents;
demotion never hides a Critical.

## Sequence correlation

**Status:** open.

A dropper, then a new administrator, then an outbound connection is an ordered
story, and CSM currently emits three unrelated findings. Ordering is
high-precision evidence that costs nothing extra to observe, because every
finding already carries a timestamp.

**Acceptance:** an ordered sequence produces one incident carrying its steps;
the same findings out of order, or far apart in time, do not.

## Join findings on file identity

**Status:** open.

Realtime, YARA and the taint engines can each flag the same file and produce
separate findings. Collapsing on account, path and time window is pure noise
reduction with no detection loss.

**Acceptance:** one file that trips three layers yields one finding carrying
three pieces of evidence, and the strongest severity wins.

## Spray correlation ingesting HTTP signals

**Status:** open. Formerly audit item Y11.

The HTTP abuse checks exist (`http_request_flood`, `http_scanner_profile`,
`http_ua_spoof`, `http_distributed_flood`, `http_asn_crawl`) and correlate under
the WordPress brute-force group. They do not feed the account-spray thresholds,
which remain mail-only.

**Acceptance:** add the HTTP checks to the spray signal set with a
request-target identity dimension, and show on recorded traffic that a
distributed low-rate campaign correlates without raising the existing
per-source detectors' false-positive rate.

## Cross-server fleet ingest

**Status:** open decision. Formerly audit item Y12.

Correlating activity seen by separate installations requires choosing between
panel-side correlation and a peer-to-peer ingest endpoint, and defining the
trust model between hosts before any protocol work. Nothing is implemented.

---

# Priority 5 -- known coverage gaps

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

---

# Priority 6 -- operability during an incident

A server stays protected while these wait, but they decide how fast an operator
can understand what happened.

## `csm support-bundle`

**Status:** planned, unimplemented. Operators grep the journal and copy state
by hand today.

Worth more than it looks: diagnosing this project's own failures repeatedly
meant extracting artifacts by hand, hitting a log capture limit that truncated
output exactly where the failure was, and sampling `/proc` manually. An
operator under incident pressure has less time and less context.

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

## Validate CageFS mount points

**Status:** open. Small, operator-facing.

`csm doctor` verifies that the PHP Shield event directory is a shared CageFS
mount and that live cages actually have it. It does not validate the rest of the
mount-point configuration, so entries pointing at directories that do not exist
make every `cagefsctl` invocation print errors, including CSM's own remount
guidance.

**Acceptance:** doctor reports configured mount points whose source is missing,
naming them; a correct configuration stays quiet or reports `[OK]`.

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

# Priority 7 -- correctness and infrastructure debt

## Firewall state migration to bbolt

**Status:** partially prepared. A `fw:blocked` bucket exists but is written only
during migration; `state.json` remains authoritative.

This is a correctness item, not a performance one: every mutator rewrites the
whole file, so a crash between mutators can leave an enforcement change
half-applied.

Move firewall state into bbolt: `fw:blocked` keyed by IP with
`{added, expires, reason, source}`, parallel `fw:allow_*` and `fw:port_*`
buckets, mutators wrapping `bolt.Update` and readers using `bolt.View`. The
existing in-memory cache stays as the hot-path index under the same invalidation
scheme. `csm store export` already snapshots bbolt, so firewall state rides
along. Provide a one-shot `csm firewall migrate-state` that reads the existing
JSON, writes the buckets and renames the file for rollback.

**Size:** 2-3 days.

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

## WordPress companion plugin for signed-cookie operator bypass

**Status:** planned. A logged-in administrator has no way to obtain the bypass
cookie without a manual request.

The plugin lives in a separate repository. This repository documents
`/challenge/admin-token` as a stable contract, with breaking changes requiring a
roadmap item, and adds a short integration note in `docs/src/challenge.md`.

**Size:** 0.5 day here; the plugin itself is separate.
