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
2. **Precision and response safety.** A false positive is not merely noise
   here. Findings drive automatic quarantine and blocking, and every past
   incident review found real compromises buried under false-positive floods.
   Precision failures cause missed detections indirectly and break customer
   sites directly, and the response machinery decides how much damage one bad
   detector can do before anyone notices.
3. **Root attack surface, supply chain and release integrity.** This project is
   open source, installs as root from a public repository, parses attacker
   controlled input and serves a web UI. A bug in any of that is a server-wide
   compromise, and the verification path is itself public.
4. **Correlation.** Turning many weak signals into few strong ones is the
   highest-leverage way to raise precision without losing coverage.
5. **Known coverage gaps.** Missed detections, mitigated somewhat by the
   overlapping realtime, deep-scan, signature and taint layers.
6. **Operability and validation.** Real work, but a server stays protected
   while it waits.
7. **Performance budgets and debt.**

## This cycle

A product review in September 2026 returned a list of hardening themes. They
are folded into the sections below rather than kept as a separate list, so
that each lands next to the evidence and the existing work it depends on.

For the next major cycle the order of effort is: correctness, false-positive
reduction, privilege isolation, cPanel/CloudLinux integration coverage,
incident replay testing, measurable detection quality, performance and
operational reliability, usability. **Prefer proving and improving the
detectors that exist over adding new ones.** A new detector without a clean
corpus result, an attack corpus sample and a correlation policy is not done.

Two rules already followed in practice are now stated here so they are not
optional:

- Every production false positive that is fixed gets a regression test that
  reproduces it before the fix.
- Every correlation or response bug found in production gets a replay fixture.

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
- [ ] Provision and maintain a licensed clean cPanel/CloudLinux environment,
  set the protected `INTEGRATION_CPANEL_IMAGE` variable, and make it a required
  release gate. See [cPanel acceptance](docs/src/cpanel-release-tests.md).
  **Blocked:** no cPanel licence is available for disposable CI clones, and the
  cloud image catalogue offers no cPanel image. Until then a tag must set
  `CSM_RELEASE_WITHOUT_CPANEL` with a stated reason, and its release evidence
  records `cpanel_coverage: "absent"`.

  A permanent licensed test server is the realistic way to close this, since
  disposable clones cannot be licensed. When it exists, the gate must cover,
  against the release candidate package: clean installation; upgrade from each
  previous supported release; rollback and recovery after a failed upgrade;
  CageFS, bind mounts, account homes, mail paths, web roots and the
  panel-specific layouts; a representative WordPress workload; the attack
  replay corpus below with its expected findings and remediation; and
  uninstall followed by reinstall leaving nothing unsafe or inconsistent
  behind. The generic cloud integration already covers install, upgrade and
  removal on AlmaLinux and Ubuntu, so the delta is the panel.

  Three shipped subsystems have completed every acceptance except this one, so
  closing the gate is all that remains for them: the narrowed service write
  scope (real-systemd tests cover denied writes, atomic updates, helper
  rejection and rollback, but not a live panel rebuild under the candidate
  package), mailbox password verification (upstream vectors are covered, a live
  Dovecot binary is not), and mail source supervision (file and journal
  recovery are covered).
- [ ] Detection-quality evidence per release. A tag records, next to the
  existing release evidence, the numbers defined under
  [detection quality metrics](#detection-quality-metrics-per-release), and the
  release is refused when a critical threshold regresses. Depends on the attack
  replay corpus and the clean corpus report below.

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
less than it claims. Several items further down deliberately create new tables
of this kind (response tiers, root-requiring operations, parser inventory).
Each of them ships with the same completeness test, or it is not done.

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

**Acceptance:** classify all 221 finding names as security events, explicitly
ignored, or categorised, with the completeness test above holding the
classification so a new finding type cannot be added without a policy. Derive
the coverage table from that classification instead of maintaining one by
hand. Re-derive the coordinated-attack threshold against recorded finding
streams rather than assuming three accounts is still right at ten times the
detector surface.

## Backlog and dropped work are reported as counters, not as failures

**Status:** open. Partly instrumented.

The daemon has several bounded queues between the kernel and an alert: the
fanotify analyzer queue, the alert channel, the spool and log watchers, the BPF
ring buffers, the dropper tracker and the staged-package verification queue.
Overflow on the analyzer queue raises a `fanotify_overflow` finding and a
reconcile scan. Every other drop is a `Warn` line and an atomic counter that
`csm status` prints as `dropped alerts`. A watcher that falls minutes behind
is not reported at all, and neither is a queue that is permanently full.

A queue that silently sheds findings is the same failure as a table that
silently narrows: healthy status, less protection.

**Acceptance:** every bounded queue reports depth, drops and lag through the
health snapshot and `csm doctor`, with a named degraded state when a threshold
is crossed; a sustained drop rate on any queue raises a finding the way the
analyzer overflow does today; no new queue can be added without those metrics
(same completeness rule as above). The budgets themselves belong to
[resource and performance budgets](#resource-and-performance-budgets).

---

# Priority 2 -- detection precision and response safety

A false positive here is not cosmetic. Findings drive automatic quarantine and
blocking on customer sites, and every past incident review found real
compromises buried under false-positive floods. The response machinery bounds
how much a bad detector can break, so it sits first in this section; the
precision items follow.

None of these should be closed by raising a threshold or excluding a path.

## Auto-response safety model

**Status:** open. Pieces exist, the model does not.

What exists: `auto_response.dry_run` defaults to on; per-IP blocks are capped
at `max_blocks_per_hour` (default 50) and service restarts at
`max_restarts_per_hour` (3); the virtual-patch mode has a safe default; the
verdict callback lets a panel downgrade a block; process signalling goes
through pidfd; quarantine and virtual patching resolve paths with `openat2`
and `RESOLVE_BENEATH`; the incident correlator has safety caps and a dry-run
mode; firewall changes record a rollback point. See
[auto-response](docs/src/auto-response.md).

What does not exist: quarantine has no hourly cap at all, so one false
positive rule on a realtime write path can quarantine every matching file on
the server; no action is classified by risk; nothing disables a response after
it keeps failing; and the reputation permablock loop (June 2026) showed that a
faulty feedback path can block indefinitely inside the per-hour cap.

**Decision:** classify every automated action into a tier, in one table with a
completeness test:

| Tier | Meaning | Examples today |
| --- | --- | --- |
| 0 | alert only | most findings |
| 1 | recommendation / dry-run record | `dry_run` blocks, virtual-patch preview |
| 2 | low-risk reversible | challenge, rate limit, mail hold |
| 3 | quarantine or block | file quarantine, nftables block, virtual patch |
| 4 | destructive or process-affecting | process kill, service restart, config rewrite |

Each tier gets a confidence floor, a per-action circuit breaker (count per
hour and per account, with quarantine gaining the cap that blocks already
have), mandatory identity revalidation immediately before tiers 3 and 4
(inode and device for files, pidfd for processes, rule handle for firewall
entries), and enough recorded metadata to reverse the action. A response
mechanism that fails N times in a window disables itself and raises a finding
saying so.

**Acceptance:** the tier table is complete or the build fails; every tier 2
to 4 action has an automated rollback test (firewall, quarantine,
configuration); a deliberately broken detector in a test cannot exceed its
circuit breaker; PID reuse, symlink swap, bind-mount ambiguity under CageFS
and a file replaced between detection and action are each covered by a test
that proves the action is refused.

**Size:** 1 week for the table, caps and revalidation; rollback tests on top.

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

## Clean corpus growth and per-detector false-positive tracking

**Status:** ongoing. The corpus is WordPress-only and pinned upstream
packages only.

After the three items above, add the pinned Joomla, Drupal and OpenCart
sources (URL, SHA-256, exact file count and in-archive licence path are ready)
and recalibrate the engine status budgets, which scale with corpus size and
were set for a WordPress-only corpus: `phptaint partial_parse`, `jstaint
oversize` and `jstaint parse_error`. Recalibration is deliberate and belongs in
the same commit as the sources, with the measured numbers in the message.
Non-WordPress CMS adapters ship without any false-positive gate until this
lands. See [the corpus gate documentation](docs/src/clean-corpus.md).

Then grow the corpus past stock upstream packages, because that is not what
runs on a hosting server: WooCommerce with its usual extensions, page builders,
caching and backup plugins, security plugins that rewrite their own files,
common premium themes, custom PHP applications, and the legitimate admin tools
(adminer, phpMyAdmin, file managers) that content rules like to flag. Sourcing
is the hard part; anonymised snapshots of real clean accounts need a
documented consent and scrubbing procedure before the first one is committed.

**Acceptance:** the corpus runs against every release candidate; the report
lists false positives per detector and per release, not only a pass/fail; a
detector whose signal-to-noise ratio is unacceptable on the corpus is reworked
or disabled, never allowlisted; severity and confidence defaults are
recalibrated from the numbers, with the change recorded in the CHANGELOG.

## Attack replay corpus

**Status:** open. Detection today is proven by per-detector unit fixtures; no
end-to-end replay records what a release detects.

Build a versioned corpus of real hosting compromises, each sample carrying its
expected findings, the expected incident the correlator should form, and
whether automatic remediation is expected, optional or prohibited. Coverage
must include web shells, PHP droppers, obfuscated malware, malicious WordPress
plugins and themes, credential stealers, injected JavaScript, phishing kits,
spam scripts, mail-account abuse, persistence mechanisms, cron abuse,
suspicious binaries and archive-based payloads. Most of these already exist as
scattered test fixtures; the work is collecting them under one manifest with
expectations, and adding what is missing.

The corpus is stored so that endpoint antivirus on a developer machine cannot
eat it (encoded at rest, decoded into a temporary directory by the runner), a
problem the existing YARA fixtures already hit.

**Acceptance:** the replay runs at release acceptance; a detector change that
loses a previously detected sample fails the run; the incident half of the
corpus is the evidence harness that [Priority 4](#priority-4----correlation)
needs, so both share one recorded-stream format.

## Detection quality metrics per release

**Status:** open. Release evidence today records package hashes, upgrade
results and cPanel coverage, nothing about detection.

Publish, for every tag, from the two corpora and the integration runs: clean
accounts and sites tested, attack samples tested, detection rate, false
positives per site and per day, automatic actions exercised, actions that
failed or rolled back, detector regressions against the previous tag, and the
performance impact measured under
[resource and performance budgets](#resource-and-performance-budgets).

**Acceptance:** the numbers are written into the release evidence next to
`cpanel_coverage`; minimum thresholds are defined and a tag is refused when
detection rate or false-positive rate regresses past them; the release notes
link the report.

---

# Priority 3 -- root attack surface, supply chain and release integrity

Everything in this section is about what happens when CSM itself is the
vulnerable component. It runs as root, reads attacker-controlled files, mail
and logs, serves a web UI and an API, and installs itself from a public
repository.

## Privilege separation

**Status:** open. The daemon is one root process.

Today the whole daemon -- detection, correlation, parsers, threat intelligence,
web UI and API -- runs as root inside the systemd confinement described in
[service confinement](docs/src/service-confinement.md): `ProtectSystem=strict`,
syscall filtering, a `ReadWritePaths` allow-list, and `systemd-run` for the
panel scripts that need the whole filesystem. One helper pattern exists: the
mail forward guard executes a fixed helper subcommand of the same binary. A
parser bug anywhere is therefore a root compromise of the host.

**Decision:** a minimal privileged helper owns the operations that require
root -- nftables and firewall changes, process termination, quarantine and
other moves across account boundaries, fanotify and BPF initialisation with
the resulting descriptors passed back over the socket, and privileged
filesystem and configuration writes -- and everything else runs with reduced
privileges. Reduced, not none: reading every account's files still needs
`CAP_DAC_READ_SEARCH`, so the unprivileged side keeps a small capability set
and loses the ability to write, signal and reconfigure. The helper exposes a
narrow Unix-socket RPC authenticated by peer credentials, with fixed verbs and
arguments validated against the same path, user, process and firewall scopes
the actions enforce today.

Stage it: first an inventory of every root-requiring operation as a table with
a completeness test; then the helper for firewall, signals and quarantine
(the tier 3 and 4 actions from the safety model, which defines the action set
and should land first); then descriptor passing for fanotify and BPF; then
dropping capabilities in the main process. Each stage is shippable on its own.

**Acceptance:** the main process holds no capability it does not use; tests
prove an RPC request cannot escape the intended path, user, process or
firewall scope, including through symlinks, bind mounts and PID reuse; the
code that executes as root is small enough to be read in one sitting.

**Size:** weeks, staged. The largest item on this list.

## Browser sessions must not carry the admin token

**Status:** open. Confirmed in `internal/webui/server.go`.

The login form sets the `csm_auth` cookie to the admin token itself, valid for
24 hours. A read-scope token exists for the API, and the CSRF boundary for
cookie sessions is in place, but the cookie is the long-lived credential, so
it cannot be revoked without rotating the token, has no idle timeout, and is
the same secret the API and the panel integrations use.

**Acceptance:** login creates a random server-side session with a configurable
lifetime and idle timeout; the identifier rotates after authentication and on
any privilege change; sessions are listed and individually revocable,
including remote logout of every session; API credentials never appear in a
cookie; MFA with WebAuthn is optional for UI administrators and lands as a
follow-up with its own recovery story. See [web UI](docs/src/webui.md).

**Size:** 2-3 days for sessions; MFA separate.

## Parser and input hardening

**Status:** partly covered. 26 test files carry fuzz targets and the seed
corpus runs as regression tests; the plugin checksum fetcher caps archive and
entry sizes; the email antivirus bounds archive members; the PHP parser runs
in a separate process because a lexer hang was reproducible.

**Acceptance:** an inventory of every parser that reads externally influenced
input -- archives, logs, configuration, CMS state, PHP and JavaScript, mail,
the challenge and control protocols -- against its fuzz target, with a
completeness test; resource limits on decompression ratio, recursion, nesting,
file size and parser execution time, each with a test that exceeds it; tests
for malformed filesystem metadata, symlink chains and mount-namespace edge
cases under CageFS; race-detector stress runs on the concurrent paths; and
input validation at the privilege boundary once the helper above exists.

## External security review

**Status:** open decision. Nobody outside the project has reviewed the root
attack surface.

Commission a focused external review of: web UI and API, authentication and
session handling, privileged filesystem operations, quarantine, the nftables
response, process termination, installer and update verification, archive
handling, symlink and TOCTOU behaviour, IPC boundaries, and the BPF and
fanotify integration. Schedule it after the sessions item and the first stage
of privilege separation have landed, otherwise it reports what this file
already says. Publish a summary of findings and remediation, and repeat a
focused review after each major architecture change.

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
Recorded finding streams in, expected incidents out. The
[attack replay corpus](#attack-replay-corpus) supplies the compromised streams
and the clean corpus supplies streams that must produce no incident, so the
harness is the same runner reading expectations for a second layer. Without
it, this section adds a layer that can be wrong in ways nothing catches, which
given the false-positive history here is a real risk rather than a theoretical
one.

**Acceptance for the harness:** real incidents from past reviews replay to
their known incident; clean streams form nothing; the run reports correlation
false-positive and false-negative rates; every correlation bug found in
production is added as a fixture before it is fixed.

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
The [fleet validation evidence](#fleet-validation-evidence) decision below
shares the same channel question and should be taken together with this one.

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

## Scheduled scans do not consult package checksums

**Status:** open. Found while triaging a stock plugin file that the deep scan
keeps flagging.

The realtime path skips detection on a file whose hash matches the official
wordpress.org release of its plugin or core version. The scheduled YARA and
signature scans never ask, so a stock file with an obfuscated-looking loader
is reported on every deep scan and can never be auto-cleared by the re-check,
which re-runs the same rules.

**Acceptance:** the deep scan and the re-check verifier consult the same
checksum cache as the realtime path, with the same fail-closed rules (complete
content, declared version, no partial reads); a stock file stops reporting; a
modified copy of the same file still does.

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

# Priority 6 -- operability and validation

A server stays protected while these wait, but they decide how fast an operator
can understand what happened and how much production evidence reaches the
defaults.

## Job model for every long-running operation

**Status:** scans done; the rest open.

Account and full scans already run as jobs with status endpoints (see
`internal/webui/scanjobs_api.go`). Other operations that can run for minutes
-- database cleanup, store export and import, rule and GeoIP updates, batch
quarantine, virtual patch application, the support bundle below -- still hold
a privileged HTTP request open for their whole duration, and a client that
disconnects leaves the operation running with nobody watching it.

**Acceptance:** every operation over a few seconds returns a job identifier
immediately and reports status, progress and result through the same
endpoints scans use; cancellation is supported where the operation can stop
safely and is explicitly refused where it cannot (a half-applied firewall
change is completed and recorded, never abandoned); job state survives a
daemon restart well enough to say what was interrupted; concurrency and
resource limits apply per job class so two full scans cannot run at once.

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

## Fleet validation evidence

**Status:** open decision.

The defaults for confidence, severity and remediation are tuned from a handful
of production servers read by hand. The panel data plane already carries every
finding off the host (per-finding HMAC webhook, SSE stream, audit log with
tenant identity), so the cheapest fleet evidence is panel-side: which findings
led to a confirmed incident, which were dismissed, per detector, per platform.
Opt-in anonymised operational metrics from installations without a panel are
the alternative, and need a documented privacy boundary before any code.

**Acceptance:** a decision on the channel, taken together with the fleet
ingest item in Priority 4; detector noise and resource usage compared across
cPanel, CloudLinux and generic Linux hosts; the numbers feed the calibration
step of the clean corpus item rather than a separate tuning process.

---

# Priority 7 -- performance budgets and debt

## Resource and performance budgets

**Status:** open. Four benchmark files exist; no budget is written down.

Shared-hosting servers run hundreds of accounts and millions of files, and CSM
competes with the sites it protects. Overload has been found by operators
(out-of-memory restarts, a copy-on-write regression) rather than by a test.

**Acceptance:** written CPU, memory, I/O and event-latency budgets for a
reference server size; benchmarks for large account and file counts, high mail
volume and high filesystem event rates, run per release and recorded in the
detection-quality report; every queue bounded with a stated cap (the staged
package verification queue and the dropper tracker are the pattern); a named
degraded mode -- deferred deep work, reconcile scans, refused new jobs --
instead of falling behind quietly, with its lag and deferred work exposed as
described in
[Priority 1](#backlog-and-dropped-work-are-reported-as-counters-not-as-failures).

## Web UI module split

**Status:** open. `internal/webui` is 47k lines; the two largest handler files
are 1859 and 1276 lines and mix HTTP handling with the logic that quarantines,
blocks and rewrites configuration.

Split the handlers by domain -- findings, incidents, firewall, quarantine,
scans, mail, settings, health -- behind narrow interfaces, and keep the
security-sensitive logic out of the handler files so it can be reviewed and
tested on its own. Do this alongside the sessions item so the authentication
path is not reworked twice, and before the external review so the reviewer
reads the boundary rather than the handlers.

**Acceptance:** no handler file performs a privileged action directly; each
domain interface has its own tests; cross-domain imports inside the web UI
package go through the interfaces.

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
