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

## Architecture direction

Keep the host agent autonomous and self-contained, with bbolt owned by one
process. Privilege separation must preserve that ownership: the helper and
online CLI clients use scoped requests for reads and writes. They must not open
the live database independently, even read-only: bbolt's writable owner holds
an exclusive file lock. Offline maintenance needs exclusive ownership, with
the daemon and helper quiesced before handoff. A local database replacement
needs measured contention, query complexity or recovery requirements that the
current design cannot meet. Both bbolt and SQLite WAL serialize writers; a
switch alone does not remove that constraint. See the
[bbolt transaction documentation](https://github.com/etcd-io/bbolt#transactions)
and [SQLite WAL concurrency](https://www.sqlite.org/wal.html#concurrency).
The separate-process lock behavior is described under
[bbolt read-only mode](https://github.com/etcd-io/bbolt#read-only-mode).

Use the existing store, action log, privileged-operation inventory, scan jobs
and incident correlator as the starting points. Add domain interfaces as each
slice needs them; a package renaming campaign or a generic bucket/key API is
not a prerequisite. Keep operator configuration in YAML and migrate remaining
authoritative operational state by domain, with a rollback contract.

The architectural priorities are privilege isolation, durable host actions and
browser credential isolation. They complement the harm-based priorities above.
The delivery order within this architecture work is below; it does not defer
Priority 1 protection failures or Priority 2 precision and response defects:

Browser sessions and their HTTP/domain boundary are implemented. Remaining work:

1. A firewall block/unblock slice of the
   [durable action lifecycle](#action-log-covers-six-of-twenty-seven-host-changes),
   including storage measurements and an explicit state-owner contract. Complete
   [firewall state migration](#firewall-state-migration-to-bbolt) with recovery
   proof, then use that action contract for the first privileged-helper verbs.
2. Expand helper coverage and action recovery by response family; extend the
   [existing jobs](#job-model-for-every-long-running-operation) as each long
   operation moves behind a service. Drop main-process privileges only when the
   required reads, descriptors and mutations have verified replacements.
3. Improve correlation through the shared replay harness, then add outbound
   fleet ingest. Panel availability must never gate local protection.

No mandatory local broker, database server or orchestration platform is added.
The fleet service owns its database choice separately; this roadmap does not
select or build a central database stack.

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

Three rules already followed in practice are now stated here so they are not
optional:

- Every production false positive that is fixed gets a regression test that
  reproduces it before the fix.
- Every correlation or response bug found in production gets a replay fixture.
- Every new selecting table ships with a completeness guard. New registered
  checks and incident sets need an explicit classification decision in the
  [incident policy contract](docs/src/incidents.md#kinds).

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

## WAF block scoring needs recorded-stream evidence

**Status:** deferred pending representative replay evidence; keep the emitted
WAF block names out of local reputation scoring for now.

Whether the emitted ModSecurity block names (`modsec_block_realtime`,
`modsec_block_escalation`, `modsec_csm_block_escalation`, `waf_attack_blocked`)
should map into the attack database is a reputation-scoring change, not a table
fix. WAF blocks are high volume and the WAF-block score branch has never run
on real data. Decide it against recorded block streams before mapping.

The replayed audit sample is sparse and provides little escalation coverage.
The candidate mappings do not raise new high-score sources in this sample,
but it does not exercise the high-volume WAF score contribution.
Realtime denies, periodic summaries and escalation findings can describe the
same traffic. Counting all three as independent attacks would inflate scores;
counting raw denies would also bypass the existing confidence and operator
exclusion checks used for escalation. A scoring proposal needs a replay that
preserves those controls and measures overlap with existing attack evidence.

## Cross-account correlation still has identity gaps

**Status:** partial; classification, calibration, re-report counting and socket
ownership are complete. Mail aggregates with no single verified submitter and
mailbox ownership outside cPanel remain unattributed.

Every registered check now carries a correlation class (security event,
malware artifact, ignored with a reason, or derived), the coverage table in
[the incidents documentation](docs/src/incidents.md#cross-account-correlation-of-findings)
is generated from that classification and a test fails when it is stale, and
eligible producers supply the owning account when available, so a database
compromise replicated across attributed accounts can raise the cross-account
signal.

Current boundaries and remaining work:

- The aggregate is still Critical-only and count-based: several corroborating
  High findings on one account never combine into anything.
- Socket checks (`backdoor_port`, `backdoor_port_outbound`, `c2_connection`
  and `bad_asn_outbound`) now resolve the kernel UID through the existing
  passwd and account-home validation. The live bad-ASN path retains this
  identity even when process enrichment misses. Root, service and unknown
  UIDs stay unattributed, and findings from different accounts retain distinct
  dispatch and audit identities.
- The per-domain mail volume aggregate retains its existing counting scope.
  It carries an owner only when every counted arrival proves the same
  authenticated mailbox, authenticated hosting user or local submitting user.
  A mixed or unverified aggregate stays unattributed; the envelope sender
  alone never establishes ownership. Two host-wide aggregates
  (`admin_cross_account_overlap`, `bulk_password_change`) already summarise
  several accounts and are excluded as inputs.
- Mailbox and domain identities need cPanel's domain-owner table. Those
  lookups stay unattributed on other panels; authenticated bare hosting users
  and PHP relay users can still resolve through validated passwd homes.
- The three-account threshold has now been re-derived against recorded
  streams (below). It stays at three; what was wrong was the absence of any
  time bound, now fixed.
- Attribution loss is now visible: the health snapshot and `csm doctor`
  name the checks whose active-set findings carry no owner and keep a
  cumulative count since start, so calibration work can see what it is
  missing on a given host.

Recorded streams now exist: `scripts/finding-stream` anonymizes a host's
audit log into a joinable stream (see
[recorded finding streams](docs/src/finding-streams.md)), and the first
recordings from production hosts are kept locally, outside the repository.
Calibration can start from them.

**What a recording is.** `scripts/finding-stream` records the *audit log*, which
is the dispatch record: it holds what was alerted, after deduplication. The
persisted latest-state set is different and larger, because every scan re-emits
the findings it still sees and the merge refreshes their timestamps. During one
sweep on a production host the audit log recorded 49 dispatched criticals while
the active set carried 157 refreshed critical rows. A replay therefore
understates how full the persisted window gets, and a percentage measured from
a recording describes the replay, not the live active set. Directional
comparisons between windows hold; absolute rates do not transfer.

**Calibration result.** `scripts/correlation-calibrate` replays a recording
through the production correlation. Against 100 days of one production host
(301,860 timestamped rows, 29,533 eligible, 92.6% attributed) and two days of a
second:

- 98.8% of attributed rows repeat an account-and-check pair: 324 distinct
  account-and-check pairs produced 27,357 attributed rows. One check alone
  contributed 15,916 rows across 26 accounts. A repeated pair can include
  distinct findings on that account, so it does not by itself prove re-reporting.
- The two derivations behave nothing alike. Per batch, the aggregate raised 51
  times in 100 days. Over the persisted set it raised 3 times and stayed raised
  for 76% of the recording, and for 99% of the two-day recording: a latch, not
  an alert, because the first three accounts that ever carried a critical
  finding never left the set.
- The account count was not the lever. Sweeping it over the same replay moves
  the persisted result barely at all, while bounding the set by age moves it
  from 76% raised (unbounded) to 46.1% at a day, 19.6% at six hours, 5.4% at
  two hours and 2.4% at one hour.

Persisted correlation only combines findings from the last hour.
Persisted merges measure age at merge time, so an empty completed scan can
clear expired aggregates; batches retain their dispatch grouping even for
carried-forward findings with older timestamps. The three-account threshold
and the Critical-only limit stay: including High
severities in the account count changed the firing count by one event in 100
days, which does not justify widening what raises a Critical aggregate.

Measured on the live host after the window shipped: of 81 accounts carrying a
critical finding in the whole active set, 75 were still inside the one-hour
window, and 20 rows reaching back to 2026-07-19 were excluded. The window drops
genuinely stale evidence and lets the aggregate clear, but on a host whose
scans restamp 157 critical rows at a time it does not make the aggregate
actionable. That is the remaining defect, not a tuning question.

That defect is now closed: a finding carries the time its condition was first
observed, the latest-state merge keeps it across re-reports, and correlation
judges window membership by it, including when a completed scan replaces its
owned findings. The first observation is not retroactive: upgraded rows adopt
their saved report time and age out one hour after it. The next completed scan
clears expired aggregates without requiring the source findings to disappear.

**Acceptance:** met for the threshold. Re-deriving it again, or changing the
Critical-only limit, uses the same tool and the same recorded-stream evidence.
The figures above record the original calibration run. The replay now applies
the selected window directly to correlation and counts the same windowed
accounts in its sweep; it recomputes on every arrival, including ignored checks.
Recordings cannot reconstruct empty scans, purges or dismissals, so replay
duration describes the observed arrivals rather than exact store history.

---

# Priority 2 -- detection precision and response safety

A false positive here is not cosmetic. Findings drive automatic quarantine and
blocking on customer sites, and every past incident review found real
compromises buried under false-positive floods. The response machinery bounds
how much a bad detector can break, so it sits first in this section; the
precision items follow.

None of these should be closed by raising a threshold or excluding a path.

## Auto-response safety model

**Status:** partial. Automatic file response limits are implemented; the full
risk model and the remaining response families are open.

What exists: `auto_response.dry_run` defaults to on; per-IP blocks are capped
at `max_blocks_per_hour` (default 50) and service restarts at
`max_restarts_per_hour` (3); the virtual-patch mode has a safe default; the
verdict callback lets a panel downgrade a block; process signalling goes
through pidfd; quarantine and virtual patching resolve paths with `openat2`
and `RESOLVE_BENEATH`; the incident correlator has safety caps and a dry-run
mode; firewall changes record a rollback point; `mode: observe` refuses to run
any of it. See [auto-response](docs/src/auto-response.md) and
[observe mode](docs/src/observe-mode.md).

Implemented for automatic file responses:

- Realtime and scheduled quarantine, PHP cleaning and access-file cleaning
  share persistent host and account budgets over a rolling hour.
- Reservations survive reloads, restarts and interrupted actions. Repeated
  failures pause these responses, and unavailable safety state refuses changes.
- Pause warnings are deduplicated while original detections remain visible.
  Account identity comes from account-home paths; unknown paths share a budget.
- Failed cleaning leaves the source and recovery evidence for review.
  Whole-directory and special-file quarantine require manual review.
- Automatic actions revalidate the target after budget persistence, and the
  cleaners receive the same file identity captured before admission.
- Tests cover shared entry points, concurrency, restart, rolling expiry,
  clock rollback, failed state writes, preserved backups and file replacement.

Remaining: no complete action risk table, no shared limits or failure pause
across the other response families, and no complete rollback and detection-time
identity proof for every action. The reputation escalation loop also needs its
own feedback-lifecycle guard; an hourly cap alone does not bound its lifetime.

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
hour and per account, extending the file-response limits to other actions),
mandatory identity revalidation immediately before tiers 3 and 4
(inode and device for files, pidfd for processes, rule handle for firewall
entries), and enough recorded metadata to reverse the action. A response
mechanism that fails N times in a window disables itself and raises a finding
saying so.

**Acceptance:** the tier table is complete or the build fails; every reversible
tier 2 to 4 action has an automated rollback test (firewall, quarantine,
configuration), and irreversible actions declare their recovery limits; a
deliberately broken detector in a test cannot exceed its circuit breaker; PID reuse, symlink swap, bind-mount ambiguity under CageFS
and a file replaced between detection and action are each covered by a test
that proves the action is refused.

The "enough recorded metadata to reverse the action" half has a start:
`internal/actionlog` records the operation, the finding that caused it, the
exact argv, the file digest before and after, and the command that reverses it.
It covers six operations, not the whole tier 3 and 4 set -- see
[action log coverage](#action-log-covers-six-of-twenty-seven-host-changes).

**Size:** 1 week for the table, caps and revalidation; rollback tests on top.

## Action log covers six of twenty-seven host changes

**Status:** open. The stream exists and its coverage is honest but small.

`internal/actionlog` writes one JSONL record per action to
`/var/log/csm/actions.jsonl`, keyed by the operation IDs from
`internal/privops`, carrying actor, `finding_id` (the same identifier the SIEM
audit log emits, so the two streams join), the exact argv when CSM ran a
program, the target file's digest before and after, the result including
refusals, and the command that reverses it. `csm actions` reads it. See
[action log](docs/src/action-log.md).

Six operations write to it: firewall blocks and unblocks, whole-ruleset
changes, file quarantine, surgical file cleaning and process termination. The
capability matrix has an "Action record" column and a test pins the audited set,
so the coverage claim cannot drift -- but twenty-one host-changing operations
are still absent, and for those the daemon log is the only record:

- `respond.*` -- virtual patch, database cleanup, mail freeze and quarantine,
  forward guard and its lookup refresh, WP-Cron fix, permission enforcement,
  mail-auth restart, AF_ALG enforce/kill/marker, BPF egress denial, outgoing
  mail hold, mail delivery gate.
- `integrate.*` -- auditd rules, panel plugin, ModSecurity section, challenge
  snippet, challenge port gate, WAF vendor rule refresh.

The wiring pattern is settled: record at the operation chokepoint, not at the
entry point, so a CLI-driven and an automatic call produce the same record.

There is no stable `action_id` or transactional action lifecycle. A JSONL
outcome is evidence, not durable intent: it cannot alone distinguish a refused
request from a mutation applied just before a crash. Existing rollback paths
are useful, but some effects, including process termination, cannot be undone.

**Decision:** every host mutation goes through a shared lifecycle at its
operation boundary. Keep execution in the responsible domain; the lifecycle
owns identity, admission, persistence, recovery and audit linkage. Reuse
`mode: observe`, `auto_response.dry_run`, existing action-specific switches and
the file-response budget/breaker settings. There is no second policy switch or
parallel set of response limits.

Start with firewall block/unblock. Persist a stable action ID, operation,
actor, target identity, finding/incident links when present, intended effect,
and recovery metadata before mutation. Distinguish planned, executing,
applied and verified from refused, failed, partial, unknown and rolled back.
After a crash, reconcile incomplete records against actual host state before
retrying; an uncertain outcome remains visible until it can be proved. A
stable ID supports deduplication, not a promise of exactly-once host effects.

If intent or budget persistence fails, refuse new automated mutations and
retain the finding. If outcome persistence fails after mutation, preserve the
pending intent, report degraded action health and reconcile before another
attempt. A bbolt transaction cannot atomically commit a filesystem or kernel
change. Keep host I/O outside the database transaction and revalidate target
identity immediately before execution, including on recovery and undo.

Keep JSONL and `csm actions` as operator-facing audit interfaces, linked by
`action_id`. Durable state and audit delivery need a retry/reconciliation
contract so an applied action cannot silently lose its audit outcome. Add
`csm action show <id>` and typed undo dispatch; never execute a stored command
string as the authority to reverse a change. Undo verifies the current target,
records its own linked action, and refuses changed or irreversible targets.
Retention must keep unresolved intent and required recovery evidence. Backup
restore must not resurrect pending actions, jobs or sessions as executable or
authenticated live state; define what is disarmed and what requires review.

**Acceptance:** every tier 2 to 4 operation in `internal/privops` maps to the
lifecycle, including manual, CLI, API, integration and automatic entry points,
with explicit bootstrap/offline handling where the daemon store is unavailable.
The coverage test proves that mapping. Inject failures before and after intent
commit, host mutation, verification, outcome commit and audit delivery; restart
and verify reconciliation, duplicate requests, refusal, partial outcomes and
safe undo. Reuse the existing action-family safety tests and add changed-target
recovery cases. Never report success solely because a request was dispatched.

**Size:** staged by response family. Audit wiring is smaller than the durable
lifecycle, recovery and undo work; estimate each slice after its failure model
is specified.

## Firewall state migration to bbolt

**Status:** partially prepared. Firewall buckets and store methods exist, and
pending configuration rollback already uses bbolt. The engine still reads and
writes its authoritative runtime state in `state.json`.

This belongs with response correctness. JSON writes already use atomic
replacement, and the block path persists intended state before touching the
kernel. Preserve those guarantees; changing the storage format alone cannot
make the database and nftables one transaction.

Inject a domain-owned firewall state interface into the engine. Reuse the
existing blocked, allowed, subnet and per-port buckets behind it, without
exposing bbolt transactions to firewall callers. The existing store schema and
methods are not yet a lossless engine backend: subnet rows lack expiry and use
a different creation-time field, while loaders hide read and decode failures.
Extend the schema and error contract before cutover; preserve original times
and explicit provenance instead of recreating them through add methods. A
failed or corrupt read must not become a successful empty or partial ruleset.
Commit each logical state change together, then update the hot-path cache only
from committed state.
Kernel application and recovery follow the durable action lifecycle above.

Provide a one-shot migration through the owning daemon, or under an exclusive
offline maintenance lock. Validate the entire source, import transactionally,
record a schema/cutover marker, and retain the original JSON for rollback.
A crash at any cutover step must be recoverable. After cutover only bbolt is
authoritative; rollback must preserve post-cutover changes, not silently
restore the now-stale JSON. Keep desired configuration in YAML.

**Acceptance:** preserve block expiry, provenance, operator exclusions, subnet
and port semantics, cache consistency, startup reapplication and failed-write
behavior. Round-trip every engine state field, including temporary subnet
expiry and original timestamps. Test import retries, corrupt input and stored
rows, read failures, concurrent CLI/daemon requests,
crashes around commit and kernel application, upgrade/downgrade and backup
restore. Existing exports disarm pending configuration rollback; preserve that
property and define the treatment of new action intent. Migration must not
reset existing response budgets or failure pauses when those move to bbolt.

**Size:** estimate after the state-owner and recovery slice; not a standalone
file-format conversion.

## Response previews show intent, not the change

**Status:** open. Dry-run says what would happen; it does not show what would
change.

`csm virtual-patch` previews which files it would deny, `db-clean --preview`
lists what it would sanitize, and `auto_response.dry_run` records blocks it
would apply. None of them shows the bytes. An operator deciding whether to let
CSM write to an account's `.htaccess`, or to rewrite a customer's infected PHP
file, has to trust a description of the edit.

The evidence exists after the fact -- the action log records the digest before
and after, and quarantine keeps a pre-clean backup -- so the missing half is
the preview: render the same edit the action would make and print it as a
unified diff without applying it. The three mutations worth covering are the
virtual-patch deny block, the surgical PHP clean, and the `.htaccess` clean.

**Acceptance:** each of those three actions can produce a diff of the exact
change it would apply, with no write; the diff for an applied action matches
what the action log's before and after digests describe; a preview that cannot
be produced fails loudly rather than falling back to applying the change.

**Size:** days. The cleaners already compute the new content; the work is
returning it instead of writing it, and a shared renderer.

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

Source additions depend on resolving
[taint laundering through value encoders](#taint-laundering-through-value-encoders),
[local-path provenance through variables](#local-path-provenance-through-variables),
and [content rules versus archive containers](#content-rules-versus-archive-containers).
These precision defects must be fixed before the new sources join the gate.

Add the pinned Joomla, Drupal and OpenCart sources (URL, SHA-256, exact file
count and in-archive licence path are ready) and source Magento, whose pins
are not ready yet, and recalibrate the engine status budgets, which scale
with corpus size and were set for a WordPress-only corpus: `phptaint
partial_parse`, `jstaint oversize` and `jstaint parse_error`. Recalibration is
deliberate and belongs in the same commit as the sources, with the measured
numbers in the message. Each of those CMSes is listed as `pending` in the
manifest today; adding its source removes the pending entry in the same
commit, and the manifest test refuses a supported CMS that is neither pinned
nor pending. Non-WordPress CMS adapters ship without any false-positive gate
until this lands. See [the corpus gate documentation](docs/src/clean-corpus.md).

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

**Status:** open; a small file-content bundle exists, the recorded-stream half
does not.

`internal/selftest` holds nine samples -- six adversarial, three benign
controls -- with a recorded verdict per rule set, and gates both `malware.yml`
and `malware.yar` in CI. It fails in both directions: a sample that stops being
detected is a regression, and a recorded gap that starts firing has to be
cleared in the bundle, so no gap becomes permanent by inertia. `csm selftest`
runs the same bundle on an installed host. Samples are base64-encoded at rest
and decoded only in memory, which solves the antivirus problem the YARA
fixtures hit.

That covers file content only, at detector level. Two things it does not do.

**Breadth.** Nine samples is a smoke test, not a corpus. Coverage must reach
web shells, PHP droppers, obfuscated malware, malicious WordPress plugins and
themes, credential stealers, injected JavaScript, phishing kits, spam scripts,
mail-account abuse, persistence mechanisms, cron abuse, suspicious binaries and
archive-based payloads. Most already exist as scattered test fixtures; the work
is collecting them under the existing manifest with expectations.

**Recorded streams.** Detection that starts from an event rather than a file --
authentication attempts, mail log lines, access-log patterns, spool activity --
has no replay path at all, and neither does the correlator. Each sample needs
the expected findings, the expected incident, and whether automatic remediation
is expected, optional or prohibited.

**Acceptance:** the replay runs at release acceptance; a detector change that
loses a previously detected sample fails the run, which the file-content half
already does; the incident half of the corpus is the evidence harness that
[Priority 4](#priority-4----correlation) needs, so both share one
recorded-stream format.

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

**Status:** open; the inventory stage is done. The daemon is one root process.

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

The inventory stage is complete: `internal/privops` lists every operation that
needs privilege beyond reading CSM's own files, with what it writes, the config
key that stops it and what an operator loses by withholding the privilege.
`csm privileges` prints it, `docs/src/capability-matrix.md` ships it, and two
gates in `internal/ci` compare it against the packaged systemd unit in both
directions, so a writable-path grant that no operation claims fails the build.
That table is the action set the helper has to cover.

`mode: observe` is the interim posture for operators who will not grant a root
daemon the ability to act: detection and alerting run, automatic remediation
and integration deployment do not. It reduces what the root process *does*, not
what it *could* do, so it is a stopgap for this item rather than a substitute.

Remaining stages, each shippable on its own: the helper for firewall, then
signals and quarantine, then privileged configuration/filesystem writes; then
descriptor passing for fanotify and BPF; then dropping capabilities in the main
process. Each family first needs its safety classification and durable action
contract, not completion of every other family's migration.

Peer credentials authenticate the caller, not the requested operation. The
helper must enforce target/account scope, identity, permitted verbs and safety
policy even if the main process is compromised. Do not expose arbitrary shell,
command execution or unrestricted file-write RPCs. Bound request sizes and
execution time; test unknown verbs, malformed requests, stale identities and
unauthorized peers. Decide how the helper verifies persisted intent and safety
admission before shipping the first helper verbs. A record in a store writable
by the main process is caller-controlled too; reading it back through RPC does
not make it trusted approval. Define which process owns the store and how
helper-enforced policy, budgets and replay protection survive a compromised
caller and helper restart. If the main process remains the owner, its records
are evidence only: it must not be able to reset or forge the helper's safety
admission. Keep one owner per live database and protect admission authority
from the caller. Test forged intent, replay and attempted budget reset as well
as valid requests. Include socket ownership, protocol compatibility and
unavailable-helper behavior in the first slice. Retain findings when mutation
cannot safely proceed.

**Acceptance:** the main process holds no capability it does not use; tests
prove an RPC request cannot escape the intended path, user, process or
firewall scope, including through symlinks, bind mounts and PID reuse; the
code that executes as root is small enough to be read in one sitting.

**Size:** weeks, staged. The largest item on this list.

## Optional MFA for browser administrators

**Status:** open. Browser sessions, expiry and revocation are implemented.

Add optional WebAuthn for administrator logins with an explicit enrollment,
recovery and credential-loss story. Reuse the existing session and named-token
identity boundary; define how enrollment and recovery invalidate active sessions.

**Acceptance:** enrollment, authentication, lost-device recovery and removal
have tested authorization and session-revocation behavior; API token scopes
remain unchanged. See [browser sessions](docs/src/webui.md#browser-sessions).

## Web UI module split

**Status:** open. HTTP handlers mix request handling with the logic that
quarantines, blocks and rewrites configuration.

Split the handlers by domain -- findings, incidents, firewall, quarantine,
scans, mail, settings, health -- behind narrow interfaces, and keep the
security-sensitive logic out of the handler files so it can be reviewed and
tested on its own. The authentication/session boundary is extracted and
browser sessions are implemented. Move each remaining domain with its
action/job slice, and complete the split before the external review so the reviewer reads the boundary rather than the
handlers.

Handlers authenticate, authorize, decode and validate request shape, call a
domain service, then encode the response. Services own policy and action/job
submission and are shared with CLI and automatic callers. Extract only the
boundary needed for each slice; file splitting alone does not reduce privilege.

**Acceptance per slice:** the extracted domain has interface tests; read-only
authorization and CSRF checks survive extraction; HTTP, CLI and automatic paths
cannot bypass its service-level safety checks. **Final acceptance:** no handler
performs a host mutation directly. Use the existing privilege inventory to
track remaining mutation coverage without gating sessions on the full split.

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
fanotify integration. Schedule it after the first stage of privilege
separation has landed so the review covers the new security boundary.
Browser sessions are already implemented. Publish a summary of findings and
remediation, and repeat a focused review after each major architecture change.

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
stale-copy failure mode that completeness guards prevent.

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

## Observation, finding, incident and action identity

**Status:** existing event sources, findings, incidents and action records are
separate; a shared provenance contract for replay and sequence joins is open.

Define an observation as a normalized fact with source, event time and verified
account/host identity; a finding is a detector conclusion, an incident links
related evidence, and an action records a response. Extend existing models and
IDs instead of replacing the correlator or requiring an incident before every
response. Operator actions may have no finding or incident.

**Acceptance:** selected observations join to findings, incidents and actions
through stable identifiers in the same replay format used by the attack corpus.
Distinguish event time, first observation and later reports so rescans and
retries cannot manufacture independent corroboration. Record provenance,
missing attribution, retention and redaction rules. Capture only evidence
needed for explanation and replay; an unbounded raw-log archive is out of scope.

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

**Status:** direction chosen; fleet protocol and correlation remain open.
Formerly audit item Y12.

Use authenticated outbound ingest and panel-side correlation, extending the
existing webhook/export contracts. Agents do not form a peer trust mesh or
require an inbound fleet endpoint. The panel owns its storage choice and can
reuse its existing infrastructure independently of the agent's bbolt store.

**Acceptance:** define host and tenant identity, schema versioning, deduplication,
replay handling, credential rotation/revocation, bounded retries and backlog,
and visible delivery loss. A compromised host cannot submit as another host or
tenant. A disconnected or rejecting panel does not stop local detection or
response. Fleet delivery and the
[fleet validation evidence](#fleet-validation-evidence) work share the same
channel and privacy contract; opt-in metrics still need a separate consent
and redaction decision.

---

# Priority 5 -- known coverage gaps

## Three obfuscation shapes are missed by both rule sets

**Status:** open. Measured by the self-test bundle, recorded there as gaps.

Neither `malware.yml` nor `malware.yar` fires on:

- a request parameter passed to `assert` with the function name split across
  string fragments;
- `base64_decode` assembled from fragments and handed to `eval`;
- a callable function name built with `chr()`, then invoked on request input
  (`$s = chr(115)...; $s($_GET['cmd'])`).

All three are the same idea -- keep the dangerous identifier out of the file as
a literal -- and all three are common enough in real drops that a scanner that
misses them is judged on it. A fourth shape, an unauthenticated uploader that
writes to a caller-supplied path, is caught by the YARA rules and missed by the
YAML ones, which is the known `.yml`/`.yar` parity gap.

Detection may still reach these through the taint analyzer, PHP Shield or the
behavioural checks; the gap is in the signature engines, which is where a
scanner is usually evaluated.

Writing rules for them is not a small change: identifier reconstruction rules
are exactly the shape that produces false-positive floods, so any rule here has
to clear the clean-corpus gate before it ships, and the realtime engine's
regex limits constrain what can be expressed. Treat this as detector work with
a corpus result attached, not as three rule edits.

**Acceptance:** each shape is detected by at least one engine with no new
finding on the clean corpus; the recorded gap in `internal/selftest` is cleared
in the same commit, which the bundle's own gate enforces.

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

**Status:** scan persistence and restart reporting exist; general job classes
and mutation reconciliation remain open.

`ScanJobManager` already uses a narrow store interface and persisted job and
finding records. Restart marks unfinished scans as `error` with
`daemon_restarted`; that is an honest interruption report, not resumability.
Extend this manager and API contract rather than adding a second queue.

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
Keep existing scan clients compatible. Record actor, operation type and linked
action IDs; define queued, running, terminal, interrupted and reconciling
semantics per class. Jobs track work while actions track mutations: restarting
a job must not repeat a completed mutation. Test client disconnect, duplicate
submission, cancellation at safe boundaries, restart and persistence failures.
Store import needs an explicit maintenance handoff so replacing the store
cannot erase the job's only completion/recovery record.

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

**Status:** panel-side channel chosen; evidence schema, consent and privacy
rules remain open.

The defaults for confidence, severity and remediation are tuned from a handful
of production servers read by hand. The panel data plane already carries every
finding off the host (per-finding HMAC webhook, SSE stream, audit log with
tenant identity), so the cheapest fleet evidence is panel-side: which findings
led to a confirmed incident, which were dismissed, per detector, per platform.
Opt-in anonymised operational metrics from installations without a panel are
the alternative, and need a documented privacy boundary before any code.

**Acceptance:** use the outbound fleet ingest contract in Priority 4;
define consent, minimization and redaction before collecting optional metrics;
detector noise and resource usage compared across
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
instead of falling behind quietly, using the implemented
[queue health reporting](docs/src/api.md#protection-queue-health) and
[required ownership inventory](docs/src/production-tests.md#required-queue-inventory).

## Storage measurements and domain contracts

**Status:** partial boundaries exist; transaction instrumentation and domain
conformance coverage remain open. `internal/store.DB` already hides its bbolt
handle, and scan jobs already consume a narrow interface.

Add consumer-owned interfaces where work above needs them, starting with
firewall state and actions. Keep domain types and atomic operations explicit:
a generic Get/Put wrapper or unrelated CRUD calls cannot express a committed
action admission with its budget update. Preserve errors, ordering, pagination,
retention and transaction semantics in conformance tests, including failed
commits and reopen. Do not build a second backend without a measured need.

Extend the existing metrics and queue-health surfaces with write wait versus
transaction duration, read duration, commit failures, batch sizes, pending
writes, physical database size, reclaimable pages, and backup/compaction cost.
Record representative contention and longest reads under the resource budgets;
keep labels bounded and free of account, path or address identifiers.

Audit transaction lifetimes: copy values before returning them, then perform
HTTP/SSE output, network calls, scans, host commands and expensive response
encoding outside the transaction. Snapshot copying is an explicit measured
exception: export already copies to a local file inside a read transaction,
then archives it after closing the transaction. Do not replace it with an
unbounded in-memory database copy or hold it open for a slow client.

**Acceptance:** contention, slow readers and failed writes are observable in
repeatable workloads; storage calls on each migrated path preserve the domain
contract; backup and compaction measurements expose their impact on live work.
Use the results before revisiting the local database choice.

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
