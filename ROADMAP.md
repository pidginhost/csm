# CSM Engineering Roadmap

Open engineering work and release acceptance checks, ordered so a contributor
can pick the top item and start. Completed work is removed from this file;
commits and `CHANGELOG.md` are the archive. End-user documentation lives in
`docs/`; design rationale lives in the book's design notes, starting with
[architecture direction](docs/src/design/architecture-direction.md).

## How this list is ordered

CSM runs as root on live web servers and takes automatic action on them.
Items are ordered by harm to a protected server, not by effort:

1. **Protection that fails silently.** Stops working while everything still
   reports healthy.
2. **Precision and response safety.** Findings drive automatic quarantine and
   blocking; real compromises have hidden under false-positive floods.
3. **Root attack surface, supply chain and release integrity.** CSM runs as
   root and parses attacker-controlled input.
4. **Correlation.** Many weak signals into few strong ones.
5. **Known coverage gaps.** Missed detections, mitigated by overlapping layers.
6. **Operability and validation.** A server stays protected while it waits.
7. **Performance budgets and debt.**

A tier with no open item has no heading below.

## Conventions

- Each item has a Problem, a testable Acceptance, Depends on when there is
  one, and a Size: S is days, M is one to two weeks, L is longer and staged.
- A fixed production false positive gets a regression test before the fix; a
  correlation or response bug found in production gets a replay fixture.
- Every new selecting table ships with a completeness guard; new checks and
  incident sets need a decision in the
  [incident policy contract](docs/src/incidents.md#kinds).
- Prove and improve existing detectors before adding new ones.
- Items are named, not numbered. `ROADMAP item N` in old commits is frozen;
  resolve it through `git log`, not this file.

## Release readiness gates

These gates run in the internal CI pipeline, which requires signed
multi-architecture builds, fixture privacy, the pinned clean corpus, the
production-tag and real-kernel jobs, release preflight and cloud integration
on fresh servers. Two gates are open:

- [ ] A licensed cPanel/CloudLinux environment behind the protected
  `INTEGRATION_CPANEL_IMAGE` variable; see
  [cPanel acceptance](docs/src/cpanel-release-tests.md). **Blocked:** no
  licence covers disposable CI clones and the cloud catalogue has no cPanel
  image, so a tag must set `CSM_RELEASE_WITHOUT_CPANEL` with a reason and
  record `cpanel_coverage: "absent"`. A single-account licensed test server
  now exists for manual end-to-end runs; CI creates fresh servers per run, so
  wiring a fixed licensed host into the pipeline is the open decision. The
  gate covers install, upgrade, rollback, panel layouts, a WordPress
  workload, the attack replay corpus and reinstall.
- [ ] Detection-quality evidence per release, as defined under
  [detection quality metrics](#detection-quality-metrics-per-release).

CI kernels are newer than the deployed EL8 and CloudLinux 8 kernel, so
kernel capabilities are probed at runtime and reported by `csm doctor`; a
new kernel dependency needs a runtime probe and a doctor check.

## Priority 2 -- detection precision and response safety

None of these should be closed by raising a threshold or excluding a path.

### WAF block scoring needs recorded-stream evidence

**Problem:** mapping the emitted ModSecurity block names into the attack
database is a scoring change whose branch has never run on real data, and
realtime denies, summaries and escalation findings can describe the same
traffic. The names stay out of scoring until decided.

**Acceptance:** a replay of recorded block streams, with the confidence and
operator-exclusion checks preserved, reports the overlap with existing
attack evidence and the score change per mapping, and the decision cites it.

**Depends on:** [attack replay corpus](#attack-replay-corpus). **Size:** M.

### Auto-response safety model

Design: [auto-response safety model](docs/src/design/auto-response-safety-model.md).

**Problem:** file responses share persistent budgets, failure pauses and
identity revalidation, and the risk tier table in `internal/privops` has a
completeness test. Automatic IP responses also pass through the admission
ledger. With `auto_response.dry_run` false and the firewall enabled outside
observe mode it applies automatic IP blocks within its ceiling and the
temporary set; in dry run it forecasts occupancy, priority eviction,
equal-priority rotation and per-scope shares. Other response families have no shared limits
or failure pause, not every action has a rollback and identity proof, and the
reputation escalation loop has no feedback-lifecycle guard.

**Acceptance:** every reversible tier 2 to 4 action has a rollback test; a
broken detector cannot exceed its breaker; PID reuse, symlink swap, CageFS
bind-mount ambiguity and a file replaced after detection are each refused by
test; withheld Critical responses stay visible under overload.

**Depends on:** [durable action lifecycle](#durable-action-lifecycle).
**Size:** L.

### Durable action lifecycle

Design: [durable action lifecycle](docs/src/design/durable-action-lifecycle.md).

**Problem:** `internal/actionlog` records only some of the privops
inventory's tier 2 to 4 operations; the rest leave only a daemon log line,
and a JSONL outcome cannot tell a refused request from a
mutation applied just before a crash. The durable firewall action service
exists behind engine injection. The admission ledger records each automatic
IP response's intent before execution, settles attempts left by a crash and
holds blocks from unresolved attempts out of the kernel at startup. Its
block executor (per-member batch checks, kernel readback, proof of an
existing block) runs those blocks on hosts outside dry run. Reader cutover,
migration, restore and operator recovery interfaces remain open.

**Acceptance:** every tier 2 to 4 operation maps to the lifecycle from every
entry point and the coverage test proves it; faults injected around intent
commit, mutation, outcome commit and audit delivery recover through
reconciliation, refusal and safe undo; `csm action show <id>` and typed undo
exist.

**Size:** L.

### Firewall state migration to bbolt

Design: [firewall state migration](docs/src/design/firewall-state-migration.md).

**Problem:** the lossless storage contract is implemented and tested without
runtime callers, but the engine still keeps its authoritative state in
`state.json`; cutover, migration, restore, downgrade and recovery are open.
The contract predates the unverified mark on block rows and the firewall
clock checkpoint in `lease.json`, so the cutover must carry both.

**Acceptance:** every engine state field round-trips with original
timestamps, including unverified marks; corrupt rows, read failures,
concurrent requests, crashes around commit, downgrade and backup restore
are tested; an unreadable store keeps the `state.json` set-aside behaviour;
migration resets no response budget or failure pause and never moves the
firewall clock backward.

**Depends on:** the firewall slice of the item above. **Size:** M.

### Taint laundering through value encoders

**Problem:** Joomla writes `return var_export($strings, true);` into its
language cache, and `internal/phptaint` has no notion of a laundering
function. Decision needed: which encoders (`var_export`, `json_encode`,
`serialize`, integer casts) neutralise a code-execution sink without hiding
an `eval` of a decoded round-trip.

**Acceptance:** the Joomla language cache stops reporting; a laundered value
later decoded and executed still reports; the WordPress corpus stays at zero.

**Size:** M.

### Local-path provenance through object properties

**Problem:** OpenCart 4's template engine includes a template whose path is
held in object properties set from method parameters, in a method that also
calls `extract()`, so each install reports a low-confidence `include` source.
A local path held in a plain variable is not the cause: measured on
WordPress, OpenCart 3 and 4, Joomla and Drupal, no finding depends on one.
`is_file()` does not prove a path local, because remote wrappers support it.

**Acceptance:** the OpenCart 4 template engine stops reporting; a path built
from request input, from a parameter the analysis cannot resolve, or from a
property written from either still reports.

**Size:** M.

### Content rules versus archive containers

**Problem:** multi-string rules match across libraries bundled in one PHAR;
`network_socks_proxy` fired on a vendored developer tool inside a supported
CMS. Decision needed: bounded offset windows, or an explicit treatment of
`.phar`, `.zip` and `.jar` containers now scanned as flat blobs.

**Acceptance:** the vendored tool stops matching, a real single-file proxy
still matches, and the fix applies to the rule class.

**Size:** M.

### Clean corpus growth and per-detector false-positive tracking

**Problem:** the corpus is pinned WordPress packages only; Joomla, Drupal and
OpenCart pins are ready and `pending` in the manifest, Magento and PrestaShop
are not. The corpus then needs real-world content (common plugins, page
builders, premium themes, admin tools) under a consent and scrubbing procedure. See
[the corpus gate](docs/src/clean-corpus.md).

**Acceptance:** the corpus runs on every release candidate and reports false
positives per detector and release; an unacceptable detector is reworked or
disabled, never allowlisted; defaults are recalibrated from the numbers.

**Depends on:** the three items above. **Size:** L.

### Attack replay corpus

**Problem:** file content is gated by the
[attack replay corpus](docs/src/attack-corpus.md) on realtime analysis, the
deep tier and the full account scan, with expected findings and remediation
per path. Event-driven detection has partial replay (`scripts/crawl-calibrate`
for access logs, `scripts/correlation-calibrate` for finding streams);
authentication, mail log and spool activity have none (stage 2), and no
sample states its expected incident (stage 3).

**Acceptance:** the replay runs at release acceptance; losing a detected
sample fails the run; each sample carries expected findings and incident;
the incident half shares one stream format with the
[correlation evidence harness](#correlation-evidence-harness).

**Size:** L.

### Detection quality metrics per release

**Problem:** release evidence records package hashes, upgrade results and
cPanel coverage, nothing about detection.

**Acceptance:** every tag records sites and samples tested, detection rate,
false positives per site and day, actions exercised and rolled back,
detector regressions against the previous tag and the performance impact
under [resource budgets](#resource-and-performance-budgets); a tag is refused
past defined thresholds.

**Depends on:** [attack replay corpus](#attack-replay-corpus), the clean
corpus report. **Size:** M.

## Priority 3 -- root attack surface, supply chain and release integrity

### Privilege separation

Design: [privilege separation](docs/src/design/privilege-separation.md).

**Problem:** the daemon runs as root under [service
confinement](docs/src/service-confinement.md). YARA-X, PHP taint analysis,
zip listings and mail attachments are already parsed in unprivileged workers;
a bug anywhere else in the daemon is still a root compromise. The inventory
stage is done. Remaining stages, each shippable alone: the helper for
firewall, then signals and quarantine, then privileged writes, then
descriptor passing for fanotify and BPF, then dropping capabilities in the
main process.

**Acceptance:** the main process holds no capability it does not use; an RPC
request cannot escape its path, user, process or firewall scope, including
through symlinks, bind mounts and PID reuse; forged intent, replay, budget
reset and unauthorized peers are refused; the root code is readable in one
sitting.

**Depends on:** [durable action lifecycle](#durable-action-lifecycle).
**Size:** L.

### Optional MFA for browser administrators

**Problem:** administrator logins have no second factor. Add optional
WebAuthn with an enrollment, recovery and credential-loss story on the
existing session and named-token boundary.

**Acceptance:** enrollment, authentication, lost-device recovery and removal
have tested authorization and session-revocation behaviour; API token scopes
are unchanged. See [browser sessions](docs/src/webui.md#browser-sessions).

**Size:** M.

### Web UI module split

**Problem:** HTTP handlers mix request handling with the logic that
quarantines, blocks and rewrites configuration; the session boundary is
extracted, the other domains still need narrow services shared with CLI and
automatic callers.

**Acceptance:** per slice, interface tests exist, read-only authorization and
CSRF checks survive, and no path bypasses service-level safety checks;
finally, no handler performs a host mutation directly.

**Size:** L.

### Parser and input hardening

**Problem:** many parsers carry fuzz targets, and YARA-X scanning, PHP
parsing, mail extraction and phishing-kit archive listing run in unprivileged
workers, but no inventory maps every parser of external input (archives,
logs, configuration, CMS state, PHP, JavaScript, mail, challenge and control
protocols) to a fuzz target.

**Acceptance:** that inventory has a completeness test; decompression ratio,
recursion, nesting, size and parser time each have a limit and a test that
exceeds it; symlink chains and CageFS mount edge cases are tested;
race-detector stress runs cover concurrent paths.

**Size:** L.

### External security review

**Problem:** nobody outside the project has reviewed the root attack surface
(web UI and API, sessions, privileged filesystem operations, quarantine,
nftables, process termination, installer verification, archives, IPC, BPF
and fanotify).

**Acceptance:** a report covering that surface is published with remediation
status after the first privilege separation stage lands; a focused review
repeats after each major architecture change.

**Depends on:** [privilege separation](#privilege-separation), first stage.
**Size:** M.

## Priority 4 -- correlation

The incident correlator in `internal/incident` is extended, not replaced;
the findings-level `CorrelateFindings` in `internal/checks` is the weak
layer. Every item after the harness depends on it.

### Correlation evidence harness

**Problem:** correlation has no equivalent of the corpus gate: recorded
finding streams in, expected incidents out, with compromised streams from
the attack corpus and clean streams that must form nothing.

**Acceptance:** real incidents from past reviews replay to their known
incident, clean streams form nothing, the run reports correlation
false-positive and false-negative rates, and every production correlation
bug becomes a fixture before its fix.

**Depends on:** [attack replay corpus](#attack-replay-corpus). **Size:** M.

### Cross-account correlation identity gaps

**Problem:** attribution loss is visible in `csm doctor` (see
[incidents](docs/src/incidents.md#cross-account-correlation-of-findings)),
but a per-domain mail aggregate stays unattributed unless every arrival
proves one authenticated mailbox or user, mailbox identities outside cPanel
are unresolved, and the Critical-only aggregate never combines corroborating
High findings. Replay through `scripts/correlation-calibrate` showed the
account count was not the lever; bounding by first-observation time was.

**Acceptance:** a verified single-submitter mail aggregate carries its owner
and a mixed one stays unattributed; a non-cPanel mailbox identity resolves
or is reported by doctor; widening beyond Critical cites a calibration run.

**Size:** M.

### Observation, finding, incident and action identity

**Problem:** event sources, findings, incidents and action records have no
shared provenance contract for replay and sequence joins.

**Acceptance:** observations join findings, incidents and actions through
stable identifiers in the attack corpus replay format; event time, first
observation and later reports are distinct so rescans cannot manufacture
corroboration; retention and redaction rules are recorded.

**Size:** M.

### Corroboration grading

**Problem:** a Warning corroborated by an independent signal on the same
account, file or address should escalate; an uncorroborated Warning in a
noisy family should demote.

**Acceptance:** replayed real incidents rise above their noise, replayed
clean streams form nothing, and demotion never hides a Critical.

**Size:** M.

### Sequence correlation

**Problem:** a dropper, then a new administrator, then an outbound connection
is one story; CSM emits three unrelated findings.

**Acceptance:** an ordered sequence yields one incident carrying its steps;
the same findings out of order or far apart do not.

**Size:** M.

### Join findings on file identity

**Problem:** realtime, YARA and the taint engines each flag the same file
separately, so one file can fill several rows on the Findings page. Taint runs
only in the scheduled deep scan and realtime findings never enter the stored
findings list, so no existing join point holds both.

**Decision:** fold same-file rows in the Findings view. This covers the
scheduled layers and leaves alerts, automatic response and dismissals working
per layer. A persistent file-evidence index that also joins realtime hits waits
until operators need realtime and scheduled evidence joined for a response
decision.

**Acceptance:** one file tripping three scheduled layers shows as one row with
three pieces of evidence and the strongest severity, and Dismiss, Fix and
Re-check still act on each layer's finding.

**Size:** M.

### Spray correlation ingesting HTTP signals

**Problem:** the HTTP abuse checks correlate under the WordPress brute-force
group but do not feed the account-spray signal set, which is mail-only.

**Acceptance:** the HTTP checks join the spray set with a request-target
identity dimension, and recorded traffic shows a distributed low-rate
campaign correlating without raising per-source false positives.

**Size:** M.

### Cross-server fleet ingest

**Problem:** the direction is authenticated outbound ingest and panel-side
correlation over the existing webhook and export contracts, with no peer
mesh or inbound endpoint; the protocol and the correlation are open.

**Acceptance:** host and tenant identity, schema versioning, deduplication,
replay handling, credential rotation, bounded retries and visible delivery
loss are defined; a compromised host cannot submit as another; a rejecting
panel never stops local protection.

**Size:** L.

## Priority 5 -- known coverage gaps

### Three obfuscation shapes are missed by both rule sets

**Problem:** neither rule set fires on `assert` with a fragmented name on
request input, on `base64_decode` assembled from fragments into `eval`, or
on a `chr()`-built callable invoked on request input, including a callable
decoded from a digit string three digits per character; the self-test bundle
records them as gaps, and identifier reconstruction rules produce
false-positive floods, so this is detector work with a corpus result.

**Acceptance:** each shape is detected by at least one engine with no new
clean-corpus finding, and the recorded gap in `internal/selftest` is cleared
in the same commit.

**Size:** M.

### Scheduled scans do not consult package checksums

**Problem:** the realtime path skips files whose hash matches the official
wordpress.org release; the scheduled scans and the re-check never ask, so a
stock file with an odd-looking loader is reported on every deep scan.

**Acceptance:** the deep scan and the re-check use the realtime checksum
cache with the same fail-closed rules; a stock file stops reporting; a
modified copy still does.

**Size:** M.

### Account and CMS scans on hosts without cPanel

**Problem:** `account_roots` reaches real-time document-root rules, scheduled
YARA sweeps, web-root performance checks and remediation. Other account and
CMS scans use platform account homes but still depend on `public_html`,
addon-directory patterns or cPanel metadata. Plesk account homes are detected,
yet site coverage remains uneven; custom roots under `/var/www` can be missed.
See [deep check platform support](docs/src/detection-deep.md#platform-support).

**Acceptance:** every account and CMS scan finds sites through one resolver
that honours `account_roots` and the detected panel layout; the same planted
samples produce the same findings under a cPanel layout, `/var/www` and
Plesk vhosts; `csm doctor` reports a host where no site roots are known.

**Size:** L.

### CMS discovery deeper than one directory below a document root

**Problem:** WordPress discovery merges the panel's document-root map with
account-home patterns, so undeclared nested installs can be missed, and the
other adapters in `cmsDiscover` do not use the panel map. See
[platform support](docs/src/detection-deep.md#platform-support).

**Acceptance:** depth and cost budget are decided per CMS; nested mapped and
unmapped installs, custom roots, symlinks, cancellation and incomplete
traversal are tested; each adapter's limits are documented.

**Size:** M.

### Accounts on additional home partitions

**Problem:** a single-account scan resolves an account whose home sits on an
additional home partition such as `/home2`, but `csm scan --all --full` skips
those accounts, the scheduled deep scan does not walk their document roots,
and quarantine cannot write there because the service sandbox grants `/home`
only.

**Acceptance:** account enumeration, the deep scan and quarantine resolve
homes through the account registry with no hardcoded `/home`; an account on a
second partition is scanned by all three paths, and a file there is
quarantined and restored under the sandbox.

**Size:** M.

### Email AV on Postfix hosts

**Problem:** Email AV scans attachments only on the Exim spool. On a Postfix
host ClamAV runs through rspamd's antivirus module, which CSM does not watch:
infected mail is rejected without a finding or Email page statistics, a
stopped clamd or stale signatures raise no alert, and CSM's YARA-X rules and
archive unpacking never see the mail. The scanner interface, either a socket
that speaks the clamd protocol rspamd already uses or an rspamd Lua plugin,
and the fail mode need a short design before work starts.

**Acceptance:** on a Postfix host with rspamd, a message rejected as infected
raises the same finding as Email AV on Exim and counts on the Email page; an
unreachable clamd and signatures past the configured age each raise a finding
that clears once fixed; CSM's YARA-X rules scan every attachment through a
scanner rspamd calls, a match rejects the message, and a scanner timeout or
outage follows the configured fail mode within rspamd's own timeout; an
integration test against real Postfix and rspamd rejects an EICAR attachment
and a YARA test sample end to end.

**Depends on:** the Postfix antispam integration's scope rule and scan
records.

**Size:** M.

## Priority 6 -- operability and validation

### Job model for every long-running operation

**Problem:** scans run as persisted jobs, but database cleanup, store export
and import, rule and GeoIP updates, batch quarantine and virtual patching
still hold a privileged HTTP request open and run unwatched after a
disconnect.

**Acceptance:** every operation over a few seconds returns a job id and
reports through the scan endpoints; cancellation is supported where safe and
refused where not; job state survives restart; per-class concurrency limits
apply; restarting a job never repeats a completed mutation.

**Size:** L.

### Validate CageFS mount points

**Problem:** `csm doctor` checks the PHP Shield event directory mount only.
A mount-point entry whose source is missing is normal: a stock CloudLinux 8
cPanel host lists entries for software it does not run, and `cagefsctl`
prints nothing about them. The `cagefsctl` errors this item was opened for
have not been reproduced.

**Acceptance:** a reproduced `cagefsctl` error caused by a mount-point entry
is reported by doctor with the entry named; a missing source alone is not.

**Size:** S.

### Fleet validation evidence

**Problem:** defaults are tuned from a handful of servers read by hand; the
panel already receives every finding, so the cheapest evidence is which
findings became confirmed incidents or were dismissed, per detector and
platform.

**Acceptance:** evidence travels over the fleet ingest contract; consent,
minimization and redaction are defined before any optional metric; detector
noise per platform feeds the clean corpus calibration.

**Depends on:** [cross-server fleet ingest](#cross-server-fleet-ingest).
**Size:** M.

## Priority 7 -- performance budgets and debt

### Resource and performance budgets

**Problem:** overload has been found by operators (out-of-memory restarts, a
copy-on-write regression) rather than by tests; benchmarks exist but no
budget is written down.

**Acceptance:** written CPU, memory, I/O and event-latency budgets for a
reference server; benchmarks for large account and file counts, mail volume
and event rates run per release into the detection-quality report; every
queue has a stated cap; a named degraded mode builds on
[queue health](docs/src/api.md#protection-queue-health).

**Size:** L.

### Storage measurements and domain contracts

**Problem:** `internal/store.DB` hides its bbolt handle, but transaction
instrumentation and domain conformance coverage are missing; consumer-owned
interfaces start with firewall state and actions, and HTTP output, network
calls, scans and host commands stay outside transactions.

**Acceptance:** write wait, transaction and read duration, commit failures,
database size and compaction cost are exposed with bounded labels;
contention, slow readers and failed writes show in repeatable workloads;
conformance tests cover each migrated path.

**Size:** M.

### Configuration defaults from one source

**Problem:** a default is written in the packaged `csm.yaml.default`, in the
built-in defaults and in the parser that tells an omitted key from an
explicit zero; a parity test pins every difference with a reason, but each
new key is still written three times.

**Acceptance:** built-in defaults and omitted-key handling derive from one
table; an omitted key, an explicit zero and an explicit empty list each keep
their current meaning, proven per key; the parity test covers only the
packaged-policy differences.

**Size:** M.

### WordPress companion plugin for signed-cookie operator bypass

**Problem:** a logged-in administrator cannot obtain the challenge bypass
cookie without a manual request; the plugin lives in a separate repository.

**Acceptance:** [challenge pages](docs/src/challenge.md) names
`/challenge/admin-token` as a stable contract whose breaking changes need a
roadmap item and carries an integration note for the plugin.

**Size:** S.
