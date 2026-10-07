# CSM Engineering Roadmap

Open engineering work and release acceptance checks, ordered so a contributor
can pick the top item and start. Completed work is removed from this file;
commits and `CHANGELOG.md` are the archive. End-user documentation lives in
`docs/`; design rationale lives in the book's design notes, starting with
[architecture direction](docs/src/design/architecture-direction.md).

## How this list is ordered

CSM runs as root on live shared-hosting servers and takes automatic action on
them. Items are ordered by harm to a protected server, not by effort:

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

Required dependencies are defined in [.gitlab-ci.yml](.gitlab-ci.yml): signed
multi-architecture builds, fixture privacy, the pinned clean corpus, the
production-tag and real-kernel jobs, release preflight and cloud integration
on fresh servers. Two gates are open:

- [ ] A licensed cPanel/CloudLinux environment behind the protected
  `INTEGRATION_CPANEL_IMAGE` variable; see
  [cPanel acceptance](docs/src/cpanel-release-tests.md). **Blocked:** no
  licence exists for disposable CI clones and the cloud catalogue has no
  cPanel image, so a tag must set `CSM_RELEASE_WITHOUT_CPANEL` with a reason
  and record `cpanel_coverage: "absent"`. A permanent licensed test server is
  the realistic fix; the gate covers install, upgrade, rollback, panel
  layouts, a WordPress workload, the attack replay corpus and reinstall.
- [ ] Detection-quality evidence per release, as defined under
  [detection quality metrics](#detection-quality-metrics-per-release).

CI kernels are newer than the deployed EL8 and CloudLinux 8 kernel, so
kernel capabilities are probed at runtime and reported by `csm doctor`; a
new kernel dependency needs a runtime probe and a doctor check.

# Priority 2 -- detection precision and response safety

None of these should be closed by raising a threshold or excluding a path.

## WAF block scoring needs recorded-stream evidence

**Problem:** mapping the emitted ModSecurity block names into the attack
database is a scoring change whose branch has never run on real data, and
realtime denies, summaries and escalation findings can describe the same
traffic. The names stay out of scoring until decided.

**Acceptance:** a replay of recorded block streams, with the confidence and
operator-exclusion checks preserved, reports the overlap with existing
attack evidence and the score change per mapping, and the decision cites it.

**Depends on:** [attack replay corpus](#attack-replay-corpus). **Size:** M.

## Auto-response safety model

Design: [auto-response safety model](docs/src/design/auto-response-safety-model.md).

**Problem:** file responses share persistent budgets, failure pauses and
identity revalidation, and the risk tier table in `internal/privops` has a
completeness test; other response families have no shared limits or failure
pause, not every action has a rollback and identity proof, and the
reputation escalation loop has no feedback-lifecycle guard.

**Acceptance:** every reversible tier 2 to 4 action has a rollback test; a
broken detector cannot exceed its breaker; PID reuse, symlink swap, CageFS
bind-mount ambiguity and a file replaced after detection are each refused by
test; withheld Critical responses stay visible under overload.

**Depends on:** [durable action lifecycle](#action-log-covers-six-of-41-host-changing-operations).
**Size:** L.

## Action log covers six of 41 host-changing operations

Design: [durable action lifecycle](docs/src/design/durable-action-lifecycle.md).

**Problem:** `internal/actionlog` records six operations; the privops
inventory has 58, 41 of them tier 2 to 4, so 35 `respond.*` and
`integrate.*` operations leave only a daemon log line, and a JSONL outcome
cannot tell a refused request from a mutation applied just before a crash.
The durable firewall action service exists behind engine injection;
production activation, reader cutover, migration, restore, downgrade and
operator recovery interfaces remain open.

**Acceptance:** every tier 2 to 4 operation maps to the lifecycle from every
entry point and the coverage test proves it; faults injected around intent
commit, mutation, outcome commit and audit delivery recover through
reconciliation, refusal and safe undo; `csm action show <id>` and typed undo
exist.

**Size:** L.

## Firewall state migration to bbolt

Design: [firewall state migration](docs/src/design/firewall-state-migration.md).

**Problem:** the lossless storage contract is implemented and tested without
runtime callers, but the engine still keeps its authoritative state in
`state.json`; cutover, migration, restore, downgrade and recovery are open.

**Acceptance:** every engine state field round-trips with original
timestamps; corrupt rows, read failures, concurrent requests, crashes around
commit, downgrade and backup restore are tested; migration resets no
response budget or failure pause.

**Depends on:** the firewall slice of the item above. **Size:** M.

## Response previews show intent, not the change

**Problem:** `csm virtual-patch`, `db-clean --preview` and
`auto_response.dry_run` say what would happen without showing the bytes,
although the cleaners already compute the new content.

**Acceptance:** the virtual-patch deny block, the surgical PHP clean and the
`.htaccess` clean each render a unified diff with no write; an applied
action's diff matches its action log digests; an unrenderable preview fails
instead of applying.

**Size:** S.

## Taint laundering through value encoders

**Problem:** Joomla writes `return var_export($strings, true);` into its
language cache, and `internal/phptaint` has no notion of a laundering
function. Decision needed: which encoders (`var_export`, `json_encode`,
`serialize`, integer casts) neutralise a code-execution sink without hiding
an `eval` of a decoded round-trip.

**Acceptance:** the Joomla language cache stops reporting; a laundered value
later decoded and executed still reports; the WordPress corpus stays at zero.

**Size:** M.

## Local-path provenance through variables

**Problem:** `argLocality` in `internal/phptaint` folds only literals and
constants, so OpenCart's `$file = DIR_TEMPLATE . $x` still seeds taint.

**Acceptance:** a read through a variable assigned from a local path constant
is not a source; one assigned from a parameter or unknown constant still is;
reassignment between the two is handled.

**Size:** S.

## Content rules versus archive containers

**Problem:** multi-string rules match across libraries bundled in one PHAR;
`network_socks_proxy` fired on a vendored developer tool inside a supported
CMS. Decision needed: bounded offset windows, or an explicit treatment of
`.phar`, `.zip` and `.jar` containers now scanned as flat blobs.

**Acceptance:** the vendored tool stops matching, a real single-file proxy
still matches, and the fix applies to the rule class.

**Size:** M.

## Clean corpus growth and per-detector false-positive tracking

**Problem:** the corpus is pinned WordPress packages only; Joomla, Drupal and
OpenCart pins are ready and `pending` in the manifest, Magento is not. The
corpus then needs real-world content (common plugins, page builders, premium
themes, admin tools) under a consent and scrubbing procedure. See
[the corpus gate](docs/src/clean-corpus.md).

**Acceptance:** the corpus runs on every release candidate and reports false
positives per detector and release; an unacceptable detector is reworked or
disabled, never allowlisted; defaults are recalibrated from the numbers.

**Depends on:** the three items above. **Size:** L.

## Attack replay corpus

**Problem:** `internal/selftest` holds nine file-content samples gating both
rule sets; coverage must reach web shells, droppers, malicious plugins,
credential stealers, injected JavaScript, phishing kits, spam scripts,
persistence, binaries and archives, mostly from existing fixtures.
Event-driven detection has partial replay (`scripts/crawl-calibrate` for
access logs, `scripts/correlation-calibrate` for finding streams);
authentication, mail log and spool activity have none, and no sample states
its expected incident or remediation.

**Acceptance:** the replay runs at release acceptance; losing a detected
sample fails the run; each sample carries expected findings and incident;
the incident half shares one stream format with the
[correlation evidence harness](#correlation-evidence-harness).

**Size:** L.

## Detection quality metrics per release

**Problem:** release evidence records package hashes, upgrade results and
cPanel coverage, nothing about detection.

**Acceptance:** every tag records sites and samples tested, detection rate,
false positives per site and day, actions exercised and rolled back,
detector regressions against the previous tag and the performance impact
under [resource budgets](#resource-and-performance-budgets); a tag is refused
past defined thresholds.

**Depends on:** [attack replay corpus](#attack-replay-corpus), the clean
corpus report. **Size:** M.

# Priority 3 -- root attack surface, supply chain and release integrity

## Privilege separation

Design: [privilege separation](docs/src/design/privilege-separation.md).

**Problem:** the whole daemon runs as root under
[service confinement](docs/src/service-confinement.md), so a parser bug
anywhere is a root compromise. The inventory stage is done. Remaining stages,
each shippable alone: the helper for firewall, then signals and quarantine,
then privileged writes, then descriptor passing for fanotify and BPF, then
dropping capabilities in the main process.

**Acceptance:** the main process holds no capability it does not use; an RPC
request cannot escape its path, user, process or firewall scope, including
through symlinks, bind mounts and PID reuse; forged intent, replay, budget
reset and unauthorized peers are refused; the root code is readable in one
sitting.

**Depends on:** [durable action lifecycle](#action-log-covers-six-of-41-host-changing-operations).
**Size:** L.

## Optional MFA for browser administrators

**Problem:** administrator logins have no second factor. Add optional
WebAuthn with an enrollment, recovery and credential-loss story on the
existing session and named-token boundary.

**Acceptance:** enrollment, authentication, lost-device recovery and removal
have tested authorization and session-revocation behaviour; API token scopes
are unchanged. See [browser sessions](docs/src/webui.md#browser-sessions).

**Size:** M.

## Web UI module split

**Problem:** HTTP handlers mix request handling with the logic that
quarantines, blocks and rewrites configuration; the session boundary is
extracted, the other domains still need narrow services shared with CLI and
automatic callers.

**Acceptance:** per slice, interface tests exist, read-only authorization and
CSRF checks survive, and no path bypasses service-level safety checks;
finally, no handler performs a host mutation directly.

**Size:** L.

## Parser and input hardening

**Problem:** 55 test files carry fuzz targets and the PHP parser runs out of
process, but no inventory maps every parser of external input (archives,
logs, configuration, CMS state, PHP, JavaScript, mail, challenge and control
protocols) to a fuzz target.

**Acceptance:** that inventory has a completeness test; decompression ratio,
recursion, nesting, size and parser time each have a limit and a test that
exceeds it; symlink chains and CageFS mount edge cases are tested;
race-detector stress runs cover concurrent paths.

**Size:** L.

## External security review

**Problem:** nobody outside the project has reviewed the root attack surface
(web UI and API, sessions, privileged filesystem operations, quarantine,
nftables, process termination, installer verification, archives, IPC, BPF
and fanotify).

**Acceptance:** a report covering that surface is published with remediation
status after the first privilege separation stage lands; a focused review
repeats after each major architecture change.

**Depends on:** [privilege separation](#privilege-separation), first stage.
**Size:** M.

## Decide the trust model for internal CI builds

**Problem:** release signing runs on tags only, so builds published between
releases carry no release signature. Options: sign every build with the
release key; sign CI builds with a separate lower-value key and embed both
public keys; or document registry authentication as the accepted boundary.

**Acceptance:** the deploy scripts and
[release signing](docs/src/release-signing.md) state the same contract, and a
tampered artifact is refused on the path operators actually use.

**Size:** S.

## Operator-copied deploy scripts drift

**Problem:** `csm doctor` reports hand-maintained deploy script copies that
drifted from the shipped verification contract but prints nothing when every
copy is current, so an operator cannot tell the check ran.

**Acceptance:** the check reports `[OK]` on a clean host; an installer-owned
operator copy is refreshed on upgrade.

**Size:** S.

## Runner capacity for the release pipeline

**Problem:** a tag pipeline runs every job at once on the shared runner and
lint package loading has reached its time cap under that load; the cap was
raised, and whether the runner needs more headroom is undecided.

**Acceptance:** to be defined. **Size:** S.

# Priority 4 -- correlation

The incident correlator in `internal/incident` is extended, not replaced;
the findings-level `CorrelateFindings` in `internal/checks` is the weak
layer. Every item after the harness depends on it.

## Correlation evidence harness

**Problem:** correlation has no equivalent of the corpus gate: recorded
finding streams in, expected incidents out, with compromised streams from
the attack corpus and clean streams that must form nothing.

**Acceptance:** real incidents from past reviews replay to their known
incident, clean streams form nothing, the run reports correlation
false-positive and false-negative rates, and every production correlation
bug becomes a fixture before its fix.

**Depends on:** [attack replay corpus](#attack-replay-corpus). **Size:** M.

## Cross-account correlation identity gaps

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

## Observation, finding, incident and action identity

**Problem:** event sources, findings, incidents and action records have no
shared provenance contract for replay and sequence joins.

**Acceptance:** observations join findings, incidents and actions through
stable identifiers in the attack corpus replay format; event time, first
observation and later reports are distinct so rescans cannot manufacture
corroboration; retention and redaction rules are recorded.

**Size:** M.

## Corroboration grading

**Problem:** a Warning corroborated by an independent signal on the same
account, file or address should escalate; an uncorroborated Warning in a
noisy family should demote.

**Acceptance:** replayed real incidents rise above their noise, replayed
clean streams form nothing, and demotion never hides a Critical.

**Size:** M.

## Sequence correlation

**Problem:** a dropper, then a new administrator, then an outbound connection
is one story; CSM emits three unrelated findings.

**Acceptance:** an ordered sequence yields one incident carrying its steps;
the same findings out of order or far apart do not.

**Size:** M.

## Join findings on file identity

**Problem:** realtime, YARA and the taint engines each flag the same file
separately.

**Acceptance:** one file tripping three layers yields one finding with three
pieces of evidence and the strongest severity.

**Size:** S.

## Spray correlation ingesting HTTP signals

**Problem:** the HTTP abuse checks correlate under the WordPress brute-force
group but do not feed the account-spray signal set, which is mail-only.

**Acceptance:** the HTTP checks join the spray set with a request-target
identity dimension, and recorded traffic shows a distributed low-rate
campaign correlating without raising per-source false positives.

**Size:** M.

## Cross-server fleet ingest

**Problem:** the direction is authenticated outbound ingest and panel-side
correlation over the existing webhook and export contracts, with no peer
mesh or inbound endpoint; the protocol and the correlation are open.

**Acceptance:** host and tenant identity, schema versioning, deduplication,
replay handling, credential rotation, bounded retries and visible delivery
loss are defined; a compromised host cannot submit as another; a rejecting
panel never stops local protection.

**Size:** L.

# Priority 5 -- known coverage gaps

## Three obfuscation shapes are missed by both rule sets

**Problem:** neither rule set fires on `assert` with a fragmented name on
request input, on `base64_decode` assembled from fragments into `eval`, or
on a `chr()`-built callable invoked on request input; the self-test bundle
records them as gaps, and identifier reconstruction rules produce
false-positive floods, so this is detector work with a corpus result.

**Acceptance:** each shape is detected by at least one engine with no new
clean-corpus finding, and the recorded gap in `internal/selftest` is cleared
in the same commit.

**Size:** M.

## Realtime coverage for files renamed into a watched tree

**Problem:** atomic saves are covered (see
[realtime coverage](docs/src/detection-realtime.md)); a file moved into an
eligible path without a create or close-write event is caught only by the
rolling content scan, because the watcher subscribes to no rename events.

**Acceptance:** name-event and file-handle support is probed at runtime
first; arrival from outside the scope, same-tree moves, lost events and
unsupported kernels are tested; the rolling scan fallback stays.

**Size:** M.

## Scheduled scans do not consult package checksums

**Problem:** the realtime path skips files whose hash matches the official
wordpress.org release; the scheduled scans and the re-check never ask, so a
stock file with an odd-looking loader is reported on every deep scan.

**Acceptance:** the deep scan and the re-check use the realtime checksum
cache with the same fail-closed rules; a stock file stops reporting; a
modified copy still does.

**Size:** M.

## CMS discovery deeper than one directory below a document root

**Problem:** WordPress discovery merges the panel's document-root map with
account-home patterns, so undeclared nested installs can be missed, and the
other adapters in `cmsDiscover` do not use the panel map. See
[platform support](docs/src/detection-deep.md#platform-support).

**Acceptance:** depth and cost budget are decided per CMS; nested mapped and
unmapped installs, custom roots, symlinks, cancellation and incomplete
traversal are tested; each adapter's limits are documented.

**Size:** M.

# Priority 6 -- operability and validation

## Job model for every long-running operation

**Problem:** scans run as persisted jobs, but database cleanup, store export
and import, rule and GeoIP updates, batch quarantine and virtual patching
still hold a privileged HTTP request open and run unwatched after a
disconnect.

**Acceptance:** every operation over a few seconds returns a job id and
reports through the scan endpoints; cancellation is supported where safe and
refused where not; job state survives restart; per-class concurrency limits
apply; restarting a job never repeats a completed mutation.

**Size:** L.

## csm support-bundle

**Problem:** operators grep the journal and copy state by hand.
`csm support-bundle <path>` writes a tar+zstd with the store export, the
last N journal lines, the configuration with secrets redacted and a
`system.txt` with versions and integrity hashes.

**Acceptance:** the archive holds those parts; a test proves no configured
secret value appears in it; the journal tail honours the line count.

**Size:** S.

## Validate CageFS mount points

**Problem:** `csm doctor` checks the PHP Shield event directory mount only;
entries pointing at missing directories make every `cagefsctl` call print
errors.

**Acceptance:** doctor names configured mount points whose source is missing
and reports `[OK]` otherwise.

**Size:** S.

## Scheduled backup exports

**Problem:** `store export` needs an operator cron entry. A hot-reloadable
`backup` block (`enabled`, `schedule`, `destination_dir`, `filename` with
`{date}`, `retention_days`) lets the daemon export on schedule and prune.

**Acceptance:** an export appears on schedule, archives past retention are
pruned, a failed export raises a `backup_export_failed` Warning, and the
block applies on reload.

**Size:** S.

## Fleet validation evidence

**Problem:** defaults are tuned from a handful of servers read by hand; the
panel already receives every finding, so the cheapest evidence is which
findings became confirmed incidents or were dismissed, per detector and
platform.

**Acceptance:** evidence travels over the fleet ingest contract; consent,
minimization and redaction are defined before any optional metric; detector
noise per platform feeds the clean corpus calibration.

**Depends on:** [cross-server fleet ingest](#cross-server-fleet-ingest).
**Size:** M.

# Priority 7 -- performance budgets and debt

## Resource and performance budgets

**Problem:** overload has been found by operators (out-of-memory restarts, a
copy-on-write regression) rather than by tests; 28 test files contain
benchmarks and no budget is written down.

**Acceptance:** written CPU, memory, I/O and event-latency budgets for a
reference server; benchmarks for large account and file counts, mail volume
and event rates run per release into the detection-quality report; every
queue has a stated cap; a named degraded mode builds on
[queue health](docs/src/api.md#protection-queue-health).

**Size:** L.

## Storage measurements and domain contracts

**Problem:** `internal/store.DB` hides its bbolt handle, but transaction
instrumentation and domain conformance coverage are missing; consumer-owned
interfaces start with firewall state and actions, and HTTP output, network
calls, scans and host commands stay outside transactions.

**Acceptance:** write wait, transaction and read duration, commit failures,
database size and compaction cost are exposed with bounded labels;
contention, slow readers and failed writes show in repeatable workloads;
conformance tests cover each migrated path.

**Size:** M.

## Consolidate bootstrap toolchain pins

**Problem:** `go.mod`, the builder images, the Linux test wrapper and CI each
carry a Go or linter version; they agree today, and nothing checks drift.

**Acceptance:** version inputs are generated from one source with a drift
check, and CI records the selected Go and linter versions.

**Size:** S.

## WordPress companion plugin for signed-cookie operator bypass

**Problem:** a logged-in administrator cannot obtain the challenge bypass
cookie without a manual request; the plugin lives in a separate repository.

**Acceptance:** [challenge pages](docs/src/challenge.md) names
`/challenge/admin-token` as a stable contract whose breaking changes need a
roadmap item and carries an integration note for the plugin.

**Size:** S.
