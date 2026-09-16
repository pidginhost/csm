# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 3.30.0 are archived: [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [Unreleased]

### Added

- Firewall actions now retain durable intent, admission accounting, verification results, and retryable audit delivery. Recovery and typed undo preserve action identity, plan against one safety snapshot, verify removals against live state, and refuse conflicting changes while an outcome is uncertain. Proven outcomes are kept for undo under the findings-history retention setting, with a hard size and count bound that applies even when retention sweeps are off. Applying an action writes only the firewall entries that change, in one atomic update whatever its size. Recovery runs before the daemon applies the firewall and again on the maintenance tick, stays available after a failed startup, and `csm firewall actions` shows what it could not settle so an operator can record the outcome by hand.
- Added an atomic firewall storage contract that preserves complete state, rejects stale or corrupt reads and reports uncertain commits so recovery can inspect state before retrying. Runtime firewall storage remains unchanged until action recovery and migration are ready.

### Changed

- The engineering roadmap now defines staged work for durable actions, privilege isolation, browser sessions and storage recovery. It keeps the embedded database and chooses panel-side fleet correlation.
- The architecture roadmap now requires lossless firewall migration and independently enforced helper admission. Browser sessions can ship before the remaining service extraction.

### Security

- Obfuscated malware remains detectable when execution is indirect, with consistent real-time, scheduled and content checks.
- Disabling a signature no longer risks removing neighboring detections from the same rule file.
- Detection self-tests now stop when the host configuration cannot be read instead of overstating available coverage.
- Browser logins now use revocable sessions with idle and absolute expiry instead of copying the administrator API credential into a cookie. Upgrades and daemon restarts require a fresh browser login; API credentials continue to work.
- A claimed crawler without reverse DNS no longer regains the softer challenge treatment after a daemon restart or when retry history fills up.
- Mail log parsing no longer takes an authenticated user from message IDs, delivery replies, quoted fields or records carrying a remote ident username.
- Mail authentication failures and authenticated arrivals keep their verified user and connecting address when login names, addresses, message IDs or optional envelope identities contain text that resembles log fields, including on TCP Fast Open connections.
- The WordPress user enumeration filter now also stops requests that name the users route in the query string or use alternate request spellings.
- Email attachment scanning can no longer hold up mail delivery indefinitely. A message is released once its scan exceeds a time budget, and if scanning keeps falling behind, mail flows unscanned for a cooldown and a critical alert says so. Attachments found to be infected after release are still quarantined.
- Real-time forwarder monitoring now sees pipe forwarders written in the quoted form cPanel uses, and a pipe counts as a cPanel built-in only when it runs that program. Scheduled and real-time checks follow the mail server's command quoting rules.
- ModSecurity rule updates now take effect after an upgrade or install when a web server reload command is configured; previously they stayed inactive until the web server restarted for another reason. Expect one web server reload after upgrading.

### Fixed

- Disabling every signature now clears the loaded rules on reload, and the self-test reports the resulting misses. Configuration validation also recognizes disabled rules with invalid expressions and counts repeated names once.
- Rule names listed under signature settings are now switched off everywhere CSM loads rules, including isolated scanning workers using custom configuration paths. Validation and loading agree on names, and self-tests measure the remaining coverage.
- Database scans no longer exhaust the SQL regular-expression budget or slow down on large styled content. If the server still stops a regular expression, plain hidden styles stay covered, later checks keep running, and coverage stays marked incomplete.
- Claimed crawlers without reverse DNS are no longer looked up again on every scan. Those repeats overflowed the bot verification queue on busy hosts, so genuine crawlers could miss verification and be handled as ordinary visitors.
- The WordPress user enumeration filter no longer blocks signed-in users, so creating Application Passwords and loading author lists in the editor work again. Unrelated page paths and REST namespaces remain accessible.
- Upgrading a standalone install no longer leaves the daemon unable to start when a directory its service sandbox needs was never created; the upgrade now creates it first.
- Mailing list aliases created by cPanel's Mailman are no longer reported as critical pipe forwarders, and autoresponder aliases are no longer reported as external forwarders. Forwarder alerts name the mailbox address once, and expected forwarders listed by full address are now recognized.
- Outbound socket findings and per-domain mail volume findings now name the owning hosting account when the connection's user or every counted submission verifies it, and different accounts keep separate alerts.
- The finding history and attack event log no longer leave their database pages half empty, so they take about half the space in the state file on a typical host. Existing files shrink after the next compaction.
- The per-address index of attack events no longer stores a second copy of every event, which cut its space in the state file to a fraction. Rows written by earlier releases are still read until they age out.
- Attack events recorded at the same instant across separate batches no longer overwrite each other or disappear from address history. Address queries also skip older index copies that belong to a different address.
- Incidents the daemon closes on its own are now kept for 7 days instead of 30, so busy hosts no longer hold tens of thousands of stale records in the state file. Incidents an operator closed or acted on keep 30 days, and large cleanups no longer pause incident processing.
- Commercially obfuscated plugin code no longer triggers a dropper alert solely for scrambled control flow or long embedded assets. Scans apply the same rule, so such a file no longer lands in the operator queue either.

## [3.38.0] - 2026-09-13

### Highlights

- The audit log now records source observations that reach alert dispatch, including repeats and findings kept out of notifications, so expect more audit records when logging is enabled. Automatic firewall actions link back to the finding that caused them when its identity is available.
- Automatic file quarantine and cleaning share host and account limits and pause after repeated failures. A clean that fails or finds nothing leaves the file for manual review.
- Incident blocks are re-applied while an attack continues and can escalate to permanent blocks. The incident view has a Block button for incidents with one source address.
- Cross-account alerts in the current findings view now age out using the first recorded observation. Alerts supported only by older dated findings clear on the next scan; notification batches keep their existing grouping.
- LiteSpeed Cache sites get a request filter for the role-simulation takeover, detection of code stored in plugin notices, and vulnerable-version alerts.
- New audit and finding-history records redact recognized credentials in messages and details, and attack events redact their messages before storage. Existing records and other finding fields are unchanged.
- Real-time YARA scan failures are now a separate finding from the scheduled coverage report. Update any filter or alert rule that matched the old shared finding.
- A scan that could not inspect a file or database no longer clears its earlier findings.

### Added

- Automatic file quarantine and cleaning now share persistent host and account limits and pause after repeated failures. Cleaning that fails or finds nothing to remove, and whole-directory findings, leave the source for manual review, and a cleaner that finds nothing does not count toward the pause.
- The incident view has a Block button for incidents with one unambiguous source address. It blocks permanently, records the block on the incident timeline, and stops the automatic hand-off from re-blocking an address an operator just handled.
- A calibration tool replays a recorded finding stream through cross-account correlation and reports what each candidate threshold would have raised, so the thresholds can be re-derived from what hosts produced.
- CSM now ships a request filter for the LiteSpeed Cache role-simulation takeover. It protects sites that have not yet upgraded the plugin while preserving ordinary crawler reads because the filter only covers privileged targets and writes.
- Code stored in a plugin's own status options, which WordPress prints in the dashboard as a notice, is now reported as a critical database finding. LiteSpeed Cache is covered first, since an unauthenticated request can write those rows on older versions.
- The known-vulnerable plugin feed now covers LiteSpeed Cache notice injection, privilege escalation and session-cookie disclosure, so a site still running an affected version alerts even after its stored payload is removed.

### Changed

- The audit log now records source observations that reach alert dispatch as well as notification findings, including repeats of an earlier finding and findings filtered out of email and webhooks. Distinct observations keep separate records; replay suppression is per destination and lasts only while its delivery history remains in memory, which resets on restart or audit reconfiguration.
- Findings with no recorded first observation omit that date from JSON output.
- Go dependencies and the pinned GitHub Actions are updated to their current releases.

### Security

- An incident-driven firewall block is re-applied when the previous one expires and the attack is still going, eventually becoming permanent after repeated expiries. A block was previously requested once per incident while the block itself expired, so an attacker who kept going past the expiry was never blocked again.
- Incident blocks keep their escalation across quiet periods and restarts, and closing an incident clears it even with a block request in flight. Manual block records validate the incident address, and refreshing a live block no longer skips an escalation step.
- Findings are no longer cleared when a scan could not inspect their source. Incomplete, interrupted and timed-out scans, unexamined WordPress installations and database aliases with missing credentials keep earlier findings, even when new results fill the active list.
- A failed database query no longer suppresses independent checks while other tables remain readable. Coverage warnings name the failed stage and error class without exposing database values.
- Script URLs stored as JSON with escaped slashes are now recognised. Injected loaders in options, posts and page-builder content were invisible to the database scan in that form.
- Plugin notice scanning inspects longer stored messages and reports incomplete reads, preserving earlier findings when the full notice cannot be checked. Existing executable-markup checks now apply consistently to these notices.
- Database cleanup refuses partial changes to plugin notices when executable content remains, including loaders on ordinary HTTPS hosts.
- The LiteSpeed Cache request filter now covers equivalent cookie and request forms while preserving ordinary crawler reads. Public links to administrative pages no longer cause false blocks.
- A client claiming to be a search crawler gets pending treatment only while its verification is admitted and inside its initial wait. Failed or unavailable verification used to renew that treatment on every retry, keeping a spoofed crawler on the challenge path instead of a block.
- Automatic file response keeps full-file validation after partial real-time checks, and replacing a file with a special file can no longer stall response processing. Safety refusals, such as a replaced or vanished source, no longer count toward the failure pause.
- WordPress database scan warnings escape account-controlled names so they cannot alter the diagnostic or terminal display.
- New audit and finding-history records redact recognized credentials in messages and details, and attack events redact their messages before storage, also protecting newly recorded history shown and exported by the web UI. Repeated and quoted password and token fields and cPanel login session identifiers are covered without changing correlation identities or unrelated log evidence; existing records and other finding fields are unchanged.

### Fixed

#### Audit and evidence

- Automatic firewall actions now link to their source findings in the audit log, including delayed retries, escalations, and failed or refused attempts. Older stored evidence without a source identity remains unlinked.
- Recent audit replays no longer duplicate records at healthy destinations while their delivery history is retained, frequently replayed records stay deduplicated during busy periods, and simultaneous findings no longer hide each other.

#### Scans and coverage

- Repeated verification failures and incomplete scans no longer pin or grow their retained state indefinitely. Failed crawler lookups release room for new verification.
- A file too large to analyze is reported as a coverage gap only when its leading bytes could be source of that language. Large images, archives and compiled catalogs no longer arrive as PHP or JavaScript the scan failed to examine, while oversize JavaScript that embeds binary characters in a literal or comment stays visible along with any earlier finding for it.
- A deep scan that has reached its time limit no longer opens further files while recording what it did not examine.

#### Cross-account correlation

- Stored cross-account alerts and attribution health now use a recent-activity window based on when findings were first observed. The next scan clears alerts supported only by older dated findings; undated legacy findings still count, and notification batches keep their existing grouping.
- Completed scans preserve the original observation when replacing a finding, so repeated reports cannot renew an expired correlation alert.

#### WordPress

- Completed database scans now clear resolved findings even when another installation failed.
- WordPress installations whose core checks or plugin inventories repeatedly fail now produce a warning naming the installation and cause, and a fault that stops many installations at once is reported once. Successful checks clear the warning even when scans finish out of order, and status distinguishes completed checks from partial output.
- Account scans retain individual WordPress verification warnings, and host-wide warnings no longer appear to belong to the first sampled account.
- WordPress database scan warnings now count config, query and content-read failures, name examples, and keep discovery gaps visible. Multisite safety-limit warnings no longer hide failures at other installs.

#### Real-time detection

- A real-time YARA scan that cannot inspect a changed file is now its own finding, separate from the scheduled coverage report it used to share a name with. A scanning outage is no longer indistinguishable from the routine backlog of files past the scan size limit.
- Shutting the daemon down no longer reports a real-time YARA scanning failure.
- The dashboard shows real-time YARA scan failures in the filesystem monitor's last event instead of leaving that event missing or stale.
- Real-time WordPress admin-creation detection now requires an administrator role token alongside the credential shape, matching the scheduled rule, and accepts the same whitespace. The user importer bundled in many themes and plugins was reported as critical on every plugin update that staged it.

#### File response

- Automatic file responses no longer repeat during alert delivery or for duplicate detections of one file. Incomplete safety records now pause changes instead of losing accounting.

## [3.37.0] - 2026-09-11

### Highlights

- Every bounded queue in the daemon now reports depth, work in flight, losses and lag through `csm status`, `/api/v1/status` and `csm doctor`. A busy cPanel host publishes around sixty rows.
- `csm doctor` exits 1 while a protection queue is degraded. Check any monitoring that treats its exit code as pass or fail before upgrading.
- Sustained overload raises one `protection_queue_degraded` notification per queue at most every five minutes, followed by a recovery event once the pressure clears.
- Queues whose work is best effort, such as live event streams and process context lookups, warn in doctor and never change the host status or the dashboard posture.
- Successful logins and cPanel File Manager use no longer block or raise the threat score of a customer's own address.
- Work that was never lost is no longer counted as lost: the startup baseline hold, temporary trees removed during bulk extraction, and installations wp-cli refuses to read.
- A kernel measurement has to stay unreadable for half a minute before it degrades anything, so a single torn reading raises nothing.
- Production checks enforce a reviewed queue inventory: a new bounded queue without an owner entry and health regressions fails the pipeline.

### Added

- WordPress core checks now report waiting installations, stalled workers and failed work through status and doctor, including interrupted commands that return partial findings. Active commands and result handling remain visible after cancellation, and concurrent scans retain separate ownership.
- Block digests now report buffered blocks, stalled preparation or delivery, and confirmed losses through status and doctor. Normal batching and disabled default destinations stay healthy; interrupted deliveries remain explicit.
- Findings parked at shutdown now report stored backlog, stalled persistence or replay, and confirmed losses through status and doctor. Failed writes distinguish retained work from uncertain outcomes, including log text repaired during storage.
- Queue health now reports pending attack record updates and deletions, including failed retries and interrupted writes. Repeated changes to one IP share pending work, while changes arriving during a write remain visible.
- Attack event persistence now reports backlog, stalled writes and confirmed losses through status and doctor. Partial writes and uncertain completion remain visible after shutdown.
- Production checks now enforce the reviewed queue inventory and reject missing or skipped health regressions, including shared reporting and recovery checks.
- Production checks now verify PHP relay queue health during startup, shutdown and watcher attachment failures.
- File mail sources now report unread bytes and stalled reads, including buffered and partial lines. Source changes retain known lost records and make uncertain backlog explicit.
- Journal mail sources now report stalled reads and source failures through status and doctor. Unmeasurable backlog stays explicit, and switching to a working file source clears retired journal errors.
- Health now reports deferred cleanup after firewall flushes, stalled cleanup and failed retries. Unreadable state is marked unknown until recovery establishes which work survived.
- Health now reports pending automatic blocks, active candidates and retry failures. Counts distinguish confirmed losses from retries still available on disk.
- Blocked automatic responses and firewall flushes now appear in health checks while they wait for shared state. The active operation remains visible through cleanup.
- Incident persistence now reports queued writes, stalled writers and failures through status and doctor. Deferred bookkeeping remains visible until a later update or shutdown flush.
- File-index scans now report waiting callers, stalled scans and failed work through status and doctor. Audit scans remain independent, and successful late baseline writes do not count as lost work.
- Reputation checks now report waiting queries, stalled result handling and failed work through status and doctor. Reserved lookups stay visible while fallback scoring runs; cache failures retain the findings, and normal quota limits remain separate from queue failures.
- WordPress plugin inventory now reports waiting sites, stalled workers and failed completion through status and doctor. Canceled commands stay visible until they return, and shared refreshes count each site once.
- Mailbox password audits now report waiting work, stalled audits and failed completion through status and doctor. Canceled audits stay visible while they finish, and failed cache writes retain the confirmed findings.
- PHP analysis now reports waiting requests, stalled worker communication and failed work through status and doctor. Cancellation keeps unfinished communication visible, and timeout evidence remains available during cleanup.
- Email antivirus scans now report stalled engines, delayed results and failed work through status and doctor. Timed-out engines stay visible until they finish.
- Full-scan jobs now report waiting work, stalled admission or persistence, and lost jobs through status and doctor. Working scans use check progress and deadlines so a long scan alone does not trigger a stall warning.
- Scan health now includes checks waiting for a worker and stalled setup or result handling. Long-running checks keep their own deadlines without making a busy scan look stalled.
- Host and account scans now report overdue checks and lost results through status and doctor. A timed-out scan keeps unfinished checks visible until they return.
- Email password audits now report waiting callers, occupied verification slots and stalled work through status and doctor. Canceled scans keep unfinished verification visible until it returns.
- Reverse DNS lookups now report occupied slots, stalled resolvers and lost results through status and doctor. Timed-out lookups remain visible until their resolver finishes.
- Panel webhooks now report durable backlog, stalled delivery and lost findings through status and doctor. Retries and clean shutdown preserve queued findings; stopped queues refuse late submissions.
- Live event streams now report backlog, stalled delivery and lost events through status and doctor. Closing a browser tab does not count as a delivery failure.
- Action logging now reports occupied write slots, stalled writers and lost records through status and doctor. A timed-out caller does not hide a write still running.
- Abuse reporting now exposes its durable backlog and delivery failures through status and doctor. Retried reports retain their waiting age without counting as lost.
- Abuse reporting now reports memory backlog, stalled persistence and lost reports through status and doctor.
- Bot verification now reports backlog, stalled work and lost requests through status and doctor. DNS and cache failures remain visible without changing bot classification.
- Central threat-intelligence actions now report backlog, stalled work and failures through status and doctor. Shutdown accounts for abandoned actions and refuses late submissions.
- Process file reads now report occupied slots, stalled work and lost results through status and doctor. Timed-out reads remain visible until the underlying operation returns.
- Process context enrichment now reports backlog, stalled work and lost requests through status and doctor. Process disappearance and stale identities remain expected outcomes.
- BPF verdict annotation now reports queued callbacks, stalled work and losses through status and doctor. Callback failures remain visible while findings continue without waiting for annotations.
- PHP relay index persistence now reports queued writes, stalled batches and failed writes through status and doctor.
- Forwarder and PHP relay notification queues now report pending work, stalled readers and known losses through status and doctor. PHP relay restarts preserve earlier failures.
- Recovery scans now report queued directories, stalled work and failed attempts through status and doctor. Evicted, expired and unfinished shutdown work stays in the loss totals; successful scans at the recovery cutoff remain successful.
- File and mail notification queues now report pending work, stalled readers and unread shutdown losses through status and doctor. Work already being processed stays visible after leaving the kernel queue.
- Mail-log delivery now reports queued work, stalled consumers and lost records through status and doctor. Loss totals survive reader retries and changes between file and journal sources.
- BPF kernel queues now report occupancy, stalled readers and lost events through status and doctor. Shutdown records the minimum known loss when kernel callbacks may still be finishing.
- BPF event delivery now reports queue pressure, decoding failures and stalled consumers through status and doctor. Shutdown counts buffered events left unprocessed.
- Status and doctor now report overdue dropper probes, delayed findings and abandoned work.
- Status and doctor now expose delayed or dropped package verification work. Repeated retries retain their original waiting time, and a stalled verifier remains visible while it holds a batch.
- Status and doctor now report delayed and dropped work in finding delivery and the realtime file and mail scanners. Sustained overload degrades health and raises a bounded notification even when the normal findings channel is full, with a recovery event once pressure clears. The startup hold does not count as delay.

### Security

- WordPress integrity checks no longer treat command timeouts as successful verification.
- Binary and configuration tamper findings now retain their host identity when joining incidents, even without account or IP attribution. Classification checks catch missing detector mappings before release.
- Busy hosts with many open files no longer lose the PHP relay watcher to a polling crash.
- Spool shutdown now prevents late scan responses from writing through a closed descriptor that the process has reused for an unrelated file.
- Dropper monitoring now bounds findings awaiting aggregation and releases failed retry state, limiting memory growth during sustained file churn. Later observations preserve the retry limit when they strengthen a file's identity.

### Fixed

#### Queue health and doctor

- Queue health no longer reports a stall from invalid kernel occupancy or work that is not yet eligible. Adopted panel webhooks retain their waiting age, and plugin commands with missing output count as incomplete work.
- Attack event health now names an uncertain write ahead of a backlog, the way the record queue already did.
- A burst of automatic responses writing to the action log no longer degrades health. Recording work is now reported as stalled on the same timescale as every other queue.
- Doctor no longer prints a mail journal source or a released log file as an empty queue. Ages are now labelled by what they measure instead of all appearing as backlog.
- Recovery scans no longer count files and directories that were removed before the scan ran as lost protection work. Bulk extraction, package restores and update temp trees stopped degrading health on every burst.
- A single unreadable kernel queue measurement no longer degrades health and raises a notification. The reading has to stay unavailable for half a minute, a stopped reader is named instead of the artefacts it causes, and records the kernel already dropped are reported ahead of an unreadable depth.
- Queues whose work is best effort no longer change the host status, the dashboard posture or the doctor exit status. A client that stops reading its event stream, an unreachable panel and expired process context reads now warn with the same evidence instead of reporting a protection failure.
- A queue that repeatedly degrades and recovers no longer sends unbounded notification pairs. The five-minute bound now survives a recovery, and a recovery is reported only for a degradation that was announced.
- BPF queue health no longer reports a permanent measurement failure when a reader consumes an event during shutdown.
- Dropper queue health now times probes and finding delivery from their actual start, so earlier delays do not trigger a false stalled-worker warning.
- Package verification saturation warnings now follow actual capacity use while work is running or being retried, without counting earlier metadata delays as time spent full.

#### Automatic response and blocking

- A failure while finishing an automatic response no longer leaves the state lock held, which stopped every later block, firewall flush and state write until a restart.
- Cleanup loss counts now include newly blocked IPs after recovery from unreadable state. Old cleanup records retain their uncertain history without hiding new failures.
- Queue health treats decisions withdrawn by the current blocking policy as expected refusals. Retry accounting keeps different kinds of evidence separate when recovering from a failed save.
- Authenticated activity no longer raises threat scores through event volume or account counts, and remains visible in threat history and the dashboard. Retained audit incidents and outdated queued decisions no longer trigger blocks, and webmail challenges respect the login-blocking setting.
- Successfully logging in, or using cPanel File Manager, no longer gets a customer's own address firewall-blocked. These events are reported only after authentication has already succeeded, so on shared hosting they fired on ordinary use of core features; one file upload was enough to block the account owner for 24 hours and to keep re-blocking them afterwards.
- Those same events no longer count towards an address's threat score, and are no longer raised as Critical or High. They remain recorded, which is where their value is -- alongside other findings on the same account. Failed and repeated-attempt checks are unchanged and still block.
- Failed firewall cleanup writes now appear in health checks even when diagnostic output is blocked. The failure remains counted once after cleanup finishes.

#### Checks and scanning

- WordPress installations that wp-cli refuses to read, such as a directory that is not an installation or one whose configuration fails to load, no longer count as lost protection work on every cycle. Interrupted and killed commands still do.
- File scan health now counts failed content and executable metadata reads. Existing findings remain available, and files disappearing during metadata enumeration do not count as lost work.
- Completed mailbox audits no longer count as lost when a deadline expires during final cleanup. Draining canceled work no longer holds up health snapshots while checking the scan context.
- Recovered PHP analyzer failures now appear in queue health even when worker communication succeeds. Existing scan results and worker recovery behavior are unchanged.
- Full scans left queued by a daemon restart now report interruption instead of waiting forever. A terminated scan worker refuses new jobs and accounts for abandoned requests.
- Recovered file and mail scanner failures now count as lost work, so repeated panics degrade health even while workers continue scanning later events.

#### Delivery and reporting

- A stored report or panel finding with missing queue accounting is now delivered or counted, instead of stopping the worker that was processing it.
- Abuse reports already acknowledged by a collector no longer count as lost if database cleanup fails and the queue later overflows.
- Event streams now close when a flush fails, releasing their subscriber slot so clients can reconnect.

#### Persistence and shutdown

- Attack event health now counts buffered records lost during an interrupted write. Only complete records submitted to the writer can have an uncertain outcome.
- Interrupted attack event writes now retain confirmed losses while cleanup finishes. Events whose write outcome is unknown remain separate from work that was never submitted.
- An interrupted bulk incident write no longer leaves later writes blocked. Abandoned writes are counted while later incident updates can continue.
- Abuse reporter shutdown now closes admission before persisting its remaining reports, so late submissions cannot be silently stranded. Persistence failures remain visible while unrelated reports continue to be saved.
- Bot verification shutdown now accounts for abandoned requests and refuses later submissions. Queued requests retain their original address when a caller reuses its input buffer.
- Process context workers now count discarded requests at shutdown and cannot restart after stopping. Active reads finish before shutdown returns.
- Verdict annotation shutdown now refuses new work and accounts for abandoned callbacks. Failed callbacks release their pending state so later findings can retry.
- PHP relay shutdown now drains accepted index writes and refuses later submissions. Flushes use bounded transactions, preserving unrelated batches when a write fails.
- Finding loss totals now include every unsent finding in a batch canceled during shutdown.

#### Build and CI

- Queue inventory checks now catch capacity changes hidden in local declarations and nested expressions, including field selections, and reject ambiguous build variants. Legal import aliases remain supported.

## [3.36.0] - 2026-09-09

### Highlights

- `mode: observe` turns CSM into a detection-only sensor. A config that still enables a state-changing subsystem is now refused at load, so check yours before upgrading.
- A new action log and `csm actions` record what CSM did to the host, including the digest of a changed file before and after and the command that reverses it.
- `csm privileges` and `csm selftest` report what CSM needs root for and what the installed rules actually catch and miss.
- The self-deleting-dropper detector no longer floods on plugin scratch files. One account was producing over a thousand warnings in two days.
- Findings that previously carried no time now carry one, so history, incidents and alerts sort correctly and finding ids stop colliding.
- On systemd 239 (EL8, CloudLinux 8) the installer stops writing the directives that host rejects, and five syscall deny groups the unit always meant to apply now actually apply.
- An upgrade health-checks the new daemon and rolls back when it fails. Nightly automatic upgrades ship switched off.
- Cross-account correlation now has an explicit per-check policy and resolves the owning account, so an eligible finding is counted instead of quietly dropped.

### Added

- `csm selftest` scans adversarial samples and benign controls, reporting what the installed rules catch and miss without reading account data. The same bundle gates both rule sets in CI.
- `csm actions` reads a new action log that records what CSM did to the host, not just what it found: the operation, who started it, the finding that caused it, the digest of a changed file before and after, and the command that reverses it. Quarantine, cleaning, process termination and firewall changes write to it today.
- `csm privileges` prints every operation that needs root or a capability, what it writes, and the setting that stops it. The same table ships as a capability matrix in the docs, and tests keep it in step with the systemd sandbox.
- `mode: observe` runs CSM as a detection-only sensor, disabling automatic host remediation and integration updates while keeping its own data and runtime sockets. A config that still enables a state-changing subsystem is refused at load, naming every conflicting key.
- A finding-stream tool turns a host's audit log into an anonymized recording for correlation calibration: hosts, accounts, domains, mailboxes and addresses become salted pseudonyms, credential material is dropped, and a leak check refuses to write output that still carries a raw identity.
- The health snapshot and `csm doctor` report which checks feed cross-account correlation findings without a hosting owner, separating what the active set shows now from the cumulative count since start, so a producer that lost attribution is visible to an operator instead of only in a log line at first occurrence.
- `firewall.tcp_out_allow` permits outbound TCP to a destination IP or CIDR on a port range, which `tcp_out` cannot express; it is emitted after the `smtp_block` guard and warns when the destination is `0.0.0.0/0`.
- A new firewall command clears one address's accumulated local threat score without changing blocks, allow lists, whitelists or event history. New findings start a fresh scoring record.
- An optional cron entry for nightly automatic upgrades, shipped switched off. It is installed alongside the other sample configuration and does nothing until an operator copies it into place; the file explains how, and warns about switching development builds to the release channel.
- The clean-corpus manifest now names the CMS of every pinned source and lists each supported CMS that has no pinned source yet with the reason, so a database scanner for a new CMS cannot ship without a corpus decision.

### Fixed

#### Realtime detection and rules

- The self-deleting-dropper detector no longer floods on plugin scratch files: an empty guard file that a plugin creates and deletes under an upload directory is no longer treated as unreadable content, and a PHP file whose first statement stops the interpreter is recognized as data. One plugin produced hundreds of these alerts a day on a busy host, enough to raise a false account-compromise incident.
- Legacy callback checks no longer mistake quoted data, comments or interpolated strings for executable input. Simple array lookups, helper calls and prefixed dynamic bodies remain covered.
- Realtime signatures no longer report socket wrappers, HTTP request fixtures or ordinary legacy callbacks as backdoors. Callback detection now ties suspicious input to the generated code instead of nearby documentation or unrelated calls. A routine plugin update raised two critical alerts on a clean site.
- A staged WordPress core or plugin update is now checked against the official wordpress.org checksums instead of trusting the directory name: stock files stay silent, a file the official package does not ship gets its own warning even after WordPress has moved it into place, and a package with no checksum source raises one warning for the staging directory. Small updates no longer produce one warning per file because WordPress finished moving the old plugin out before real-time scanning looked for it.

#### Correlation and incidents

- The correlation policy table in the incidents documentation is generated from the check registry and a test fails when it is stale. Regeneration preserves surrounding text and marker line endings; checks also work with trimmed build paths.
- Cross-account correlation initializes host detection before updating active findings, so a slow platform probe does not block readers of the current state.
- Every check now carries an explicit cross-account correlation policy with a stated reason when it is excluded, and a test refuses a new check that has none. Two file-index finding names that older releases emitted are registered again so a completed scan can finally clear them from the active list.

#### Findings and history

- Findings raised without a time (suspicious mail logins, sensitive file writes, mail AV degradation, YARA worker crashes) now carry the moment the daemon received them in history, incidents, alerts and the audit log, instead of the zero time that sorted before every real event and collided finding ids.

#### Firewall and blocking

- Destination-scoped outbound rules now handle IPv4-mapped subnets correctly. Lockout warnings remain visible when an exception cannot cover the connection's address family or has invalid ports.
- Clearing a local threat score now handles equivalent stored IP address spellings and concurrent requests correctly, including overlapping saves. Extra command arguments are rejected before any record is cleared.

#### Reputation and address lookups

- Address lookups retain available network details even when country data is missing or comes from the country-block store.
- Looking up an address now reports the network and organisation it belongs to. That database was already being opened and its answer discarded.
- The attack database no longer reads or writes state files, including event history used for statistics, when it has no configured directory. It previously resolved to a relative path and used whatever directory the process was started from.

#### Upgrades and packaging

- The installer no longer writes the three sandbox directives that systemd 239 (EL8, CloudLinux 8) rejects at every start; it says which were left out. Newer systemd keeps the full unit.
- An upgrade now confirms the new daemon is actually working before keeping it. A daemon that stops or fails health diagnostics triggers rollback.
- Upgrades now stop an unhealthy daemon before restoring the previous release, and reject invalid health-check wait settings. Failed nightly upgrades also notify root through cron mail.

#### Service lifecycle

- Service shutdown now lets the daemon stop its workers in order, closing a race that could still report an orderly restart as a worker crash.
- A normal CSM restart no longer reports the YARA worker as crashed. The worker is stopped along with the daemon, and that orderly stop was raising a critical alert every time the service was restarted.

#### Diagnostics and CLI

- Detection self-tests now fail on incomplete rule loads, scan errors and empty input, and explicitly report unavailable engines. The obfuscated sample now uses a callable PHP function, and error details and newly closed gaps appear in the text report.
- Correct the privilege inventory to describe actual kernel access, writes and disable controls, including operations with no config switch. Sandbox checks now reject empty or unrelated claims, and the service no longer grants write access to read-only mail policies.
- Inventory exports now report output failures in every format, so a failed write no longer looks successful.
- Doctor reports the running posture and warns when a configured mode change still needs a restart.
- Doctor now names the CageFS cages that lack the PHP Shield event mount and gives the per-account remount command, instead of a count that pointed at every cage. An account it cannot resolve stays visible by uid, with a note to resolve the name first rather than an invalid command.
- The PHP relay guard now says why it is inactive and which setting turns it on, instead of reporting itself as unimplemented.

#### Corpus and test coverage

- The release integration test repairs the Ubuntu cloud image's own unmet dependencies before installing the built package, so a stale base image no longer fails the job and blocks publishing.
- Clean-corpus metadata tests now work with trimmed build paths and check that invalid manifests leave existing files untouched.
- The list of supported content management systems is now declared once and tested against the taint analyzer's path knowledge and the database scanners. Tests reject incomplete or duplicate declarations; clean-corpus coverage remains separate.

### Security

- Self-deleting dropper detection now requires conclusive content evidence before suppressing a finding: it handles separate file-creation events, preserves evidence of concurrent writes and executable-mode changes, and refuses to exempt a PHP file whose unreachable tail could be decoded back into source. Content and signature findings keep priority over content filtering.
- Scheduled and realtime scans now share a simpler check for directly supplied dynamic callback bodies. Ordinary callback assertions and factory methods no longer raise critical alerts; complex generated code needs further analysis.
- Action records now cover missed response and firewall paths, preserve recovery evidence after partial failures, and avoid duplicate block records. Evidence hashing no longer delays quarantine or follows symlinks, and broken log sinks cannot stop completed actions.
- Observe mode now blocks independent kernel and mail actions, skips web and mail integration changes, and refuses startup with a pending firewall rollback.
- Mail hold and governor alerts now require a local mail-server decision; a message subject or peer name can no longer forge one.
- Failed directory reads no longer clear file-index findings, including findings left by older releases. Incomplete scans retain their previous baseline, and retries and startup scans recheck directories even when cached timestamps still match.
- Cross-account correlation now follows the explicit per-check policy, and database, mail, crontab, process and realtime findings carry the owning account, resolved from the panel's domain owner table, a passwd home directly under an account root, or the file path. Service users, envelope senders and display labels never become an owner; an eligible finding without one is reported rather than counted.
- Five of the six syscall groups the service unit meant to deny were silently discarded by systemd, so module loading, mounting and raw I/O were never blocked. The unit read as hardened while the hardening was absent.
- The operator's web server override in the configuration is applied before crash reporting starts. Crash reporting tags its events with the detected platform, and on a host with it enabled that detection ran first, so the override was silently ignored at every daemon start and log watchers followed the probe instead of the configuration.
- The manual, automatic and full-scan quarantine sets and the attack database mapping are declared once each and tested against the check registry, so a renamed or never-emitted check name cannot sit inert in a response table. Three never-emitted names are removed: one dropper name from every quarantine set, and the two WAF block names the attack database listed, which means WAF blocks have never contributed to local reputation scoring.

## [3.35.0] - 2026-09-08

### Highlights

- A WordPress core, plugin or theme update now raises one finding for the package instead of one per file. On a busy host these were over 3,000 warnings in a day, and nearly all of them came from ordinary updates.
- Real-time scanning no longer reports credential theft on plugin screens that sign in to a vendor account. That finding was Critical, and Critical real-time matches feed automatic quarantine.
- Password-protected archive attachments are reported honestly instead of as a disk failure, and archives made by 7-Zip and recent WinZip are no longer skipped in silence.
- The firewall refuses to block loopback and other non-routable addresses, and new installs filter IPv6 as well as IPv4. A dual-stack host previously let a blocked attacker return over IPv6.
- Findings across process monitoring, automatic response, scanner health, mail and sensitive-file writes now carry the time they were raised instead of a zero date.
- Country lookups and configuration validation reflect what is actually installed, so a mistyped download key no longer passes validation while nothing is downloaded.
- Firewall integrity monitoring checks the rules CSM applied, so reconfiguring no longer reports the ruleset as changed outside CSM.

### Security

- Firewall integrity monitoring now checks the rules CSM actually applied, so editing configuration cannot conceal an external ruleset change. Subnet safety checks cover protected scopes inside wider ranges while still allowing legitimate ranges beginning at zero.
- Dropper path suppressions now follow configuration reloads for new and pending findings. Exploit scripts using shell download commands remain detectable without a shebang.
- Subnet blocking and promotion to a permanent block now refuse non-routable addresses, matching the single-address path. The existing range check reads the host's interface addresses, which omit loopback, so a range covering it was accepted; promotion bypasses the ordinary block path by design and so bypassed its guard too.
- The firewall now refuses to block loopback and other non-routable addresses. The existing guard was built from the host's interface addresses, which deliberately omit loopback, so the one address that can never be an attacker was the one the guard did not cover; a block was accepted rather than refused and only the rule ordering kept traffic flowing.
- WAF attacker reports no longer name the server itself. A control panel proxies its own requests, so denials attributed to loopback or to the machine's own address accumulated until the report advised permanently blocking the host.
- A Revolution Slider exploit rule no longer fires on a security plugin's own block log. The rule matched the request payload wherever it appeared, so a log quoting the attack it stopped looked identical to an attack tool; it now requires the payload to sit in code that issues the request. Exploit tools in PHP, Python and shell are still detected.
- An Exim exploit rule no longer fires on a security plugin's own signature database. The rule joined two unrelated keywords across an unbounded stretch of text, so any file discussing exim exploits matched with no exploit present, and it now requires the keywords close together or an actual command-execution primitive. Genuine exploits are still detected.
- New installs filter IPv6 as well as IPv4. The shipped configuration never mentioned the setting, so on a dual-stack host every IPv6 packet bypassed the firewall while the blocked-address list applied only to IPv4, letting a blocked attacker return over IPv6. Existing installations keep their current setting and continue to be warned when it leaves them exposed.
- Attack evidence attributed to the host remains visible, including failed FTP authentication through local connections.
- The privileged database account audit verifies the stock MariaDB authentication setup before exempting its system account; modified accounts remain reportable.
- Malware rules and their directory now install with permissions the scanner accepts, including when the installer runs with a permissive umask.
- Encrypted-archive reports now stay bounded for attachments with many members, without deferring delivery solely because member names were omitted. A dropped encrypted-archive warning no longer silences later warnings for an hour.
- Email attachment scanning no longer passes over an encrypted archive member in silence. Archives made by 7-Zip and recent WinZip were skipped without any record, so a password-protected attachment could be delivered unscanned with nothing reported; an archive member CSM cannot decompress is now reported as well.

### Fixed

#### Firewall and blocking

- Reconfiguring the firewall no longer reports the ruleset as modified outside CSM. Applying a configuration change rewrites the rules, so every legitimate edit raised a tampering alert. An edit made while the configuration is unchanged is still reported.
- Firewall commands answer a request for help with their own usage instead of complaining that the help flag is not an address, and refuse an option-looking word where a free-text reason belongs rather than silently recording it as the reason.
- A web front end proxying to its own backend over the machine's public address is no longer treated as a user connecting to an unusual destination. That traffic never leaves the host, but it was classed as command-and-control and drove the server's own address to a critical threat score no operator could clear. Connections to any other address are reported as before.

#### GeoIP and configuration

- Country lookups from the command line now read the same databases the service uses. The command consulted only the country-blocking store, so it reported no data on hosts where lookups demonstrably worked, and pointed at a command that could not have fixed it.
- Configuration validation now checks that a country database is actually installed, rather than that download credentials are filled in. Credentials only authorize a download, so a mistyped key passed validation while nothing was ever downloaded and the trusted-country setting stayed inert.
- GeoIP validation distinguishes download credentials from locally provisioned databases. Installation instructions keep repository key approval interactive and explain unattended key trust correctly.
- Configuration validation now warns when trusted countries are listed without GeoIP credentials. Country lookups need the GeoIP database, so without it no address was ever treated as trusted and a setting operators rely on to avoid locking themselves out did nothing.

#### Mail

- Password-protected archive attachments are reported as encrypted rather than as a failure to stage the file, at most once an hour, and no longer count as an incomplete extraction. Operators running the deferring fail mode had such messages retried until they bounced, and the alerts pointed at a disk problem that did not exist.
- Email antivirus findings now carry the time they were raised instead of a zero date.
- Successful FTP logins over loopback no longer raise an unfamiliar-address warning for routine control-panel transfers.

#### Malware detection and rules

- Repeated scan errors remain rate-limited when failures contain many different paths or offsets, while preserving counts of suppressed failures.
- Two OWASP protocol-policy rules are now classified, so enabling the rule set no longer produces an unresolvable warning on every hit. They fire on unusual but legitimate requests as often as on attacks, and a rule carrying real attack evidence still overrides the classification.
- A malware scanner that loaded no rules no longer describes itself as active, and a repeated scan failure is written once with a count of what it suppressed rather than once per file. A broken rules directory previously produced hundreds of identical log lines a minute while the daemon reported a healthy scanner.
- Legitimate code that uses goto for a state machine is no longer reported as obfuscation. WordPress core's HTML parser is built that way, so every site on a server reported the same unmodified core file. Obfuscated code is still reported: what counts now is whether the labels carry meaning, and whether the file reaches a code-execution call.
- Real-time scanning no longer reports credential theft for plugin screens that sign in to a vendor cloud account or send a registration notice. A match now requires the mail builtin itself to carry the posted credentials, which is what the on-demand scanner already required.

#### WordPress and real-time detection

- A WordPress core update staged in a generated working directory now collapses to one finding like every other update shape. That shape alone accounted for a third of one day's per-file warnings on a busy host.
- A WordPress core, plugin, or theme update now reports one finding for the staged package instead of one per file it unpacks, and that finding clears itself once WordPress removes the staging directory. A single plugin update had been producing over a hundred warnings. Files staged under a name matching nothing installed on the site still report individually, and content scanning of every staged file is unchanged.
- Real-time dropper detection now honours the ignored-paths list, like every other content check. Security plugins that rotate their own files under the web root produced findings an operator could not suppress without turning the check off entirely.

#### Findings and alerting

- Process monitoring, automatic response, scanner health, and mail relay storage errors now report the time they occurred instead of a zero date.
- Suspicious email login and sensitive file write findings now carry the time they were raised instead of a zero date.

#### Web UI

- Host-address lookups no longer hold the cache lock while querying interfaces, and replacing the lookup source cannot restore stale results. PHP-FPM worker counts now match process titles, and database memory reporting accepts server arguments mentioning a wrapper.
- The performance panel now counts PHP workers on Apache hosts and reports database memory on MariaDB. It recognised only the LiteSpeed process name and read a pid file that does not exist on cPanel, so a busy server showed no PHP activity and no database memory, which reads as an idle machine rather than a collector looking in the wrong place.

#### Database auditing

- The MySQL superuser audit no longer flags the unmodified stock MariaDB system account. Accounts with the same name on other hosts remain reportable.

## [3.34.1] - 2026-09-07

3.34.0 was tagged but never published: its pipeline stopped at lint before
building anything, and release tags are protected against being moved.

### Highlights

- Installs and upgrades refuse a release they cannot verify. Hosts whose OpenSSL cannot check Ed25519 now verify through the installed binary or python3-cryptography instead of skipping the check, and `csm doctor` reports any deploy script on the host that could still install an unverified artifact.
- The service no longer holds write access to all of `/etc`. Configuration writes are limited to the directories CSM manages, and mail configuration changes run in a separate constrained operation.
- Automatic termination signals its target through a verified kernel handle, so a process that exits mid-action cannot hand the signal to whatever reuses its process ID. Kernels that cannot do this leave termination disabled and say so in health and doctor output rather than failing quietly.
- Quarantine is a durable transaction: content and metadata are written before the original is removed, and a restore puts back the original ownership, permissions and modification time.
- Mailbox password auditing no longer passes stored hashes or candidate passwords as command arguments.
- Sites other than WordPress are handled properly. Administrator baselines are per installation instead of per account, configuration reads are bounded and reject symlinks and special files, and a failed query no longer retires that CMS's earlier findings.
- Firewall changes report persistence failures instead of recording success, overlapping address ranges apply without dropping coverage, and a firewall that fails to start degrades health instead of reporting ok.
- Mail monitoring keeps reading after an in-place log truncation, preserves records split across writes, and recovers a lost log source without a daemon restart.

### Security

- Internal registry upgrades accept an unsigned CI build again, which only tagged releases are signed for, while a release fetched through that path still requires its signature and `CSM_REQUIRE_SIGNATURES=1` refuses both.
- PHP taint analysis no longer reports remote execution for an assertion over a type check, and recognises the filesystem path constants of Joomla, Drupal, OpenCart and Magento rather than only WordPress's.
- Operator copies of the deploy scripts are now reported by `csm doctor` when they predate mandatory signature verification, so a hand-maintained copy cannot keep installing unverified releases unnoticed.
- The SOCKS proxy rule no longer treats a single 0x05 byte as evidence, which had reduced it to matching any file that opens a socket.
- Release verification now rejects special and oversized inputs without blocking. Python verification no longer loads modules from caller-controlled locations.
- Update checks no longer execute downloaded code to read its version.
- Standalone installs and upgrades now require successful release signature verification. Hosts whose OpenSSL cannot verify Ed25519 verify through the installed binary's new `csm verify-release` or through python3-cryptography instead, and installs and upgrades stop when no verifier is available; only explicitly selected pre-signing releases may omit a signature.
- The service now limits configuration writes to managed directories. Mail configuration changes run in a separate constrained operation, and opted-in module removal retains the daemon sandbox.
- Rule permission checks now cover every filename extension accepted by the YARA loader.
- Package integrity rechecks keep reported modifications unresolved when a previously flagged file loses its executable mode or disappears.
- Journal mail monitoring now follows new records when the selected services have no prior journal entries.
- Process termination now uses a verified process handle, preventing recycled process IDs from redirecting an action. Kernels without `pidfd_open`, including EL8 and CloudLinux 8, pin the target through its process directory instead of losing termination. Kernels that support neither leave termination disabled, fail the matching health and doctor check, and report the cause.
- Quarantine restore preserves recorded ownership, permissions, and modification times. Historical entries use their saved quarantine dates when available.
- Quarantine and restore now make recovery data durable before removing originals. Storage failures preserve recovery copies and report partial completion.
- Mail monitoring preserves records written in fragments and discards oversized records through their terminating newline, preventing partial records from hiding or distorting authentication events.
- Overlapping firewall ranges now apply without disabling protection. Removing or expiring one range keeps coverage supplied by the remaining entries.
- Email password checks no longer expose passwords or stored hashes through process arguments or findings. Password formats outside the supported audit limits are reported as incomplete and remain eligible for retry.
- Partial CMS database scans now preserve earlier findings for the affected CMS without delaying cleanup of findings from successful scans. Failed or truncated scans no longer establish administrator baselines.
- CMS administrator monitoring now tracks each installation separately, preventing one site's known accounts from hiding a new administrator on another site. Existing installations establish a fresh baseline after upgrading.
- CMS configuration scans now reject oversized files, symlinks, and special files. Unreadable configurations keep scan coverage incomplete and prevent manual re-checks from clearing findings.
- Stronger hidden-link evidence now raises a fresh alert after an earlier warning was acknowledged. Growth in affected rows no longer creates duplicate findings for the same destinations.
- Realtime scanning now checks files during atomic saves and restores. Verified WordPress content remains quiet, while modified files receive normal content analysis.
- Quarantine restore now keeps filesystem operations inside the permitted destination when account directories change during restoration. Conflicts preserve the quarantine copy for recovery.
- Quarantine rollback preserves concurrent file replacements and keeps recovery copies when it cannot safely finish. Failed restores no longer remove files through names another writer can replace.

### Fixed

- Lint no longer times out loading packages on a fully loaded pipeline, which blocked a release.
- Kernel validation now runs to completion on its dedicated runner: it builds against a checkout owned by another user, starts and exits correctly on the production image, and leaves results the runner can collect, instead of failing before any test ran.
- Release test jobs no longer run two full race suites against one runner at the same time, and the production suite reports its failures instead of losing them past the log capture limit.
- Process termination health now recovers after transient resource failures.
- Development and readiness documentation now matches required test jobs, completed fixes, and outstanding release infrastructure checks.
- Credential rotation instructions now state the restart requirement for environment-backed tokens and signing secrets.
- Fixture privacy checks now block CI and publication, cover all fixture formats, and report scanner failures without printing suspected private addresses.
- Release publication now requires tests with the shipped features and real kernel and service checks. Failed BPF monitor startup releases its event reader.
- Tagged releases now require cPanel package and upgrade validation before publication, or a stated reason for releasing without it. Missing cPanel test infrastructure stops the release early, and a release taken without that coverage records the gap in its own evidence. Blank, padded, and flag-like waiver values are rejected.
- Release publication now requires pinned clean-application checks across the signature and taint engines, with retained measurements for review.
- Configured account roots now work with manual remediation and quarantine restore. Operators can generate narrow service write grants and check them with health diagnostics.
- Large state databases can now be backed up and restored under the same configurable archive limit. Restore checks available staging space before replacing live files.
- Backup restore rejects corrupt, truncated, and unsupported trailing archive data before replacing live files.
- Audit logging retries failed destinations without reopening healthy ones. Delivery failures remain visible in metrics, and reloads wait for active writes to finish.
- Firewall changes now report persistence and rollback failures without success audit records. Failed allow removals remain eligible for retry, and port-specific changes say when a reload is required.
- Mail monitoring retries failed source attachment and recovers without a daemon restart. Automatic source selection can switch to journal input after a file disappears, while explicit source settings stay in effect.
- Mail monitoring resumes from the start after detecting an in-place log truncation, so new authentication events are read again.
- Firewall startup now retries temporary failures and reports a persistent failure in health status and diagnostics. Failed attempts preserve the existing kernel rules.
- A WordPress core rebuilt from an older release reported every leftover file of the newer one as its own finding, which on one install produced over a thousand rows and buried the rest of the scan. The install now gets one finding that counts the files and samples them.
- The audit log was never rotated, so it grew without limit; on one host it reached 93 MB. The packaged logrotate fragment now covers it.
- Upgrades refresh log rotation rules, so existing installations receive the audit log rotation policy too.
- Database findings stored a second copy of themselves whenever the panel's domain map failed to load mid-scan, because a line about the document root appeared and disappeared with it.
- Shared administrator emails now retain one finding identity while the account set is unchanged. Previously, refreshed last-seen metadata created duplicate queue entries.

### Changed

- Findings whose duplicate copies were fixed in this release get a new identity, so any dismissal recorded against the old one is dropped and the finding is shown once more.

## [3.33.1] - 2026-09-04

### Highlights

- Realtime false positives that flooded the alert channel are fixed. On a busy shared host this removed every Critical the self-deleting-dropper detector was raising and about 90 percent of realtime warnings.
- A path taken over by a newer file no longer reports as a self-deleting dropper. Wordfence rewrites its firewall state that way every few minutes on every site that runs it.
- A file whose whole directory was removed now reports at a lower severity, which is what a WP Toolkit site clone does when it tears its staging tree down.
- Plugin files staged by an update are verified against the plugin's official release, so a routine update no longer opens a warning for every file it unpacks.
- Translation caches larger than 64KB are recognised as data. Nearly half of them are larger than that, and each one used to open a warning.
- The short-lived-file tracker no longer fills up during a site clone or package restore, which left new files untracked until the storm passed.

### Security

- A WordPress core or plugin file exactly as large as the verification read limit could have a payload appended and still be accepted as an unmodified official file, which suppressed signature and YARA findings on it. Verification now reads the whole file or refuses to verify it.

### Changed

- Updated the Sentry Go SDK to 0.49.0.

### Fixed

- A plugin update in progress opened one realtime warning for every file in the package. Files staged by an update are now checked against the plugin's official release, including plugins whose main file name differs from their package directory.
- The self-deleting-dropper detector reported a Critical for every file whose path was taken over by a newer file, which is how Wordfence rewrites its firewall state every few minutes. A replacement now reports at a lower severity, and so does a file whose original directory was removed, as happens when WP Toolkit tears down a site clone.
- Realtime scanning read only the first 64KB of a PHP file in a WordPress languages or upgrade directory before deciding whether its contents were inert data, so it could never clear a translation cache larger than that. Nearly half of them are, and each one opened a warning.
- The short-lived-file tracker filled up during a site clone or package restore and stopped following new files until the storm passed. It now holds four times as many files while keeping retained content bounded.

## [3.33.0] - 2026-09-04

### Highlights

- Realtime scanning now sees writes inside CloudLinux CageFS cages. Every write that reached an account through a bind mount previously raised no event at all, so the accounts most likely to be compromised had no realtime coverage.
- WordPress installs on subdomains, on addon domains and one directory below a document root are scanned by every database, core-integrity and plugin check. On a typical cPanel host this roughly triples the number of installs examined, so expect a batch of findings from sites that were never scanned before, and a longer first deep cycle.
- The Re-check action works on real servers. It resolved account directories from a list only tests ever filled in, so on a live host every malware, permission and .htaccess re-check failed on the path before opening the file, and no cleaned file could leave the queue.
- Realtime phishing, credential-log, archive and CGI detection works on Plesk, DirectAdmin and any layout whose accounts are not under `/home`.
- Automatic responses verify what they are about to act on: a process is killed only when it is still the process the finding described, and a file is quarantined only when it is still the file the scanner read.
- Daemon shutdown no longer waits on a Cloudflare range refresh. On a host that cannot reach cloudflare.com, stopping the daemon took two HTTP timeouts.
- The YARA engine moves to YARA-X 1.20.0, validated by compiling and scanning both rulesets under each version and diffing the results.
- `csm doctor` reports binary, `csm.yaml` and conf.d hash mismatches while the daemon is still running, instead of leaving the mismatch to be discovered when a restart refuses to start.

### Security

- Realtime scanning was blind to writes that reached a file through a bind mount, which is how every CloudLinux CageFS account reaches its own files. Marks now cover the filesystem rather than a single mount, and any watch root left with narrower coverage is named at startup.
- The realtime phishing, credential-log, archive and CGI detectors only recognised `/home` and `public_html`, so on Plesk, DirectAdmin, or a cPanel host with accounts elsewhere they never fired at all.
- A file could be swapped between the moment the realtime scanner read it and the moment it was quarantined, which moved the replacement and left the malware in place under another name. Quarantine is now pinned to the file that was actually scanned.
- The verified-CMS exemption hashed the path rather than the content that had been scanned, so presenting a clean core file at that moment skipped both the signature and YARA engines for content already read as malicious.
- A `wp-config.php` that is a symlink is refused rather than scanned, because wp-cli follows it as root: an account could otherwise point its own config at another account's and have that tenant's database inventoried under its name.
- Automatic responses and the Fix action killed a process by number alone. A recycled PID meant an unrelated process was killed as root; the kill now requires the process to still match the finding, and the kill that precedes a quarantine requires it to still hold the file.
- The connection monitor performed its verdict callback inside the event loop, so one denied connection could stall the reader for the callback's timeout and overflow the event buffer. Findings are dispatched first and enrichment is bounded; when it saturates the annotation is dropped, never the finding.
- File-specific scan gaps no longer block retirement of findings for files that were examined. Findings stay open when their scanner did not examine the file, including interrupted and shared scans.
- Branded webshells and plugin-directory droppers stay detectable when padding separates their identifying content from the dangerous operation.

### Added

- Firewall validation now warns when the outbound policy omits the port of an enabled outbound endpoint (webhook, heartbeat, SMTP, syslog, verdict callback, threat-intel and update URLs) or port 443 for the built-in feeds. A host whose policy dropped its control-plane port went silent with "connection refused" while looking healthy locally.
- A conf.d fragment can declare the outbound ports its service needs under `firewall.required_tcp_out`. The list is checked against the effective policy, never merged, and `csm doctor` reports a drop.
- Fragments an integration rewrites on its own schedule can be listed under `confd.integrity_exempt` in the main config so each rewrite no longer makes the next restart fail. Every other fragment stays covered by the integrity hash, and a fragment cannot exempt itself.
- `csm doctor` now reports a binary, `csm.yaml` or conf.d hash mismatch, with the remedy, while the daemon is still running on its old hashes and before a restart refuses to start. A host with no recorded baseline gets a warning instead of a clean report.

### Changed

- The YARA engine moves from YARA-X 1.19.0 to 1.20.0. Both rulesets were compiled and scanned under each version first: the shipped rules produce the same matches file for file, and the warning sets are identical apart from one diagnostic 1.20 adds. Nothing detected today stops being detected, and the version a developer runs locally is now the version that ships.
- A `www` directory in an account home is scanned as the document root it is, and collapsed into `public_html` when it is the usual cPanel symlink, instead of being excluded as an alias.
- `csm rehash` is listed in `csm --help`, and an integrity refusal at startup names it as the fix after an intentional change. It was discoverable only from a source comment.

### Fixed

#### WordPress and CMS scanning

- WordPress installs on subdomains, on addon domains and one directory below a document root are now scanned by the database-object, admin-overlap, credential-reuse, core-integrity and plugin checks, and findings raised on them can be fixed and re-checked instead of staying unresolvable because the fixer could not re-locate the install.
- WordPress discovery treats document-root resolution failures as incomplete, retains and evaluates plugin inventory after partial discovery, keeps account cleanup pointed at the primary install, and does not mistake account names for backup or cache directories.

#### Findings and re-checks

- Re-checking a malware, permission or .htaccess finding now resolves the account directories of the running host instead of an allow list that was only ever filled in by tests. On a real server every one of those re-checks failed on the path before the file was opened, so the Re-check action never worked and no cleaned file could leave the queue.
- The Re-check action now applies a demotion, and reverses one when the file stops being inert, instead of computing the verdict and discarding it. The UI reports a severity change only after the stored finding was actually updated.
- A finding whose flagged content is gone, but whose file changed since detection, now drops to Warning instead of staying Critical. It is never cleared, so an attacker cannot retire one by editing the file; what changes is that finished cleanup work stops ranking beside live threats. Only a replacement that can be proven inert qualifies -- an empty file, or a comment-only stub that never reopens into HTML -- and the severity comes straight back if the file stops being inert. An unconfirmed demotion also survives a scan that does not raise the finding again, so the state is not lost before the re-verifier has read the file.
- Findings are re-verified once per deep-scan cycle as well as when the re-check logic changes. An operator cleaning a file, or a virtual patch closing an exposure, moves the world without moving CSM's rules, and a finding gated only on those sat at its original severity until an unrelated upgrade happened to land.
- The re-verification sweep at startup now also re-runs when the sweep's own behaviour changes, not only when detection logic does. A change to what the sweep may do previously waited for the next deep-scan cycle to take effect on a host that had already recorded one.
- Finding re-verification summaries now count only state changes the store accepted and report severity restorations separately from cleared findings.
- The finding re-verification sweep always reports what it did, including how many findings it could not check and the commonest reason. A sweep that changed nothing logged nothing, so one failing on every finding looked exactly like one that never ran.
- Web-exposed file findings can now be re-checked and are retired after a complete probe against the local origin confirms remediation. Re-checks stay pinned to current vhost routing and fail closed when routing data, either web protocol, or phpinfo body confirmation is incomplete.

#### Deep scanning and coverage

- The YARA deep scan now handles a file it could not read the way the PHP and JavaScript scans already did: it re-emits that file's existing finding and retires everything else it examined, instead of holding its entire finding set. One error log permanently over the scan limit was enough to freeze every YARA finding on a host for as long as that file existed.
- Deep-scan carry-forward now preserves every prior YARA rule match and the current PHP or JavaScript finding for each unexamined file across equivalent path spellings, without undoing concurrent dismissals or severity changes. Ambiguous file-type or identity changes retain the affected scan range rather than retiring findings without coverage.
- A YARA coverage gap now says what it was -- how many files were oversized, unreadable or changed mid-read, and how much was lost to a directory the walk could not enter -- rather than only how many entries were missed. The kinds are not equivalent: a file that can be named is carried forward, while an unreadable directory hides an unknown range and still holds everything.

#### Rules

- Large PHP logs no longer combine a family name or failed write with unrelated quoted source from another diagnostic record and report the file as malware.
- The duplicate YARA detectors for a shell download pipeline are now one rule, and commands contained by fenced code or Markdown links are treated as documentation.

#### Daemon and connectivity

- Daemon shutdown cancels an in-flight Cloudflare range refresh instead of waiting out the HTTP timeout, twice, on a host that cannot reach cloudflare.com.

## [3.32.0] - 2026-09-02

### Highlights

- WordPress database scans now find what a filesystem sweep cannot: PHP snippets stored by WPCode, identifiers built by XOR-ing binary strings, hidden link blocks, spam taxonomy, and doorway options and sitemap rewrites. An active backdoor was running from a database row while a full file scan of the same site came back clean.
- Two content-scanning bypasses are closed: a webshell uploaded as `.phtml` or `.php5`, and any file carrying four bytes of ZIP or gzip magic in front of its PHP, were skipped by every signature and YARA rule.
- Passing the proof-of-work challenge no longer adds the visitor to the operator firewall allow list, which opened every port and skipped later checks.
- A forged SMTP HELO can no longer point brute-force blocking or a reputation lookup at an address of the sender's choosing.
- `csm doctor` now reports how many CageFS cages are missing PHP Shield's event mount. Until each cage is remounted, PHP there drops every detection, which looked exactly like a quiet server.
- An active known-vulnerable plugin is reported as unprotected and raised to Critical when ModSecurity does not filter its traffic, and the alert says when a shipped virtual patch cannot run.
- Database findings now say whether the document root is currently served, so a dormant compromise and a live one stop looking identical in the queue.
- Store export and restore no longer stage archives where a local account can redirect or read them.

### Added

- A site that suddenly publishes far more than it ever has is now reported. Spam floods are found by the change in publishing rate rather than by a word list, so the detection does not depend on which language the spam is written in.
- `csm doctor` now reports how many CageFS cages are missing PHP Shield's event mount. Registering the mount is not enough: until each cage is remounted, PHP there cannot reach the event socket and every detection is dropped, which until now looked exactly like a quiet server.
- Categories, tags and other taxonomy terms created by spam kits are now reported. Removing spam posts leaves the taxonomy behind and a category archive is a public page, so a site can keep serving spam links after every spam post is gone.
- A spam finding whose sample hit the per-pattern row limit now says the count is a lower bound instead of reporting it as the total. An exact-looking small number reads as trivial, which is how a site with hundreds of spam posts was deprioritised.
- PHP snippets stored in the database by WPCode are now scanned. Code kept in a database row is invisible to every filesystem scan, and an active backdoor was running from one while a full file sweep of the same site came back clean.
- Code that builds its own function and constant names by XOR-ing two binary strings is now reported. The technique exists only to keep those names out of the file, so keyword-based rules never saw it, and it was hiding an active backdoor stored in a site's database rather than in a file.
- An active known-vulnerable plugin is now reported as unprotected, and raised to Critical, when ModSecurity does not filter its traffic; where CSM ships a virtual patch for that CVE the alert says the patch cannot run. A cPanel addon domain is matched to its exact associated subdomain, so a disabled flag recorded against either name covers the site, without treating every vhost that happens to share a document root as the same site.
- Link blocks a page hides from its readers are now found in the database. A container pushed off the canvas, or hidden outright, that wraps links to other domains lends the site's ranking to those domains while a visitor sees nothing; subdomains of one target count as one domain.
- Doorway scaffolding kept in the WordPress options table is now reported: an autoloaded option named after a digest holding encoded configuration, which cannot be found without already knowing the key, and rewrite rules routing a numbered sitemap into a matching numbered feed so crawlers are handed generated pages the real sitemap never lists. Partial or oversized option reads are treated as incomplete scans instead of evidence.
- A stored PHP snippet that disables caching for the request and, in the same snippet, tests the visitor's user agent for a search or SEO crawler is now reported as cloaking. Neither half means anything alone, which is why both are required: caching helpers and user-agent checks are ordinary by themselves.
- Database findings now say whether the document root is currently served. A dormant install still holds a live database and publishes again the moment a domain is pointed at it, but it is not reachable today; without that distinction a dormant compromise and a live one look identical in the queue.
- A WordPress site address pointing at a domain the account does not own is now reported, but only for a document root the panel is currently serving. A site that moved away is no longer served, which separates a hijack from a migration; incomplete ownership data stays inconclusive, and delegated subdomains follow the account that actually serves them.

### Changed

- Bumped Go module dependencies: `tdewolff/parse/v2` 2.8.15 -> 2.8.16, `golang.org/x/net` 0.57.0 -> 0.58.0, `golang.org/x/text` 0.40.0 -> 0.41.0.
- Pinned `github/codeql-action` to v4.37.8 in the CodeQL and Scorecard workflows.
- GitHub release pages now lead with the release's highlights and security fixes and collapse the rest of the changelog behind them, with a link to the full file at the tag. A release cut from a busy cycle used to paste well over a hundred entries onto the page.

### Fixed

#### Malware scanning and response

- PHP Shield no longer records a webshell command parameter for the single-letter names `c` and `e` unless the value looks like a command; WordPress core's own load-styles.php and load-scripts.php take `c=0`, so every admin page view raised an event and buried the real probes. A value carrying shell metacharacters, a path, a binary name, base64 that decodes to any of those, or one longer than 512 bytes still counts, a parameter actually named cmd, command, exec, execute or shell is still recorded on its name alone, and blocking is unchanged.
- A modified WordPress core file that PHP never executes and the browser never runs as script is now High rather than Critical, so a stylesheet or image that an optimiser touched, or an install whose version.php no longer names the release its files came from, no longer pages as a compromise. Core PHP, JavaScript and HTML stay Critical, and so does an SVG that carries a script or an event handler.
- The cPanel credential-phishing rule now accepts normal whitespace and quote variations in password and form-action attributes without weakening its three-part match.
- The OpenCart, Joomla, Magento and Drupal scanners now cap every query, run it under the scan deadline, discover installs under addon-domain document roots too, and baseline administrator accounts so only a newly appeared admin is reported instead of a warning per admin every cycle.
- The PHP taint analyzer now follows remote content through a file write into an include of the same path, so the fetch, write and include dropper is reported instead of coming back analyzed with no results.
- Quarantine and pre-clean backup file names are now shortened (hash plus path tail) when the flattened source path would exceed the filename limit; a deeply nested file used to fail its move with ENAMETOOLONG and stay in place.
- The phishing scanner now analyses the whole of each accepted HTML page (up to 100 KB) instead of its first 16 KB, and no longer skips WordPress core, cache, tmp and logs directories by name; a kit that opened with a large stylesheet, or that was dropped under `wp-includes/`, passed as clean before.
- The PHP content analyzer now recognises `eval()` or `assert()` applied directly to request input, a string literal concatenated in front of the decoder (the `"?>" . base64_decode(...)` form), and the `hex2bin`, `strrev`, `urldecode` and `convert_uudecode` decoders. Each shape passed as ordinary code before.
- The rolling PHP content scan now also runs in the reduced deep tier used while the realtime file monitor is active. The monitor only sees close-after-write, so a file written under a temporary name and renamed into place, or written through a bind mount, was never content-scanned by the YAML rules until a full scan.
- Three rule twins were brought back into agreement: the realtime `phishing_cpanel_login` rule no longer scores a hosting provider's own login page as Critical (it counted "cpanel" and "cPanel Login" as two hits and needed no off-site form action), the realtime `miner_hidden_iframe` rule carries the same word-boundary and miner-brand hardening its scan twin already had, and the scan-side `obfuscation_variable_function`, `dropper_rfi_include` and `webshell_encoded_eval_oneline` rules now match case-varied PHP the realtime engine already caught.
- A realtime scanner running with zero rules now raises a `realtime_rules_missing` finding at startup and after every rule reload. A mistyped rules directory or an empty rule sync used to leave every file write scanned against nothing while the daemon looked healthy.
- Realtime findings raised during the startup baseline scan are no longer silently dropped: the alert dispatcher now starts before the watchers and holds a bounded batch until the baseline has published. Any overflow is logged, and dropped reload or update findings are included in the dropped-alert count.
- The rule for a decoded request parameter fed to a command sink now matches its `call_user_func` and backtick forms in both scanning engines. A double-escaped dollar sign made those two forms unmatchable, so a shell using either was only caught by the direct-call form.
- The automatic re-check of stored content findings now honours the full-scan file size ceiling for signature and YARA findings. A flagged file that had since been grown to gigabytes was read whole, several times over, by the daemon.
- A crash inside the real-time file analyzer or the email attachment scanner no longer takes the whole daemon down. The event is skipped, a critical finding reports it, and the worker keeps going; until now one malformed message could restart the daemon, and Exim's redelivery of that same message restarted it again.
- A full scan run with `--quarantine` now applies the same bar as the scheduled auto-response: only critical findings on regular files are acted on, and an infected WordPress core, plugin or theme file is cleaned in place or left for review if cleaning fails. A single-heuristic warning used to be enough to move a plugin file or an entire folder out of a site with no one watching, and a file flagged twice in one job was reported as a failed second move.
- A WordPress core file whose content no longer matches its shipped checksum is now reported as a critical finding naming the file. Until now only files that should not exist were reported, so a backdoor appended to a shipped core file passed the integrity check in silence.
- The kernel-level sensitive-file monitor now keys its watch list with the device number the kernel itself uses. The previous key only matched on tmpfs-style filesystems, so on a real disk every live write to a watched file such as `/etc/shadow` went unreported while the monitor advertised itself as active; only the periodic content check noticed, without saying who wrote.
- PHP Shield alerts now name the request URI and user agent, so an event identifies the scanner that sent it instead of showing only a parameter name. A command parameter that was merely observed is no longer rated the same as an execution the Shield actually blocked, and one scanner sweeping many accounts now raises a single alert per source address rather than one per site.

#### WordPress and database scans

- Database hidden-link scans now keep containment across malformed markup and bounded values, recognize equivalent inline hiding syntax, and grade distinct target domains within each hidden container. Truncated candidate values now report incomplete coverage.
- The `wp_options` script-loader pre-filter no longer requires a literal `src=`, so a loader written as `src = "..."` is fetched and classified like any other.
- An external script loader stored in `wp_options` on an ordinary HTTPS host is now reported once as a Warning (`db_options_new_external_script`) the first time that host appears after the site's baseline scan. The structural classifier only flags raw-IP, abused-TLD, plaintext-HTTP and known exfil hosts, so a careful injection on a mainstream domain never produced a finding.
- The WordPress version and locale read from a site's `version.php` are now validated against the shapes WordPress ships before they name the checksum cache file or the checksum API query. The file is tenant-writable, and a crafted locale could steer the root-written cache path or rewrite the query.
- The re-check for `db_post_injection` findings now searches every published post for the injected pattern instead of re-reading only the five example post IDs the finding lists, so cleaning the examples no longer resolves a finding whose injection is still present in other posts.
- Dropping a rogue database trigger, event, procedure or function now records a backup that can actually be restored. The backup used to hold the whole raw result row rather than the CREATE statement, so every restore attempt failed after the object was already gone; a drop now refuses to proceed when no restorable statement can be captured.
- WordPress database scans now inspect server-executed WPCode snippets and spam taxonomy on every active multisite blog, bound finding evidence, and report incomplete row or byte samples.

#### Web exposure and .htaccess rules

- The .htaccess upload-tree gate now judges only directories inside the account's web tree; a "tmp" or "files" component above it used to disable the sibling-PHP gate for everything below.
- The scheduled `.htaccess` scan now walks twelve levels below a document root instead of five, reaching uploads trees where droppers plant the handler-enabling `.htaccess` next to their payload.
- A version-control directory served from a document root (`.git/`, `.svn/`) is now detected as a Critical `web_exposed_repo_metadata` finding and virtual-patched by denying the whole directory; the exposure walker used to skip those directories entirely, so a checked-out repository handing out the site's source and credentials was never reported.
- Scheduled `.htaccess` reads are now bounded to 1 MiB everywhere (audit, handler overlay reconstruction, executable-name resolution). An oversized file is reported as a High finding instead of being loaded whole, so a tenant can no longer park a multi-gigabyte `.htaccess` and turn the deep scan into an out-of-memory crash loop.
- Nested file-match expressions, conditional cPanel WAF directives, yearless leap-day logs, rolling scan wraparound, and equivalent empty platform override lists are now interpreted consistently.
- A PHP handler placed inside an .htaccess file-match block that selects files by name rather than by extension is now reported as a handler remap, and the files it selects are content-scanned as PHP. Until now such a block was invisible to both, so a backdoor stored under a name like `logo` executed without ever being examined.
- An .htaccess rule that redirects several search-engine crawlers at once to another site is now reported as crawler cloaking. The long-list exemptions meant for scraper blocklists no longer apply when the list is mostly made of search engines, since no site blocks Googlebot, Bingbot, Yandex and Baidu together.
- An .htaccess prelude directive (auto_prepend_file, auto_append_file) is now judged by the file it points at rather than by words found anywhere on the line. Targets are normalized and quoted paths are parsed whole; account-owned targets disguised with path traversal or stored as a font or under a directory named after a trusted product are reported, while a malformed directive cannot consume the next line as its target.

#### Firewall and blocking

- Firewall rollback operations now share the configuration writer lock and stale requests cannot overwrite or confirm a later change. Live-config responses use one reload generation, and promoting an incident no longer reports it as newly created.
- A firewall apply now aborts when the kernel table listing fails instead of appending every rule a second time to the live chains (doubled meters, halved rate limits) until a later successful apply.
- The apply-confirmed rollback now restores the firewall state file together with the kernel snapshot, so an address unblocked inside the window no longer comes back blocked in the kernel while the UI still reports it free.
- `csm firewall restart` and `csm firewall apply-confirmed` now read the firewall block from csm.yaml before applying, and a rollback or a failed apply restores the previous block in the running engine. Both commands used to re-apply the copy taken at daemon start, reporting success while an edited ruleset stayed unapplied until the next daemon restart, where it took effect with no rollback timer.
- Whitelisting or unblocking an address that a blocked subnet still covers now says so (web UI single and bulk whitelist responses carry a warning naming the subnet, and the CLI unblock message does the same) instead of reporting plain success while the address stays dropped.
- Firewall allow, flush and unban, whitelist removal, ModSecurity rule apply and escalation changes, verified-bots saves and rule reloads now leave entries in the web UI audit log like the other state-changing actions.
- The web UI firewall check now compares IPv6 addresses as parsed values, so a block saved in one spelling is found when queried in another.
- The web UI threat actions, including bulk actions, now act on the canonical form of the address. A pasted address with a stray space or an upper-case IPv6 spelling passed validation but matched nothing in the firewall, threat or attack databases while the page still reported success.
- IPv6 addresses are now extracted intact from log lines and finding messages when they end in `::`, are bracketed with a port, or carry trailing punctuation. The old extractors mangled or rejected those forms, so the real source could evade lookup and blocking.
- Country blocking now works with the documented default of an empty `country_db_path`: the path defaults to the geoip directory under the state path, which is where `csm firewall update-geoip` already wrote its files. Until now the firewall built no country sets in that configuration while the CLI reported the update and lookups as working.
- A Cloudflare range refresh preserves each cached address family independently and restores cached protection on startup when the network is unavailable. A failure in one family no longer discards fresh data from the other, and a first partial refresh still installs the ranges it received.
- Replacing a live firewall block that is missing from saved state no longer fails at the configured deny limit merely because the block already occupies the counted slot.
- The challenge IP maps that Apache, LiteSpeed and Nginx read now live in a directory that survives stopping CSM and are recreated if missing, so a stopped or upgrading daemon no longer makes the web server fail its configuration check and take every site down. Outdated integration snippets are refreshed when the daemon starts, and uninstall keeps the maps if any snippet cannot be removed safely.
- An operator deny or temporary ban placed on an address that is already blocked now changes the block the kernel enforces, including at configured limits and when an expiring block disappears during the update. Re-adding an existing address left its old expiry in place, so a permanent deny over an automatic one-hour block quietly expired after the hour while the status page kept saying permanent, and a temporary ban over a permanent deny kept dropping traffic after CSM reported it lifted.

#### Brute force and login tracking

- The PAM listener now reads `infra_ips` from the live configuration, so an infrastructure address added by reload stops counting failures at once.
- The SMTP account-spray tracker now keys mailboxes case-insensitively and trimmed, so a spray across case variants of one mailbox reaches the distinct-source threshold.
- Dovecot login failures now count every password attempt the "Login aborted" line reports instead of one per connection, so a client that tries many passwords per connection no longer stays under the brute-force thresholds.
- A successful PAM login now clears only the failures recorded against the account that logged in; failures against other accounts and the credential-stuffing breadth from that source are kept.
- PAM failure retention now follows the configured brute-force window, including windows longer than the previous fixed cleanup period.
- Future-dated FTP log records no longer create failure buckets that evade the configured retention window.
- The scheduled SSH login check now reads the authentication log forward from where it last stopped instead of looking at a fixed number of trailing lines each cycle, so a login is no longer hidden by the brute-force noise that follows it. Logins older than an hour found on a first run are treated as history rather than reported as new.
- FTP brute-force detection now counts each failed login at the time the system log recorded it. The first run after an install or upgrade, or a large gap in reading, could replay days of scattered failures as one burst and auto-block an address that was never brute-forcing.
- PAM brute-force and credential-stuffing detections now block the source address as the auto-response documentation has always said; until now they only produced a finding. The PAM trigger also gets its own `pam_bruteforce_threshold` and `pam_bruteforce_window_min` settings instead of silently reusing the multi-IP login keys, so the documented default of five failures in ten minutes is what actually runs.

#### Mail

- The Email Security page now reports the clamd socket actually in use rather than the configured one, so a host running on a discovered socket no longer shows "ClamAV: Unavailable" and an AV degraded badge over a scanner that is working.
- The clamd socket is now discovered when the configured one is not answering: the path belongs to whoever packaged clamd, and a host naming the wrong one scanned no mail at all while every health signal still reported the watcher running. Only a root-owned socket in a directory no other account can write to is accepted, and only when it answers clamd's own PING, so discovery cannot point mail scanning at something an account controls. Validate says which socket answered and asks for the setting to be corrected.
- Quoted pipe destinations in cPanel valiases files are now recognised as pipe forwarders; the quotes hid every one of them from the detector.
- The email quarantine handle and the AV watcher mode the daemon installs into the web UI after its listener is already serving are now held atomically; request handlers read them through accessors instead of racing plain field writes.
- Split Exim spool directories are watched again after removal and recreation, so reusing a hash directory name cannot leave later messages unscanned.
- Email attachment scanning now watches every hash subdirectory of a split Exim spool, the cPanel default layout, instead of only the spool root, so messages are no longer delivered without a scan on such hosts. Hash directories Exim creates later are picked up within a minute.
- Mailbox logins from a trusted country now count toward the login history the new-country alert is built on. They were skipped entirely, so a mailbox whose owner always logged in from home never reached the alert threshold and its first login from abroad was silently recorded as normal.

#### Web UI

- Suppression rules imported through the web UI bundle are now validated like rules added by hand: a rule without a check is dropped and a rule without an ID gets one, so imported rules can always be deleted from the UI.
- The finding detail view now resolves the stored finding's real key, so findings that carry details show their first-seen and last-seen times instead of blanks.
- The three web UI endpoints that rewrite `csm.yaml` (settings save, verified-bots save, tentative firewall apply) now serialize on one lock; they used three different locks, and the firewall path none, so two operators saving from different pages could silently lose one change despite matching `If-Match` headers.
- The web UI now accepts API requests from loopback origins (an SSH tunnel such as `https://localhost:9443`) and from any origin listed in the new `webui.allowed_origins` setting, instead of only `https://<hostname>:<port>`; reaching the UI through a tunnel or a second name used to leave it read-only because every POST was rejected as cross-origin.
- The web UI now reads the live configuration after a reload: email thresholds, firewall policy, ModSecurity settings, scan options, the hardening audit, the test alert and the feature flags followed the startup snapshot until a restart.
- Stored Web UI remediations now keep using server-side evidence when an older finding has no separate path field, and successful single or bulk fixes clear the exact finding.

#### Findings, alerts and reporting

- Pending findings are dispatched only after their saved batch clears, database injection re-checks page through every candidate, cancelled scans do not start more checks, and successful PAM logins subtract that account's failures.
- The active findings file is now written once per scan cycle, only when its content changed, in a stable order by severity and recency, so the cap keeps the most important findings instead of a random subset.
- The status command's JSON output now carries a status field, prints the offline stub only when the daemon is not running, and exits non-zero on any other control socket error.
- Shutdown no longer clears the finding broadcast bus after closing it; late publishers on untracked goroutines read that global without a lock, and a closed bus already drops what they publish.
- The threat, whitelist and reputation prune helpers now report zero rows removed when their database transaction fails to commit, instead of the count they had tallied inside the rolled-back transaction.
- The alert-state and latest-findings backups are now refreshed only after the file parses, and a corrupt file falls back to the backup. Opening a corrupt state file used to overwrite the backup with the corrupt copy and silently reset the alert dedup state, re-alerting every known finding.
- A credential-spray trip now promotes the per-IP incident that the same attacker already had open instead of opening a second incident under the same key, which left the first one open forever with nothing able to merge into or close it.
- Sub-threshold findings waiting in the incident correlator and stale spray-detector state are now pruned on every auto-close tick instead of only by the daily retention sweep.
- Cancelling an account scan now stops it cleanly: checks still waiting for a worker slot no longer start, checks cut short by the cancel no longer leave a spurious `check_timeout` warning in the kept partial results, and a cancelled `--quarantine` job stops quarantining the findings it produced while shutting down.
- Findings still queued when the daemon stops are now parked in the state directory and replayed through the full auto-response and alert pipeline at the next start. They used to be written to history only, so a webshell caught by the realtime scanner seconds before a restart never got its block or quarantine because nothing re-detects realtime-only findings.
- The `bad_asn_egress` abuse-report class now actually reports: its only detector emits high-severity findings while the report gate demanded critical ones, so enabling the class silently sent nothing.
- Findings from the rolling PHP content scan now survive between cycles: a cycle that covered only part of an account's files no longer counts as complete and no longer purges what earlier windows found, and a finding name shared by two checks is only cleared once both have run. Until now a dormant backdoor found by one window vanished from the findings list on the next cycle.
- Scan-job retention no longer deletes jobs that are still queued or running. A burst of queued scans was older than the job that had just finished, so the first completion pruned the waiting jobs and they were silently skipped.
- A PHP Shield block from an address that had earlier only been observed probing is now alerted as its own event. The per-address collapse that keeps one scanner from raising an alert per site was also swallowing the escalation, so the block never reached alerts, history or incidents for a day.
- Audit-log delivery to a syslog receiver over TCP or TLS now gives up on a receiver that stops reading instead of waiting forever. That wait held up the alert pipeline itself, so a stalled SIEM silently stopped every alert, history entry and incident on the host until the daemon was restarted.

#### Threat intelligence and reputation

- A YARA Forge tier whose merged reload fails is now removed and reported as a Critical rollback like a rule-count collapse; it used to stay on disk with a log line, so the next scanner restart compiled the same directory, failed, and ran with zero rules until the file was deleted by hand.
- `reputation.whitelist` changes now take effect on config reload: configured entries stay separate from runtime entries, are labelled as configured in the Web UI, and can only be removed by editing the config.
- External intelligence inputs are bounded and validated: an oversized or empty country CIDR download is rejected without replacing the last good file, an upstream reputation answer can shorten but no longer extend the configured cache lifetime, and the known-bad script host list matches whole domain labels so a name that merely ends in the same characters is not reported.
- A failed registry (RDAP) lookup is retried after ten minutes instead of standing as an empty answer for a day, and an oversized response is rejected rather than accepting a complete prefix.
- Threat-feed caches are written atomically, and a cached feed that holds fewer entries than its minimum is ignored and refreshed at the next cycle instead of being served for up to twenty hours. The last successful refresh time is retained so stale-feed health alerts still fire.
- The PHP-relay evaluator and its auto-freeze action now read one live configuration snapshot per operation, including account thresholds, freeze rate limits, and policy directories. Turning the relay pipeline on or off is reported as requiring a restart, which is what it always needed.
- Abuse reports and central-intelligence actions now apply the same protection list: infrastructure, private and documentation addresses, Cloudflare edges and verified crawlers are never reported to the shared abuse set and never challenged or blocked from central data. The real-time detectors also share the scan path's infrastructure test, which had drifted and no longer recognised Cloudflare edges.

#### Platform, configuration and storage

- The CageFS event-mount check now counts only cages that could serve PHP. CloudLinux in "Enable All" mode cages service accounts too, and rspamd, chrony and memcached inflated the number with cages that will never execute PHP; an account under any home root, including cPanel's /home2 and Plesk's /var/www/vhosts, is still counted.
- Account-scoped checks, remediations and re-checks now resolve account homes through the detected platform (/home on cPanel and DirectAdmin, /var/www/vhosts on Plesk) instead of a hardcoded /home, so Plesk hosts are scanned and remediated.
- Store export now stages the archive under the daemon's state directory and the CLI moves it to the requested path, copying and verifying the digest across filesystems, so destinations outside the daemon's sandbox such as /var/backups work again.
- Validate's deep probes now read the installed service unit and reject a state path outside its ReadWritePaths grants, which used to pass validation and then crash-loop the daemon under ProtectSystem=strict.
- suppress_webmail_alerts now defaults to true in code as it does in the shipped templates and documentation, an explicit false is kept, and the installer template no longer ships a placeholder API token name.
- Store restore now stages the archive next to the state directory instead of the system temp directory, so the final rename stays on one filesystem and a small tmpfs cannot fill up.
- The hardening audit's web-user crontab check and the group-writable PHP scan now use the detected platform's web server account (www-data, apache, nginx) alongside nobody instead of assuming cPanel's nobody.
- ModSecurity serial-format audit logs are now parsed per transaction, so the denial in the H section is attributed to the client on the A header and high-volume attackers are reported; the check also reads enough of the log to reach its threshold.
- The DNS connection check now treats the upstreams behind a loopback stub resolver as configured and skips systemd-resolved and dnsmasq themselves, so a systemd-resolved host no longer reports every upstream query.
- The systemd service unit is now replaced atomically on install and rehash instead of being truncated and rewritten in place.
- The sshd configuration change detector now hashes every file sshd reads, so a drop-in under an Include that flips PermitRootLogin or PasswordAuthentication is reported instead of being baselined silently.
- The hardening audit's default-deny check and the MySQL exposure check now look for a drop or reject policy on the nft input hook only; a Docker FORWARD chain used to satisfy both.
- A file that appears in /etc/cron.d after the first complete scan is now reported as added, with a redacted excerpt of its content.
- Debian crontab paths are now used by the remaining hardening and managed-job checks, and findings name the file that was actually inspected.
- Default config convergence now ignores generated hash differences only inside the integrity block, so similarly named operator settings are never discarded.
- The `web_server` overrides in the configuration are installed before anything in the daemon command detects the platform, and a detection that ran without them is now reported as an error instead of silently discarding them. The challenge-snippet refresh added earlier in this release detected the platform first, which pinned the probe's result for the whole run.
- On cPanel, the WAF check now reads the ModSecurity engine mode from the files WHM and operators actually write (the included cpanel and user configuration) and applies the last directive, as Apache does, so a global DetectionOnly setting is reported. It also does so on cPanel hosts running LiteSpeed, which read the same Apache configuration tree.
- User crontabs on Debian and Ubuntu, which live one directory deeper than on RHEL-family hosts, are now covered by the scheduled crontab check, the per-account scan, the sensitive-file watch list and the real-time crontab watcher. Until now every one of them looked only in the cronie location and was blind on those systems.
- A host that still has real config files at both the current and the legacy default path no longer ends up with a daemon that refuses to start after `csm rehash`: the daemon accepts copies that differ only in the hashes CSM writes itself, and rehash turns the legacy copy into the compatibility link.

### Security

- Backup and restore no longer retain pending rollback state or expose in-progress exports. Detection now preserves security state on incomplete scans and handles credential-bearing process data and platform-specific inputs safely.
- Quarantine captures now remain private when the source has other names, incomplete forensic snapshots are removed, and persistent missing-rule states no longer repeat the same alert on every reload.
- The install and deploy scripts now abort when a release from v2.2.0 onward is served without its detached signature, even without CSM_REQUIRE_SIGNATURES; only releases older than signing may skip with a warning. The upgrade command refuses to install an older release unless CSM_ALLOW_DOWNGRADE=1.
- A destination directory created by store export is no longer world-readable, so the export of every recorded finding is not left listable by every local account.
- Store export across filesystems now writes a private temporary file beside the destination and renames it into place, so a symlink planted at the destination by a local account is replaced instead of written through, and a copy that fails verification no longer destroys the previous export.
- Store export is refused, before the daemon writes anything, when the destination already exists as a symlink or another account's file, or when the destination directory or any directory above it is writable by or owned by another account; sticky directories such as /tmp are still accepted. The destination's directory is resolved before it is checked, so a ".." after a symlink cannot land the archive somewhere else. The daemon also opens the archive and its digest file with O_NOFOLLOW, so an export written directly can no longer follow a planted symlink.
- Process findings now redact credential-bearing command-line arguments before they reach the finding store or an alert channel, so a mysqldump -pSECRET, a PGPASSWORD= assignment, a --password value, a user:password pair or a URL with embedded credentials no longer leaks the secret.
- Webhook, heartbeat, callback and reputation URLs are shown as scheme and host only by validate, config show and hot-reload logging; the path, query and userinfo carry the credential for Slack, Discord and healthcheck endpoints.
- The brute-force trackers never evict the source entry a login attempt is currently being recorded into, so a flood cannot stop the very source causing it from reaching its detection threshold.
- The mail and SMTP brute-force trackers now give attacker-chosen account names their own budget and evict source entries that hold good-source standing or slow-brute evidence last; a flood of unique mailbox names used to push those entries out of the shared cap and strip a legitimate client of its auto-block exemption.
- The web UI's unauthenticated per-IP rate-limit maps are now capped at ten thousand addresses at insert time instead of only shrinking on the five-minute prune, so a scan from many addresses cannot grow them without bound in between.
- The findings CSV export now neutralises spreadsheet formula triggers: a message or detail starting with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with a quote so attacker-chosen text (a filename, a User-Agent) cannot execute when the file is opened.
- The `.htaccess` FilesMatch-shield detector's suppression gates can no longer be steered by the attacker: a pattern counts as targeted only when every alternative names a file (`^(a|.*)\.php$` no longer passes), and the sibling-PHP gate is not applied inside upload, cache and temp trees, where three dummy `.php` files used to silence the finding.
- The YARA worker socket is now created private (0600) from the moment it exists instead of being chmodded after the listen, closing the window in which any local user could connect to the scanner and keep that connection.
- Forensic snapshots now refuse an output path that already exists, symlink or file: the archive and its checksum sidecar used to be written through whatever sat at the destination, so a symlink planted by the compromised account made root overwrite another file with the tar stream.
- `signatures.update_url` and the YARA Forge download URL must now use https; a plain-http URL fails validation.
- Quarantining a file that has other hard links now copies the content into quarantine instead of linking the account-owned inode, and reports the links that remain; a file swapped into the detected path between capture and removal is now reported as a failed remediation with the captured copy kept, instead of a silent success that left the replacement live.
- Signed YAML rule updates now refuse a downgrade: a download with an older version than the installed rules, or fewer than half as many rules, raises a Critical finding instead of silently replacing the ruleset. Operators can explicitly permit an intentional rule-count reduction without permitting a version downgrade.
- Quarantine deletion and restore only accept real quarantine entries with metadata and never the pre-clean backup or email quarantine subtrees. An ID equal to one of those directory names used to resolve to the subtree itself.
- Real-time file scanning now runs the YARA rules on every file even when a YAML signature already matched it. A file that hit a high-severity YAML rule used to skip YARA entirely, so the critical YARA rule and the immediate quarantine it triggers never ran for it, and a file suppressed by the per-directory alert dedup was not scanned by YARA at all.
- Web UI fix requests now act on the path recorded in the stored finding and refuse a request that names a different one, and a remediation target can no longer be a remediation root or an account's home directory. Until now a single authenticated request could move `/home`, `/tmp` or a whole account into quarantine.
- A file is now skipped as a compressed archive only when its name says so as well as its first bytes. Four bytes of ZIP or gzip magic in front of a PHP file used to switch off every YARA and content rule for it on every scan path, while PHP happily echoed the junk and ran the rest.
- The content rules written for `.php` now also run on every other extension a stock PHP handler executes (`.phtml`, `.pht`, `.php5` and friends). A webshell uploaded as `.phtml` was skipped by more than a hundred rules, sixty of which have no YARA counterpart.
- Passing the proof-of-work challenge no longer adds the visitor to the firewall allow list. That allow was the same one operators use, so solving a trivial puzzle opened every port, skipped rate limits and country blocks, and made the address immune to auto-blocking for four hours. The challenge endpoints now also answer only for addresses that are actually on the challenge list.
- Exim client attribution now ignores malformed or message-supplied bracketed values across authentication, reputation, and connection-rate processing, and no longer mistakes a logged local interface address for the peer.
- Cleaning a customer's .htaccess no longer stages the rewritten file under a predictable name inside the customer's own directory, which let a compromised account plant a symlink there and have CSM, running as root, write the cleaned content into any file on the server. The replacement now also keeps the file's original owner and permissions.
- An SMTP client that announces itself with a bracketed IP address in its HELO can no longer steer the brute-force tracker, and with it the firewall, at an address of its choosing. Failed logins are now attributed to the connecting address, so the attacker is the one who gets blocked.
- IP reputation lookups read the connecting client from Exim's log with the same parser the brute-force tracker uses, so a forged HELO can no longer point a reputation check, and any block that follows it, at someone else's address.

## [3.31.0] - 2026-09-01

### Added

- Database scans now report large groups of published posts attributed to a user that does not exist as Critical. Small orphan groups are Warning because direct SQL user deletion can leave them behind, and multisite blogs are checked against the shared user table.

### Fixed

- A publicly reachable archive is now judged by what it holds, not only by its name. ZIP entry lists are scanned within a fixed metadata budget instead of an entry cutoff, so large sites stay detectable without letting crafted archives consume unbounded resources. A backup that nests its document root several directories deep is recognised by the WordPress files beside its configuration, while plugin bundles shipping a configuration fixture stay quiet.
- A script writing PHP into the plugins directory is now reported only when the content is PHP source, so scans no longer flag PHP error logs that quote a failed write on one line. Short-tag openers that start with a sigil, a backslash or a comment count as PHP too.
- Webmail phishing pages, mailer relays and the PHP-FPM exploit are now judged on a rendered credential field, on PHP source, and on a second exploit marker, in realtime as well as in scans. Interface text in scripts, documentation examples, and a lone encoded server setting stay quiet.
- A standalone Adminer or Tiny File Manager copy is now reported by scheduled and on-demand scans, not only in the moment it is written. Security plugins that merely name those tools in their blocklists stay quiet.
- A page cloning a webmail login is now reported by scans as well as realtime. Stock Roundcube templates, which build their login form dynamically, stay quiet.
- A mailer script that takes its recipient straight from the request is now reported by scans as well as realtime. Contact forms that pass only a sender name through stay quiet.
- A fake plugin that decodes a shell into a PHP file when it is activated, and a script that writes PHP straight into the plugins directory, are now reported by scans as well as realtime. A plugin writing its own template cache stays quiet.
- A dropper that fetches its payload from raw GitHub and runs it is now reported by scans as well as realtime, including when the fetch goes through the WordPress HTTP API. Plugin updaters that read a release manifest from the same host stay quiet.
- The Weevely backdoor agent and the PHP-FPM path underflow exploit are now reported by scans as well as realtime. A compatibility shim for the function Weevely abuses stays quiet.
- A script that pushes PHP into a theme through the WordPress theme editor is now reported by scans as well as realtime. The old rule read a function name that does not exist and matched ordinary core update code instead.
- Realtime detection of a hidden block stuffed with off-site links now works at all. The pattern could never match real page markup, so link farms injected into pages went unreported until the next scan.
- Credential phishing pages that send submitted form data with JavaScript are now reported, including kits that use extensionless collector endpoints. Legitimate plugin integrations for those brands stay quiet.
- A phishing page that mails both posted login values to an address written into the file is now reported even when it uses one-letter variables. Ordinary signup notices stay quiet, including sites with a literal owner address.
- Hidden pharma spam is now reported when it advertises a pharmacy or a sleep aid, not only the handful of drug names the rule used to know.
- More shells that route a command-named request value through a variable and immediately evaluate it are now reported by scheduled scans, not only in realtime. Unrelated request selection and template evaluation stay quiet.
- A request-fed or encoded backdoor planted in a theme is now detected the same way as one planted in a plugin. Ordinary theme template code stays quiet.
- An .htaccess line that maps an extension onto the PHP interpreter is now judged by which extensions it maps, in every form Apache accepts: quoted, without the leading dot, split across a line continuation, and the versioned handler names EasyApache and CloudLinux generate. The stock mapping hosting panels write stays quiet, while .phtml, .pht, .phps and anything appended to a stock line are reported.
- A shell script that downloads a crypto miner is now detected whatever case it is written in, and still when the space after the command is hidden behind a shell variable. Scheduled scans previously missed uppercase downloaders, and a name that merely joins the download and miner words is no longer reported on its own.
- Backup archives inside plugin-owned directories are now also denied one level up, where the plugin cannot overwrite the rule. All-in-One WP Migration rewrites its own access rules on every run, which left the archives downloadable until the next scan noticed and re-applied the block.
- A denial that has to be written again because something removed or damaged it is now reported as such, instead of looking like a fresh one each time. Equivalent rollback states share one archived copy without losing it after a failed re-apply, while ownership or permission changes keep a separate rollback point.
- PHP Shield can now record events from CloudLinux CageFS through a daemon-owned socket without exposing tenant-writable shared storage. Installation registers the mount safely and leaves the disruptive live-cage remount to an operator maintenance window.
- An empty PHP file in an uploads or WordPress system directory is now a Warning instead of High. A file with no content cannot run anything, and rating it High buried real findings under directory-guard placeholders that plugins create by the dozen. Bodies that could not be read still fail closed at High.

## [3.30.0] - 2026-08-22

### Added

- The server hardening audit now inspects Postfix hosts, covering open relaying, missing inbound TLS, obsolete SSL versions still being accepted, authentication offered without encryption, and address harvesting through the VRFY command.

### Fixed

- Builds now require Go 1.26.7, picking up the standard library security fixes released since 1.26.6.
- The server hardening audit now follows Apache include directives in precedence order, so snippet settings count as applied and incomplete or conditional trees are not reported clean. Directory listing is reported per configuration scope and names the block that enables it.
- Exim checks in the server hardening audit now run only when Exim is the detected delivery agent, and its cPanel-only override check stays limited to cPanel. A Postfix host previously collected phantom Exim warnings plus a pass for a setting it never had.

[Unreleased]: https://github.com/pidginhost/csm/compare/v3.33.0...HEAD
[3.33.0]: https://github.com/pidginhost/csm/compare/v3.32.0...v3.33.0
[3.32.0]: https://github.com/pidginhost/csm/compare/v3.31.0...v3.32.0
[3.31.0]: https://github.com/pidginhost/csm/compare/v3.30.0...v3.31.0
[3.30.0]: https://github.com/pidginhost/csm/compare/v3.29.0...v3.30.0
