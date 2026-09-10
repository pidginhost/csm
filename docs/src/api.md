# API Reference

Machine-readable HTTPS API. All endpoints require token authentication. State-changing POST, PUT, PATCH, and DELETE requests require CSRF protection for browser cookie sessions.

## Authentication

```bash
# Bearer token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" https://server:9443/api/v1/status

# Cookie-based (after login)
curl -b "csm_auth=YOUR_TOKEN" https://server:9443/api/v1/status
```

Cookie-authenticated state-changing requests require the `X-CSRF-Token` header (obtained from the login response or page meta tag). Admin-scope Bearer requests are CSRF-exempt because the `Authorization` header is the write credential.

### Token scopes

Configure tokens under `webui.tokens:` with a `scope` of `admin` or `read`:

```yaml
webui:
  tokens:
    - name: "operator"
      token: "..."
      scope: admin       # full read+write
    - name: "panel-readonly"
      token: "..."
      scope: read        # status, findings, history, stats, challenge stats, blocked IPs, scan jobs, health, components, capabilities, SSE
```

The legacy single-token `webui.auth_token:` is migrated automatically to a `legacy-auth-token` admin entry on first start. Read-scope tokens are intended for orchestrators and dashboards that consume status, findings, history, stats, challenge stats, blocked-IP summaries, scan jobs, health, components, capabilities, and SSE events. Admin scope is still required for write routes and for sensitive reads such as quarantine, settings, firewall internals, threat-intel detail, rules, account detail, exports, incident timelines, and audit history. (ModSecurity `stats`/`blocks`/`events` are read scope; only the ModSecurity rules and escalation routes need admin.) `metrics_token:` is a separate, read-only credential for `/metrics` only.

## Status & Data

```
GET  /api/v1/status              Full health snapshot: version, uptime, watchers, severity counts,
                                 store health, blocklist size, capabilities[], config_hash, binary_hash,
                                 automation rollout state, challenge pending count, rollback state.
                                 `started_at_token` changes after a daemon restart and is suitable
                                 for restart polling.
                                 `security_posture` is `healthy`, `warning`, or `critical` after
                                 combining daemon faults with active high/critical incidents.
                                 `incidents_open_by_severity` breaks open and contained incidents
                                 down by `critical`, `high`, and `warning`.
                                 `correlation_attribution` (present after the first active-set
                                 merge) lists per check the findings correlation could not
                                 attribute to an account: `current` for the active set now,
                                 `cumulative` since daemon start.
                                 `queues` reports named protection queues, including depth,
                                 capacity, running work, recent and cumulative drops, and lag.
                                 A degraded queue changes `status` and `security_posture`.
                                 `latest_scan` is the canonical last-scan timestamp; `last_scan_time`
                                 is a legacy alias kept for older clients and will be removed.
GET  /api/v1/challenge/stats     Challenge-routing activity for the UI: `pending`, `escalated`
                                 (timeouts that became hard blocks), `routed_by_check` (per source
                                 check, since restart), and `recent` routes. Read scope.
GET  /api/v1/capabilities        Static feature list (e.g. `confd.dropins.v1`, `events.sse.v1`,
                                 `webhook.phpanel.v1`, `webui.prefs.v1`, `webui.undo.v1`,
                                 `mail.queue.composition.v1`,
                                 `detect.http_scanner_profile.v1`, `challenge.stats.v1`,
                                 `firewall.rollback.v1`, `firewall.dos_exempt.v1` on Linux builds).
                                 Use for orchestrator feature-detect.
GET  /api/v1/components          Watcher/component matrix with attachment, event, and upstream freshness state.
GET  /api/v1/events              Server-Sent Events stream of findings as they dispatch.
                                 Read-scope token sufficient. One JSON event per `data:` line.
                                 Writes and flushes have a three-second deadline. A failed
                                 write or flush closes the stream and frees its subscriber slot.
GET  /api/v1/health              Daemon health (fanotify, watchers, engines)
GET  /api/v1/findings            Current active findings
GET  /api/v1/findings/enriched   Enriched findings with GeoIP, accounts, fix info
GET  /api/v1/finding-detail      Finding detail with action history (?check=&message=)
GET  /api/v1/history             Paginated history (?limit=&offset=&from=&to=&severity=&search=)
GET  /api/v1/history/csv         CSV export (up to 5,000 entries)
GET  /api/v1/stats               24h severity counts, accounts at risk, auto-response summary
GET  /api/v1/stats/trend         30-day daily severity counts
GET  /api/v1/stats/timeline      Event timeline
GET  /api/v1/quarantine          Quarantined files with metadata (incl. htaccess pre_clean backups)
GET  /api/v1/quarantine-preview  Preview quarantined file content (?id=)
GET  /api/v1/db-object-backups   db_object_backups bucket (MySQL trigger/event/procedure/function drops)
GET  /api/v1/db-object-backup-preview Preview captured CREATE SQL (?key=)
GET  /api/v1/blocked-ips         Blocked IPs with reason and expiry
GET  /api/v1/accounts            cPanel account list
GET  /api/v1/account             Per-account findings, quarantine, history (?name=)
GET  /api/v1/audit               UI audit log
GET  /api/v1/export              Export state (suppressions, whitelist)
GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)
GET  /api/v1/performance         Performance metrics snapshot (admin scope)
POST /api/v1/perf/fix-error-log  Truncate a fixed-row error_log finding (admin scope, CSRF)
POST /api/v1/perf/fix-display-errors
                                  Disable display_errors for a fixed-row config finding (admin scope, CSRF)
POST /api/v1/perf/fix-wp-cron    Disable WP-Cron and install a system cron for a perf_wp_cron finding (admin scope, CSRF)
GET  /api/v1/hardening           Last stored hardening audit report (admin scope)
```

### Protection queue health

`status.queue_health.v1` advertises the `queues` map on status responses.
The same measurements appear under `snapshot.queues` in `csm status --json`
and as named checks in `csm doctor`.

`findings.ingest`, `fanotify.analyzer`, `fanotify.staged_packages`,
`fanotify.dropper`, `fanotify.dropper_findings` and `spool.scanner` report
waiting work, capacity, running work, cumulative losses,
losses during the last minute, the oldest waiting item's age and the oldest
running item's processing time.
Waiting work includes producers blocked on admission. Ingest work remains
running while the dispatcher holds or processes its batch, including startup.
Loss totals include the undelivered tail of a batch canceled during shutdown;
scan warnings intentionally excluded from alerts do not count as lost work.
Recovered file and spool scanner panics count as lost scan work. The workers
continue processing later events, but repeated failures still degrade health.
`fanotify.reconcile` reports the recovery queue in directory tasks, with
1,024 waiting slots. Repeated drops in a directory retain its original queue
age. A detached scan batch remains running while new drops queue separately,
including new work for a directory that is already being scanned.
Eviction, work older than the recovery scan window, unreadable directories or
candidate files, interrupted batches and unfinished shutdown work count as
failed recovery tasks. An incomplete task may still have scanned some files;
each directory task counts at most once.
The recovery window includes its cutoff; work completed exactly at that
boundary does not count as expired.
Staged package verification reserves capacity for its whole running batch.
Its full-queue timer starts when admission fills the queue and continues while
the verifier retains those slots, including between retries.
Files awaiting another attempt retain their original waiting age; retrying
does not reset lag. Shutdown counts files still awaiting verification after
the analyzer workers have stopped. Package metadata I/O cannot block health
polling for this queue.
Dropper candidates and held findings each have 16,384 waiting slots. Their
lag starts after the configured unlink TTL or the finding's 45-second grace
period, respectively; intentional waiting does not count as overdue work.
Detached probes and emission batches remain visible as running work.
Processing time starts when each batch leaves its waiting queue, independently
of the timestamp used to decide which work is eligible.
Retries and refreshed observations retain earlier eligibility, and exhausted
probes, capacity refusals and unfinished shutdown work count as losses.
`mail.delivery` reports the selected mail-log reader's 64-slot delivery queue.
Its running time includes parsing and delivery of resulting findings. Losses
include oversized complete file records, unreadable journal entries, canceled
admission, consumer failure and buffered records abandoned on shutdown.
Counters survive reader replacement and changes between file and journal
sources. They count records already read, not unread source history or partial
file records that have not reached a newline.
When their BPF backends are active, `bpf.af_alg.output`,
`bpf.connection.output`, `bpf.execution.output` and
`bpf.sensitive_files.output` report the 256-slot userspace delivery queues.
Their losses include decoding failures, admission refusals, consumer panics
and buffered output left after the reader stops. A received event remains
running until evaluation and delivery to the finding queue finish, including
events intentionally filtered during evaluation. Kernel ring occupancy and
reservation failures are separate from these userspace measurements.
`bpf.connection.verdict` reports the advisory annotation pool's 256 waiting
slots and up to four running callbacks. Repeated findings for a pending
destination, reason and severity share one request and retain its original age.
Capacity refusal, callback failure and abandoned shutdown work count as lost
annotations, separately from lost findings. Callback errors release the pending
key and allow a later finding to retry; a successful retry preserves earlier
loss totals. Shutdown closes admission, waits for running callbacks and counts
the queued requests left behind. Cached answers remain available without new
work. Findings continue immediately when an annotation is unavailable.
`processctx.enrichment` reports 1,024 waiting requests and up to two running
process-context workers. It appears only after a BPF consumer initializes the
shared pool; reading health does not start workers. Overflow replaces the oldest
queued request and preserves the waiting age of the remaining requests.
Running time includes the process read, latency observer, account resolution and
cache write. Read errors and interrupted processing count as lost enrichment;
vanished processes and stale or unverified identities are completed filtering.
The queue dropped metric counts refused, evicted and abandoned requests;
queue health also includes failures after a worker receives the request.
The daemon stops the pool after BPF producers have joined, lets running reads
finish and counts buffered requests discarded at shutdown. Final loss evidence
remains available. This row measures enrichment requests, not each individual
deadline-based file read inside a request.
`processctx.proc_reads` reports the 64 shared slots for deadline-limited process
file and symlink reads, including process-start captures on the BPF path.
Waiting and running reads share this capacity. A slot remains occupied until
both the underlying read and its caller have finished; an undelivered result
still occupies its slot. A timeout counts the lost result immediately and keeps
a blocked syscall visible as running work until it returns. Timeout and a later
read failure count as one loss. Refusals at capacity and read failures count as
losses; missing process files are expected churn. Synchronous reads without a
deadline consume no slots. The initial process-directory check and the cached
boot-time read are synchronous and are not measured by this row.
`smtp_rdns.resolves` reports the 64 reverse-DNS lookup slots used by direct SMTP
egress detection. A slot remains occupied until its resolver and caller finish.
The one-second caller deadline also bounds healthy processing age; timing out
counts a lost result once while keeping a resolver still running visible.
Capacity refusals and resolver failures count as losses, while NXDOMAIN and
successful empty responses are normal negative results. Cache hits perform no
queued work. The bounded result cache is retained data, not waiting lookups.
Status can initialize the empty cache but never performs DNS or waits for its
cache lock. Synchronous lookups without a deadline use no slots or queue row.
`email_password.hashes` reports the three shared password-verification slots.
Each slot remains occupied until its KDF and caller have both finished, including
after scan cancellation. `email_password.waiting` reports callers awaiting a
slot; it sets `capacity_unavailable` because concurrent scans have no fixed
global waiting limit. Both rows use the password audit's five-minute check budget
for lag. The occupied pool also reports sustained full capacity. A deadline while
waiting counts one admission loss; a deadline after admission counts one lost
verification result. A later KDF error or abnormal exit cannot count it twice.
Explicit cancellation withdraws demand without loss; actual verification errors
still count. Successful matches and nonmatches are normal results. Rejected
input and already canceled callers start no queued work. These rows contain no
password, hash, mailbox or account data, and status never runs a verification.
The outer mailbox scan's discovery, network enrichment and persistence are
separate work from these hash slots.
`checks.executions` reports dispatched check functions across host and account
scans. An execution remains present until both its function and caller finish,
including while its result awaits consumption or its function outlives a timeout.
Lag is evaluated against each call's original deadline, including a shorter parent
deadline; a delayed function start does not reset it. Timeouts, panics and
abandoned results count once per execution. Explicit cancellation withdraws
demand without counting a loss, but a later function failure still counts.
This aggregate sets `capacity_unavailable`: separate scans have their own wrapper
limits, and timed-out functions can outlive those slots. It does not measure
checks awaiting dispatch, scan-job persistence or later automatic actions.
Status reads memory without waiting for a check or accessing the state database.
`central.actions` reports 1,024 waiting central-intelligence actions and one
running action. Backlog remains visible while the signed feed refreshes;
processing time includes the action handler and its evidence delivery.
Overflow, action failure and abandoned shutdown work count as losses. A
protected-address refusal or absent firewall engine completes the queue task
without claiming that a block happened. Challenge tasks measure delivery to
the challenge list; they do not measure its later file or firewall writes.
Shutdown cancels feed refreshes, waits for an already-running action and
discards the remaining queue. Captured dispatch hooks refuse later work and
preserve its loss count after shutdown. Logging does not reset loss totals.
`bot_verification.requests` reports 256 waiting bot-identity requests and one
running verification. Duplicate requests share their original waiting age.
Running time includes DNS lookups and the cache write. Queue overflow, DNS
timeouts or transient failures, failed cache writes and abandoned shutdown
requests count as losses. Missing PTR records, unknown bot identities and
definitive positive or negative answers remain expected outcomes; queue health
does not turn a resolver failure into a spoof finding. Shutdown cancels DNS,
waits for any active cache write and discards waiting work. Late submissions
are refused, pending keys are released and loss totals remain available.
`abuse_reporting.ingress` measures reports awaiting durable storage, with a
capacity of 10,000 or the configured spool limit when smaller. Running time
includes persistence to every configured target. Memory overflow, incomplete
persistence and work abandoned by a worker failure count as losses; one source
report counts once even when several targets fail. Outbound delivery can delay
memory work, and that backlog remains visible. The queue stays open through
the daemon's final finding flush. Reporter shutdown then closes admission and
persists every accepted report before closing the spool; a failed write does
not discard unrelated waiting reports. Captured hooks refuse later reports.
This row measures the memory queue, not reports already retained on disk for
retry; normal shutdown does not count those durable reports as lost.
`abuse_reporting.spool` measures durable reports per destination, with the
configured spool capacity. Reports already being sent remain in flight through
the database acknowledgment. Failed admission and discarded records count as
losses; a delivery retry, failed acknowledgment or normal shutdown retains the
report and does not count it as lost. An evicted record counts as lost only if
no send was acknowledged during this process. An active send settles that count
when it finishes; a failed retry cannot undo a prior acknowledgment.
`lag_basis: observed_age` means waiting age starts when this process first sees
the record. Existing records start at spool open; retries keep that age. Doctor
labels this as `observed_lag`, since time spent waiting before restart is unknown.
Waiting or running work degrades after two minutes, allowing for the normal
one-minute delivery interval. The common full-queue and recent-loss thresholds
also apply. `spool_io` names failed admission, read or acknowledgment operations;
`delivery_failed` names a failed or panicking sender. These states clear when
the affected operation recovers. Health reads remain independent of database
writes and outbound requests. Reopening with a smaller cap preserves existing
records until the next admission applies the configured overflow policy.
`phpanel.spool` measures the durable panel webhook queue, capped at 100,000
records per state directory. In-flight work includes writes waiting to commit
and deliveries awaiting database acknowledgment. Retried findings keep their
original waiting age; a failed attempt is not a lost finding while its record
remains durable. An overflowed record counts as lost only when no send was
acknowledged during this process; an active send settles that count when it
finishes. Malformed findings count once when removed from delivery;
their bounded diagnostic archive is retained history, not pending work.
Waiting age uses the persisted enqueue timestamp after restart. Missing,
damaged or future timestamps are timed from queue open. A minute of waiting
or processing degrades the row; delivery and database errors remain visible
until the affected operation succeeds. Health reads use memory only, so a
stalled database or collector cannot block status. Disabling delivery preserves
the durable backlog and cumulative loss; enabling it resumes the stored work.
Stopped queue instances refuse late admissions.
`actionlog.writes` measures the 64 process-wide action-log write slots. A sink
write running past the caller's 250ms wait budget degrades the row and stays in
flight until the sink and any panic reporting finish. A caller deadline after
admission does not count as loss, since the sink may still record the action.
Refused admission, sink errors and panics count as lost records, once per record.
Changing or disabling the sink preserves outstanding work and cumulative loss.
Health reads do not wait for the sink. Normal writes still complete before the
caller returns; saturated or stalled recording keeps the existing caller budget.
`events.deliveries` aggregates live event-stream subscribers in one row without
client identities. Capacity sums their buffers (64 findings per daemon stream);
depth counts waiting deliveries and in-flight work includes encoding, writing
and flushing. One full subscriber can degrade this row even while others drain.
The common one-minute lag, 30-second fullness and recent-loss thresholds apply.
Overflow, encoding errors and failed streams count as losses; a failed stream
also counts its abandoned buffered events. Normal request cancellation and
server shutdown withdraw pending demand without adding losses. Cumulative loss
survives subscriber removal, and an outstanding write remains visible until it
returns. Closing the bus preserves buffered work for consumers still draining it.
HTTP writes retain their three-second deadline; successful delivery here means
the write and flush returned, not that the remote application acknowledged it.
Each active BPF backend also exposes a `.kernel` row. `depth_unit: bytes`
labels ring occupancy and capacity. `lag_basis: consumer_progress` means
`lag_seconds` measures time without observed consumption while data remains,
starting at the first sample that sees pending data. It is not an event age.
One minute without progress degrades the row; recently observed reservation
failures use the same loss threshold as userspace queues. Kernel loss counters
are separate from decode failures and userspace admission loss.
After a reader unmaps its ring, `depth_unavailable: true` and
`lag_basis: unavailable` prevent zero fields from claiming an empty live ring.
The last counter sample adds submitted records the reader never consumed.
Submission accounting precedes publication, so a fast reader cannot consume
an event before it has been counted.
`dropped_lower_bound: true` marks this final shutdown total: kernel detachment
can leave callbacks finishing after the sample. Doctor prints `dropped>=...`
for that bound. Counter lookup failure degrades the row as
`measurement_unavailable`; a failed final sample remains degraded.
The required kernel suite fills the shipped connection program's ring with
real non-root connect calls and checks reservation loss and retained output.
`fanotify.kernel` and `spool.kernel` report pending notification records and
use the same consumer-progress lag measurement. Their group capacity is not
exposed by the kernel: `capacity_unavailable: true` marks it as unknown, and
doctor prints `depth=N/unknown records`. The current system queue limit may
differ from the limit captured when the watcher was created.
Their loss totals are lower bounds: each overflow record proves at least one
loss, and shutdown adds the records known to be unread before closing the
descriptor. Events can still arrive between that sample and close.
An unavailable pending-record measurement degrades the row; a failed final
sample remains degraded. Closing a descriptor leaves known zero occupancy.
`fanotify.reader` and `spool.reader` track batches after a kernel read, until
all records have been dispatched or filtered. A stalled batch remains visible
even when the kernel queue is empty. Reader losses count batches interrupted
by consumer failure, separately from kernel-record losses.
Spool replacements retain loss and running-batch evidence, while the new
descriptor starts its own occupancy and progress measurements. Health reads,
event reads and permission responses cannot use a descriptor after close.
The required kernel suite verifies pending records, stalls, drain recovery
and unread shutdown loss using real fanotify events.

`forwarder.kernel` and `phprelay.kernel` report inotify backlog in bytes,
because records include variable-length filenames. Capacity is unknown and
lag follows observed consumer progress. Overflow markers each prove at least
one lost event. Closing with unread bytes adds one further known loss; the
byte count does not reveal the number of discarded events. These totals use
`dropped_lower_bound: true`.
`forwarder.reader` and `phprelay.reader` track the running read batch, including
synchronous callbacks. Failed callbacks count as interrupted batches. PHP
relay replacements retain earlier losses with fresh occupancy measurements.
Descriptor reads, watch changes, polling and close share one lifetime guard.

`phprelay.index.persistence` reports the message attribution writer's 4,096
waiting slots. Writes remain running from channel receipt through the pending
batch and its database transaction. Batches contain at most 256 writes, also
during an explicit flush. Each flush covers the backlog present when the
writer accepts it; concurrent arrivals cannot extend that flush indefinitely.
Refused submissions, encoding failures and writes in a failed transaction count
as losses. Failed writes are settled before emitting their error finding, so a
blocked reporter cannot hide the loss. A failed transaction counts each of its
writes once and does not prevent subsequent batches from committing.
Shutdown closes admission and drains accepted writes; later submissions count
as refused work. The existing persistence dropped metric counts refused
submissions, while queue health also includes writes that fail after admission.

A queue becomes degraded after three losses in a minute, thirty seconds
continuously full, or a minute waiting or processing. These are operational
alert budgets, not measured throughput guarantees. Health is computed directly
from the counters, independently of finding delivery. The daemon records and
dispatches `protection_queue_degraded` at most once per queue every five
minutes while pressure remains, then one `protection_queue_recovered` event.
These are CSM health events and do not feed account-compromise correlation or
automatic response. Recovery preserves cumulative loss evidence; restarting a
spool watcher also preserves it. Restarting the daemon resets the counters.

Inspect worker errors and CPU, memory and I/O pressure when a queue degrades.
Reduce competing bulk work and confirm the queue drains and recent losses
stop. This surface currently covers finding delivery, file and spool kernel
readers and scanners, recovery scans, staged package verification, dropper
processing, BPF queues, process context enrichment and deadline reads, mail-log
delivery, forwarder and PHP relay notification queues, and PHP relay index
persistence; other bounded queues remain in the roadmap.

## GeoIP

```
GET  /api/v1/geoip               IP geolocation (?ip=&detail=1)
POST /api/v1/geoip/batch         Batch GeoIP lookup (body: {"ips":["192.0.2.1"]}, maximum 500)
```

## Threat Intelligence

```
GET  /api/v1/threat/stats        Attack stats, type breakdown, hourly trend
GET  /api/v1/threat/top-attackers Top attacking IPs with GeoIP (?limit=)
GET  /api/v1/threat/ip           IP threat lookup (?ip=)
GET  /api/v1/threat/events       IP event history (?ip=&limit=)
GET  /api/v1/threat/whitelist    Whitelisted IPs
GET  /api/v1/threat/db-stats     Attack database statistics
POST /api/v1/threat/block-ip     Block IP permanently
POST /api/v1/threat/whitelist-ip       Permanent whitelist
POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist (with expiry)
POST /api/v1/threat/clear-ip           Clear IP from attack database
POST /api/v1/threat/unwhitelist-ip     Remove from whitelist
POST /api/v1/threat/bulk-action        Bulk block/clear/whitelist across many IPs
```

## Firewall

```
GET  /api/v1/firewall/status         Config, blocked/allowed counts
GET  /api/v1/firewall/allowed        Whitelisted IPs
GET  /api/v1/firewall/subnets        Blocked subnets
GET  /api/v1/firewall/audit          Firewall audit log
GET  /api/v1/firewall/check          Check if IP is blocked (?ip=)
POST /api/v1/block-ip                Block an IP
POST /api/v1/unblock-ip              Unblock an IP
POST /api/v1/unblock-bulk            Bulk unblock IPs
POST /api/v1/firewall/allow-ip       Allow an IP
POST /api/v1/firewall/remove-allow   Remove IP from allow list
POST /api/v1/firewall/deny-subnet    Block subnet
POST /api/v1/firewall/remove-subnet  Remove subnet block
POST /api/v1/firewall/flush          Clear all blocks
POST /api/v1/firewall/unban          Unblock IP + flush cphulk
POST /api/v1/firewall/cphulk-clear   Flush cphulk bans only
```

## ModSecurity

```
GET  /api/v1/modsec/stats              WAF statistics (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/blocks             Blocked requests log, aggregated per IP, with resolved source country (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/events             WAF event details with resolved source country (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/rules              Loaded rules list
POST /api/v1/modsec/rules/apply        Apply custom rules
POST /api/v1/modsec/rules/escalation   Change rule severity/action
```

## Rules & Suppressions

```
GET  /api/v1/rules/status        YAML/YARA rule counts, version
GET  /api/v1/rules/list          Rule files
GET  /api/v1/suppressions        Suppression rules
POST /api/v1/rules/reload        Reload signature rules from disk
POST /api/v1/suppressions        Add or delete suppression rule
POST /api/v1/rules/modsec-escalation   ModSec escalation override
```

## Email

```
GET  /api/v1/email/stats         Email scanning statistics
GET  /api/v1/email/forwarders    Mail forwarder inventory with destination providers and local-copy flags (read scope)
GET  /api/v1/email/deferrals     Outbound deferral rollup by provider and sending IP with reason codes, parsed from exim_mainlog (read scope)
GET  /api/v1/email/queue-composition  Mail queue makeup: real vs null-sender bounce backscatter, frozen count, oldest age, top stuck recipients (read scope)
POST /api/v1/email/queue/flush-backscatter  Request removal of frozen null-sender messages from the exim queue on cPanel hosts; returns the count of targeted messages no longer queued, reports incomplete verification as 500, or returns 503 when unavailable (admin scope, CSRF)
GET  /api/v1/email/held          Forward copies held by the forward guard (admin scope)
POST /api/v1/email/held/{id}/release   Re-inject a held forward copy to its external recipient (admin scope, CSRF)
DELETE /api/v1/email/held/{id}   Discard a held forward copy (admin scope, CSRF)
GET  /api/v1/email/groups        Server-grouped action rows (kind=compromised_account|spam_outbreak|auth_failure|queue_alert|malware) with from/to/limit (read scope)
GET  /api/v1/email/relay-abuse   Outbound PHP-mail abuse detections (spam outbreaks, high-volume scripts/accounts) with per-site script breakdown; from/to/limit (read scope)
GET  /api/v1/email/quarantine    Quarantined email list
GET  /api/v1/email/av/status     Email AV watcher status
GET  /api/v1/email/quarantine/{id}          One quarantined message
POST /api/v1/email/quarantine/{id}/release  Release a quarantined message (admin scope, CSRF)
DELETE /api/v1/email/quarantine/{id}        Delete a quarantined message (admin scope, CSRF)
```

## Hardening

```
GET  /api/v1/hardening           Load last hardening audit report (admin scope)
POST /api/v1/hardening/run       Run hardening audit and save report (admin scope, CSRF)
```

## Scan Jobs

`csm scan --full` enqueues full-scan jobs that run inside the daemon and persist to the store. Jobs are report-only unless an account-scope request sets `quarantine: true`; server-wide jobs reject quarantine.

```
GET  /api/v1/scan-jobs              List full-scan jobs (read scope)
GET  /api/v1/scan-jobs/{id}         Job status and stored report (read scope)
GET  /api/v1/scan-jobs/{id}/findings
                                      Paginated findings for one job (?offset=&limit=) (read scope)
POST /api/v1/scan-jobs              Enqueue a full-scan job (admin scope, CSRF)
POST /api/v1/scan-jobs/{id}/cancel  Cancel a queued or running job (admin scope, CSRF)
```

## Verified Bots

```
GET  /api/v1/verified-bots        Configured verified-crawler allowlist plus live verification state (admin scope)
POST /api/v1/verified-bots/apply  Validate, apply, and reload an edited verified-bots list (admin scope, CSRF)
```

## Actions

```
POST /api/v1/fix                      Apply fix for a finding
POST /api/v1/fix-bulk                 Bulk fix multiple findings
POST /api/v1/dismiss                  Dismiss a finding
POST /api/v1/scan-account             On-demand account scan
POST /api/v1/verify-finding           Re-check a single finding on demand (admin scope, CSRF)
POST /api/v1/quarantine-restore       Restore quarantined file
POST /api/v1/quarantine/bulk-delete   Bulk-delete quarantined files
POST /api/v1/db-object-backup-restore Restore a dropped MySQL object from its db_object_backups record
POST /api/v1/test-alert               Send test alert through all channels
POST /api/v1/import                   Import state bundle (suppressions, whitelist)
```

`fix` and `fix-bulk` act on the file the stored finding names. A request may
repeat that path in `file_path`, but a different path is refused, and a target
is never a remediation root itself (`/home`, `/tmp`, `/var/tmp`, `/dev/shm`)
or an account's home directory.

`verify-finding` returns the verifier verdict in `checked`, `resolved`,
`demote`, and `detail`. When that verdict also changes the stored finding,
`severity_change` is `demoted` or `restored`. A `demote` verdict without
`severity_change` means no stored severity changed; for example, the finding
was already demoted or a scan replaced its snapshot while verification was
running. Callers must not report a state change from the verdict alone.

## Settings

```
GET  /api/v1/settings             List editable config sections
GET  /api/v1/settings/<section>   Read a config section (secrets redacted)
POST /api/v1/settings/<section>   Update a config section (safe fields reload, restart fields queue)
POST /api/v1/settings/restart     Request a daemon restart. Returns 202 with `started_at_token`
                                  for polling until the restarted daemon reports a new marker.
POST /api/v1/settings/firewall/tentative-apply  Save firewall config, restart, and arm rollback timer
GET  /api/v1/settings/firewall/rollback         Read pending rollback state
POST /api/v1/settings/firewall/confirm          Confirm tentative firewall changes
POST /api/v1/settings/firewall/revert           Revert tentative firewall changes now
```

Sections map to top-level config keys: `alerts`, `auto_response`, `challenge`, `reputation`, `performance`, `infra_ips`, `sentry`, etc. Writes persist to `csm.yaml`, re-sign the integrity hash, and hot-reload where possible; restart-required changes are queued for `/api/v1/settings/restart`. Invalid field values return 422 and do not touch disk. Firewall tentative apply is restart-class by design: it snapshots the previous config, writes the new one, restarts the daemon, and auto-reverts unless the operator confirms before the timer expires.

## Operator preferences

Per-operator state (UI density, timestamp display, default auto-refresh,
saved filter views) is keyed server-side by SHA-256 of the auth token,
so preferences follow the operator across browsers and devices without
the daemon ever storing the raw credential. Capability flag:
`webui.prefs.v1`. These endpoints require admin scope because they read
or mutate operator-private UI state.

```
GET    /api/v1/prefs/user        Read this operator's UI preferences
PUT    /api/v1/prefs/user        Replace the prefs blob (CSRF on cookie sessions)
GET    /api/v1/prefs/views       List saved views; `?page=findings` filters by page
PUT    /api/v1/prefs/views       Upsert one view {page, name, params} (CSRF on cookie sessions)
DELETE /api/v1/prefs/views       Delete one view {page, name} (CSRF on cookie sessions)
```

Response shape for `GET /api/v1/prefs/user`:

```json
{
  "density":       "comfortable",
  "timezone":      "local",
  "auto_refresh":  "on",
  "table_columns": { "findings-table": ["check","severity","when"] }
}
```

`density` is `comfortable` or `compact`. `timezone` is `server`, `local`,
or an IANA-shaped zone string (e.g. `Europe/Bucharest`). `auto_refresh`
is `on` or `off`. Server-side sanitisation drops any other value. Unset
prefs encode as empty strings; the UI applies `comfortable`, `local`, and
`on` defaults.

Response shape for `GET /api/v1/prefs/views`:

```json
[
  {
    "name": "Critical SSH",
    "page": "findings",
    "params": { "severity": "critical", "check": "smtp_bruteforce" },
    "updated": 1779743255
  }
]
```

Saved views are operator-scoped and capped at 200 per operator. The saved
view collection is stored as one 64 KiB preference blob. `page` and
`params` keys must be simple identifiers: ASCII letters, digits,
underscore, hyphen, or dot, up to 64 bytes. Each view has at most 32
params, and param string values are capped at 256 bytes. `name` must be
1-80 bytes with no control characters. `PUT` and `DELETE` return
`{"status":"ok"}` on success.

## Bulk-action undo

Bulk threat block / whitelist and bulk firewall unblock responses return
an `undo_token` when the daemon queues an inverse operation server-side
for 30 seconds. The UI surfaces a banner with the same TTL; CLI callers
can act on the token through the endpoints below. Each successful undo
writes an `undo_<original_action>` audit entry. Capability flag:
`webui.undo.v1`. These endpoints require admin scope because they read
or mutate operator-private action state.

```
GET  /api/v1/undo/pending    Latest pending undo entry for this operator (empty object if none)
POST /api/v1/undo/run        Consume an entry and dispatch its inverse {id}; empty id uses latest
```

Non-empty response shape for `GET /api/v1/undo/pending`:

```json
{
  "id": "188d1f2a6c8b0000",
  "action": "threat_bulk_block",
  "inverse": "threat_bulk_unblock",
  "summary": "Blocked 2 IPs",
  "recorded_at": "2026-05-26T00:07:09Z",
  "expires_at": "2026-05-26T00:07:39Z"
}
```

`POST /api/v1/undo/run` returns `{status, action, inverse, count}` on
success, or `410 Gone` when the entry is missing, already consumed, or
past its 30-second TTL. Recognised inverse action keys are
`threat_bulk_unblock`, `threat_bulk_block`, `threat_bulk_unwhitelist`,
`threat_bulk_whitelist`, and `firewall_bulk_reblock`. Other bulk actions
(quarantine delete, generic fix) do not surface an undo token because
they have no clean inverse.

## Finding fields

Every finding in `/api/v1/findings`, `/api/v1/events`, and the JSONL audit log carries optional correlation fields when CSM can attribute them:

| Field | Meaning |
|---|---|
| `tenant_id` | Tenant attribution from the verdict callback or panel-side webhook reply |
| `domain` | Domain associated with the event (e.g. PHP-relay scriptKey host, mailbox domain) |
| `mailbox` | Mailbox attribution (e.g. mail brute-force target, PHP-relay envelope-from) |
| `relay_total` | PHP-relay trigger count for the path that fired |
| `relay_breakdown` | PHP-relay script samples that contributed to the alert, with script key, hit count, last seen time, and a bounded sample subject when available |

Fields are omitted when the daemon could not attribute them. Orchestrators should treat absence as "unknown," not "global."

## Cleanup fields

`GET /api/v1/quarantine` also powers the Cleanup page's file-backup list. Entries include:

| Field | Meaning |
|---|---|
| `kind` | `quarantine` or `pre_clean` |
| `live_state` | `original_missing`, `live_differs`, `original_not_file`, `archive_missing`, `archive_not_file`, or `unknown`. Byte-identical restored entries are hidden. |

`GET /api/v1/db-object-backups` returns `restored` and `restored_at` when a captured MySQL trigger/event/procedure/function backup has already been replayed.

## Incidents

`GET /api/v1/incidents/groups` is a read-scope rollup of active incidents by kind and source. It accepts `status=active|all|open|contained|resolved|dismissed`, `kind`, and `limit`, allowing a credential spray to render as one row per attacker rather than one row per target.

### `GET /api/v1/incidents`

Returns every incident (open, contained, resolved, dismissed) sorted by
`updated_at` descending.

### `GET /api/v1/incidents/<id>`

Returns one incident by id. 404 if not found.

### `POST /api/v1/incidents/<id>/status`

Body:

```json
{"status": "resolved", "details": "operator-marked"}
```

Status values: `open`, `contained`, `resolved`, `dismissed`. Closing an
incident (resolved/dismissed) means future findings for the same
correlation key start a fresh incident. Reopening an incident binds the
same key again. Incident JSON includes `correlation_key` when CSM has a
stored account, mailbox, domain, process, or remote-IP key.
