# Durable action lifecycle

Why every host mutation records its intent before acting, and how recovery
and undo are meant to work.

`internal/actionlog` writes one JSONL record per action to
`/var/log/csm/actions.jsonl`, keyed by the operation IDs from
`internal/privops`. A record carries the actor, the `finding_id` the SIEM
audit log also emits so the two streams join, the exact argv when CSM ran a
program, the target file's digest before and after, the result including
refusals, and the command that reverses the change. `csm actions` reads it.
See [action log](../action-log.md). The wiring pattern is settled: record at
the operation chokepoint, not at the entry point, so a CLI-driven and an
automatic call produce the same record.

A JSONL outcome is evidence, not durable intent. It cannot alone distinguish
a refused request from a mutation applied just before a crash, and some
effects, including process termination, cannot be undone.

## Decision

Every host mutation goes through a shared lifecycle at its operation
boundary. Execution stays in the responsible domain; the lifecycle owns
identity, admission, persistence, recovery and audit linkage. It reuses
`mode: observe`, `auto_response.dry_run`, the existing action-specific
switches and the file-response budget and breaker settings. There is no
second policy switch and no parallel set of response limits.

The first slice is firewall block and unblock. Before mutation it persists a
stable action ID, operation, actor, target identity, finding and incident
links when present, intended effect and recovery metadata. States distinguish
planned, executing, applied and verified from refused, failed, partial,
unknown and rolled back. After a crash, incomplete records are reconciled
against actual host state before any retry; an uncertain outcome stays
visible until it can be proved. A stable ID supports deduplication, not a
promise of exactly-once host effects.

A firewall action can carry a batch: a header and a manifest of
single-target members, each with its own charge and the rows it removes to
make room. Each member ID belongs to exactly one batch. Admitting a known ID
with any change to the members, their order or their effects is refused, and
a refused batch charges nothing. A batch only adds its members' rows:
nothing evicts for a batch, so admission refuses one whose result drops a row
that has not expired or changes any other entry. Kept rows retain their
order. Unverified rows remain until their owner settles the outcome, even
after expiry, and a batch cannot add a block for an address they hold.
Actions written before batches read as one-member batches and keep their
stored format. A record written by a newer
build is refused as unsupported, never read or overwritten. Audit delivery
writes one record per member, with the member's action ID and the batch's
outcome and version, in one durable write. The block batch planner checks
each automatic temporary block on its own against one committed snapshot,
leaves out refused members and runs the rest as one batch with one kernel
transaction; a lone valid member runs as an ordinary single action, and a
stored batch ID is observed, never planned again. A firewall-only
import moves the durable journal and its snapshot as one unit, and refuses
while either database has an unresolved action or undelivered audit. A
refusal, including one for nested firewall buckets on either side, leaves the
target database unchanged.

Batch evidence selects each member's current row by ID, target and planning
time; retained rows from an earlier use of that ID are not current evidence.
An unresolved batch with an expired member remains unknown: absence does
not prove that member was never applied. This also holds during immediate
verification after apply. A durable terminal outcome is preserved on replay
after expiry. A rejected kernel batch is not retried inside the lifecycle.
Its owner must first prove rejection and use a new charged action for any
retry. The existing single-request path is unchanged. Audit is delivered at
least once; consumers deduplicate each member event by its action ID and
transition version, not by the batch ID.

Batch replay returns the stored manifest, not a fresh decision on candidates
left out of the original action. Nil refusals on replay do not mean every
supplied candidate ran. The stored requests must appear as an ordered
subsequence; extra candidates, including previously refused duplicate IDs,
never execute. The original refused list cannot be reconstructed. A
singleton uses its member ID as the durable action ID; its unused header ID
is not reserved. Retrying that exact automatic temporary block returns the
original action before checking current policy or expiry, and cannot add
other members. Two stored singletons in one call are a conflict. A caller
needing a durable header alias for singletons must wait for a stored-format
extension.

Batch planning dates member rows and kernel evidence by one lease-clock
instant, even when the wall clock moves backward during a lease.

If intent or budget persistence fails, new automated mutations are refused
and the finding is retained. If outcome persistence fails after mutation, the
pending intent is preserved, action health reports degraded, and
reconciliation runs before another attempt. A bbolt transaction cannot
atomically commit a filesystem or kernel change, so host I/O stays outside
the database transaction and target identity is revalidated immediately
before execution, including on recovery and undo.

JSONL and `csm actions` remain the operator-facing audit interfaces, linked
by `action_id`. Durable state and audit delivery need a retry and
reconciliation contract so an applied action cannot silently lose its audit
outcome. `csm action show <id>` and typed undo dispatch follow; a stored
command string is never executed as the authority to reverse a change. Undo
verifies the current target, records its own linked action, and refuses
changed or irreversible targets. Retention keeps unresolved intent and
required recovery evidence. Backup restore must not resurrect pending actions,
jobs or sessions as executable or authenticated live state; what is disarmed
and what requires review is defined per record type.

The open work is tracked in the
[roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#action-log-covers-seven-of-43-host-changing-operations).
