# Durable action lifecycle

This note explains why every host mutation records its intent before acting, and how recovery and undo are meant to work. A host mutation is any change CSM makes to the server, such as a firewall rule, a file or a process.

## What exists: the action log

`internal/actionlog` writes one JSONL record per action to `/var/log/csm/actions.jsonl`, keyed by the operation IDs from `internal/privops`. `csm actions` reads it. See [action log](../action-log.md).

A record carries:

- The actor.
- The `finding_id`. The SIEM audit log emits it too, so the two streams join.
- The exact argv when CSM ran a program.
- The target file's digest before and after.
- The result, including refusals.
- The command that reverses the change.

The wiring pattern is settled: record at the operation chokepoint, not at the entry point. A CLI-driven call and an automatic call then produce the same record.

## Why the log is not enough

A JSONL outcome is evidence, not durable intent. It cannot alone distinguish a refused request from a mutation applied just before a crash. Some effects, including process termination, cannot be undone.

## Decision

Every host mutation goes through a shared lifecycle at its operation boundary. Execution stays in the responsible domain. The lifecycle owns identity, admission, persistence, recovery and audit linkage. Admission is the check that decides whether an action may go ahead.

The lifecycle reuses `mode: observe`, `auto_response.dry_run`, the existing action-specific switches and the file-response budget and breaker settings. There is no second policy switch and no parallel set of response limits.

### The first slice: firewall block and unblock

The first slice is firewall block and unblock. Before the mutation, the lifecycle persists:

- A stable action ID.
- The operation.
- The actor.
- The target identity.
- Finding and incident links, when present.
- The intended effect.
- Recovery metadata.

States distinguish planned, executing, applied and verified from refused, failed, partial, unknown and rolled back.

After a crash, incomplete records are reconciled against actual host state before any retry. An uncertain outcome stays visible until it can be proved. A stable ID supports deduplication. It is not a promise of exactly-once host effects.

### When persistence fails

| Case | What happens |
|------|--------------|
| Intent or budget persistence fails | New automated mutations are refused and the finding is retained. |
| Outcome persistence fails after the mutation | The pending intent is preserved, action health reports degraded, and reconciliation runs before another attempt. |

A bbolt transaction cannot atomically commit a filesystem or kernel change. Host I/O therefore stays outside the database transaction. Target identity is checked again immediately before execution, including on recovery and undo.

### Audit interfaces and undo

JSONL and `csm actions` remain the operator-facing audit interfaces, linked by `action_id`. Durable state and audit delivery need a retry and reconciliation contract, so an applied action cannot silently lose its audit outcome.

`csm action show <id>` and typed undo dispatch follow. A stored command string is never executed as the authority to reverse a change. Undo verifies the current target, records its own linked action, and refuses changed or irreversible targets.

Retention keeps unresolved intent and required recovery evidence. Backup restore must not resurrect pending actions, jobs or sessions as executable or authenticated live state. What is disarmed and what requires review is defined per record type.

The open work is tracked in the [roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#durable-action-lifecycle).

## Details

This section is reference material: the exact rules of the firewall block slice.

### Batches

A firewall action can carry a batch: a header and a manifest of single-target members. Each member has its own charge and the rows it removes to make room. A charge is the budget an action spends when it is admitted.

- Each member ID belongs to exactly one batch.
- Admitting a known ID with any change to the members, their order or their effects is refused.
- A refused batch charges nothing.

### Evicting a row to make room

A single-target block that removes a row to make room records that row as its victim. The victim is the only row that names its address before the action, and no row names that address after the action.

- Selection requires a verified, unexpired row in its canonical spelling and uses complete committed state.
- Safety and capacity use the active view of the same snapshot. The saved result preserves unrelated rows.
- In-memory unverified or failed marks also exclude victims, including for operator blocks, without changing the saved rows.
- The block's audit writes an `evict_temp` record beside the block's record in the same durable write.

### What a batch may change

A batch only adds its members' rows, each starting when the batch is planned. Nothing evicts for a batch. Admission therefore refuses a batch whose result drops a row that has not expired or changes any other entry. Kept rows retain their order.

In batch planning, unverified rows remain until their owner settles the outcome, even after expiry. A batch cannot add a block for an address that an unverified row holds. An unverified address stays pending even when another spelling of the same address has a verified block.

### Stored formats and import

- Actions written before batches existed read as one-member batches and keep their stored format.
- A record written by a newer build is refused as unsupported, never read or overwritten.
- A firewall-only import moves the durable journal and its snapshot as one unit. It refuses while either database has an unresolved action or undelivered audit.
- A refusal, including one for nested firewall buckets on either side, leaves the target database unchanged.

### Planning a batch

The block batch planner checks each automatic temporary block on its own against one committed snapshot. It leaves out refused members and runs the rest as one batch with one kernel transaction.

| Case | What happens |
|------|--------------|
| A lone valid member | It runs as an ordinary single action. |
| A stored batch ID | It is observed, never planned again. |
| A member too short to outlive its own verification | It is refused, since its expiry would leave the batch unknown. |
| A changed committed revision | Admission is refused, for both batches and lone members. |

Batch planning takes its clock readings and its operator allow entries from these sources:

- Batch planning dates member rows and kernel evidence by one lease-clock instant, even when the wall clock moves backward during a lease. The lease clock is the engine's clock for block expiry, separate from the wall clock.
- Operator IP and port allows come from the same committed planning snapshot.
- Allow expiry uses one wall-clock reading.

### One outcome per batch

A batch has one outcome. A crash or lost write at any step, from admission to audit acknowledgment, leaves recovery to prove an outcome or keep it unknown. The kernel is written at most once and each member is charged once.

- Storage and audit failures reach the caller even when recovery can later prove the outcome.
- A kernel holding only some members proves neither outcome. The batch stays unknown until the kernel proves one, an operator resolves it, or it retires.
- A rejected kernel batch is not retried inside the lifecycle. Its owner must first prove rejection and use a new charged action for any retry.

### Batch evidence

- Batch evidence selects each member's current row by ID, target and planning time. Retained rows from an earlier use of that ID are not current evidence.
- An unresolved batch with an expired member remains unknown: absence does not prove that member was never applied. This also holds during immediate verification after apply.
- A durable terminal outcome is preserved on replay after expiry.

### Retiring an unknown action

An unknown block action retires as `expired_unproven` once all of these hold:

- All member targets are timed and expired.
- Every row that differs between the action's before and after states is a verified timed block that has expired by the lease clock.
- Its owner attests a trusted clock.
- Its unknown outcome has reached the audit trail.
- The kernel holds exactly the rows both states agree on.

Recovery then commits those rows as the next revision in one transaction and frees the pending interlock. After retirement:

- The outcome stays unknown.
- Its charges stay spent.
- Its audit records say `expired_unproven`.
- Nothing is applied again.
- The retired action cannot be resolved or undone.

These cases stop retirement:

| Case | Result |
|------|--------|
| The lease clock runs ahead of the kernel | Recovery finds an element the kernel still holds and retires nothing. |
| A permanent, unverified or non-block effect, or any change outside the blocked rows | The action waits for an operator. |
| The clock attestation is missing or degraded | The action stays pending. |
| The clock attestation failed | The action stays pending and the error is reported. |
| Saved blocked-set evidence is not present | The action does not retire. |
| The set topology changed | The action does not retire. |
| A kernel read is slow | Retirement is refused. Kernel timeouts are checked against the clock sample taken before each read. |
| The unknown outcome lacks its recorded audit acknowledgment | The action does not retire. An empty outbox alone does not prove delivery. |

IPv6 proof uses saved evidence even if IPv6 is now disabled.

### Audit delivery

- Audit delivery writes one record per member, with the member's action ID and the batch's outcome and version, in one durable write.
- Audit is delivered at least once. Consumers deduplicate each member or victim event by action ID, transition version, action and target, so a block and its eviction remain distinct.
- An acknowledged audit is not delivered again.

### Replay

Batch replay returns the stored manifest, not a fresh decision on candidates left out of the original action.

- Nil refusals on replay do not mean every supplied candidate ran.
- The stored requests must appear as an ordered subsequence. Extra candidates, including duplicate IDs refused earlier, never execute.
- The original refused list cannot be reconstructed.
- Replaying a settled batch leaves its charges, committed revision and kernel unchanged.

A singleton, a lone member that ran as a single action, follows these rules:

- A singleton uses its member ID as the durable action ID. Its unused header ID is not reserved.
- Retrying that exact automatic temporary block returns the original action before checking current policy or expiry, and cannot add other members.
- Two stored singletons in one call are a conflict.
- Dry run refuses only new work: a retry still returns the stored action.
- A caller needing a durable header alias for singletons must wait for a stored-format extension.

### Undo

Whole-action undo requires the complete saved after-state and kernel proof.

Member undo removes only that member's unchanged row and preserves other members and later live changes. Two rules apply to it:

- Another live or unverified block on its address refuses member undo.
- Member undo checks alias expiry on the engine's lease clock, so a backward wall-clock step cannot make an expired alias prevent undo.

Every undo follows these rules:

- It omits expired blocks, allows and subnets, including expired unverified blocks.
- Restored rows keep their original absolute expiry.
