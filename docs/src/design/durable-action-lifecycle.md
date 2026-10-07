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
[roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#action-log-covers-six-of-41-host-changing-operations).
