# Architecture direction

Why the host agent stays autonomous, keeps one database owner and grows by
slices instead of a rewrite.

Keep the host agent autonomous and self-contained, with bbolt owned by one
process. Privilege separation must preserve that ownership: the helper and
online CLI clients use scoped requests for reads and writes. They must not
open the live database independently, even read-only, because bbolt's
writable owner holds an exclusive file lock. Offline maintenance needs
exclusive ownership, with the daemon and helper quiesced before handoff.

A local database replacement needs measured contention, query complexity or
recovery requirements that the current design cannot meet. Both bbolt and
SQLite WAL serialize writers; a switch alone does not remove that constraint.
See the [bbolt transaction documentation](https://github.com/etcd-io/bbolt#transactions),
[SQLite WAL concurrency](https://www.sqlite.org/wal.html#concurrency) and
[bbolt read-only mode](https://github.com/etcd-io/bbolt#read-only-mode) for
the separate-process lock behaviour.

Use the existing store, action log, privileged-operation inventory, scan jobs
and incident correlator as the starting points. Add domain interfaces as each
slice needs them; a package renaming campaign or a generic bucket/key API is
not a prerequisite. Keep operator configuration in YAML and migrate remaining
authoritative operational state by domain, with a rollback contract.

The architectural priorities are privilege isolation, durable host actions and
browser credential isolation. They complement the harm-based ordering of the
[roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md) and never
defer a protection failure or a precision and response defect. Browser
sessions and their HTTP/domain boundary are implemented. Delivery order for
the rest:

1. A firewall block/unblock slice of the
   [durable action lifecycle](durable-action-lifecycle.md), including storage
   measurements and an explicit state-owner contract. Complete the
   [firewall state migration](firewall-state-migration.md) with recovery
   proof, then use that action contract for the first privileged-helper verbs.
2. Expand [helper coverage](privilege-separation.md) and action recovery by
   response family; extend the existing job model as each long operation
   moves behind a service. Drop main-process privileges only when the required
   reads, descriptors and mutations have verified replacements.
3. Improve correlation through the shared replay harness, then add outbound
   fleet ingest. Panel availability must never gate local protection.

No mandatory local broker, database server or orchestration platform is
added. The fleet service owns its database choice separately; the agent does
not select or build a central database stack.
