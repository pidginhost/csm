# Architecture direction

This note explains why the host agent stays autonomous, keeps one database owner and grows by slices instead of a rewrite.

## One process owns the database

The host agent stays autonomous and self-contained. One process owns bbolt, the embedded database that holds CSM's state.

Privilege separation must preserve that ownership. The helper and online CLI clients use scoped requests for reads and writes. They must not open the live database on their own, even read-only, because bbolt's writable owner holds an exclusive file lock. Offline maintenance needs exclusive ownership: the daemon and the helper are quiesced before the handoff.

## When a database replacement is justified

A local database replacement needs measured contention, query complexity or recovery requirements that the current design cannot meet. Both bbolt and SQLite WAL serialize writers, so a switch alone does not remove that constraint.

For how the lock behaves across separate processes, see the [bbolt transaction documentation](https://github.com/etcd-io/bbolt#transactions), [SQLite WAL concurrency](https://www.sqlite.org/wal.html#concurrency) and [bbolt read-only mode](https://github.com/etcd-io/bbolt#read-only-mode).

## Growing by slices

The starting points are the code that exists: the store, the action log, the privileged-operation inventory, scan jobs and the incident correlator. Add domain interfaces as each slice needs them. A package renaming campaign or a generic bucket/key API is not a prerequisite.

Operator configuration stays in YAML. The remaining authoritative operational state migrates by domain, with a rollback contract.

## Priorities and delivery order

The architectural priorities are privilege isolation, durable host actions and browser credential isolation. They complement the harm-based ordering of the [roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md). They never defer a protection failure or a precision and response defect.

Browser sessions and their HTTP/domain boundary are implemented. The rest is delivered in this order:

1. A firewall block/unblock slice of the [durable action lifecycle](durable-action-lifecycle.md), including storage measurements and an explicit state-owner contract. Complete the [firewall state migration](firewall-state-migration.md) with recovery proof, then use that action contract for the first privileged-helper verbs.
2. Expand [helper coverage](privilege-separation.md) and action recovery by response family. Extend the existing job model as each long operation moves behind a service. Drop main-process privileges only when the required reads, descriptors and mutations have verified replacements.
3. Improve correlation through the shared replay harness, then add outbound fleet ingest. Panel availability must never gate local protection.

## What stays out of the agent

No mandatory local broker, database server or orchestration platform is added. The fleet service owns its database choice separately. The agent does not select or build a central database stack.
