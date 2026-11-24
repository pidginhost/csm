# Firewall state migration

This note explains why the firewall engine's authoritative state moves from `state.json` into bbolt, and the rules the cutover has to keep.

## Where the work stands

The engine still reads and writes its authoritative runtime state in `state.json`. These parts are in place:

- The lossless firewall state storage contract is implemented and tested independently of runtime callers. It preserves complete ordered state with revision checks and atomic replacement.
- Firewall buckets and store methods exist.
- Pending configuration rollback already uses bbolt.

## Why it matters

This work belongs with response correctness. Two guarantees exist today and stay: JSON writes use atomic replacement, and the block path persists intended state before it touches the kernel. Changing the storage format alone cannot make the database and nftables one transaction.

## Engine interface

A domain-owned firewall state interface is injected into the engine. It reuses the existing blocked, allowed, subnet and per-port buckets, and it does not expose bbolt transactions to firewall callers.

The original store schema and methods were not a lossless engine backend:

- Subnet rows lacked expiry and used a different creation-time field.
- Loaders hid read and decode failures.

The schema and error contract are extended before cutover. The extended contract follows these rules:

- Original times and explicit provenance are preserved. They are not recreated through add methods.
- A failed or corrupt read must not become a successful empty or partial ruleset.
- Each logical state change commits together.
- The hot-path cache updates only from committed state.
- Kernel application and recovery follow the [durable action lifecycle](durable-action-lifecycle.md).

## Cutover

Migration is a one-shot step. It runs through the owning daemon, or under an exclusive offline maintenance lock. The step does four things:

- It validates the entire source.
- It imports transactionally.
- It records a schema and cutover marker.
- It retains the original JSON for rollback.

A crash at any cutover step is recoverable. After cutover only bbolt is authoritative. Rollback preserves post-cutover changes. It does not silently restore the stale JSON.

The cutover also keeps these rules:

- Desired configuration stays in YAML.
- Backup and store export leave out a pending configuration rollback, so a restored archive cannot re-arm an old confirmation window. That property is kept, and the treatment of new action intent is defined with it.
- Migration must not reset existing response budgets or failure pauses when those move to bbolt.

The open work is tracked in the [roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#firewall-state-migration-to-bbolt).
