# Firewall state migration

Why the firewall engine's authoritative state moves from `state.json` into
bbolt, and the rules the cutover has to keep.

The lossless firewall state storage contract is implemented and tested
independently of runtime callers. It preserves complete ordered state with
revision checks and atomic replacement. Firewall buckets and store methods
exist, and pending configuration rollback already uses bbolt. The engine
still reads and writes its authoritative runtime state in `state.json`.

This belongs with response correctness. JSON writes already use atomic
replacement, and the block path persists intended state before touching the
kernel. Those guarantees stay; changing the storage format alone cannot make
the database and nftables one transaction.

## Engine interface

A domain-owned firewall state interface is injected into the engine. It
reuses the existing blocked, allowed, subnet and per-port buckets without
exposing bbolt transactions to firewall callers. The original store schema
and methods were not a lossless engine backend: subnet rows lacked expiry and
used a different creation-time field, and loaders hid read and decode
failures. The schema and error contract are extended before cutover;
original times and explicit provenance are preserved instead of recreated
through add methods. A failed or corrupt read must not become a successful
empty or partial ruleset. Each logical state change commits together, and the
hot-path cache updates only from committed state. Kernel application and
recovery follow the [durable action lifecycle](durable-action-lifecycle.md).

## Cutover

Migration is a one-shot step through the owning daemon, or under an
exclusive offline maintenance lock. It validates the entire source, imports
transactionally, records a schema and cutover marker, and retains the
original JSON for rollback. A crash at any cutover step is recoverable. After
cutover only bbolt is authoritative; rollback preserves post-cutover changes
instead of silently restoring the now-stale JSON. Desired configuration stays
in YAML. Existing exports disarm pending configuration rollback; that
property is kept and the treatment of new action intent is defined with it.
Migration must not reset existing response budgets or failure pauses when
those move to bbolt.

The open work is tracked in the
[roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#firewall-state-migration-to-bbolt).
