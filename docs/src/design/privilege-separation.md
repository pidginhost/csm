# Privilege separation

This note explains why a minimal privileged helper will own the operations that need root, and what the helper must enforce on its own.

## The problem today

The whole daemon runs as root: detection, correlation, parsers, threat intelligence, Web UI and API. It runs inside the systemd confinement described in [service confinement](../service-confinement.md):

- `ProtectSystem=strict`
- syscall filtering
- a `ReadWritePaths` allow-list
- `systemd-run` for the panel scripts that need the whole filesystem

A parser bug anywhere is therefore a root compromise of the host.

One helper pattern exists: the mail forward guard executes a fixed helper subcommand of the same binary.

## Decision

A minimal privileged helper owns the operations that require root:

- nftables and firewall changes
- process termination
- quarantine and other moves across account boundaries
- fanotify and BPF initialization, with the resulting descriptors passed back over the socket
- privileged filesystem and configuration writes

Everything else runs with reduced privileges. Reduced, not none: reading every account's files still needs `CAP_DAC_READ_SEARCH`. The unprivileged side keeps a small capability set and loses the ability to write, signal and reconfigure.

The helper exposes a narrow Unix-socket RPC authenticated by peer credentials. Its verbs are fixed. Its arguments are validated against the same path, user, process and firewall scopes the actions enforce today.

## The inventory is complete

The inventory stage is complete. `internal/privops` lists every operation that needs privilege beyond reading CSM's own files. For each operation it records:

- what the operation writes
- the config key that stops it
- its risk tier
- what an operator loses by withholding the privilege

`csm privileges` prints the inventory, and the [capability matrix](../capability-matrix.md) ships it. Two gates in `internal/ci` compare it against the packaged systemd unit in both directions, so a writable-path grant that no operation claims fails the build.

That table is the action set the helper has to cover.

## Observe mode in the meantime

`mode: observe` is the interim posture for operators who will not grant a root daemon the ability to act. Detection and alerting run. Automatic remediation and integration deployment do not.

Observe mode reduces what the root process does, not what it could do. It is a stopgap, not a substitute.

## Staging

Each stage ships on its own, in this order:

1. The helper for firewall.
2. The helper for signals and quarantine.
3. The helper for privileged configuration and filesystem writes.
4. Descriptor passing for fanotify and BPF.
5. Dropping capabilities in the main process.

Each family first needs its safety classification and [durable action contract](durable-action-lifecycle.md). It does not need every other family's migration to be complete.

## What the helper must enforce

Peer credentials authenticate the caller, not the requested operation. The helper enforces target and account scope, identity, permitted verbs and safety policy even if the main process is compromised.

The helper also keeps these limits:

- It exposes no arbitrary shell, command execution or unrestricted file-write RPC.
- Request sizes and execution time are bounded.
- Unknown verbs, malformed requests, stale identities and unauthorized peers are tested.

### Persisted intent and safety admission

How the helper verifies persisted intent and safety admission is decided before the first helper verbs ship. Safety admission is the check that decides whether an automatic action may go ahead.

A record in a store writable by the main process is caller-controlled too. Reading it back through RPC does not make it trusted approval. These rules apply:

- One process owns the store.
- Helper-enforced policy, budgets and replay protection survive a compromised caller and a helper restart.
- If the main process remains the owner, its records are evidence only. It must not be able to reset or forge the helper's safety admission.
- Forged intent, replay and attempted budget reset are tested alongside valid requests.
- Socket ownership, protocol compatibility and unavailable-helper behavior are part of the first slice.
- Findings are retained when a mutation cannot safely proceed.

The open work is tracked in the [roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#privilege-separation).
