# Privilege separation

Why a minimal privileged helper will own the operations that need root, and
what it must enforce on its own.

Today the whole daemon, including detection, correlation, parsers, threat
intelligence, web UI and API, runs as root inside the systemd confinement
described in [service confinement](../service-confinement.md):
`ProtectSystem=strict`, syscall filtering, a `ReadWritePaths` allow-list, and
`systemd-run` for the panel scripts that need the whole filesystem. One helper
pattern exists: the mail forward guard executes a fixed helper subcommand of
the same binary. A parser bug anywhere is therefore a root compromise of the
host.

## Decision

A minimal privileged helper owns the operations that require root: nftables
and firewall changes, process termination, quarantine and other moves across
account boundaries, fanotify and BPF initialisation with the resulting
descriptors passed back over the socket, and privileged filesystem and
configuration writes. Everything else runs with reduced privileges. Reduced,
not none: reading every account's files still needs `CAP_DAC_READ_SEARCH`,
so the unprivileged side keeps a small capability set and loses the ability
to write, signal and reconfigure. The helper exposes a narrow Unix-socket RPC
authenticated by peer credentials, with fixed verbs and arguments validated
against the same path, user, process and firewall scopes the actions enforce
today.

The inventory stage is complete. `internal/privops` lists every operation
that needs privilege beyond reading CSM's own files, with what it writes, the
config key that stops it, its risk tier and what an operator loses by
withholding the privilege. `csm privileges` prints it, the
[capability matrix](../capability-matrix.md) ships it, and two gates in
`internal/ci` compare it against the packaged systemd unit in both
directions, so a writable-path grant that no operation claims fails the
build. That table is the action set the helper has to cover.

`mode: observe` is the interim posture for operators who will not grant a
root daemon the ability to act: detection and alerting run, automatic
remediation and integration deployment do not. It reduces what the root
process does, not what it could do, so it is a stopgap rather than a
substitute.

## Staging

Each stage ships on its own: the helper for firewall, then signals and
quarantine, then privileged configuration and filesystem writes; then
descriptor passing for fanotify and BPF; then dropping capabilities in the
main process. Each family first needs its safety classification and
[durable action contract](durable-action-lifecycle.md), not completion of
every other family's migration.

## What the helper must enforce

Peer credentials authenticate the caller, not the requested operation. The
helper enforces target and account scope, identity, permitted verbs and
safety policy even if the main process is compromised. It exposes no
arbitrary shell, command execution or unrestricted file-write RPC. Request
sizes and execution time are bounded; unknown verbs, malformed requests,
stale identities and unauthorized peers are tested.

How the helper verifies persisted intent and safety admission is decided
before the first helper verbs ship. A record in a store writable by the main
process is caller-controlled too; reading it back through RPC does not make
it trusted approval. One process owns the store, and helper-enforced policy,
budgets and replay protection survive a compromised caller and a helper
restart. If the main process remains the owner, its records are evidence
only: it must not be able to reset or forge the helper's safety admission.
Forged intent, replay and attempted budget reset are tested alongside valid
requests. Socket ownership, protocol compatibility and unavailable-helper
behaviour are part of the first slice. Findings are retained when a mutation
cannot safely proceed.

The open work is tracked in the
[roadmap](https://github.com/pidginhost/csm/blob/main/ROADMAP.md#privilege-separation).
