# Auto-response safety model

How automatic actions are tiered, budgeted and paused so that one bad
detector cannot damage a protected server.

## What exists

`auto_response.dry_run` defaults to on. The scan block path uses the
configurable `max_blocks_per_hour` budget and service restarts use
`max_restarts_per_hour`. The virtual-patch mode has a safe default. The
verdict callback lets a panel downgrade a block. Process signalling goes
through pidfd. Quarantine and virtual patching resolve paths with `openat2`
and `RESOLVE_BENEATH`. The incident correlator has safety caps and a dry-run
mode. Firewall changes record a rollback point. `mode: observe` refuses to run
any of it. See [auto-response](../auto-response.md) and
[observe mode](../observe-mode.md).

Automatic file responses share one admission model: realtime and scheduled
quarantine, PHP cleaning and access-file cleaning draw on persistent host and
account budgets over a rolling hour. Reservations survive reloads, restarts
and interrupted actions. Repeated failures pause these responses, and
unavailable safety state refuses changes. Pause warnings are deduplicated
while the original detections stay visible. Account identity comes from
account-home paths; unknown paths share a budget. Failed cleaning leaves the
source and recovery evidence for review. Whole-directory and special-file
quarantine require manual review. Actions revalidate the target after budget
persistence, and the cleaners receive the same file identity captured before
admission. The file-response failure pause is host-wide across automatic
quarantine and cleaning paths.

Automatic per-address blocks use the firewall engine's infrastructure,
local-address, operator-allow and verified-crawler guards. Block candidates
are admitted through reserved lanes and fair scope shares in
`internal/admission`, so independently supported findings keep bounded
capacity when one scope floods.

## Risk tiers

Every operation in `internal/privops` carries a risk tier, and a test fails
when one is missing or disagrees with the reviewed inventory:

| Tier | Meaning | Examples |
| --- | --- | --- |
| 0 | alert only | most findings |
| 1 | recommendation or dry-run record | `dry_run` blocks, virtual-patch preview |
| 2 | low-risk reversible | challenge, rate limit, mail hold |
| 3 | quarantine or block | file quarantine, nftables block, virtual patch |
| 4 | destructive or process-affecting | process kill, service restart, config rewrite |

Each tier gets a confidence floor, a per-action circuit breaker that follows
the rules below, mandatory identity revalidation immediately before tiers 3
and 4 (inode and device for files, pidfd for processes, rule handle for
firewall entries), and enough recorded metadata to reverse the action. The
[durable action lifecycle](durable-action-lifecycle.md) carries that
metadata; there is no parallel policy switch or second set of limits.

## Adversarial workloads

Safeguards are designed for attacker-triggered load as well as operational
faults. Limits bound both resource use and harm to hosted sites while keeping
detection and response health visible. Finite action, queue and storage
budgets sit alongside evidence-based failure breakers. Budgets are calibrated
against representative response demand, including bursts, and measured host
capacity; behaviour under overload is validated and withheld responses are
visible.

- A breaker pauses automatic action only. Detection, findings and alerts
  continue at their own severity.
- Budgets and pauses are scoped by verified account and action ownership,
  with shared bounds for common resources and unknown ownership. A source
  address or check name alone does not establish an independent actor.
  Admission is deterministic and fair, with bounded reserved capacity for
  independently supported findings.
- Only the affected action scopes pause unless a shared mechanism is unsafe.
  Verified shared storage or execution failures can require a wider pause at
  once; failures in several accounts alone do not prove that condition.
  Unavailable intent or budget persistence still refuses new mutations.
- Target refusals are recorded separately from execution and storage
  failures. Admitted attempts stay charged, and uncertain outcomes are
  reconciled before a retry. Every pause has bounded recovery and
  revalidation; reloads, restarts and policy changes do not silently reset it.
- Alternative containment must be supported for the affected protocol, honor
  existing mode and action opt-ins, and pass admission and identity checks.
  Resource pressure alone never authorizes broader targets or stronger
  actions. If no safe action is available, the finding is retained with the
  deferred or refused outcome and the required operator review.
- A pause that leaves a Critical finding without its automatic action raises
  a deduplicated Critical alert and is reported by status and `csm doctor`.
  Every deferred, refused or dropped candidate is accounted for without an
  unbounded alert queue. A dispatched request is not proof of containment.

## Firewall feedback

For firewall blocks, correctness feedback supplements resource limits:

- Hard address exclusions and automatic allow protections stay at the
  authoritative action boundary, including range overlap checks and the
  existing explicit operator-command semantics. Source attribution is
  verified against the connecting peer or an explicitly trusted proxy chain.
  Any operator-session safeguard needs authenticated provenance, expiry and
  service scope.
- A detector-specific breaker needs reviewed correctness evidence linked to
  the original finding and action. Authentication or an operator unblock
  alone is not proof of a false positive. Independent attack evidence and
  other healthy response paths are preserved; corrective feedback does not
  demote findings.
- Temporary-block expiry and renewal are specified together with the
  escalation lifecycle. Escalation evidence is validated with corroboration
  grading; response records and repeated reports are not new corroboration.
  Operator exclusions and undo are preserved.
- Firewall sets and admission stay bounded. Range or ASN-based containment
  requires separate corroboration, protected-range checks and an explicit
  policy limiting collateral impact; it is not a substitute for capacity.

## One admission authority

The same admission authority covers automatic entry points, retries and
recovery. Under [privilege separation](privilege-separation.md) the executor
verifies policy and admission independently of caller-supplied findings or
state, while a single owner holds the live database.

## Calibration

Budgets are calibrated with recorded finding streams joined to action
outcomes and reviewed operator decisions. Raw recordings and operational
tuning stay private; only sanitized fixtures and aggregate validation results
are published.
