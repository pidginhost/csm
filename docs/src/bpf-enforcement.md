# BPF cgroup-deny enforcement

Phase 4 of the BPF Incident Response Roadmap. Optional in-kernel
denial of outbound connections that match a Phase 3 detection
(direct SMTP egress is the only gate landed today). Defaults are
all-safe; operators flip live denial only after Phase 3 telemetry
review.

## What it does

When `bpf_enforcement.enabled=true` and `dry_run=false`:

- The cgroup/connect4 + cgroup/connect6 BPF program inspects each
  outbound TCP connect.
- If destination port is in the protected set AND the source UID is
  not in the safe-UID map AND the gated detector matches, the
  program returns 0 (kernel denies the connect).
- Userspace observes the decision via the `decision` field on the
  ringbuf event and emits an audit-log entry.

When `dry_run=true` (the default), the program emits the decision
but always returns 1 (allow). Operators can run dry-run for as long
as they need to gather telemetry before flipping to live denial.

## What it does NOT do

- It does NOT wait on remote verdict callbacks in-kernel. That would
  add HTTP latency to every connect. The verdict callback (if
  enabled) runs in userspace AFTER the BPF decision and can only
  downgrade an action.
- It does NOT enforce on UDP, ICMP, or non-cgroup paths.
- It does NOT replace any Phase 3 detection. Detections still run
  regardless; enforcement is a separate, layered control.

## Configuration

```yaml
bpf_enforcement:
  enabled: false              # master switch; default off
  dry_run: true               # safety default; flip after telemetry review
  direct_smtp_egress: false   # gate enforcement on the Phase 3 detector
  verdict_callback: false     # userspace post-decision callback
```

`bpf_enforcement.enabled=true` requires at least one feature gate.
Today the only gate is `direct_smtp_egress`, which itself requires
`detection.direct_smtp_egress.enabled=true`.

## Kernel requirements

- Linux >= 4.10 with `CONFIG_CGROUP_BPF=y`.
- `cgroup/connect4` and `cgroup/connect6` BPF program types.
- The capability surface `bpf_enforcement.available.v1` is the wire
  signal that the binary supports the feature; combined with
  `bpf_enforcement_active` on the health snapshot, operators can
  detect both feature presence and runtime state.

## Metrics

- `csm_bpf_enforcement_decisions_total{decision="allow|dry_run|deny"}`
- `csm_bpf_enforcement_uid_map_refresh_total` -- successful periodic
  refreshes of the safe-UID BPF map.
- `csm_bpf_enforcement_uid_map_refresh_failures_total` -- failed
  refreshes (e.g. /etc/passwd unreadable).

## Dry-run precedence

Three independent dry_run knobs interact:

1. `auto_response.dry_run` (global): suppresses every automatic
   action (firewall block, kill, etc.).
2. `detection.direct_smtp_egress.dry_run`: detector-scoped action
   knob.
3. `bpf_enforcement.dry_run`: kernel-side denial knob.

Rule: any dry_run=true wins. Live denial requires all three to be
false at the layer they apply. Defaults are dry_run=true everywhere
on first install.

## Rollout recipe

1. Phase 3 detector enabled, no Phase 4 wiring. Watch
   `csm_direct_smtp_egress_findings_total` for a week.
2. Phase 4 enabled with `dry_run: true`. Watch
   `csm_bpf_enforcement_decisions_total{decision="dry_run"}` and
   confirm dry-run denials track expected hosted-account egress.
3. Phase 4 dry_run=false on a single canary host. Audit incidents
   for false positives.
4. Roll out to fleet.
