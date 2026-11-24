# BPF cgroup-deny enforcement

CSM can deny, in the kernel, outbound connections that match an enabled userspace detector. The feature is optional and off by default. Direct SMTP egress is currently the only enforcement gate.

Every layer starts in dry run, so you can review telemetry before you allow live denial.

## Rollout recipe

1. Enable the direct SMTP detector without BPF enforcement. Watch `csm_direct_smtp_egress_findings_total` for a week.
2. Enable BPF enforcement with `dry_run: true`. Watch `csm_bpf_enforcement_decisions_total{decision="dry_run"}` and confirm dry-run denials track expected hosted-account egress.
3. Set BPF `dry_run: false` on a single canary host. Audit incidents for false positives.
4. Roll out to fleet.

## Configuration

```yaml
bpf_enforcement:
  enabled: false              # master switch; default off
  dry_run: true               # safety default; flip after telemetry review
  direct_smtp_egress: false   # gate enforcement on the direct SMTP detector
  verdict_callback: false     # userspace post-decision callback
```

`bpf_enforcement.enabled=true` has these requirements:

- At least one feature gate is on. Today the only gate is `direct_smtp_egress`.
- `direct_smtp_egress` itself requires `detection.direct_smtp_egress.enabled=true`.
- `detection.connection_tracker_backend` is `auto` or `bpf`.
- `detection.direct_smtp_egress.backend` is `auto` or `bpf`.

## Dry-run precedence

Three independent dry_run knobs interact:

1. `auto_response.dry_run` keeps automatic network response in observe-only mode.
2. `detection.direct_smtp_egress.dry_run` is the detector-scoped action knob.
3. `bpf_enforcement.dry_run` is the kernel-side denial knob.

Rule: any dry_run=true wins. Live denial requires all three knobs to be false, and a BPF runtime backend. Defaults are dry_run=true everywhere on first install.

## What it does

Live denial runs when all of these hold:

- `bpf_enforcement.enabled=true`.
- `direct_smtp_egress=true`.
- The connection tracker is running on BPF.
- All dry-run layers are false.

In that state:

1. The cgroup/connect4 + cgroup/connect6 BPF program inspects each outbound TCP connect.
2. If the destination port is in the protected set AND the source UID is not in the safe-UID map AND the detector that gates enforcement matches (today the direct SMTP egress detector), the program returns 0. The kernel denies the connect.
3. Userspace observes the decision via the `decision` field on the ringbuf event and emits an audit-log entry.

When any dry-run layer is true (the default), the program emits the decision but always returns 1 (allow). You can stay in dry run for as long as you need to gather telemetry before you switch to live denial.

### Exempt accounts

The safe-UID map lists the accounts the program never denies. It includes:

- System UIDs below 1000.
- Traditional MTA accounts.
- Accounts listed in `firewall.smtp_allow_users`.

Stalwart usernames are exempt only as system UIDs. A hosted account cannot gain an exemption by choosing a Stalwart name.

CSM rereads `/etc/passwd` every 5 minutes and drops the exemption of hosted accounts that were deleted or renamed. A new account that reuses such a UID is therefore exempt for at most one refresh.

## What it does NOT do

- It does NOT wait on remote verdict callbacks in-kernel. That would add HTTP latency to every connect. The verdict callback, if enabled, runs in userspace after the BPF decision and enriches the emitted finding. It cannot undo a kernel denial.
- It does NOT enforce on UDP, ICMP, or non-cgroup paths.
- It does NOT replace detection. Findings still emit regardless. Enforcement is a separate, layered control.

## Kernel requirements

- Linux >= 4.10 with `CONFIG_CGROUP_BPF=y`.
- `cgroup/connect4` and `cgroup/connect6` BPF program types.

### Checking feature presence and runtime state

`bpf_enforcement.available.v1` in the capabilities list means the binary supports the feature. `bpf_enforcement_active` on the health snapshot reports the runtime state. Together they tell you whether the feature is present and whether it is active.

### Without BPF

On older kernels, or default builds without the BPF tag, `detection.connection_tracker_backend: auto` falls back to the legacy `/proc/net/tcp[6]` poller. In that state direct SMTP findings still work when `detection.direct_smtp_egress.backend` is `auto` or `legacy`, but BPF enforcement is inactive.

When CSM attempts BPF and cannot start it, it emits a `bpf_unavailable` finding. The message reports whether the daemon is running on a fallback backend or has no live fallback active.

## Metrics

- `csm_bpf_enforcement_decisions_total{decision="allow|dry_run|deny"}` counts decisions by outcome.
- `csm_bpf_enforcement_uid_map_refresh_total` counts successful periodic refreshes of the safe-UID BPF map.
- `csm_bpf_enforcement_uid_map_refresh_failures_total` counts failed refreshes, for example when /etc/passwd is unreadable.
