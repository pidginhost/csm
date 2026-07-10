# Direct SMTP egress

CSM watches the local mail stack via spool + log scanning. Non-MTA
processes that open outbound SMTP connections directly bypass that
path. The direct SMTP egress detector catches that at connect time
and feeds the incident correlator.

## What fires

A finding with `check: "direct_smtp_egress"` is emitted when:

- A non-root process opens an outbound TCP connection.
- Destination port is one of the configured SMTP ports (default 25,
  465, 587).
- Destination IP is not loopback, infra, or in the operator's
  `infra_ips` list.
- The process user is NOT a known MTA user (mail, mailnull, postfix,
  dovecot, dovenull, mailman, plus exim on cPanel).

Process names are never a standalone allow condition. A hosted account
renaming malware to `smtp` or `smtpd` still emits a finding.

The detector always emits findings when enabled. The dry_run knob does
not suppress findings; it participates in the BPF enforcement
gate, where any dry_run=true layer keeps kernel denial in observe-only
mode.

## Configuration

```yaml
detection:
  direct_smtp_egress:
    enabled: true
    backend: auto       # auto / bpf / legacy / none
    dry_run: true       # safety default for detector-scoped action
    ports:             # each value must be 1-65535
      - 25
      - 465
      - 587
```

## Backends

- `auto` -- allow both BPF and legacy scan paths. Live backend choice
  still follows `detection.connection_tracker_backend`.
- `bpf` -- emit only from the cgroup/connect4,6 consumer.
- `legacy` -- emit only from the `/proc/net/tcp[6]` polling path
  (live poller or scheduled critical scan). This path lacks PID/comm;
  MTA matching is user-only.
- `none` -- detector disabled even when `enabled: true` is set
  elsewhere; useful for staged rollout.

The generic outbound connection tracker is still governed by
`detection.connection_tracker_backend`; this setting only gates
`direct_smtp_egress` findings.

## Metric

`csm_direct_smtp_egress_findings_total` -- monotonic counter,
incremented per finding emitted by the BPF connection consumer. The
legacy poller does not bump this counter today; operators who run
backend=legacy should track findings via the audit log.

## rDNS enrichment

When the BPF backend is active, finding details include a Domain
field populated from a TTL-cached reverse lookup (30 min TTL, 1
second per-lookup deadline). The lookup runs only after the cheap
direct-SMTP filters match. On resolver miss or timeout the field is
omitted; the finding still fires.

## Caveats

- `2525` is intentionally NOT in the default port list. Many operators
  run unrelated services on it. Add it to `ports` if your infra uses
  it for submission.
- The detector emits regardless of the dry_run knob. Kernel denial
  requires `auto_response.dry_run`, this dry_run key, and
  `bpf_enforcement.dry_run` to all be explicitly false.
