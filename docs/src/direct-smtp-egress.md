# Direct SMTP egress

CSM watches the local mail stack via spool + log scanning. Non-MTA
processes that open outbound SMTP connections directly bypass that
path. The direct SMTP egress detector catches that at connect time
and feeds the incident correlator from Phase 2.

## What fires

A finding with `check: "direct_smtp_egress"` is emitted when:

- A non-root process opens an outbound TCP connection.
- Destination port is one of the configured SMTP ports (default 25,
  465, 587).
- Destination IP is not loopback, infra, or in the operator's
  `infra_ips` list.
- The process user is NOT a known MTA user (mail, mailnull, postfix,
  dovecot, dovenull, mailman, plus exim on cPanel).
- The process basename (comm or exe) is NOT a known MTA process name
  (postfix, smtpd, smtp, qmgr, pickup, cleanup, local, dovecot,
  imap-login, pop3-login, lmtp, plus exim/exim4 on cPanel).

The detector is detection-only in Phase 3. The dry_run knob exists in
config but does not gate emission today; Phase 4 introduces the
auto-response action that the knob will gate.

## Configuration

```yaml
detection:
  direct_smtp_egress:
    enabled: true
    backend: auto       # auto / bpf / legacy / none
    dry_run: true       # safety default; flip to false when Phase 4 lands
    ports:
      - 25
      - 465
      - 587
```

## Backends

- `auto` -- BPF when available, otherwise the `/proc/net/tcp[6]`
  poller.
- `bpf` -- the cgroup/connect4,6 program in
  `internal/daemon/connection_bpfprog/_connection.bpf.c`.
- `legacy` -- the polling path. Lacks PID/comm; MTA matching is
  user-only on this path. Higher false-positive rate than BPF.
- `none` -- detector disabled even when `enabled: true` is set
  elsewhere; useful for staged rollout.

## Metric

`csm_direct_smtp_egress_findings_total` -- monotonic counter,
incremented per finding emitted by the BPF connection consumer. The
legacy poller does not bump this counter today; operators who run
backend=legacy should track findings via the audit log.

## rDNS enrichment

When the BPF backend is active, finding details include a Domain
field populated from a TTL-cached reverse lookup (30 min TTL, 1
second per-lookup deadline). On resolver miss or timeout the field
is omitted; the finding still fires.

## Caveats

- `2525` is intentionally NOT in the default port list. Many operators
  run unrelated services on it. Add it to `ports` if your infra uses
  it for submission.
- The detector emits regardless of the dry_run knob in Phase 3.
  Phase 4 will introduce an action that the knob will gate.
