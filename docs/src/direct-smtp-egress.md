# Direct SMTP egress

CSM watches the local mail stack via spool + log scanning. A non-MTA process that opens an outbound SMTP connection directly bypasses that path. The BPF backend sees the connection attempt. The legacy backend can find a connection while it is open. Both report findings to the incident correlator.

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

`2525` is intentionally NOT in the default port list, because many operators run unrelated services on it. Add it to `ports` if your infra uses it for submission.

## What fires

CSM emits a finding with `check: "direct_smtp_egress"` when all of these hold:

- A non-root process opens an outbound TCP connection.
- The destination port is one of the configured SMTP ports (default 25, 465, 587).
- The destination IP is not loopback and is not in the operator's `infra_ips` list.
- The process user is NOT a known MTA user. See [Known MTA users](#known-mta-users).
- The process user is NOT listed under `firewall.smtp_allow_users`. See [Allowed users](#allowed-users).

Process names are never a standalone allow condition. A hosted account renaming malware to `smtp` or `smtpd` still emits a finding.

### Known MTA users

The known MTA users are mail, mailnull, postfix, dovecot, dovenull and mailman, plus exim on cPanel.

On non-cPanel hosts, Stalwart's stalwart and stalwart-mail users are also recognized when their UID is below 1000. Hosted UIDs do not receive this automatic exemption, even when they use a Stalwart username.

### Allowed users

`firewall.smtp_block` blocks outgoing mail except for allowed users. Users listed under `firewall.smtp_allow_users` pass that block, so their connections are expected. List any other mail server's service user there.

<a id="caveats"></a>

### Findings and dry run

A matching connection can raise a finding in dry run. The selected backend must be active.

The knob takes part in the BPF enforcement gate, where any dry_run=true layer keeps kernel denial in observe-only mode. Kernel denial requires `auto_response.dry_run`, this dry_run key, and `bpf_enforcement.dry_run` to all be explicitly false. See [BPF cgroup-deny enforcement](bpf-enforcement.md).

## Backends

| `backend` | What it does |
|-----------|--------------|
| `auto` | Allows both the BPF and the legacy scan paths. Live backend choice still follows `detection.connection_tracker_backend`. |
| `bpf` | Emits only from the cgroup/connect4,6 consumer. |
| `legacy` | Emits only from the `/proc/net/tcp[6]` polling path (live poller or scheduled critical scan). This path lacks PID/comm; MTA matching uses the username and UID. |
| `none` | Disables the detector even when `enabled: true` is set elsewhere. Useful for staged rollout. |

`detection.connection_tracker_backend` still governs the generic outbound connection tracker. The `backend` setting only gates `direct_smtp_egress` findings.

## Metric

`csm_direct_smtp_egress_findings_total` is a monotonic counter. It is incremented per finding emitted by the BPF connection consumer.

The legacy poller does not bump this counter today. If you run backend=legacy, track findings via the audit log.

## rDNS enrichment

When the BPF backend is active, finding details include a Domain field. CSM fills it from a TTL-cached reverse lookup, with a 30 min TTL and a 1 second per-lookup deadline.

The lookup runs only after the cheap direct-SMTP filters match. On a resolver miss or timeout the field is omitted; the finding still fires.
