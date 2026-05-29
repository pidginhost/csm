# Fleet Correlation Contract (v1)

CSM is a per-host sensor. It does not correlate findings across hosts
itself; cross-host ("fleet") correlation is owned by phpanel, which
already receives every finding through the per-finding webhook. This
document defines the contract phpanel implements to turn that stream
into one fleet incident per attacker instead of N identical per-host
incidents.

This is the **phpanel-side correlation** design: CSM stays a sensor with
no new inbound network surface on hosts. A peer-to-peer ingest endpoint
inside CSM was considered and rejected for v1 (it would add an inbound
auth plane and key distribution to every host).

## What CSM already provides

With `alerts.webhook.type: phpanel` and `per_finding: true`, CSM POSTs
one HMAC-signed message per finding (see the per-finding webhook in
`internal/alert/webhook.go`):

```
POST <alerts.webhook.url>
Content-Type: application/json
X-CSM-Signature: sha256=<hex>      (HMAC-SHA256 over the raw body)
X-CSM-Hostname: <hostname>

{
  "hostname":  "host-7.example",
  "timestamp": "2026-05-29T10:00:00Z",
  "finding": {
    "check":     "ssh_bruteforce",
    "severity":  3,
    "source_ip": "203.0.113.10",
    "message":   "...",
    "tenant_id": "...",   // when known
    "domain":    "...",   // when known
    ...
  }
}
```

Every field phpanel needs to correlate across hosts is present:
`hostname` identifies the reporting sensor, and `finding.source_ip`
identifies the attacker. No CSM change is required to enable fleet
correlation; it is purely a matter of phpanel aggregating the stream it
already receives.

## Correlation rule (phpanel side)

1. Verify `X-CSM-Signature` (HMAC-SHA256 over the raw body) with the
   shared secret before trusting any field. Reject unsigned or
   mismatched messages.
2. Group incoming findings by `finding.source_ip` within a sliding
   window (recommend matching CSM's 15-minute incident merge window).
3. When the same `source_ip` appears in findings from **two or more
   distinct `hostname` values** inside the window, open one fleet
   incident keyed on `(source_ip)` rather than per-host incidents.
4. Attach each contributing `(hostname, finding)` to the fleet
   incident's timeline so an operator sees the spread across the fleet.
5. Account/mailbox/domain identifiers are host-local; do not use them as
   the cross-host key (they collide across tenants). `source_ip` is the
   only globally meaningful attacker key.

## Severity and de-duplication

- A fleet incident's severity is the max of its contributing findings.
- Findings carrying no `source_ip` (host-integrity events, config
  drift) are not fleet-correlated; they stay per-host.
- The same `(hostname, source_ip, check)` arriving repeatedly is the
  normal heartbeat of an ongoing attack; collapse on `(source_ip)` and
  count contributions rather than opening a new incident per message.

## Out of scope (v1)

- Peer-to-peer ingest between CSM hosts.
- A CSM-side fleet incident store. CSM remains stateless with respect to
  other hosts; the fleet view lives in phpanel.
- Cross-host auto-block orchestration. phpanel may drive per-host blocks
  through each host's existing control surface; CSM does not coordinate
  blocks across the fleet.
