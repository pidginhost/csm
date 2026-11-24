# Fleet Correlation Contract (v1)

CSM is a per-host sensor. It does not correlate findings across hosts. Cross-host ("fleet") correlation belongs to phpanel, which already receives every deduplicated finding through the per-finding webhook.

This document defines the contract phpanel implements to turn that stream into one fleet incident per attacker instead of N identical per-host incidents.

This is the phpanel-side correlation design: CSM stays a sensor with no new inbound network surface on hosts. A peer-to-peer ingest endpoint inside CSM was considered and rejected for v1, because it would add an inbound auth plane and key distribution to every host.

## What CSM already provides

With `alerts.webhook.type: phpanel`, CSM POSTs one HMAC-signed message per deduplicated finding that reaches `alert.Dispatch`. The per-finding webhook is in `internal/alert/webhook.go`.

This sink runs before operator alert suppression and the operator alert rate limit. phpanel therefore receives the correlation stream even when local notifications are muted:

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
    "severity":  2,
    "source_ip": "203.0.113.10",
    "message":   "...",
    "timestamp": "2026-05-29T10:00:00Z",
    "tenant_id": "...",   // when known
    "domain":    "...",   // when known
    ...
  }
}
```

No extra CSM API or peer transport is required. Fleet correlation is a matter of phpanel aggregating the stream it already receives.

### Delivery and answers

CSM keeps each finding in a durable queue and delivers them in order.

| Answer | What CSM does |
|---|---|
| 2xx | Treats the finding as acknowledged. |
| HTTP 400, 413 or 422 | Treats the record itself as refused: moves it to a bounded local archive, counts it as lost and sends the next finding. |
| Redirect | Does not follow it. A redirect does not acknowledge a finding. |
| Any other failure | Retries with backoff. Later findings wait behind it. |

Use 400, 413 or 422 only for a problem with that one record.

After a long run of refusals with nothing accepted, CSM stops archiving and retries instead. A panel that refuses every request therefore does not lose the queue. The hold survives config reloads and daemon restarts, and it ends after an accepted delivery.

### Fields to correlate on

Every field phpanel needs to correlate across hosts is present:

- `hostname` identifies the reporting sensor.
- `finding.source_ip` identifies the attacker when the detector has a remote source.
- For `mail_subnet_spray` and `smtp_subnet_spray`, use `source_ip` when present (older findings). Otherwise use the single subnet in `finding.cidrs`.
- Other checks' `cidrs`, including `http_asn_crawl`, are response targets and must not become an attacker key.
- Severity is the CSM numeric enum (`0` warning, `1` high, `2` critical).

## Correlation rule (phpanel side)

1. Verify `X-CSM-Signature` (HMAC-SHA256 over the raw body) with the shared secret before trusting any field. Reject unsigned or mismatched messages.
2. Group incoming findings by the attacker address described above within a sliding window. Matching CSM's 15-minute incident merge window is recommended.
3. When the same attacker address appears in findings from two or more distinct `hostname` values inside the window, open one fleet incident keyed on that address rather than per-host incidents.
4. Attach each contributing `(hostname, finding)` to the fleet incident's timeline, so an operator sees the spread across the fleet.

Use only the attacker address as the cross-host key. Account, mailbox and domain identifiers are host-local and collide across tenants, so do not use them as the cross-host key.

## Severity and de-duplication

- A fleet incident's severity is the max of its contributing findings.
- Findings carrying no attacker address (host-integrity events, config drift) are not fleet-correlated. They stay per-host.
- The same `(hostname, attacker address, check)` arriving repeatedly is the normal heartbeat of an ongoing attack. Collapse on the attacker address and count contributions rather than opening a new incident per message.

## Out of scope (v1)

- Peer-to-peer ingest between CSM hosts.
- A CSM-side fleet incident store. CSM remains stateless with respect to other hosts; the fleet view lives in phpanel.
- Cross-host auto-block orchestration. phpanel may drive per-host blocks through each host's existing control surface. CSM does not coordinate blocks across the fleet.
