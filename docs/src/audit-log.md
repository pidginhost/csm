## Audit Log

CSM ships every deduplicated finding to one or more SIEM-friendly
sinks before the operator-alert rate limiter runs, so Splunk, Loki,
Elastic, and friends always see the complete picture even when
email and webhook traffic is throttled.

Two sink types ship today, both opt-in via `csm.yaml`. They can be
enabled together or independently.

### Schema

Every event, regardless of transport, has the same shape:

```json
{
  "v": 1,
  "ts": "2026-04-28T10:32:14.512938Z",
  "finding_id": "8e3f1c204c1d8b95",
  "severity": "CRITICAL",
  "check": "webshell_realtime",
  "message": "PHP execution primitive in uploads/",
  "details": "...",
  "file_path": "/home/customer/public_html/uploads/x.php",
  "hostname": "host.example.com"
}
```

The `v` field is the schema version. CSM bumps it on incompatible
changes and will not bump it for additive fields, so SIEM parsers
can pin on `v: 1` and ignore unknown keys.

`finding_id` is a stable 16-hex-char hash of the canonical fields
(timestamp, check, severity, message, file path). Two emits of the
same finding produce the same ID, so downstream dedup works across
re-runs.

### File sink (JSONL)

```yaml
alerts:
  audit_log:
    file:
      enabled: true
      path: /var/log/csm/audit.jsonl    # default
```

The default path is created with mode `0640` and the parent dir
with `0750`. The packaged logrotate fragment uses `copytruncate`
mode so the daemon's open file descriptor stays valid across
rotation -- no SIGHUP needed.

Tail it for an interactive view:

```bash
tail -F /var/log/csm/audit.jsonl | jq -c
```

Or hand it to a log shipper like Vector, Filebeat, or Fluentbit.

### Syslog sink (RFC 5424)

```yaml
alerts:
  audit_log:
    syslog:
      enabled: true
      network: udp                  # udp | tcp | unix | unixgram | tls
      address: 127.0.0.1:514        # host:port for udp/tcp/tls, path for unix*
      facility: local0              # default
      tls_ca: ""                    # optional PEM file for tls transport
```

Wire-line is RFC 5424 with the JSON event embedded as the MSG body,
so receivers that already understand the JSONL schema parse it the
same way regardless of transport. UDP and unix-datagram emit one
datagram per message; TCP, TLS, and unix-stream use LF framing.

Severity mapping onto the standard syslog level set:

| CSM severity | Syslog level | Numeric |
|--------------|--------------|---------|
| CRITICAL     | crit         | 2       |
| HIGH         | err          | 3       |
| WARNING      | warning      | 4       |

Tested against `rsyslog` and `syslog-ng` receivers in integration.

### Backfill

When you first turn on the audit log, the SIEM has no history. Use
`csm export --since <when>` to dump prior findings in the same JSONL
schema:

```bash
csm export --since 24h > recent.jsonl
csm export --since 2026-04-01T00:00:00Z > q2.jsonl
```

`<when>` is either an RFC 3339 timestamp or a duration relative to
now (`24h`, `7d`). The output is one JSON event per line on stdout,
identical in shape to what the live sinks emit, so you can pipe it
straight into the same ingest pipeline.

Requires a running daemon.

### What gets logged

Every finding the alert pipeline produces, after deduplication but
before:

- the per-account rate limiter (so audit signal is not lost when
  email and webhook are throttled);
- the "blocked IP suppression" filter (so SIEM correlation sees
  events that operators were spared);
- the per-sink disabled-checks list (audit log is not subject to
  email's `disabled_checks`).

This means audit-log volume is generally higher than the email or
webhook stream. Plan SIEM retention accordingly.

### What does not get logged

The audit log is not a replacement for `csm.history` (the bbolt
history bucket). Only findings that pass through `alert.Dispatch()`
are emitted. Internal state changes -- daemon startup, reload events,
config changes -- live in journald via `csm.service` and are not
mirrored here.
