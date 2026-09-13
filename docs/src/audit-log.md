## Audit Log

CSM ships source observations and notification findings to one or more
SIEM-friendly sinks, deduplicated by observation identity within each batch
and against each destination's recent successful deliveries.
Audit records include sources suppressed by notification filtering or
rate limits, so SIEM correlation can still identify the original observation.

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

Firewall actions caused by a finding carry this same identity in the action
log, including failed and refused attempts. The identity is captured before
reason text is shortened and survives queued retries, challenge timeouts,
central-intelligence decisions, and permanent-block promotion. Subnet and
incident escalation link the latest known contributing finding. Older stored
evidence without an identity and manual or maintenance operations remain
unlinked; CSM does not reconstruct an identity from display text. Database
session blocks link the original database finding, not a synthetic IP candidate.

The daemon audits source observations even when they repeat an earlier finding
or are filtered from operator notifications. Distinct observations keep their
own identities; recent replays of the same observation are suppressed per sink.
Receipts are kept in bounded memory and survive temporary sink failures. A
destination that missed a record can receive its replay without duplicating a
healthy destination's record. Restarting or reconfiguring sinks clears receipts;
observations older than the receipt cache can be emitted again, so collectors
should still deduplicate by `finding_id` for longer retention.
Notification suppression and downstream finding observers keep their existing
behavior. Audit delivery still depends on the configured sink and scan findings
reaching the dispatcher.

The `ts` field records when CSM raised the finding, including process
monitoring, automatic actions, scanner health, and mail relay storage errors.
It is independent of when a sink delivers the event. A producer that builds
a finding without a time gets the moment the daemon received it, so `ts` is
never the zero time.

Alert dispatch fills missing times on its own copy of the findings. Reusing
an unstamped input for a later occurrence gets a fresh time and finding id;
replaying a finding with an existing time preserves its time and id.

### Process context

Exec and outbound-connection findings on BPF-backed hosts carry an
optional `process` object with PID, PPID, UID, user, cPanel account
(when known), comm, exe, sanitized cmdline, and a parent chain. The
field is omitted when no context is available, so existing parsers
that ignore unknown keys see no schema change.

```json
{
  "severity": "HIGH",
  "check": "outbound_connection",
  "message": "Suspicious outbound connection",
  "process": {
    "pid": 4242,
    "ppid": 4200,
    "uid": 1001,
    "user": "alice",
    "account": "alice",
    "comm": "ncat",
    "exe": "/usr/bin/ncat",
    "cmdline": ["ncat", "203.0.113.10", "587"],
    "parent": {
      "pid": 4200,
      "ppid": 4100,
      "uid": 1001,
      "comm": "sh"
    }
  },
  "timestamp": "2026-05-07T12:34:56Z"
}
```

The parent chain may be truncated at depth 5 and may stop early if
an intermediate parent has been evicted from the cache.

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
rotation -- no SIGHUP needed. It rotates daily and keeps 14 compressed
rotations. The file sink enforces the same 100 MB size budget before each
append, including when multiple local writers share the file. Once full, it
rejects further records until logrotate truncates the live file. The existing
dropped-event counter and degraded-sink metric expose those losses; syslog
delivery continues independently. On busy hosts, configure a shorter
time-based rotation interval and run logrotate at least that often; merely
invoking the daily stanza more often cannot clear a file below its size trigger.
Installation and upgrades refresh the fragment, including upgrades through
`csm rehash`.

If you move the audit log off the default path, add your own
logrotate stanza for it: the packaged fragment names the default
path only.

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

Automated tests cover RFC 5424 output and UDP, TCP, TLS, Unix datagram,
and Unix stream framing. Validate the chosen receiver configuration in a
staging environment before production rollout.

### Delivery failures and recovery

Each enabled destination retries independently after an open or write failure.
The delay starts at one second and doubles up to one minute. A later dispatch
retries a missing destination once its delay has elapsed; a quiet daemon waits
until another finding arrives. Healthy destinations stay open during retries.
Reloading audit configuration waits for in-flight writes before replacing sinks.

Failures and recovery are logged to journald. Monitor
`csm_audit_sink_degraded{sink="jsonl"}` and
`csm_audit_sink_degraded{sink="syslog"}` on `/metrics`: one means a configured
destination failed, zero means it is healthy or disabled. These values are
initialized when the audit pipeline first runs. Syslog health reflects local
connection/write results, not an acknowledgement from the receiving SIEM.

`csm_audit_events_dropped_total{sink}` counts events whose destination was
unavailable or whose write failed. Failed deliveries are not replayed
automatically; use the backfill command below to recover stored findings.
Backoff resets after a successful delivery, and configuration changes take
effect on the next dispatch.

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

Source observations and notification findings reaching the audit dispatcher,
deduplicated by observation identity within each batch, before:

- the per-account rate limiter (so audit signal is not lost when
  email and webhook are throttled);
- the "blocked IP suppression" filter (so SIEM correlation sees
  events that operators were spared);
- the per-sink disabled-checks list (audit log is not subject to
  email's `disabled_checks`).

This means audit-log volume is generally higher than the email or
webhook stream. Plan SIEM retention accordingly.

### What does not get logged

Before a record is written, its message and details replace recognized
password fields, API tokens, command-line secrets and cPanel session
identifiers with `[REDACTED]`. Session redaction covers cPanel, WHM,
Webmail, the shared server daemon, DAV and security purge log lines. It
keeps the account name beside a session identifier, leaves unrelated
lines of a multiline finding alone, and leaves already redacted text
unchanged when it runs again. Repeated and quoted values are all
covered, including the displayed form of NUL-separated arguments.

The same redaction runs on email digests, on new finding history in
both the bbolt and the legacy JSONL backend, and therefore on the
history the web UI serves and exports as CSV. Attack event messages are
redacted before truncation, so a truncated line cannot hide a
credential behind a cut service tag; attack events store no finding
details. Account and IP attribution is read from the original finding,
and finding IDs are computed from it too, so audit records still
correlate with remediation records. Other structured fields are copied
unchanged.

Two limits are worth knowing. Records written by earlier versions are
not rewritten, so an existing log keeps whatever it already holds. The
active-finding snapshot and the pending queues are process-local state
that is read back and compared by the daemon itself, so they are not
redacted.

The audit log is not a replacement for `csm.history` (the bbolt
history bucket). Only findings that pass through the audit dispatcher
are emitted. Internal state changes -- daemon startup, reload events,
config changes -- live in journald via `csm.service` and are not
mirrored here.
