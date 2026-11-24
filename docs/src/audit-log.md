## Audit Log

CSM can ship its findings as JSON records to one or more SIEM-friendly sinks. There are two sink types: a JSONL file and RFC 5424 syslog. Both are opt-in via `csm.yaml`, and you can enable them together or independently.

The audit log carries source observations and notification findings. It includes sources that notification filtering or rate limits suppressed, so SIEM correlation can still identify the original observation. Records are deduplicated by observation identity within each batch, and against each destination's recent successful deliveries.

### Turning it on

1. Enable the [file sink](#file-sink-jsonl), the [syslog sink](#syslog-sink-rfc-5424), or both in `csm.yaml`.
2. Give the SIEM its history with [Backfill](#backfill).
3. Watch the sink health metrics in [Delivery failures and recovery](#delivery-failures-and-recovery).

### File sink (JSONL)

```yaml
alerts:
  audit_log:
    file:
      enabled: true
      path: /var/log/csm/audit.jsonl    # default
```

Tail the file for an interactive view:

```bash
tail -F /var/log/csm/audit.jsonl | jq -c
```

Or hand it to a log shipper like Vector, Filebeat, or Fluentbit.

The default path is created with mode `0640` and the parent dir with `0750`.

#### Rotation

The packaged logrotate fragment rotates the file daily and keeps 14 compressed rotations. It uses `copytruncate` mode, so the daemon's open file descriptor stays valid across rotation and no SIGHUP is needed.

The 100 MB threshold permits early rotation when the host runs logrotate more often than daily. It does not cap growth between runs. The sink never drops records to stay under that size, because a detection flood would otherwise blind the audit trail until the next rotation.

On busy hosts, run logrotate more often than daily so the size trigger can take effect.

Installation and upgrades refresh the fragment, including upgrades through `csm rehash`.

If you move the audit log off the default path, add your own logrotate stanza for it. The packaged fragment names the default path only.

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

The wire line is RFC 5424 with the JSON event embedded as the MSG body. Receivers that already understand the JSONL schema parse it the same way regardless of transport.

| Transport | Framing |
|-----------|---------|
| UDP and unix-datagram | One datagram per message. |
| TCP, TLS, and unix-stream | LF framing. |

CSM severities map onto the standard syslog level set:

| CSM severity | Syslog level | Numeric |
|--------------|--------------|---------|
| CRITICAL     | crit         | 2       |
| HIGH         | err          | 3       |
| WARNING      | warning      | 4       |

Automated tests cover RFC 5424 output and UDP, TCP, TLS, Unix datagram, and Unix stream framing. Validate the chosen receiver configuration in a staging environment before production rollout.

### Backfill

When you first turn on the audit log, the SIEM has no history. Use `csm export --since <when>` to dump prior findings in the same JSONL schema:

```bash
csm export --since 24h > recent.jsonl
csm export --since 2026-04-01T00:00:00Z > q2.jsonl
```

`<when>` is either an RFC 3339 timestamp or a duration relative to now (`24h`, `7d`).

The output is one JSON event per line on stdout, identical in shape to what the live sinks emit. You can pipe it straight into the same ingest pipeline.

The command requires a running daemon.

### Delivery failures and recovery

Each enabled destination retries independently after an open or write failure.

- The delay starts at one second and doubles up to one minute.
- A later dispatch retries a missing destination once its delay has elapsed. A quiet daemon waits until another finding arrives.
- Healthy destinations stay open during retries.
- Backoff resets after a successful delivery.
- Configuration changes take effect on the next dispatch.
- Reloading audit configuration waits for in-flight writes before replacing sinks.

Failed deliveries are not replayed automatically. Use [Backfill](#backfill) to recover stored findings.

#### What to monitor

Failures and recovery are logged to journald. Two metrics on `/metrics` report sink health:

| Metric | Meaning |
|--------|---------|
| `csm_audit_sink_degraded{sink="jsonl"}` and `csm_audit_sink_degraded{sink="syslog"}` | One means a configured destination failed. Zero means it is healthy or disabled. |
| `csm_audit_events_dropped_total{sink}` | Counts events whose destination was unavailable or whose write failed. |

The degraded values are initialized when the audit pipeline first runs. Syslog health reflects local connection/write results, not an acknowledgement from the receiving SIEM.

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

The `v` field is the schema version. CSM bumps it on incompatible changes and will not bump it for additive fields, so SIEM parsers can pin on `v: 1` and ignore unknown keys.

#### `finding_id`

`finding_id` is a stable 16-hex-char hash of the canonical fields (timestamp, check, severity, message, file path). Two emits of the same finding produce the same ID, so downstream dedup works across re-runs.

Distinct findings can share a legacy `finding_id` and still need separate records. The legacy `finding_id` remains an action correlation key. Collectors must not treat it alone as a unique-record key.

#### `ts`

The `ts` field records when CSM raised the finding. This includes findings from process monitoring, automatic actions, scanner health, and mail relay storage errors. It is independent of when a sink delivers the event.

A producer that builds a finding without a time gets the moment the daemon received it, so `ts` is never the zero time.

#### `context`

An optional `context` key carries background beside the details. An example is ModSecurity being switched off for the account a malware finding concerns.

`context` is not part of `finding_id` or receipt matching, so a change in it alone never produces a new record. Recognized credentials in context are redacted before alert and audit output, using the same policy as messages and details.

### Process context

Exec and outbound-connection findings on BPF-backed hosts carry an optional `process` object. It holds the PID, PPID, UID, user, cPanel account (when known), comm, exe, sanitized cmdline, and a parent chain.

The field is omitted when no context is available, so existing parsers that ignore unknown keys see no schema change.

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

The parent chain may be truncated at depth 5. It may stop early if an intermediate parent has been evicted from the cache.

### What gets logged

CSM logs the source observations and notification findings that reach the audit dispatcher, deduplicated by observation identity within each batch. It logs them before three filters apply:

- The per-account rate limiter, so audit signal is not lost when email and webhook are throttled.
- The "blocked IP suppression" filter, so SIEM correlation sees events that operators were spared.
- The per-sink disabled-checks list. The audit log is not subject to email's `disabled_checks`.

Audit-log volume is therefore generally higher than the email or webhook stream. Plan SIEM retention accordingly.

### What does not get logged

#### Internal state changes

The audit log is not a replacement for `csm.history` (the bbolt history bucket). Only findings that pass through the audit dispatcher are emitted.

Internal state changes, such as daemon startup, reload events and config changes, live in journald via `csm.service` and are not mirrored here.

#### Secrets

Before a record is written, CSM replaces these values in the record's message and details with `[REDACTED]`:

- recognized password fields,
- API tokens,
- command-line secrets,
- cPanel session identifiers.

Repeated and quoted values are all covered, including the displayed form of NUL-separated arguments.

Two limits apply:

- Records written by earlier versions are not rewritten, so an existing log keeps whatever it already holds.
- The active-finding snapshot and the pending queues are not redacted. They are process-local state that the daemon itself reads back and compares.

The exact scope is in [Redaction scope](#redaction-scope).

### Details

The sections below are reference material for collector authors and for edge cases.

#### Replays and receipts

CSM keeps a receipt for each observation a destination accepted. It uses the receipts to suppress replays for each sink separately.

- The daemon audits source observations even when they repeat an earlier finding or are filtered from operator notifications.
- Distinct observations keep their own identities. Recent replays of the same observation are suppressed per sink.
- Receipts are kept in bounded memory and survive temporary sink failures.
- A destination that missed a record can receive its replay without duplicating a healthy destination's record.
- A replay marks its receipt as recently used. When the receipt memory is full, CSM drops the receipts that have gone unused longest first.
- Receipt matching includes original details, scanner identity and source attribution.
- Process enrichment alone does not create a new observation.
- Restarting or reconfiguring sinks clears receipts. Observations that are not in the receipt cache can be emitted again.

Auditing a repeated or filtered observation does not change which notifications CSM suppresses, or what other consumers of findings receive. Audit delivery still depends on the configured sink and on scan findings reaching the dispatcher.

#### Finding identity in the action log

Firewall actions caused by a finding carry the same `finding_id` in the [action log](action-log.md), including failed and refused attempts.

- The identity is captured before reason text is shortened.
- It survives queued retries, challenge timeouts, central-intelligence decisions, and permanent-block promotion.
- Subnet and incident escalation link the latest known contributing finding.
- Database session blocks link the original database finding, not a synthetic IP candidate.
- Older stored evidence without an identity remains unlinked, and so do manual or maintenance operations. CSM does not reconstruct an identity from display text.

#### Times filled in by alert dispatch

Alert dispatch fills missing times on its own copy of the findings.

| Case | Result |
|------|--------|
| An unstamped input is reused for a later occurrence | It gets a fresh time and finding id. |
| A finding with an existing time is replayed | Its time and id are preserved. |

#### Redaction scope

Session redaction covers cPanel, WHM, Webmail, the shared server daemon, DAV and security purge log lines.

- It keeps the account name beside a session identifier.
- It leaves unrelated lines of a multiline finding alone.
- It leaves already redacted text unchanged when it runs again.

The same redaction runs on email digests and on new finding history in both the bbolt and the legacy JSONL backend. It therefore also covers the history the Web UI serves and exports as CSV.

Attack event messages are redacted before truncation, so a truncated line cannot hide a credential behind a cut service tag. Attack events store no finding details.

Account and IP attribution is read from the original finding, and finding IDs are computed from it too, so audit records still correlate with remediation records. Other structured fields are copied unchanged.
