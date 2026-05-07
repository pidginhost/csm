# Incidents

CSM groups related findings into Incident objects so operators see one
escalating story per account, mailbox, or process instead of a stream
of unrelated findings. Original findings are not mutated or suppressed
-- the Incident is layered on top.

## Lifecycle

| Status      | Meaning                                                                |
|-------------|------------------------------------------------------------------------|
| `open`      | Active. New findings for the same correlation key keep merging in.     |
| `contained` | Operator marked under control. Findings still merge in window.         |
| `resolved`  | Closed. Future findings start a new incident.                          |
| `dismissed` | False positive. Future findings start a new incident.                  |

Resolved and dismissed incidents are pruned 30 days after their last
update. Open and contained incidents are never auto-pruned.

## Kinds

- `web_account_compromise` -- default for findings attributable to a
  hosted account (PHP relay, webshell, login bruteforce, etc.).
- `mailbox_takeover` -- SMTP/SASL signals against a specific mailbox.
- `post_exploit_process` -- process exec from `/tmp`, `/var/tmp`,
  `/dev/shm`.
- `host_integrity_risk` -- daemon/kernel-level signals (sensitive file
  writes, fake kernel threads, auditd disabled).

## Severity policy

Severity escalates only. Each incident keeps the highest severity any
joined finding has carried. Findings themselves are never re-emitted at
a higher severity. The audit trail records an
`incident_severity_changed` action when an incident's severity bumps.

## Correlation window

15 minutes by default. Findings outside the window for the same key
start a new incident. The window is a named constant in code; not yet
exposed via config.

## API

- `GET /api/v1/incidents` -- list, newest first.
- `GET /api/v1/incidents/<id>` -- one incident.
- `POST /api/v1/incidents/<id>/status` -- transition status.

See [api.md](api.md) for endpoint detail.

## Control socket

```
csm incidents list
csm incidents show <id>
csm incidents status <id> <open|contained|resolved|dismissed> [details]
```

## Metrics

- `csm_incidents_open` -- gauge of currently open + contained incidents.
- `csm_incidents_created_total`
- `csm_incidents_severity_changed_total`
- `csm_incidents_status_changed_total`
- `csm_incidents_findings_merged_total`
- `csm_incidents_compacted_total`
