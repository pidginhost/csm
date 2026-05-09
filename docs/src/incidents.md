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
  hosted account or script (PHP relay, webshell, login bruteforce, etc.).
- `mailbox_takeover` -- SMTP/SASL, suspicious-login, credential-abuse,
  and rate signals tied to a mailbox or cPanel-local mail account.
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

## Open threshold

Non-Critical findings need at least two correlated sightings inside
the merge window before an incident opens. The first sighting is held
in a pending bucket and counted toward the threshold; the second
promotes both into a new incident with a two-event timeline. Stale
pending entries are pruned by the daily retention sweep.

Critical-severity findings (account compromise, cloud-relay abuse,
modsec rule escalations) bypass the threshold and open immediately
so escalations still page on first hit.

The threshold suppresses one-shot scanner noise (a single modsec
deny from a wandering scanner, an isolated mistyped password) without
hiding sustained activity. The current pending-bucket size is exposed
as the `csm_incidents_pending` gauge.

The stored incident includes the full correlation key, including process
PID/UID and remote IP when those are the only available dimensions, so
active incidents keep merging after daemon restart.

## API

- `GET /api/v1/incidents` -- list, newest first. Without query
  parameters the response is a bare JSON array (compat with the
  existing wire shape phpanel/SIEM consumers decode against).
  When `?limit=`, `?offset=`, or `?status=` is present the response
  switches to an envelope: `{"items":[...], "total":N, "offset":N,
  "limit":N, "status":"..."}`. Status accepts the four spec values
  plus `active` (open + contained, the default web UI filter).
  Limit is capped server-side at a safe maximum.
- `GET /api/v1/incidents/<id>` -- one incident.
- `POST /api/v1/incidents/<id>/status` -- transition status.

See [api.md](api.md) for endpoint detail.

## Web UI

Open **Monitor -> Incidents**. The default Correlated tab lists open
and contained Incident objects, shows the merged timeline, and lets an
admin mark an incident open, contained, resolved, or dismissed. The
Timeline Search tab keeps the older IP/account history search.

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
- `csm_incidents_pending` -- gauge of findings held in the threshold gate, awaiting a second correlated sighting.
