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
update. Open and contained incidents are never auto-pruned by the
retention loop, but they may be auto-resolved by the per-kind idle
threshold described under "Auto-close" below.

## Auto-close

To stop the open-incident backlog from growing without bound on busy
hosts, the daemon scans Open / Contained incidents shortly after startup
and then once an hour, auto-resolving any whose `updated_at` exceeds the
per-kind idle threshold. A live sweep closes at most 1000 stale incidents
at a time; if more stale incidents remain, follow-up sweeps run every 30
seconds until the backlog drains. Dry-run sweeps still scan the full set
so the counters show every would-close decision. Auto-resolved incidents
carry `closed_by: "auto:stale"` and an `incident_auto_closed` action in
their timeline so reporting can distinguish them from operator closes.

Defaults (configurable in `csm.yaml`):

```yaml
incidents:
  auto_close:
    enabled: true            # set false to disable
    dry_run: false           # set true to log decisions without writing back
    by_kind:
      mailbox_takeover: 24h
      credential_spray: 24h
      web_account_compromise: 168h
```

Kinds absent from `by_kind` are never auto-closed. The default map
omits `host_integrity_risk`, `host_takeover`, and `post_exploit_process`
because those host-level incidents should stay open until an operator
reviews them. `host_takeover` is the compound escalation raised when any
two of three host-takeover legs (a new uid-0 account, a planted suid
binary, an outbound connection to a bad ASN) are correlated for the same
host inside the merge window.

If a fresh finding for the same correlation key arrives after the
auto-close, the merge-window stale-binding logic creates a new open
incident -- nothing about auto-close blocks re-detection. History is
preserved on the closed record.

**Tuning on high-volume hosts.** Each `by_kind` threshold is the idle
time before a kind auto-resolves; they are independent and operator-set.
A host under sustained brute-force keeps a large open set mostly from the
longer-lived kinds (`web_account_compromise` defaults to 168h). If the
open-incident count is higher than you want to triage, shorten the
relevant `by_kind` entry (e.g. `web_account_compromise: 72h`) rather than
disabling auto-close. The closed records are retained 30 days regardless,
measured from when the incident resolves, so shortening the threshold also
moves the eventual prune point earlier relative to the last finding.
Auto-close still keeps a resolved record for follow-up instead of deleting
history at close time.

Metrics: `csm_incidents_auto_closed_total` and
`csm_incidents_auto_close_dry_run_total`.

## Credential-spray suppression

Without this path, an attacker IP that brute-forces 6500 distinct
usernames produces 6500 `mailbox_takeover` incidents because the
correlator keys on the mailbox, not the source IP. The
spray-suppression detector tracks the distinct-mailbox set per source
IP across the merge window and, once an IP exceeds `distinct_mailboxes`,
opens a single `credential_spray` super-incident keyed on the IP.
Subsequent findings from that IP attach to the spray incident's
timeline instead of opening per-mailbox incidents.

Defaults (configurable in `csm.yaml`):

```yaml
incidents:
  spray_suppression:
    enabled: false           # default OFF; opt-in
    dry_run: true            # default ON; counters move, routing unchanged
    distinct_mailboxes: 10   # threshold to trip
    severity_escalate_at: 50 # bump severity to CRITICAL at this many
    per_check:
      - email_auth_failure_realtime
      - pam_auth_failure
      - ssh_bruteforce
    max_tracked_ips: 10000
    block_at_severity: ""    # "" detection-only, "high" block on open,
                             # "critical" block on escalation
```

Setting `block_at_severity` hands the source IP to the firewall as soon
as the spray detector trips at the chosen tier, once
`spray_suppression.dry_run` is false. The detector also requires
`auto_response.enabled` and `auto_response.block_ips`; the firewall still
honors `auto_response.dry_run`, so a dry-run host logs the would-be block
without applying nftables rules. Live accepted requests are recorded on
the incident timeline as a `credential_spray_block_requested` action.
Non-live outcomes (dry-run, verdict-allow, already blocked) and failed
attempts do not latch the incident, so a later finding can retry after
blocking is live again. Concurrent findings for the same incident share
one in-flight firewall call, and resolved or dismissed spray incidents do
not make new block decisions.

Whitelisted IPs (entries in `reputation.whitelist` and the live bbolt
whitelist updated via the Web UI) are skipped from spray detection so
internal mail relays, NAT egresses, and known-good infrastructure
never produce a spray incident.

Choosing `block_at_severity`:

- `""` (default) -- detection-only. Spray incidents open, no firewall
  hand-off. Use during dry-run validation and on hosts where blocking
  is owned by a separate system.
- `high` -- block at the `distinct_mailboxes` trip. Recommended once
  the dry-run counter looks clean. Trips on the first sustained
  burst before the source IP goes idle for longer than the merge
  window.
- `critical` -- block only after severity escalates, i.e. one IP hits
  `severity_escalate_at` distinct mailboxes before the source IP is
  idle for more than the merge window. A low-and-slow attacker that
  stays below that count before each idle reset never escalates and
  never blocks. Pick this only when you have strong shared-NAT exposure
  and accept that slow sprayers evade the gate.

Rollout:

1. Ship the daemon with `enabled: false, dry_run: true`. The detector
   tracks per-IP mailbox sets and increments
   `csm_credential_spray_dry_run_total` whenever the threshold would
   have tripped, but routing stays on the legacy per-mailbox path.
2. Validate the counter on your own infrastructure for 24h. If a
   trusted IP shows up in the dry-run trips, add it to
   `reputation.whitelist`.
3. Flip `enabled: true, dry_run: false`. New attacker IPs route
   through the spray path; existing per-mailbox backlog drains via the
   auto-close path.
4. After another 24h, set `block_at_severity: high`. The firewall
   hand-off runs on every spray decision (open + merge), so an
   incident opened before the flag was armed still blocks on the
   next finding from the same IP.

Metrics: `csm_credential_spray_opened_total`,
`csm_credential_spray_suppressed_mailbox_takeover_total`,
`csm_credential_spray_dry_run_total`,
`csm_credential_spray_tracked_ips`.

## Incident auto-block

`spray_suppression` only handles the credential_spray super-incident
kind. Low-and-slow scanners that never trip a per-detector window
(modsec escalation, mail brute-force, smtp probe) still produce
mailbox_takeover or web_account_compromise incidents but never get
firewalled. The `incidents.auto_block` block adds a generic
incident-driven firewall hand-off:

```yaml
incidents:
  auto_block:
    enabled: false           # default OFF; opt-in
    block_at_severity: ""    # "" / "high" / "critical"
    kinds: []                # empty = any non-spray kind with one source IP
```

When the gate trips, the correlator hands the source IP to the firewall
through the same dry-run / block_ips gate as the spray path. A live
accepted request records `incident_block_requested`; non-live outcomes
(dry-run, verdict-allow, already blocked) do not latch the incident, so
an operator who arms `auto_block` AFTER an incident has already crossed
the gate still gets a block on the next finding while the incident is
open or contained. Incidents with multiple source IPs are left for manual
review.
If a long-running incident's timeline was truncated and the source IP is
not part of the incident key, auto-block also stays off because the
remaining visible timeline may not contain every source IP.

credential_spray is explicitly excluded from this path; the dedicated
spray hand-off owns it. Set `kinds` to narrow the surface (e.g. only
`web_account_compromise`) if you do not want every CRITICAL
mailbox_takeover incident to block its source IP.

This pairs naturally with the ModSecurity escalation thresholds
(`thresholds.modsec_escalation_hits`,
`thresholds.modsec_escalation_window_min`) -- raising the window from
the shipped default of 10 minutes to e.g. 4 hours lets the modsec
detector promote paced scanners to a Critical escalation finding,
which then trips the generic auto_block gate.

## Kinds

- `web_account_compromise` -- default for findings attributable to a
  hosted account or script (PHP relay, webshell, login bruteforce, etc.).
- `mailbox_takeover` -- SMTP/SASL, suspicious-login, credential-abuse,
  and rate signals tied to a mailbox or cPanel-local mail account.
- `post_exploit_process` -- process exec from `/tmp`, `/var/tmp`,
  `/dev/shm`.
- `host_integrity_risk` -- daemon/kernel-level signals (sensitive file
  writes, fake kernel threads, auditd disabled).
- `host_takeover` -- any two of a new uid-0 account, a planted suid
  binary, and an outbound connection to a bad ASN, seen for the same host
  inside the merge window.
- `credential_spray` -- one source IP brute-forcing many distinct
  mailboxes/accounts inside the merge window. Keyed on the source IP
  rather than per-mailbox, so a scanner spraying thousands of usernames
  produces one super-incident instead of thousands of mailbox_takeover
  rows. Findings from the same IP after the trip attach to this
  incident's timeline. See "Credential-spray suppression" below.

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

Open **Monitor -> Incidents**. The page has three tabs:

- **Correlated** -- the default flat list of incidents with status
  filter, page size, and detail panel. The detail panel shows the
  current firewall block state for the incident's source IP (permanent,
  temporary, cphulk, or not blocked) when an IP is known.
- **Grouped** -- rolls up incidents by `(kind, source)` so a credential
  spray that produced thousands of mailbox_takeover incidents shows as
  one row per attacker IP. Pageable with the same page-size selector
  as Correlated. Click a group to see member incidents in the detail
  panel, which also surfaces the source IP's firewall block state;
  clicking a sample id jumps back to the Correlated tab focused on
  that incident.
- **Timeline Search** -- the older IP/account history search across
  the audit log.

Admin tokens can transition incident status (open / contained /
resolved / dismissed); read-scope tokens can browse all three tabs.

## Control socket

```
csm incidents list [--status all|active|open|contained|resolved|dismissed] [--limit N] [--offset N] [--all]
csm incidents show <id>
csm incidents status <id> <open|contained|resolved|dismissed> [details]
csm incidents bulk-status --older-than 24h [--last-seen-before RFC3339] [--status active|open|contained] [--kind K] [--domain D] [--account A] [--mailbox M] [--limit N] [--to resolved|dismissed] [--apply --confirm]
```

`csm incidents list` returns the first 100 incidents by default. Use
`--offset` for the next page, `--status active` for open + contained
incidents, or `--all` for an explicit full dump.

`csm incidents bulk-status` defaults to dry-run. It prints the total
match count and a bounded preview of the incidents that would change.
At least one age guard is required: `--older-than`, `--last-seen-before`,
or both. To mutate incidents, pass both `--apply` and `--confirm`.

## Metrics

- `csm_incidents_open` -- gauge of currently open + contained incidents.
- `csm_incidents_created_total`
- `csm_incidents_severity_changed_total`
- `csm_incidents_status_changed_total`
- `csm_incidents_findings_merged_total`
- `csm_incidents_compacted_total`
- `csm_incidents_pending` -- gauge of findings held in the threshold gate, awaiting a second correlated sighting.
