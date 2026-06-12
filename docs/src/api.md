# API Reference

Machine-readable HTTPS API. All endpoints require token authentication. State-changing POST, PUT, PATCH, and DELETE requests require CSRF protection for browser cookie sessions.

## Authentication

```bash
# Bearer token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" https://server:9443/api/v1/status

# Cookie-based (after login)
curl -b "csm_auth=YOUR_TOKEN" https://server:9443/api/v1/status
```

Cookie-authenticated state-changing requests require the `X-CSRF-Token` header (obtained from the login response or page meta tag). Admin-scope Bearer requests are CSRF-exempt because the `Authorization` header is the write credential.

### Token scopes

Configure tokens under `webui.tokens:` with a `scope` of `admin` or `read`:

```yaml
webui:
  tokens:
    - name: "operator"
      token: "..."
      scope: admin       # full read+write
    - name: "panel-readonly"
      token: "..."
      scope: read        # status, findings, history, stats, blocked IPs, health, components, capabilities, SSE
```

The legacy single-token `webui.auth_token:` is migrated automatically to a `legacy-auth-token` admin entry on first start. Read-scope tokens are intended for orchestrators and dashboards that consume status, findings, history, stats, blocked-IP summaries, health, components, capabilities, and SSE events. Admin scope is still required for write routes and for sensitive reads such as quarantine, settings, firewall internals, threat-intel detail, rules, ModSecurity, account detail, exports, incident timelines, and audit history. `metrics_token:` is a separate, read-only credential for `/metrics` only.

## Status & Data

```
GET  /api/v1/status              Full health snapshot: version, uptime, watchers, severity counts,
                                 store health, blocklist size, capabilities[], config_hash, binary_hash,
                                 automation rollout state, challenge pending count, rollback state.
                                 `latest_scan` is the canonical last-scan timestamp; `last_scan_time`
                                 is a legacy alias kept for older clients and will be removed.
GET  /api/v1/capabilities        Static feature list (e.g. `confd.dropins.v1`, `events.sse.v1`,
                                 `webhook.phpanel.v1`, `webui.prefs.v1`, `webui.undo.v1`,
                                 `mail.queue.composition.v1`,
                                 `detect.http_scanner_profile.v1`). Use for orchestrator feature-detect.
GET  /api/v1/components          Watcher/component matrix with attachment, event, and upstream freshness state.
GET  /api/v1/events              Server-Sent Events stream of findings as they dispatch.
                                 Read-scope token sufficient. One JSON event per `data:` line.
GET  /api/v1/health              Daemon health (fanotify, watchers, engines)
GET  /api/v1/findings            Current active findings
GET  /api/v1/findings/enriched   Enriched findings with GeoIP, accounts, fix info
GET  /api/v1/finding-detail      Finding detail with action history (?check=&message=)
GET  /api/v1/history             Paginated history (?limit=&offset=&from=&to=&severity=&search=)
GET  /api/v1/history/csv         CSV export (up to 5,000 entries)
GET  /api/v1/stats               24h severity counts, accounts at risk, auto-response summary
GET  /api/v1/stats/trend         30-day daily severity counts
GET  /api/v1/stats/timeline      Event timeline
GET  /api/v1/quarantine          Quarantined files with metadata (incl. htaccess pre_clean backups)
GET  /api/v1/quarantine-preview  Preview quarantined file content (?id=)
GET  /api/v1/db-object-backups   db_object_backups bucket (MySQL trigger/event/procedure/function drops)
GET  /api/v1/db-object-backup-preview Preview captured CREATE SQL (?key=)
GET  /api/v1/blocked-ips         Blocked IPs with reason and expiry
GET  /api/v1/accounts            cPanel account list
GET  /api/v1/account             Per-account findings, quarantine, history (?name=)
GET  /api/v1/audit               UI audit log
GET  /api/v1/export              Export state (suppressions, whitelist)
GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)
GET  /api/v1/performance         Performance metrics snapshot
POST /api/v1/perf/fix-error-log  Truncate a fixed-row error_log finding
POST /api/v1/perf/fix-display-errors
                                  Disable display_errors for a fixed-row config finding
GET  /api/v1/hardening           Last stored hardening audit report
```

## GeoIP

```
GET  /api/v1/geoip               IP geolocation (?ip=&detail=1)
POST /api/v1/geoip/batch         Batch GeoIP lookup (JSON array of IPs)
```

## Threat Intelligence

```
GET  /api/v1/threat/stats        Attack stats, type breakdown, hourly trend
GET  /api/v1/threat/top-attackers Top attacking IPs with GeoIP (?limit=)
GET  /api/v1/threat/ip           IP threat lookup (?ip=)
GET  /api/v1/threat/events       IP event history (?ip=&limit=)
GET  /api/v1/threat/whitelist    Whitelisted IPs
GET  /api/v1/threat/db-stats     Attack database statistics
POST /api/v1/threat/block-ip     Block IP permanently
POST /api/v1/threat/whitelist-ip       Permanent whitelist
POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist (with expiry)
POST /api/v1/threat/clear-ip           Clear IP from attack database
POST /api/v1/threat/unwhitelist-ip     Remove from whitelist
POST /api/v1/threat/bulk-action        Bulk block/clear/whitelist across many IPs
```

## Firewall

```
GET  /api/v1/firewall/status         Config, blocked/allowed counts
GET  /api/v1/firewall/allowed        Whitelisted IPs
GET  /api/v1/firewall/subnets        Blocked subnets
GET  /api/v1/firewall/audit          Firewall audit log
GET  /api/v1/firewall/check          Check if IP is blocked (?ip=)
POST /api/v1/block-ip                Block an IP
POST /api/v1/unblock-ip              Unblock an IP
POST /api/v1/unblock-bulk            Bulk unblock IPs
POST /api/v1/firewall/allow-ip       Allow an IP
POST /api/v1/firewall/remove-allow   Remove IP from allow list
POST /api/v1/firewall/deny-subnet    Block subnet
POST /api/v1/firewall/remove-subnet  Remove subnet block
POST /api/v1/firewall/flush          Clear all blocks
POST /api/v1/firewall/unban          Unblock IP + flush cphulk
POST /api/v1/firewall/cphulk-clear   Flush cphulk bans only
```

## ModSecurity

```
GET  /api/v1/incidents/groups          Roll up open/contained incidents by (kind, source) so credential spray collapses into one row per attacker IP. Read scope. Accepts ?status=active|all|open|contained|resolved|dismissed, ?kind=, ?limit=.

GET  /api/v1/modsec/stats              WAF statistics (read scope)
GET  /api/v1/modsec/blocks             Blocked requests log, aggregated per IP (read scope)
GET  /api/v1/modsec/events             WAF event details (read scope)
GET  /api/v1/modsec/rules              Loaded rules list
POST /api/v1/modsec/rules/apply        Apply custom rules
POST /api/v1/modsec/rules/escalation   Change rule severity/action
```

## Rules & Suppressions

```
GET  /api/v1/rules/status        YAML/YARA rule counts, version
GET  /api/v1/rules/list          Rule files
GET  /api/v1/suppressions        Suppression rules
POST /api/v1/rules/reload        Reload signature rules from disk
POST /api/v1/suppressions        Add or delete suppression rule
POST /api/v1/rules/modsec-escalation   ModSec escalation override
```

## Email

```
GET  /api/v1/email/stats         Email scanning statistics
GET  /api/v1/email/forwarders    Mail forwarder inventory with destination providers and local-copy flags (read scope)
GET  /api/v1/email/deferrals     Outbound deferral rollup by provider and sending IP with reason codes, parsed from exim_mainlog (read scope)
GET  /api/v1/email/queue-composition  Mail queue makeup: real vs null-sender bounce backscatter, frozen count, oldest age, top stuck recipients (read scope)
POST /api/v1/email/queue/flush-backscatter  Remove only frozen null-sender (backscatter) messages from the exim queue on cPanel hosts; returns removed count or 503 when unavailable (admin scope, CSRF)
GET  /api/v1/email/held          Forward copies held by the forward guard (admin scope)
POST /api/v1/email/held/{id}/release   Re-inject a held forward copy to its external recipient (admin scope, CSRF)
DELETE /api/v1/email/held/{id}   Discard a held forward copy (admin scope, CSRF)
GET  /api/v1/email/groups        Server-grouped action rows (kind=compromised_account|spam_outbreak|auth_failure|queue_alert|malware) with from/to/limit (read scope)
GET  /api/v1/email/relay-abuse   Outbound PHP-mail abuse detections (spam outbreaks, high-volume scripts/accounts) with per-site script breakdown; from/to/limit (read scope)
GET  /api/v1/email/quarantine    Quarantined email list
GET  /api/v1/email/av/status     Email AV watcher status
POST /api/v1/email/quarantine/   Release or delete quarantined email
```

## Hardening

```
GET  /api/v1/hardening           Load last hardening audit report
POST /api/v1/hardening/run       Run hardening audit and save report
```

## Actions

```
POST /api/v1/fix                      Apply fix for a finding
POST /api/v1/fix-bulk                 Bulk fix multiple findings
POST /api/v1/dismiss                  Dismiss a finding
POST /api/v1/scan-account             On-demand account scan
POST /api/v1/quarantine-restore       Restore quarantined file
POST /api/v1/quarantine/bulk-delete   Bulk-delete quarantined files
POST /api/v1/db-object-backup-restore Restore a dropped MySQL object from its db_object_backups record
POST /api/v1/test-alert               Send test alert through all channels
POST /api/v1/import                   Import state bundle (suppressions, whitelist)
```

## Settings

```
GET  /api/v1/settings             List editable config sections
GET  /api/v1/settings/<section>   Read a config section (secrets redacted)
POST /api/v1/settings/<section>   Update a config section (safe fields reload, restart fields queue)
POST /api/v1/settings/restart     Request a daemon restart (after editing restart-required fields)
POST /api/v1/settings/firewall/tentative-apply  Save firewall config, restart, and arm rollback timer
GET  /api/v1/settings/firewall/rollback         Read pending rollback state
POST /api/v1/settings/firewall/confirm          Confirm tentative firewall changes
POST /api/v1/settings/firewall/revert           Revert tentative firewall changes now
```

Sections map to top-level config keys: `alerts`, `auto_response`, `challenge`, `reputation`, `performance`, `infra_ips`, `sentry`, etc. Writes persist to `csm.yaml`, re-sign the integrity hash, and hot-reload where possible; restart-required changes are queued for `/api/v1/settings/restart`. Invalid field values return 422 and do not touch disk. Firewall tentative apply is restart-class by design: it snapshots the previous config, writes the new one, restarts the daemon, and auto-reverts unless the operator confirms before the timer expires.

## Operator preferences

Per-operator state (UI density, timestamp display, default auto-refresh,
saved filter views) is keyed server-side by SHA-256 of the auth token,
so preferences follow the operator across browsers and devices without
the daemon ever storing the raw credential. Capability flag:
`webui.prefs.v1`. These endpoints require admin scope because they read
or mutate operator-private UI state.

```
GET    /api/v1/prefs/user        Read this operator's UI preferences
PUT    /api/v1/prefs/user        Replace the prefs blob (CSRF on cookie sessions)
GET    /api/v1/prefs/views       List saved views; `?page=findings` filters by page
PUT    /api/v1/prefs/views       Upsert one view {page, name, params} (CSRF on cookie sessions)
DELETE /api/v1/prefs/views       Delete one view {page, name} (CSRF on cookie sessions)
```

Response shape for `GET /api/v1/prefs/user`:

```json
{
  "density":       "comfortable",
  "timezone":      "local",
  "auto_refresh":  "on",
  "table_columns": { "findings-table": ["check","severity","when"] }
}
```

`density` is `comfortable` or `compact`. `timezone` is `server`, `local`,
or an IANA-shaped zone string (e.g. `Europe/Bucharest`). `auto_refresh`
is `on` or `off`. Server-side sanitisation drops any other value. Unset
prefs encode as empty strings; the UI applies `comfortable`, `local`, and
`on` defaults.

Response shape for `GET /api/v1/prefs/views`:

```json
[
  {
    "name": "Critical SSH",
    "page": "findings",
    "params": { "severity": "critical", "check": "smtp_bruteforce" },
    "updated": 1779743255
  }
]
```

Saved views are operator-scoped and capped at 200 per operator. The saved
view collection is stored as one 64 KiB preference blob. `page` and
`params` keys must be simple identifiers: ASCII letters, digits,
underscore, hyphen, or dot, up to 64 bytes. Each view has at most 32
params, and param string values are capped at 256 bytes. `name` must be
1-80 bytes with no control characters. `PUT` and `DELETE` return
`{"status":"ok"}` on success.

## Bulk-action undo

Bulk threat block / whitelist and bulk firewall unblock responses return
an `undo_token` when the daemon queues an inverse operation server-side
for 30 seconds. The UI surfaces a banner with the same TTL; CLI callers
can act on the token through the endpoints below. Each successful undo
writes an `undo_<original_action>` audit entry. Capability flag:
`webui.undo.v1`. These endpoints require admin scope because they read
or mutate operator-private action state.

```
GET  /api/v1/undo/pending    Latest pending undo entry for this operator (empty object if none)
POST /api/v1/undo/run        Consume an entry and dispatch its inverse {id}; empty id uses latest
```

Non-empty response shape for `GET /api/v1/undo/pending`:

```json
{
  "id": "188d1f2a6c8b0000",
  "action": "threat_bulk_block",
  "inverse": "threat_bulk_unblock",
  "summary": "Blocked 2 IPs",
  "recorded_at": "2026-05-26T00:07:09Z",
  "expires_at": "2026-05-26T00:07:39Z"
}
```

`POST /api/v1/undo/run` returns `{status, action, inverse, count}` on
success, or `410 Gone` when the entry is missing, already consumed, or
past its 30-second TTL. Recognised inverse action keys are
`threat_bulk_unblock`, `threat_bulk_block`, `threat_bulk_unwhitelist`,
`threat_bulk_whitelist`, and `firewall_bulk_reblock`. Other bulk actions
(quarantine delete, generic fix) do not surface an undo token because
they have no clean inverse.

## Finding fields

Every finding in `/api/v1/findings`, `/api/v1/events`, and the JSONL audit log carries optional correlation fields when CSM can attribute them:

| Field | Meaning |
|---|---|
| `tenant_id` | Tenant attribution from the verdict callback or panel-side webhook reply |
| `domain` | Domain associated with the event (e.g. PHP-relay scriptKey host, mailbox domain) |
| `mailbox` | Mailbox attribution (e.g. mail brute-force target, PHP-relay envelope-from) |
| `relay_total` | PHP-relay trigger count for the path that fired |
| `relay_breakdown` | PHP-relay script samples that contributed to the alert, with script key, hit count, last seen time, and a bounded sample subject when available |

Fields are omitted when the daemon could not attribute them. Orchestrators should treat absence as "unknown," not "global."

## Cleanup fields

`GET /api/v1/quarantine` also powers the Cleanup page's file-backup list. Entries include:

| Field | Meaning |
|---|---|
| `kind` | `quarantine` or `pre_clean` |
| `live_state` | `original_missing`, `live_differs`, `original_not_file`, `archive_missing`, `archive_not_file`, or `unknown`. Byte-identical restored entries are hidden. |

`GET /api/v1/db-object-backups` returns `restored` and `restored_at` when a captured MySQL trigger/event/procedure/function backup has already been replayed.

## Incidents

### `GET /api/v1/incidents`

Returns every incident (open, contained, resolved, dismissed) sorted by
`updated_at` descending.

### `GET /api/v1/incidents/<id>`

Returns one incident by id. 404 if not found.

### `POST /api/v1/incidents/<id>/status`

Body:

```json
{"status": "resolved", "details": "operator-marked"}
```

Status values: `open`, `contained`, `resolved`, `dismissed`. Closing an
incident (resolved/dismissed) means future findings for the same
correlation key start a fresh incident. Reopening an incident binds the
same key again. Incident JSON includes `correlation_key` when CSM has a
stored account, mailbox, domain, process, or remote-IP key.
