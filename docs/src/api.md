# API Reference

65+ REST endpoints. All require token authentication. POST mutations require CSRF token.

## Authentication

```bash
# Bearer token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" https://server:9443/api/v1/status

# Cookie-based (after login)
curl -b "csm_auth=YOUR_TOKEN" https://server:9443/api/v1/status
```

POST requests require the `X-CSRF-Token` header (obtained from the login response or page meta tag).

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
      scope: read        # status, findings, history, stats, blocked IPs, health, capabilities, SSE
```

The legacy single-token `webui.auth_token:` is migrated automatically to a `legacy-auth-token` admin entry on first start. Read-scope tokens are intended for orchestrators and dashboards that consume status, findings, history, stats, blocked-IP summaries, health, capabilities, and SSE events. Admin scope is still required for write routes and for sensitive reads such as quarantine, settings, firewall internals, threat-intel detail, rules, ModSecurity, account detail, exports, incident timelines, and audit history. `metrics_token:` is a separate, read-only credential for `/metrics` only.

## Status & Data

```
GET  /api/v1/status              Full health snapshot: version, uptime, watchers, severity counts,
                                 store health, blocklist size, capabilities[], config_hash, binary_hash
GET  /api/v1/capabilities        Static feature list (e.g. `confd.dropins.v1`, `events.sse.v1`,
                                 `webhook.phpanel.v1`, `sd_notify.ready`). Use for orchestrator feature-detect.
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
GET  /api/v1/blocked-ips         Blocked IPs with reason and expiry
GET  /api/v1/accounts            cPanel account list
GET  /api/v1/account             Per-account findings, quarantine, history (?name=)
GET  /api/v1/audit               UI audit log
GET  /api/v1/export              Export state (suppressions, whitelist)
GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)
GET  /api/v1/performance         Performance metrics snapshot
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
GET  /api/v1/modsec/stats              WAF statistics
GET  /api/v1/modsec/blocks             Blocked requests log
GET  /api/v1/modsec/events             WAF event details
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
GET  /api/v1/settings/<section>   Read a config section (secrets redacted)
POST /api/v1/settings/<section>   Update a config section (hot-reload-safe sections only)
POST /api/v1/settings/restart     Request a daemon restart (after editing restart-required fields)
```

Sections map to top-level config keys: `alerts`, `auto_response`, `challenge`, `reputation`, `performance`, `infra_ips`, `sentry`, etc. Writes persist to `csm.yaml`, re-sign the integrity hash, and hot-reload where possible; restart-required changes are queued for `/api/v1/settings/restart`.

## Finding fields

Every finding in `/api/v1/findings`, `/api/v1/events`, and the JSONL audit log carries optional correlation fields when CSM can attribute them:

| Field | Meaning |
|---|---|
| `tenant_id` | Tenant attribution from the verdict callback or panel-side webhook reply |
| `domain` | Domain associated with the event (e.g. PHP-relay scriptKey host, mailbox domain) |
| `mailbox` | Mailbox attribution (e.g. mail brute-force target, PHP-relay envelope-from) |

Fields are omitted when the daemon could not attribute them. Orchestrators should treat absence as "unknown," not "global."
