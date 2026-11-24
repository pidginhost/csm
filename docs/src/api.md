# API Reference

CSM has a machine-readable HTTPS API. Every endpoint requires token authentication. Browser cookie sessions also need CSRF protection on state-changing POST, PUT, PATCH and DELETE requests.

## Authentication

```bash
# Bearer token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" https://server:9443/api/v1/status

# Cookie-based (after login)
curl -b "csm_auth=SESSION_COOKIE_FROM_LOGIN" https://server:9443/api/v1/status
```

A cookie-authenticated request that changes state must send the `X-CSRF-Token` header. Take the token from the meta tag of the authenticated page.

- The token belongs to the browser session that loaded the page. CSM refuses another session's token.
- The token can also be sent as a form field. CSM reads that field from the request body only, never from the URL.
- Admin-scope Bearer requests are exempt from CSRF, because the `Authorization` header is the write credential.

### Browser session management

A successful browser login exchanges an admin token for an opaque session cookie. An API token is never valid as a cookie. A session expires on an idle deadline or an absolute deadline, and every session ends when the daemon restarts.

The Sessions page in the header offers the same operations as these admin-only endpoints:

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v1/sessions` | `items` list of sessions with `id`, `name`, `created`, `last_seen`, `expires`, `remote_ip`, `user_agent`, `current` |
| DELETE | `/api/v1/sessions/<id>` | Revoke that session; an unknown ID answers 404 |
| DELETE | `/api/v1/sessions` | Revoke all browser sessions, including the caller's |

- Revocation returns `{"ok":true}` only after the change is committed to the store. A failure returns 503, and an invalid session ID returns 404.
- Lists contain no credential hashes or session verifiers.
- Cookie-authenticated DELETE requests require CSRF. Admin bearer callers are exempt.
- Read-scope bearers cannot list or revoke sessions.

`POST /logout` requires authentication, and CSRF for browser callers. It revokes the current session and clears the cookie. `GET /logout` cannot log a user out.

### Token scopes

Configure tokens under `webui.tokens:`, each with a `scope` of `admin`, `read` or `unban`:

```yaml
webui:
  tokens:
    - name: "operator"
      token: "..."
      scope: admin       # full read+write
      issued_at: "<UTC RFC3339 time when this token was generated>"
    - name: "panel-readonly"
      token: "..."
      issued_at: "<UTC RFC3339 time when this token was generated>"
      scope: read        # status, findings, history, stats, challenge stats, blocked IPs, scan jobs, health, components, capabilities, SSE
    - name: "panel-unban"
      token: "..."
      scope: unban       # GET /api/v1/firewall/check and POST /api/v1/firewall/unban only
      issued_at: "<UTC RFC3339 time when this token was generated>"
      expires_at: "<UTC RFC3339 time when this token stops working>"
      allowed_ips: ["203.0.113.10", "198.51.100.0/24"]
```

Replace the placeholders above with fresh random tokens and real times.

#### What each scope can reach

| Scope | Access |
| --- | --- |
| `admin` | Everything. Write routes need it, and so do sensitive reads: quarantine, settings, firewall internals, threat-intel detail, rules, account detail, exports, incident timelines and audit history. |
| `read` | Status, findings, history, stats, challenge stats, blocked-IP summaries, scan jobs, health, components, capabilities and SSE events. Meant for orchestrators and dashboards. |
| `unban` | `GET /api/v1/firewall/check` and `POST /api/v1/firewall/unban` only. Meant for hosting panels that let customers lift their own blocks. |

ModSecurity `stats`, `blocks` and `events` are read scope. Only the ModSecurity rules and escalation routes need admin.

An unban-scope token cannot log in to the dashboard, read status or reach any other route. It is exempt from CSRF only on its two routes.

Two other credentials exist outside `webui.tokens:`:

- The legacy single token `webui.auth_token:`, with its optional `webui.auth_token_issued_at` and `webui.auth_token_expires_at`, is loaded as an admin entry named `legacy-auth-token`.
- `metrics_token:` is a separate read-only credential for `/metrics` only.

#### Expiry and issue time

A credential expires at its `expires_at`. Without one it never expires. The optional `issued_at` records when the token was generated.

CSM refuses authentication in these cases:

- `issued_at` is malformed or in the future.
- `expires_at` is malformed or not after `issued_at`.
- `expires_at` is in the past.

See [credential rotation](webui.md#credential-rotation).

#### Limiting a token to addresses

`allowed_ips` limits a token to the listed addresses and CIDR ranges. The limit covers API calls, browser login and the browser sessions the token starts. CSM matches the TCP peer address and ignores forwarded headers. A token without `allowed_ips` is accepted from any address.

- An entry that is not an address or a CIDR fails configuration loading.
- IPv4-mapped addresses and CIDRs within the mapped range match IPv4 peers: `::ffff:192.0.2.0/120` matches the same peers as `192.0.2.0/24`.
- CIDR host bits are masked.
- An entry with an interface zone, such as `2001:db8::1%eth0`, fails configuration loading. Use an address without a zone.
- A peer's interface zone does not affect address matching.

#### What an unban releases

`POST /api/v1/firewall/unban` releases an address in one of two modes. The credential selects the mode.

| Credential | What CSM clears |
| --- | --- |
| Unban-scope token | The address's block and its mail spray re-block marker. |
| Admin token or browser session | A full operator release. It also clears the address's mail failure history and counts, as described in [automatic blocking](auto-response.md#findings-that-always-trigger-ip-block). |

After an unban-scope release, spray failure history and SMTP, IMAP and POP failure counts remain. That includes shared IPv6 /64 evidence and other addresses' markers. Renewed spraying can still trigger a block.

The credential accepted at authorization selects the release mode. If it expires while CSM reads the request body, the mode does not change. A valid browser session takes precedence over a bearer token, and it still needs CSRF when it comes with an unban bearer.

#### Subnet blocks that cover the address

Either credential also removes subnet blocks that CSM added automatically and that cover the address. The response names them in `subnet_removed`.

- A subnet that an operator blocked is kept and named in `subnet_kept`. The address stays dropped until that subnet is unblocked.
- Operator descriptions do not grant automatic-unban eligibility.
- Older subnet entries without recorded automatic ownership are also kept, even if their source label says automatic. They expire normally, or you can remove them explicitly through the admin-only subnet removal endpoint.
- If a subnet changes during the request, CSM leaves the replacement intact and returns HTTP 500 with a retry message.

#### When an unban fails

| Case | Answer |
| --- | --- |
| The individual-IP removal fails | HTTP 500. CSM clears no threat state and reports no successful unban. |
| A subnet removal fails | HTTP 500. The individual-IP release and any earlier subnet removals have already taken effect. |
| An unban-scope caller, on a firewall backend without self-service unban support | HTTP 501. CSM never falls back to an operator release. |
| A covering automatic subnet needs removal, on a backend without conditional subnet removal | HTTP 501. |

The cPHulk flush remains best effort and runs only after the firewall removals succeed.

### Read-only MCP endpoint

Support agents that speak the Model Context Protocol get these reads at `/mcp` on the same listener, with their own credentials. See [MCP endpoint](mcp.md). The endpoint cannot reach any route that changes state.

## Errors

Every failure answers a non-2xx status with a JSON body that has an `error` message. That includes CSRF, origin, rate-limit and wrong-method refusals. No 2xx response reports a failure.

```json
{"error": "invalid IP address"}
```

Some failures add detail next to `error`. A settings save that fails validation adds `errors`, a list of fields and messages. An unknown path under `/api/` answers 404.

## Actions

A request that changes state answers `"ok": true` with the action's own fields, such as `undo_token` or `warning`.

| Case | Answer |
| --- | --- |
| Work continues after the answer, such as a daemon restart, a firewall rollback or a scan job | 202 |
| A batch where some items failed | 200, with the failures listed |
| A batch where nothing changed | An error status |
| An empty fix batch | Rejected |
| Any method but GET on a read-only route | 405 |
| A response that cannot be encoded | 500 with an error body |

Threat actions report firewall failures. Bulk actions list invalid addresses as well as failed changes. A failed action can have applied some steps before the error, so inspect the current state before you retry it.

`/api/v1/firewall/check` and `/api/v1/firewall/unban` also send `"success": true` for callers written against the older API. That field will be removed. Use the status code and `ok`.

## Lists

Every GET route that returns a list answers a JSON object, never a bare array. The list is under `items`.

```json
{"items": [{"ip": "203.0.113.9", "reason": "wp_login_bruteforce"}], "total": 1}
```

An empty list anywhere in a response is `[]` and an empty map is `{}`, never null. Null means a value is not known.

| Key | Meaning |
| --- | --- |
| `total` | The number of matches the server counted. It is larger than the length of `items` when the route pages or cuts the list. |
| `offset`, `limit` | Sent by routes that page or cap the list. Capped routes that do not support paging report `offset: 0`. |
| `truncated` | True when matches were left out: past the page, past the limit, or past a scan cap. |
| Other keys next to `items` | Describe the whole list, such as `check_types` on `/findings/enriched` or `summary` on `/email/forwarders`. |

When a scan cap stopped the count, `total` counts only what was scanned. Incident groups also send `scan_truncated` to tell a scan cap from a page limit. Their `total` is exact when `scan_truncated` is false.

`/audit`, `/threat/top-attackers` and `/threat/events` do not count every match. They send `limit` and `truncated` without `total`.

## Times and durations

Every time is an RFC 3339 instant in UTC with sub-second precision, such as `2026-09-22T10:04:05.123456Z`. The event stream follows the same rule. A time that is not set is left out, never sent as `0001-01-01T00:00:00Z`.

The API does not send times formatted for reading, such as "5m ago", "1h2m" or a clock time without a date. Clients format instants in their own time zone and count down to an `expires_at` themselves.

Durations are numbers of seconds in keys that end in `_seconds`, such as `uptime_seconds`, `elapsed_seconds`, `duration_seconds`, `oldest_age_seconds` and `update_interval_seconds`. Temporary whitelist responses use `duration_seconds`, rollback status uses `remaining_seconds`, and incident timelines use `window_seconds`. Request parameters such as `hours` and editable configuration values keep their documented units.

Two values keep a text form:

- `started_at_token` is an opaque token for restart polling.
- The `temporary` reason on `/api/v1/firewall/check` keeps its "(expires in ...)" text for existing callers. `expires_at` carries the instant.

## Severity

A severity is its label: `CRITICAL`, `HIGH` or `WARNING`. That covers `severity`, `severity_max`, `demoted_from` and the attack event `sev`. Clients derive colors and sort order from the label.

A `severity` filter takes the label in any case, or the older `0`, `1` or `2` level. The findings inside an email quarantine entry keep the scanning engine's own rating.

## Status & Data

```
GET  /api/v1/status              Full health snapshot: version, uptime, watchers, severity counts,
                                 store health, blocklist size, capabilities[], config_hash, binary_hash,
                                 automation rollout state, challenge pending count, rollback state.
                                 `started_at_token` changes after a daemon restart and is suitable
                                 for restart polling.
                                 `security_posture` is `healthy`, `warning`, or `critical` after
                                 combining daemon faults with active high/critical incidents.
                                 `incidents_open_by_severity` breaks open and contained incidents
                                 down by `critical`, `high`, and `warning`.
                                 `correlation_attribution` (present after the first active-set
                                 merge) lists per check the findings correlation could not
                                 attribute to an account: `current` for the active set now,
                                 `cumulative` since daemon start.
                                 `queues` reports named protection queues, including depth,
                                 capacity, running work, recent and cumulative drops, and lag.
                                 A degraded queue changes `status` and `security_posture`.
                                 `backends` names the backend each started live monitor
                                 selected (`af_alg`, `connection_tracker`, `exec_monitor`,
                                 `sensitive_files`, `placement`): `bpf`, `legacy` or `none`.
                                 `latest_scan` is the canonical last-scan timestamp; `last_scan_time`
                                 is a legacy alias kept for older clients and will be removed.
                                 `uptime_seconds` is the time since the daemon started.
GET  /api/v1/challenge/stats     Challenge-routing activity for the UI: `pending`, `escalated`
                                 (timeouts that became hard blocks), `passed` (challenges solved
                                 or bypassed, since restart), `routed_by_check` (per source
                                 check, since restart), and `recent` routes. Read scope.
GET  /api/v1/capabilities        Static feature list (e.g. `confd.dropins.v1`, `events.sse.v1`,
                                 `webhook.phpanel.v1`, `webui.prefs.v1`, `webui.undo.v1`,
                                 `mail.queue.composition.v1`, `mail.forwarders.delete.v1`,
                                 `detect.http_scanner_profile.v1`, `challenge.stats.v1`,
                                 `firewall.rollback.v1`, `firewall.dos_exempt.v1` on Linux builds).
                                 Use for orchestrator feature-detect. `csm capabilities` prints
                                 the same build tokens without a running daemon.
GET  /api/v1/components          Watcher/component matrix with attachment, event, and upstream freshness state.
GET  /api/v1/events              Server-Sent Events stream of findings as they dispatch.
                                 Read-scope token sufficient. One JSON event per `data:` line.
                                 Writes and flushes have a three-second deadline. A failed
                                 write or flush closes the stream and frees its subscriber slot.
GET  /api/v1/health              Daemon health (fanotify, watchers, engines)
GET  /api/v1/findings            Current active findings
GET  /api/v1/findings/enriched   Enriched findings with GeoIP, accounts, fix info, and a list version.
                                 ?limit=N orders by severity, then newest, even when all rows fit;
                                 returns at most N rows with limit and truncated, while total and
                                 the severity counts cover all.
                                 ?fields=version returns only {version, total}, for change polling.
                                 block_ip is set only for checks that report an attacker address,
                                 the same evidence auto-block acts on
GET  /api/v1/finding-detail      Finding detail with action history (?check=&message=)
GET  /api/v1/history             Paginated history (?limit=&offset=&from=&to=&severity=&search=&checks=&scope=).
                                 checks is a comma-separated list of check names to include.
                                 scope=email limits results to the /api/v1/email/checks list when checks is absent.
                                 total counts every match; truncated is true when matches exist past the page
GET  /api/v1/history/csv         CSV export of the newest 5,000 entries matching the /history filters
GET  /api/v1/stats               24h severity counts and auto-response summary, accounts with active high or critical findings
GET  /api/v1/stats/trend         30-day daily severity counts; each `date` is a calendar day in the server's time zone
GET  /api/v1/stats/timeline      Hourly severity counts for the last 24 hours; each bucket names its `start` instant
GET  /api/v1/quarantine          Quarantined files with metadata (incl. htaccess pre_clean backups)
GET  /api/v1/quarantine-preview  Preview quarantined file content (?id=)
GET  /api/v1/db-object-backups   db_object_backups bucket (MySQL trigger/event/procedure/function drops)
GET  /api/v1/db-object-backup-preview Preview captured CREATE SQL (?key=)
GET  /api/v1/blocked-ips         Blocked IPs with reason and expiry
GET  /api/v1/accounts            Accounts a server-wide scan covers
GET  /api/v1/account             Per-account findings, quarantine, history (?name=)
GET  /api/v1/audit               Newest 200 UI audit log entries; truncated marks older ones. Each entry names the credential that acted (actor) and whether it came as an API token or a browser login (via)
GET  /api/v1/export              Export state (suppressions, whitelist)
GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)
GET  /api/v1/performance         Performance metrics snapshot (admin scope)
POST /api/v1/perf/fix-error-log  Truncate a fixed-row error_log finding (admin scope, CSRF)
POST /api/v1/perf/fix-display-errors
                                  Disable display_errors for a fixed-row config finding (admin scope, CSRF)
POST /api/v1/perf/fix-wp-cron    Disable WP-Cron and install a system cron for a perf_wp_cron finding (admin scope, CSRF)
GET  /api/v1/hardening           Last stored hardening audit report (admin scope)
```

The sections below describe parts of these responses in more detail.

### Performance telemetry

`GET /api/v1/performance` returns `metrics` and `findings`. The `csm_performance` MCP tool returns the same response.

In `metrics`, `mysql_mem_mb`, `mysql_conns`, `redis_mem_mb`, `redis_maxmem_mb` and `redis_keys` are `null` when CSM could not read them. Zero is a measured zero. CSM reads the two Redis memory fields together and `redis_keys` separately. A `redis_maxmem_mb` of 0 means Redis has no memory limit.

### Accounts at risk

`accounts_at_risk` in `GET /api/v1/stats` lists accounts that have a current high or critical finding, whatever its age. Suppressed findings and internal records are left out.

- `findings` counts all of the account's current findings, warnings included.
- `severity` is the highest severity among them.
- The list holds at most 50 accounts, ordered by severity, then finding count, then name.
- An empty list is `[]`.

### Date ranges

These routes take `from` and `to`: `/api/v1/history`, `/api/v1/email/groups`, `/api/v1/email/overview`, `/api/v1/email/rejects`, `/api/v1/email/senders` and `/api/v1/email/relay-abuse`. Each bound is a calendar date (`YYYY-MM-DD`) or an RFC 3339 time.

| Bound | Meaning |
| --- | --- |
| A calendar date | A day in the server's time zone. A `to` date includes the whole day. |
| An RFC 3339 `to` | Exclusive. |
| Empty or whitespace only | Treated as absent. |
| A value in neither form | Rejected with 400. |
| `to` without `from`, on the `/api/v1/email/` endpoints | Covers the 24 hours before `to`. |

The Web UI sends RFC 3339 times, so a day follows the operator's time zone preference. Fractional seconds are preserved when filtering RFC 3339 bounds.

A calendar day starts at its first valid local time, including when midnight is skipped or repeated. A skipped calendar date covers an empty range.

### WordPress verification coverage

`wordpress_verification` contains `core` and `plugins` coverage when installation history is available. The same fields appear in `csm status --json`, and human status shows the counts.

Each entry reports `verified`, `modified`, `unverified`, `unknown`, `not_wordpress` and `last_attempt`.

- `unknown` means discovery found a directory, but no completed attempt is recorded.
- `modified` means core verification completed with integrity differences, including missing core files.
- `last_attempt` is the latest recorded attempt in that group.
- A verified plugin inventory can still contain vulnerable versions.

How CSM keeps the counts:

- Counts keep the last observed results across restarts and cached scan cycles.
- Overlapping scans keep the latest attempt and its consecutive failure history, in scan order.
- Discovery without an attempt does not replace verification evidence.
- An absent group means there is no retained installation history. It is not proof of coverage.
- An `error` field reports unreadable history in place of clean counts.

#### Failed verification attempts

The first failed attempt increases `unverified`. Repeated failures also produce an installation-specific Warning.

In a host scan, one cause can stop more installations than the per-cause limit. The warnings then collapse into a single finding that names the cause, the total and a sample. A host-wide fault therefore cannot spend the whole `alerts.max_per_hour` budget.

- The limit applies across accounts, for each kind of verification and cause.
- Account scans keep installation-specific warnings.
- A summary finding has no installation path. It names an account only when all affected installations share it.

These findings are separate from queue health. A command that completed with a refusal did not lose queue work. Queue loss accounting still covers interrupted or missing command work.

### Firewall confirmation

`automation.firewall_confirmation` describes a pending CLI `apply-confirmed` window. It is present also when the firewall is disabled or its engine failed to start. It is absent when no window is pending.

- `deadline` is the saved deadline in UTC, when it can be read.
- `error` says why the window cannot settle without `csm firewall confirm` or repair of the reported recovery problem.

This window is separate from the Web UI configuration rollback timer.

### Automatic response admission

Admission is the part of CSM that every automatic response is handed to. When it executes, it decides and applies the automatic IP blocks. Otherwise it only previews or forecasts. It keeps its records in a ledger. `status.admission.v1` advertises the `admission` object on status responses.

The same view appears under `admission` in `csm status --json` and as `admission` rows in `csm doctor`. The daemon reads it on a timer, so `checked_at` says how old it is.

Every automatic response that a blocking path selects is also handed to the ledger. The ledger refuses disabled responses. What it does with the rest depends on the mode:

| Mode | What the ledger does |
| --- | --- |
| `auto_response.dry_run` false, firewall on, outside observe mode | It applies the automatic IP blocks it is handed (`owner.executing`). The blocking paths leave those blocks to it. |
| Any other mode | It previews or forecasts eligible work and never applies it. The view is then not an enforcement record. |

The `admission` object has three parts: `ledger`, `ingress` and `owner`.

#### `ledger`: what the ledger has stored

| Part | Content |
| --- | --- |
| Admission time | The stored admission time. |
| Queue | The queue and its lifetime counters, including newly checkpointed ingress drops. |
| Outcomes | Hourly and daily outcomes. |
| Ingress generations | The ingress generations. |
| Hourly ceiling | The ceiling with its general and reserved lanes. |
| Storage, outbox, notices | Storage, the outbox and notice records. |
| `unresolved` | Unresolved outcomes: the `running` and `unknown` counts, and when the next unknown one can retire. |
| `effects` | The temporary set slots that the ledger's own automatic blocks hold, pending and verified, in `general` and `reserved`. `next` says when the first of them expires. |

Each section carries its own `error`, so one damaged record does not hide the rest. The `effects` section reports an `error` if its records, tally or schema disagree, including damage beyond the first expiry.

Lifetime counters include ingress drops only from the release that started counting them. Earlier drops are not added afterwards. On an upgraded host, retained outcome windows can therefore exceed the matching lifetime totals. A restart does not fill that gap.

Once the ledger has started live, a preview ends as a dry run does. The outcome windows and the candidate's state show it as `dry_run`, while the hourly comparison counts it as `observe`.

#### `ingress`: whether responses are admitted

`ingress` says whether automatic responses are admitted. While they are not, it says since when, and how many Critical arrivals were refused.

#### `owner`: the state of the ledger owner

The ledger owner is the daemon component that works through the ledger in turns.

| Field | Meaning |
| --- | --- |
| `executing` | Admission runs automatic blocks. |
| `settled` | The owner has completed a turn since the daemon started. |
| `error` | Why the ledger owner is not running. |
| `turn_error` | Why its last turn failed while it runs. |
| `retirement_error` | The last fault met while retiring uncertain blocks. It is kept until none is left faulted. |
| `retirement_held_by` | What keeps unknown outcomes from retiring while the ledger holds some. |
| `block_entries` | The entries whose automatic IP blocks admission may run on this host. |
| `tick_error` | Why the last clock reading, or the live start, failed. |
| `ceiling_source` | Where the ceiling came from: `default`, `configured` or `clamped`. |
| `import` | The legacy hourly count imported at the first start. |
| `damage_error` | Why responses naming a damaged record were discarded. |

The owner also reports whether the clock is degraded, and the last inventory read.

The first completed turn publishes `settled: true` and clears any earlier `turn_error`. Later failed turns and policy reloads do not reset `settled`. A daemon restart does.

`retirement_held_by` has two values:

- `engine` means the owner has no firewall engine, as with the firewall disabled or in observe mode.
- `policy` means the execution policy was refused.

In both cases the addresses stay held. The field is omitted otherwise, including while a configured firewall engine has not started. Policy refusals and recovery update this cause together with the execution hold, without waiting for the next ledger sample. Once the cause is gone, each block still retires only after it has expired and the firewall shows nothing of it.

`block_entries` is present while the owner has the firewall engine. It names the entries whose automatic IP blocks the live configuration lets admission run on this host. The possible entries are `scan`, `challenge_timeout`, `incident`, `incident_spray` and `central`. The comparison gate expects each named entry to be seen.

`import` counts at least until an hour after its `at`. When the count could not be read, at the first start or when execution began, `import` names why. A committed read error survives startup retries.

`preview_replacements`, `preview_replacements_last_hour`, `preview_rotations` and `preview_rotations_last_hour` remain in the API for compatibility. They read zero in this build and do not describe live replacements or rotations. Live blocks execute and dry-run blocks forecast, and neither increments these counters.

#### Fields of an owner on the firewall engine

An owner that runs on the firewall engine, with the firewall on and outside observe mode, adds these fields:

| Field | Meaning |
| --- | --- |
| `execution_held`, `execution_held_by` | Whether execution is held and by what: `policy` for a refused execution policy, `firewall` for the firewall engine. |
| `verdict` | The panel verdict callback. Its counters count this process and restart at zero. |
| `dry_run` | The dry-run forecast. See [`owner.dry_run`](#ownerdry_run-the-capacity-forecast). |
| `set` | The temporary block set outside a dry run. See [`owner.set`](#ownerset-the-temporary-block-set). |
| `set_error` | Present when the last turn could not read the set. |

`verdict.enabled` is true while the owner itself asks the panel: with the callback configured, during a dry-run forecast and while it runs automatic blocks itself (`executing`). This staging route does not advertise `admission.dry_run_verdict.v1`. That capability requires the complete admission-gates contract and activation evidence.

#### `owner.set`: the temporary block set

`owner.set` combines two things: the occupants that did not come from admission, as the last scheduling turn saw them, and the ledger's current holds. It divides the set as automatic admission divides it.

- `limit`, `unlimited`, `capacity`, `unclaimed`, `imported` and `drain_seconds` mean the same as in the forecast's `occupancy`, described in the next section.
- `general` and `reserved` give each partition's `size`, the legacy and admission blocks it holds (`used`) and its `free` slots.

A scheduling turn places block work, previewed or run, in a free slot of the partition its lane occupies. It can also take the slot of a lower-priority automatic block that it is allowed to replace, including a legacy automatic block that recorded its origin. Other block work waits as `set_full`. CSM checks it again when a held slot expires, or after a minute.

The object is absent in three cases:

- The last scheduling turn found no ready block work.
- The owner is in dry run.
- The set could not be read.

A maintenance-only turn keeps the last non-admission snapshot unless the owner enters dry run. Status still refreshes the ledger holds. Entering dry run, including through a reload, clears both `set` and `set_error` before the next clock reading or forecast is attempted.

Blocks that the firewall engine reports as written by admission are not counted a second time when the ledger already holds their slots. If the engine reports more of them than the ledger holds, the excess counts as `unclaimed` and makes `drain_seconds` unknown (-1), because the engine's drain estimate excludes admission rows. This view is not a fresh kernel inventory.

#### `owner.dry_run`: the capacity forecast

`owner.dry_run` is a capacity forecast, not a record of blocks. [Dry-run forecasts](auto-response.md#dry-run-forecasts) explains what a forecast is.

| Field | Meaning |
| --- | --- |
| `active` | True while the owner forecasts instead of blocking. |
| `session_id`, `since`, `reset_reason` | The forecast session. `reset_reason` is `startup`, `mode_change` or `model_error`. |
| `modelled_kinds`, `prediction_scope` | What the model covers: `block_ip` against the hourly ceiling and the temporary block capacity. |
| `occupancy` | The modelled temporary block set. Null while no snapshot is available. |
| `ceiling` | The forecast's own copy of the hourly ceiling. Null while no forecast runs. |
| `picks`, `last_hour` | Counts of the session's predictions. |
| `examples_lost`, `summaries_lost`, `record_errors` | This process's losses and failed writes. |
| `examples_stale` | True while a purge of earlier sessions' examples is pending. |
| `comparison_incomplete` | True after any loss in this process. |
| `forecast_error`, `last_error_at` | Why forecasting last failed, and when. |

Absent values are null, never missing keys. The durable outcome windows in `ledger` keep counting dry-run endings across sessions and restarts.

##### The forecast session

A session starts at startup, on entry into dry run, or after its model failed. The three session fields are null while no session has started, including after a failed start. Leaving dry run keeps the last session's identity.

##### `occupancy`

| Key | Meaning |
| --- | --- |
| `actual` | The real temporary occupancy: addresses, plus two elements per timed subnet. |
| `shadow_only` | The forecast addresses that the real sets do not hold. |
| `replaced` | The listed legacy automatic blocks that the forecast replaced. |
| `predicted` | The sum of `actual` and `shadow_only`, minus `replaced`. |
| `limit` | The configured limit of the set. |
| `unlimited` | Whether the set is unlimited. |
| `limited` | Whether retained forecast state fills its modelling bound. |
| `capacity` | The finite capacity that automatic admission is modelled within: a positive limit, or 10000 for an unlimited set. |
| `unclaimed` | The real timed entries that automatic admission never evicts. |
| `imported` | The real, verified, stamped legacy automatic blocks. |
| `drain_seconds` | An estimate of how long the last unclaimed or imported entry has left at the snapshot. |
| `general`, `reserved` | The two partitions of the slots that the unclaimed entries leave. |
| `shares` | How the scopes share each partition. |

`unclaimed` counts operator blocks, blocks of unknown origin, two elements per timed subnet, and admission blocks that no ledger record holds. Entries counted in `unclaimed` are never replaced.

Until validation rejects negative limits, a negative limit uses the same fallback as zero and keeps its configured value in `limit`.

Imports follow these rules:

- `actual` and `imported` count at least the listed imports, matching the partition counts.
- A replaced import is subtracted only while it is listed, until its own expiry. That holds even if the forecast block that replaced it expires or is replaced first.
- Unlisted imports count again.
- A renewal with a new name is a new import.

`drain_seconds` reads as follows:

- Zero means no remaining known whole seconds.
- -1 means a kernel expiry is unavailable. Treat it as unknown, not as expired.
- A combined horizon is unknown if any contributing horizon is unknown.
- The drain is unknown while admission blocks have no ledger record.
- New blocks, renewals and subnet wall-clock changes can extend the estimate. It is not an automatic removal deadline.

##### Partitions and shares

`general` and `reserved` divide the slots that the unclaimed entries leave. A fifth, rounded up, is reserved for direct or corroborated work. Each partition reports three values:

- `size` is the number of slots in the partition.
- `used` counts the real and forecast automatic blocks it holds. After a period of live blocking, the slots that ledger records still hold are counted in the partition they belong to. CSM reads them again each turn.
- `free` counts its free slots, also bounded by the total remaining capacity.

Existing occupants keep their partition when limits change.

`shares` gives two values for `general` and for `reserved`:

- `scopes` counts the scopes that share the partition. A scope shares it when it holds a forecast block there that the real sets do not hold, or when a pick from the last turn waits in it.
- `share` is the fewest slots each scope is due: the partition size divided among the scopes. The remainder goes one each to the scopes after the session's cursor.

Both are zero without a scope. All share keys stay present, including zeros. Without a snapshot, `occupancy` is null. It is never an object with missing share keys.

Real blocks are never forecast replacement victims, and their scopes do not share a partition. A forecast scope may therefore be due more than live admission would give it.

##### What the forecast does in a full set

| Case | What the forecast predicts |
| --- | --- |
| A strictly lower-priority automatic block holds a slot | The forecast block may replace it. |
| A forecast block of exactly the pick's class and severity holds a slot, and the pick is a new attack | The pick may rotate it out (`capacity_rotate`). |
| A pick waits while such an equal block holds its partition | `equal_tier_wait`, not `set_full`. |
| The set is overfull | Nothing is admitted. |

A strictly lower-priority automatic block is one of two things: a forecast block of a lower class or severity, or a listed legacy automatic block that recorded its origin. The forecast counts such a legacy block as gone while it is still listed, until the import's own expiry.

Rotation has further conditions:

- The block to rotate out must be in the partition of the pick's own lane.
- That block's 30-minute hold must have passed, on both the admission clock and the session's elapsed time.
- The set's scopes share each partition. A pick at or over its share rotates only its own scope's blocks. A pick below its share rotates only blocks of the scope that borrows most. A pick without a share waits.
- A rotated or replaced forecast block's address cannot rotate again until that block would have expired.

Real coverage replaces forecast occupancy:

- A manual timed block reduces available capacity.
- An automatic block counts in general until ledger partitions are wired.
- Permanent coverage takes no temporary slot.

##### `ceiling`, `picks` and losses

`ceiling` holds `limit`, `general_used`, `reserved_used`, `general_budget` and `reserved_budget`.

`picks` counts the session's predictions by name. `last_hour` counts them over the last sixty one-minute buckets of process monotonic time. That is an approximation, and a wall-clock change cannot age it. Every prediction name is present, and both are zero while no forecast runs.

A restart alone does not set `comparison_incomplete`, because each run's hourly summaries carry its `epoch`.

`forecast_error` is one of `engine_unavailable`, `clock_degraded`, `ledger_unavailable`, `snapshot_mismatch`, `session_id_unavailable`, `invalid_policy` or `model_error`. It stays until a turn succeeds. `last_error_at` keeps its time until the next session starts.

#### The hourly ceiling

The hourly ceiling follows `auto_response.max_blocks_per_hour`, capped at 20000.

| Configured value | Ledger ceiling | Shared scan-driven block budget |
| --- | --- | --- |
| Omitted or zero | 1000 | 50 |
| An explicit value | That value | That value |

`csm doctor` warns when an explicit value puts the ceiling below 1000. After you edit the configuration, run `systemctl reload csm`. Settings saved in the Web UI apply at the next ledger tick. See [automatic response](auto-response.md) for the scope of the current budget.

#### Admission rows in `csm doctor`

The rows depend on whether admission executes:

| Mode | What the rows say |
| --- | --- |
| Admission previews or forecasts | Existing blocking paths still decide every block. The rows say existing blocking is unaffected. `admission execution` warns while execution is held. |
| The owner executes (`owner.executing` is set) | The rows say admission decides automatic blocks. A row fails for every outage that stops automatic blocks, held execution included. |

Rows warn in these cases:

- The ledger owner is not running.
- Its clock reading is refused.
- An owner turn fails (`admission turns`).
- Retiring an uncertain block fails (`admission retirement`).
- The ledger is damaged.
- Admission has stopped.
- A Critical finding would not have received its response in the last hour.

Partial containment and protected or allowlisted addresses keep their individual notices and do not count toward this gap. Doctor can still show a gap recorded before an upgrade until its one-hour window ends.

The rows also show:

- a degraded clock
- a clamped ceiling
- a ceiling of 1, where only the reserved lane runs
- a legacy hourly count that could not be read
- a failed inventory read
- automatic blocks with an unproven outcome, which hold their addresses until they expire and the firewall shows nothing of them

Once `owner.executing` is set, a row fails on any of these:

- held execution
- a stopped owner
- a refused clock reading
- a failing turn
- a damaged ledger
- stopped admission
- discarded responses
- a Critical gap in the last hour
- a ledger the firewall could not read at startup

Two exceptions keep a failure down to a warning, and the row says so:

- Until `owner.settled` is set, and for at most two minutes after the daemon starts, those rows warn. The check that follows an upgrade runs before the first turn, and its failure would roll the upgrade back.
- A Critical gap recorded before the daemon started only warns. A flood of the hourly ceiling could otherwise fail every check for an hour after a restart.

The `admission execution` fix names the configuration for a refused policy, and the firewall otherwise.

##### Dry-run rows

An owner that forecasts adds three rows: `admission dry run`, `admission dry-run capacity` and `admission dry-run examples`. They show the forecast's session, real against predicted capacity, and lost examples.

The capacity row also shows:

- the automatic slots of each partition
- how long the entries that automatic admission never evicts take to drain
- the legacy automatic blocks the forecast counts as replaced
- the forecast blocks of the last hour that would have replaced a lower-priority automatic block
- how many scopes share each partition

A replacement is an admission, not a wait. A dry run alone is not a failure. A row warns on any of these:

- a held forecast
- model limits
- waits the model predicts, `equal_tier_wait` among them
- forecast blocks of the last hour that would have rotated out an equal-priority block
- a set that the never-evicted entries fill
- no free automatic slot
- an unknown drain time
- lost or stale examples

Recent rotation and wait warnings remain visible when the forecast has no current capacity snapshot. Current occupancy and scope shares are then unavailable. These warnings clear when they leave the last-hour window or the forecast session ends.

Outside a dry run, the `admission set` row shows the slot counts that the last turn used as its budget for block work. It warns about unavailable capacity or an unreadable set.

#### Delivery of admission records and notices

`admission.audit` and `admission.notices` in `queues` report two deliveries: admission records to the [action log](action-log.md), and admission notices.

`admission.owner.audit_error` names the last failed audit delivery. That includes an applied-block consumer's state read or threat-store write. The batch stays pending, and later rows can wait behind it. `queues["admission.audit"]` reports no-progress stalls. Successful delivery clears the error.

Keep the database and the pending rows. Repair the reported storage failure before you retry.

#### Alerts and notices

A ledger that cannot start, or admission that stops, raises one `auto_response_withheld` alert. It goes through the same path as protection queue alerts. It is a Warning while admission previews or forecasts, and Critical while it executes. The alert follows the notification channel settings but bypasses `alerts.max_per_hour`.

Ledger notices cover withheld responses, exhausted capacity, partial containment of an outbound destination, and their summaries. Where they go depends on the mode:

| Raised while the owner | What happens |
| --- | --- |
| Previews or forecasts | The notice describes what the ledger would have done. CSM records it in findings history as a Warning that starts with "Admission preview:" and sends it to no alert channel. |
| Executes | The notice goes to the alert channels with its kind's severity and no prefix. |

The ledger paces notices per notice key and summary. A preview is acknowledged only after its history write succeeds.

Delivery errors leave notices pending for retry. The next two cycles retry at once. After that each attempt waits twice as long as the one before, up to an hour. Ledger notices and the stopped-admission alert retry independently, so a failing path does not defer the other. A successful delivery resets only its own path's wait.

### Protection queue health

`status.queue_health.v1` advertises the `queues` map on status responses. The same measurements appear under `snapshot.queues` in `csm status --json` and as named checks in `csm doctor`.

Each entry of the map is called a row here. A row measures one queue, pool or stage of work inside the daemon. Start with the general rules below, then look up the row you need under [Rows by area](#rows-by-area).

#### What a row reports

A row reports waiting work, capacity, running work, cumulative losses, losses during the last minute, the age of the oldest waiting item and the processing time of the oldest running item. Running work is also called work in flight.

Some rows add fields:

| Field | Meaning |
| --- | --- |
| `depth_unit` | What the depth counts when it is not queue items, such as `bytes` or `installations`. |
| `capacity_unavailable` | The queue has no fixed capacity, or its capacity is not known. |
| `depth_unavailable` | The depth could not be measured. Zero fields then do not claim an empty queue. |
| `dropped_lower_bound` | The loss total is a lower bound. Doctor prints `dropped>=...` for it. |
| `lag_basis` | What the reported age measures. |
| `advisory` | The work is best effort. See [Advisory rows](#advisory-rows). |

`lag_basis` takes these values. Doctor names each age by what it measures:

| `lag_basis` | What the age measures | Doctor label |
| --- | --- | --- |
| `consumer_progress` | Time without consumption while unread work remains. It is not the age of an event. | `consumer_stall` |
| `operation_progress` | Time without progress of the current operation. A batch that keeps advancing does not degrade only because its total duration exceeds a minute. | `operation_stall` |
| `deferred_checkpoint` | The age of work parked on purpose, for example until a restart or the next flush. Age alone does not degrade the row. | `deferred_age` |
| `observed_age` | Age since this process first saw the record. | `observed_lag` |
| `unavailable` | No age exists. The row does not report a waiting time of zero. | `lag=unavailable` |

#### When a row is degraded

A queue becomes degraded after three losses in a minute, thirty seconds continuously full, or a minute waiting or processing. These are operational alert budgets, not measured throughput guarantees. A row with a different budget says so in its own section. CSM computes health directly from the counters, independently of finding delivery.

Each degraded row names its condition:

| Condition | Meaning |
| --- | --- |
| `backlog_lag` | The oldest waiting item is past its budget. |
| `processing_lag` | The oldest running item is past its budget. |
| `queue_full` | Capacity was held continuously. |
| `dropped_work` | Work was lost recently. |
| `consumer_stalled` | A sampled queue's consumer stopped advancing. |
| `reader_stopped` | A kernel descriptor was released. |
| `measurement_unavailable` | A reading stayed unavailable. |
| `persistence_uncertain` | The outcome of a write is unknown. |

The owner-specific conditions `retry_failed`, `source_io`, `spool_io`, `state_io`, `delivery_failed`, `delivery_uncertain` and `consumer_stopped` are described with their rows.

#### Degradation and recovery events

The daemon records and dispatches `protection_queue_degraded` at most once per queue every five minutes while pressure remains. It then sends one `protection_queue_recovered` event.

- The five-minute bound spans recoveries. A queue that clears and degrades again inside the window stays degraded in status without a second event.
- No recovery event follows a degradation that the bound suppressed.
- These are CSM health events. They do not feed account-compromise correlation or automatic response.
- Recovery preserves cumulative loss evidence. Restarting a spool watcher also preserves it.
- Restarting the daemon resets the counters.

#### Advisory rows

Some rows carry `advisory`. Their work is best effort. Examples are a client that stops reading its event stream, an unreachable panel asked for an optional annotation, and expired process context reads. All of these lose detail around findings that are still detected, stored and delivered.

An advisory row reports its own degradation with the same evidence. It differs from other rows in three ways:

- It leaves the host status and the security posture unchanged.
- It warns in `csm doctor` instead of failing.
- It raises no notification.

#### What to do when a queue degrades

1. Inspect worker errors, and CPU, memory and I/O pressure.
2. Reduce competing bulk work.
3. Confirm that the queue drains and recent losses stop.

This surface currently covers:

- finding delivery
- file and spool kernel readers and scanners
- recovery scans
- staged package verification
- dropper processing
- BPF queues
- process context enrichment and deadline reads
- mail-log delivery
- forwarder and PHP relay notification queues
- PHP relay index persistence

Other bounded queues remain in the roadmap.

#### Rules that hold for every row

- Reading status never runs the work a row measures and never waits for it. A health snapshot reads counters and metadata in memory. It takes no scan, state, database, cache, worker or collector lock. It reads no file, calls no journal, performs no DNS, country or filesystem lookup, and waits for no firewall or delivery callback. It runs no password verification and starts no workers.
- Queue health only measures. It adds no retry, scheduler or replay. It changes no quota, expiry, overflow, retention, flush, persistence or shutdown policy, and no finding, verdict or returned error.
- The common thresholds apply to every row unless its section gives another budget. Confirmed losses stay in the lifetime totals after recovery.

#### Rows by area

| Area | Rows |
| --- | --- |
| [Findings and file monitoring](#findings-and-file-monitoring) | `findings.ingest`, `fanotify.*`, `spool.*` |
| [BPF monitors and process context](#bpf-monitors-and-process-context) | `bpf.*`, `placement.dir_walk`, `processctx.*`, `php_shield.eval_sites` |
| [Mail](#mail) | `mail.*`, `smtp_rdns.resolves`, `email_password.*`, `email_av.scans`, `forwarder.*`, `phprelay.*` |
| [Checks and scans](#checks-and-scans) | `checks.*`, `scans.*`, `php_taint.requests`, `yara.requests` |
| [Automatic blocking and threat data](#automatic-blocking-and-threat-data) | `auto_block.*`, `attackdb.*`, `central.actions`, `bot_verification.requests` |
| [Stored findings and incidents](#stored-findings-and-incidents) | `state.*`, `incident.persist.*` |
| [Notifications and delivery](#notifications-and-delivery) | `block_digest.*`, `abuse_reporting.*`, `phpanel.spool`, `actionlog.writes`, `events.deliveries` |

`admission.audit` and `admission.notices` are described under [Delivery of admission records and notices](#delivery-of-admission-records-and-notices).

#### Findings and file monitoring

##### `findings.ingest`, `fanotify.analyzer` and `spool.scanner`

These rows, and the staged-package and dropper rows below, report the standard values.

- Waiting work includes producers blocked on admission to the queue.
- Ingest work stays running while the dispatcher holds or processes its batch, including at startup.
- Ages pause while the startup hold is in place and resume from its release. A long baseline scan is therefore not reported as a stall. Work lost during the hold still counts.
- Work that was deferred on purpose keeps its scheduled time when the startup hold is released.
- Loss totals include the undelivered tail of a batch canceled during shutdown.
- Scan warnings that are excluded from alerts on purpose do not count as lost work.
- Recovered file and spool scanner panics count as lost scan work. The workers go on to process later events, but repeated failures still degrade health.

##### `fanotify.reconcile`

`fanotify.reconcile` reports the recovery queue in directory tasks, with 1,024 waiting slots.

- Repeated drops in a directory keep its original queue age.
- A detached scan batch stays running while new drops queue separately. That includes new work for a directory that is already being scanned.
- The recovery window includes its cutoff. Work completed exactly at that boundary does not count as expired.

These count as failed recovery tasks: eviction, work older than the recovery scan window, unreadable directories or candidate files, interrupted batches and unfinished shutdown work. An incomplete task may still have scanned some files. Each directory task counts at most once.

Directories and files that are gone when recovery runs hold nothing left to scan, so they complete the task. This keeps bulk extraction and package restores out of the loss counters.

##### `fanotify.staged_packages`

- Staged package verification reserves capacity for its whole running batch.
- Its full-queue timer starts when admission fills the queue. It continues while the verifier keeps those slots, including between retries.
- Files that wait for another attempt keep their original waiting age. Retrying does not reset lag.
- Shutdown counts the files still awaiting verification after the analyzer workers have stopped.

##### `fanotify.dropper` and `fanotify.dropper_findings`

Dropper candidates and held findings each have 16,384 waiting slots.

- Lag for a candidate starts after the configured unlink TTL. Lag for a held finding starts after its 45-second grace period. Intentional waiting does not count as overdue work.
- Detached probes and emission batches stay visible as running work.
- Processing time starts when a batch leaves its waiting queue. It does not depend on the timestamp that decides which work is eligible.
- Retries and refreshed observations keep their earlier eligibility.
- Exhausted probes, capacity refusals and unfinished shutdown work count as losses.

##### `fanotify.kernel` and `spool.kernel`

These rows report pending notification records. Their lag follows consumer progress, as on the BPF `.kernel` rows.

- The kernel does not expose the group capacity. `capacity_unavailable: true` marks it as unknown, and doctor prints `depth=N/unknown records`.
- The current system queue limit may differ from the limit captured when the watcher was created.
- Loss totals are lower bounds. Each overflow record proves at least one loss. Shutdown adds the records known to be unread before the descriptor closes, and events can still arrive between that sample and the close.
- An unavailable pending-record measurement degrades the row once it lasts half a minute. The reading taken at close degrades at once and stays degraded.
- Records the kernel has already dropped are reported ahead of an unreadable depth.
- Closing a descriptor leaves known zero occupancy.

##### `fanotify.reader` and `spool.reader`

These rows track a batch after a kernel read, until all its records have been dispatched or filtered.

- A stalled batch stays visible even when the kernel queue is empty.
- Reader losses count batches interrupted by a consumer failure. They are separate from kernel-record losses.
- When a spool watcher is replaced, the row keeps its loss and running-batch evidence. The new descriptor starts its own occupancy and progress measurements.

The required kernel suite verifies pending records, stalls, drain recovery and unread shutdown loss with real fanotify events.

#### BPF monitors and process context

##### `bpf.af_alg.output`, `bpf.connection.output`, `bpf.execution.output` and `bpf.sensitive_files.output`

When their BPF backends are active, these rows report the 256-slot userspace delivery queues.

- Losses include decoding failures, admission refusals, consumer panics and buffered output left after the reader stops.
- A received event stays running until evaluation and delivery to the finding queue finish. That includes events filtered on purpose during evaluation.
- Kernel ring occupancy and reservation failures are separate from these userspace measurements.

##### The `.kernel` row of each BPF backend

Each active BPF backend also exposes a `.kernel` row. `depth_unit: bytes` labels ring occupancy and capacity.

`lag_basis: consumer_progress` means that `lag_seconds` measures time without observed consumption while data remains. It starts at the first sample that sees pending data. One minute without progress degrades the row.

Recently observed reservation failures use the same loss threshold as userspace queues. Kernel loss counters are separate from decode failures and userspace admission loss.

After a reader unmaps its ring:

- `depth_unavailable: true` and `lag_basis: unavailable` keep zero fields from claiming an empty live ring.
- The last counter sample adds the submitted records that the reader never consumed.
- `dropped_lower_bound: true` marks this final shutdown total, because kernel detachment can leave callbacks finishing after the sample.

A counter lookup failure or an incoherent occupancy reading marks the measurement unavailable:

- The row degrades as `measurement_unavailable` once that lasts half a minute. One artifact of reading a live ring therefore raises nothing.
- A failed final sample degrades at once and stays degraded.
- A stopped reader is reported in place of the measurement artifacts it causes.
- Invalid occupancy cannot inherit fullness or consumer stall alarms from an earlier sample. Independently counted losses stay visible.

The required kernel suite fills the shipped connection program's ring with real non-root connect calls, and checks reservation loss and retained output.

##### Placement rows

Three rows report whichever [placement backend](detection-realtime.md#files-moved-or-linked-into-a-site) runs:

| Row | What it reports |
| --- | --- |
| `bpf.placement.output` | Placements waiting for a worker. |
| `bpf.placement.kernel` | Placements the kernel lost. |
| `bpf.placement.unresolved` | Placements whose path could not be resolved. |

A full output queue counts the placements it refuses as drops and hands them to overflow recovery. Recovery rescans the directory a file landed in and walks a moved-in directory.

The `legacy` backend adds `bpf.placement.create_settle`, for new files waiting for their own close-write. When this queue fills, its oldest entry is sent for early analysis and counted as a drop from the settle queue. Pending entries discarded at shutdown also count as drops.

`placement.dir_walk` reports directories that were moved into a watched tree and wait for their walk, counted in directories. Evicted directories and walks cut short count as lost and raise `placed_dir_incomplete_realtime`.

##### `bpf.execution.docroot`

`bpf.execution.docroot` reports up to 1,024 non-root process starts that wait for a check of a program in a document root. One worker resolves the running image, then reads and scans it. All non-root starts enter this queue, because a launch path outside a document root can be an alias into one.

These count as lost: starts refused by a full queue, starts left waiting at shutdown, and findings suppressed during shutdown. The scheduled deep scan still reads programs in its scope, and the periodic process check judges running programs.

##### `bpf.connection.verdict`

`bpf.connection.verdict` reports the advisory annotation pool: 256 waiting slots and up to four running callbacks.

- Repeated findings for a pending destination, reason and severity share one request and keep its original age.
- Capacity refusal, callback failure and abandoned shutdown work count as lost annotations, separately from lost findings.
- A callback error releases the pending key, so a later finding can retry. A successful retry preserves earlier loss totals.
- Shutdown closes admission, waits for running callbacks and counts the queued requests left behind.
- Cached answers stay available without new work.
- Findings continue immediately when an annotation is unavailable.

##### `processctx.enrichment`

`processctx.enrichment` reports 1,024 waiting requests and up to two running process-context workers. The row appears only after a BPF consumer initializes the shared pool.

- Overflow replaces the oldest queued request and preserves the waiting age of the remaining requests.
- Running time includes the process read, the latency observer, account resolution and the cache write.
- Read errors and interrupted processing count as lost enrichment.
- A process that has exited, or whose identity is stale or could not be verified, is filtered out. That counts as completed work, not as a loss.
- The queue dropped metric counts refused, evicted and abandoned requests. Queue health also includes failures after a worker receives the request.
- At shutdown the daemon stops the pool after the BPF producers have joined. It lets running reads finish and counts the buffered requests it discards. Final loss evidence stays available.

This row measures enrichment requests, not each deadline-based file read inside a request.

##### `processctx.proc_reads`

`processctx.proc_reads` reports the 64 shared slots for deadline-limited process file and symlink reads, including process-start captures on the BPF path. Waiting and running reads share this capacity.

- A slot stays occupied until both the underlying read and its caller have finished. An undelivered result still occupies its slot.
- A timeout counts the lost result immediately. A blocked syscall stays visible as running work until it returns.
- A timeout and a later read failure count as one loss.
- Refusals at capacity and read failures count as losses. Missing process files are expected churn.
- Synchronous reads without a deadline use no slots. The initial process-directory check and the cached boot-time read are synchronous, so this row does not measure them.

##### `php_shield.eval_sites`

`php_shield.eval_sites` is advisory grading work. It reports running ownership walks and completed results still held for callers.

- A timeout or a refused lookup counts as a lost proof. The finding stays High.
- A completed walk releases its single admission slot before it publishes, so later events do not wait for that caller.
- Concurrent callers can hold completed results, which makes the aggregate capacity unavailable.

#### Mail

##### `mail.delivery`

`mail.delivery` reports the 64-slot delivery queue of the selected mail-log reader. Its running time includes parsing and the delivery of resulting findings.

Losses include:

- oversized complete file records
- unreadable journal entries
- canceled admission
- consumer failure
- buffered records abandoned on shutdown

Counters survive reader replacement and changes between file and journal sources. They count records already read, including complete records abandoned in file read-ahead. They do not count unread source history, or partial file records that have not reached a newline.

##### `mail.file_source`

`mail.file_source` reports sampled untransferred bytes after the first file attachment, with `depth_unit: bytes` and `capacity_unavailable: true`. The bytes include disk backlog, buffered read-ahead and raw partial-line bytes, even when the reader keeps only a bounded prefix of an oversized line.

Transfer to `mail.delivery` removes the source bytes before output admission can block. The byte and record measurements are separate stages and must not be added.

How the row measures lag:

- A sampler that belongs to the reader checks the current descriptor every two seconds, so appends stay visible while delivery is blocked.
- `lag_basis: consumer_progress` measures time without consumption while unread work remains. Sampling or new arrivals do not reset this clock.
- A partial line at EOF waits for more input and does not report a stalled consumer.
- Reader and sampler operations also report `processing_lag` after one minute without progress, including blocked reads, metadata calls and cleanup.

How the row reports failures:

- File I/O failures report `source_io`.
- A successful read cannot clear a failed cursor check. Each operation must recover.
- Failed metadata sampling makes depth unavailable until a successful sample.
- A working file or journal replacement clears the retired source's current error and keeps that history.
- When the source path disappears, the watcher's grace period still applies.

How the row handles rotation and loss:

- Each open of the log file, and each rewind after a truncation, starts a new generation. Rotation and observed truncation retire the old generation. A late sample of the old generation cannot overwrite the reading of its replacement.
- The initial attachment starts at EOF. Replacements start at the beginning.
- Copytruncate detection has a limit. Truncation followed by growth past the old descriptor offset between checks may be indistinguishable from an append.
- Complete records already held in read-ahead count once in delivery loss when discarded.
- Unread disk data and unterminated fragments have no measured record count. Generation changes, source failures and shutdown preserve `dropped_lower_bound` in the source row.

##### `mail.journal_source`

`mail.journal_source` reports the journal reader after its first successful attachment.

The cursor exposes no exact unread-record count and no queue capacity. `depth_unavailable` and `capacity_unavailable` are therefore always set. `lag_basis: unavailable` marks the missing backlog age, so the row does not report a waiting time of zero. The row measures the current operation instead.

- An entry that the reader has selected stays in flight until `mail.delivery` takes it.
- Known unreadable or abandoned selected entries count once in `mail.delivery`. The two stages must not be added together.
- Journal progress follows cursor advancement, entry reads, bounded idle waits, output admission and close.
- One minute without operation progress reports `processing_lag`, including a stuck cursor with no known selected entry.
- Cursor, entry, wait and close failures report `source_io`. Known abnormal exits stay visible through actual cleanup.
- An unknown cursor outcome or an unread shutdown sets `dropped_lower_bound` without inventing a record count.
- Successful reads restore current health. Historical uncertainty survives reader replacement.
- Successful attachment of a file source clears the retired journal's current error. Failed attachment leaves it visible.

Health does not change the journal's tail positioning, retry or delivery policy.

##### `smtp_rdns.resolves`

`smtp_rdns.resolves` reports the 64 reverse-DNS lookup slots used by direct SMTP egress detection. A slot stays occupied until its resolver and its caller finish.

- The one-second caller deadline also bounds healthy processing age. A timeout counts a lost result once, and a resolver that is still running stays visible.
- Capacity refusals and resolver failures count as losses.
- NXDOMAIN and successful empty responses are normal negative results.
- Cache hits perform no queued work. The bounded result cache is retained data, not waiting lookups.
- Synchronous lookups without a deadline use no slots and no queue row.

##### `email_password.mailboxes`

`email_password.mailboxes` reports waiting mailboxes and the five concurrent audits per scan. It keeps each audit through finding collection and cache writes. Concurrent scans have no fixed combined waiting capacity.

- A busy pool uses each audit's five-minute budget, or the scan deadline when that is shorter.
- An idle slot with no dispatch progress for one minute reports backlog lag.
- Admission and post-audit work have their own one-minute budgets.
- Cancellation removes waiting demand without adding losses. Actual audits stay visible until they return.
- Expired work, failed verification, cache write failures and abnormal exits count once per mailbox.
- Unsupported, malformed and over-budget hashes remain normal incomplete-audit outcomes.
- Loss counts stay after the batch drains.
- A deadline loss is recorded where an audit actually stops unfinished. A deadline that arrives after a successful cache write does not turn that mailbox into a loss.

##### `email_password.hashes` and `email_password.waiting`

`email_password.hashes` reports the three shared password-verification slots. Each slot stays occupied until its KDF and its caller have both finished, including after scan cancellation. The occupied pool also reports sustained full capacity.

`email_password.waiting` reports callers that wait for a slot. It sets `capacity_unavailable`, because concurrent scans have no fixed global waiting limit.

Both rows use the password audit's five-minute check budget for lag.

| Case | Counted as |
| --- | --- |
| A deadline while waiting | One admission loss. |
| A deadline after admission | One lost verification result. A later KDF error or abnormal exit cannot count it twice. |
| Explicit cancellation | Withdrawn demand, no loss. Actual verification errors still count. |
| A successful match or nonmatch | A normal result. |
| Rejected input, or a caller already canceled | No queued work starts. |

These rows contain no password, hash, mailbox or account data. The outer mailbox scan's discovery, network enrichment and persistence are separate work from these hash slots.

##### `email_av.scans`

`email_av.scans` reports antivirus engine work through execution and both result handoffs.

- Timed-out engines stay in flight until they return. Buffered results stay queued until the message scan consumes them.
- Execution lag uses the original per-part deadline. Result waiting and result processing each have a one-minute budget.
- Moving a result between buffers preserves its waiting age.
- Capacity is unavailable, because concurrent messages and engines that outlive timeouts have no fixed global limit.
- Timeouts, errors and abandoned work count once per engine scan. Later failures cannot count the same scan twice.
- Detections and unavailable engines are normal outcomes.
- Watcher restarts reuse the same engine health.

##### `forwarder.kernel` and `phprelay.kernel`

These rows report inotify backlog in bytes, because records include variable-length filenames. Capacity is unknown, and lag follows observed consumer progress.

- Each overflow marker proves at least one lost event.
- Closing with unread bytes adds one further known loss. The byte count does not reveal the number of discarded events.
- These totals use `dropped_lower_bound: true`.

##### `forwarder.reader` and `phprelay.reader`

These rows track the running read batch, including synchronous callbacks. Failed callbacks count as interrupted batches. When a PHP relay watcher is replaced, the row keeps earlier losses and starts fresh occupancy measurements.

##### `phprelay.index.persistence`

`phprelay.index.persistence` reports the 4,096 waiting slots of the message attribution writer. A write stays running from channel receipt through the pending batch and its database transaction.

- A batch contains at most 256 writes, also during an explicit flush.
- Each flush covers the backlog present when the writer accepts it. Concurrent arrivals cannot extend that flush indefinitely.
- Refused submissions, encoding failures and writes in a failed transaction count as losses.
- Failed writes are settled before their error finding is emitted, so a blocked reporter cannot hide the loss.
- A failed transaction counts each of its writes once and does not prevent later batches from committing.
- Shutdown closes admission and drains accepted writes. Later submissions count as refused work.
- The persistence dropped metric counts refused submissions. Queue health also includes writes that fail after admission.

#### Checks and scans

##### `checks.dispatch`

`checks.dispatch` reports pending checks and occupied runner wrappers across host and account scan batches. Capacity is unavailable, because concurrent batches have no fixed global waiting limit.

- Lag uses `consumer_progress` within each batch. Pending work degrades after one minute without progress when that batch has a free worker slot.
- A busy pool may keep working within each check's own deadline.
- Setup and result handling have a separate one-minute budget. They cannot borrow a heavy check's longer deadline.
- A wrapper panic or abnormal exit counts a loss. So does a parent deadline that arrives before a check can start.
- Explicit cancellation withdraws queued demand without loss.
- Execution failures belong to `checks.executions`. Dispatch tracks the surrounding scheduling operation.

##### `checks.executions`

`checks.executions` reports dispatched check functions across host and account scans.

- An execution stays present until both its function and its caller finish. That includes the time its result awaits consumption or its function outlives a timeout.
- Lag is evaluated against each call's original deadline, including a shorter parent deadline. A delayed function start does not reset it.
- Timeouts, panics and abandoned results count once per execution.
- Explicit cancellation withdraws demand without counting a loss, but a later function failure still counts.
- This aggregate sets `capacity_unavailable`. Separate scans have their own wrapper limits, and timed-out functions can outlive those slots.
- The row does not measure checks awaiting dispatch, scan-job persistence or later automatic actions.

##### `checks.plugin_inventory`

`checks.plugin_inventory` reports sites that wait for the five inventory workers per refresh. It keeps each site through command execution, result collection and cache storage or failed-result cleanup. Concurrent refreshes have no fixed combined capacity.

Budgets:

- Inventory uses a four-minute budget for its two bounded commands, or the check deadline when that is shorter.
- Admission and result handling each have one minute.
- A full pool stays healthy within those budgets.
- A free slot with no dispatch progress for one minute reports backlog lag.

| Case | Counted as |
| --- | --- |
| A command, decoding or storage failure | One loss per site, including when cleanup also fails. |
| A command that ran and returned output, on stdout or stderr, with an error, such as a tree wp-cli will not inventory | No loss. The command answered the check. |
| Missing command output | Lost work, including when the command exited with an error. |
| Cancellation | No loss. |
| Deadline withdrawal | The unfinished sites count as lost. |

Sites still in the buffer stay visible until the original workers stop taking them and the refresh has waited for those workers to finish. Actual commands stay in flight until they return. Shared-refresh waiters stay owned by `checks.executions` and do not create another set of site jobs.

##### `checks.wordpress_core`

`checks.wordpress_core` reports installations that wait for the five checksum workers per scan. It keeps each one through its command, integrity findings and verified-file caching. The unit is `installations`. Concurrent scans have no fixed combined capacity.

Budgets:

- Command lag uses the two-minute command budget, or a shorter parent deadline.
- Result and cache work use one minute without progress.
- A full finite batch stays healthy within those budgets.
- A free worker with no dispatch progress for one minute reports backlog lag.

| Case | Counted as |
| --- | --- |
| A returned operational failure, or abandoned work | One loss per installation. |
| A command killed by a signal | Failed work. Any partial integrity findings are kept. |
| Recognized integrity results from a completed command, including deliberately filtered output | No loss. |
| A command that ran and refused the tree, such as a directory that is not a WordPress installation or one whose configuration fails to load | No loss. |
| Missing command output | Lost work. |
| Cancellation | Unfinished demand is withdrawn without loss. |
| Deadline withdrawal | The unfinished installations count as lost. |

Commands that ignore cancellation stay in flight until they return. A deadline during caching cannot undo completed verification. An ordinary cache read failure does not turn a verified site into lost work. Discovery is separate check work.

##### `checks.file_index.waiting` and `checks.file_index.active`

`checks.file_index.waiting` reports live scans that wait for the shared baseline slot, with no fixed waiting capacity. Each wait keeps the file-index check budget, or its parent deadline when that is shorter. A free slot with no admission for one minute also reports backlog lag.

`checks.file_index.active` reports the single occupied slot.

- Walking and file analysis use the check's original execution deadline, normally 15 minutes, or the shorter parent deadline.
- Setup, persistence and cleanup each have a separate one-minute budget.
- A healthy long scan alone does not report a full queue.
- Actual filesystem work stays visible after cancellation until it returns.

These count once per live scan: deadline withdrawal, incomplete walks, unreadable PHP content, failed executable metadata or state reads and writes, and abnormal exits. These add no loss: executable entries that disappear during enumeration, explicit cancellation alone, and a successful late baseline commit.

Force-file-index audits do not use the shared baseline slot. Their work stays in the `checks.executions` row.

##### `checks.reputation_queries`

`checks.reputation_queries` publishes accepted lookups immediately after quota reservation, including while refused lookups receive fallback scoring. It follows the accepted work through HTTP, response cleanup, buffered results, supplemental scoring and cache or quota-backoff storage.

Each scan has at most five requests. Concurrent scans have no fixed combined capacity.

Budgets:

- HTTP uses the client's timeout.
- Cleanup, local result handling and persistence have separate one-minute budgets.
- Supplemental scoring uses the combined timeout of its enabled sources, or the shorter parent deadline.
- Buffered results follow their own active consumer's deadline. Another scan cannot hide their delay.

Losses and normal outcomes:

- Query failures, failed storage and abnormal exits count once per result.
- Quota responses and refusal before dispatch remain expected outcomes, with the quota health warning.
- Parent cancellation does not cancel the HTTP requests already sent. They stay visible until response handling and storage finish.
- Successful late results add no loss.
- Local feed matches, cache hits and serial pre-query discovery do not create query jobs.
- A failed cache write keeps the findings already produced.

##### `scans.jobs` and `scans.admission`

`scans.jobs` reports eight waiting full-scan jobs and one worker. Work stays visible through enumeration, scanning, remediation, persistence and cleanup.

- Its `consumer_progress` lag follows that worker and its own check batches. Healthy check deadlines let long scans proceed, while an overdue child cannot be hidden by another child's progress.
- Enumeration, result handling, individual file actions and database operations each have a one-minute progress budget.
- Thirty seconds at full waiting capacity also degrades health.
- Operator polling does not advance the worker's clock.

`scans.admission` separately reports callers that wait for admission and write their initial job record. It has a one-minute lag budget and unavailable capacity.

These rules cover both rows:

- Queue refusal, failed job operations and abandoned work count once per job.
- Configured finding-history truncation, explicit cancellation and successful shutdown draining do not count as loss.
- A terminated worker refuses new jobs.
- At startup, both queued and running records from the previous process become errors with reason `daemon_restarted`. Their lost requests count in job health.

##### `php_taint.requests`

`php_taint.requests` follows callers that wait for the worker lock, active requests, and pipe operations that outlive their callers. Capacity is unavailable, because callers have no fixed global waiting limit.

- Waiting, setup, reply handling and cleanup each have a one-minute lag budget.
- Active worker communication uses its configured timeout, or the shorter caller deadline. A buffered reply cannot borrow a long worker timeout.
- The request stays in flight through reply decoding and cleanup, and until any outstanding pipe operation finishes.
- Worker failures, timeouts, breaker refusals and abnormal exits count once per request. Known failures are recorded before cleanup.
- Recovered analyzer panics also count as failed work when they arrive in a valid worker reply.
- Oversize input, caller cancellation and refusal after an intentional stop add no losses.
- Shutdown keeps the supervisor's health evidence.

##### `yara.requests`

`yara.requests` follows scans that wait for the single YARA scan worker, the active scan, and the rules load of a freshly started worker. Capacity is unavailable, because callers have no fixed global waiting limit. Worker failures and breaker refusals count once per request.

#### Automatic blocking and threat data

##### `auto_block.waiting` and `auto_block.active`

`auto_block.waiting` reports scan, direct-block, firewall-flush and startup observation calls that wait for shared state. It has no fixed waiting capacity. `auto_block.active` reports the single state owner through firewall operations, state writes and cleanup.

- `lag_basis: operation_progress` times the current operation within a batch. Advancing batches do not degrade solely because their total duration exceeds a minute.
- One minute without progress degrades the active row and any waiting callers.
- A free state slot with no admission for one minute also reports lag.
- Returned direct-block or flush errors, failed state reads and writes, and abnormal exits count once per call. Protected-address refusals do not count.
- Known write failures are recorded before readback and diagnostic output. Known errors stay visible during later cleanup.

These rows count state-lock callers, independently of the persisted per-IP retry records.

##### `auto_block.pending` and `auto_block.candidates`

`auto_block.pending` reports durable retry records, including records loaded at startup when automatic blocking is disabled. Its capacity is the retry admission limit of 1,000 records. Records selected for a cycle stay in flight until their state-file outcome is known. Newly requeued records also stay in flight until persistence finishes.

`auto_block.candidates` reports distinct IPs admitted to the current cycle, with no fixed capacity. A candidate stays visible through its firewall callback, the bookkeeping that follows and the durable requeue. Candidate and record counts describe different stages and must not be added together.

How age is measured:

- Pending age uses the record's original queue timestamp, or first observation when that timestamp is absent.
- An eligible record receives a timestamp on its first requeue.
- Refreshing the reason, check or severity does not reset the original queue age.
- Normal quota waits stay healthy within the two-hour retry lifetime. Older waiting records report `backlog_lag`.
- Active record and candidate work use one minute without operation progress, so advancing batches can run longer without a false warning.

| Case | Counted as |
| --- | --- |
| An unsuccessful attempt whose retry survives | `retry_failed`, no loss. |
| A successful block, a dry run or an expected refusal | Completed, even if later bookkeeping fails. |
| Withdrawal under the current check policy or login-blocking setting | An expected refusal, no loss. |
| Confirmed removal of an expired, invalid or overflowed record | A pending loss. |
| A fresh candidate that neither completes nor survives on disk | A candidate loss. |
| Duplicate coalescence while a retry survives | No loss. |

Records without check identity are withdrawn under the current block policy. Persisted record identities include check and severity, so a refused record cannot acknowledge a different eligible retry after a failed write.

State read or write failures report `state_io`.

- Failed writes are read back, because an error after rename can leave the new state in place.
- If that read also fails, `depth_unavailable` and `dropped_lower_bound` expose the uncertainty.
- A later successful read restores measured depth. Lifetime loss totals remain lower bounds when earlier outcomes could not be established.
- New work with known outcomes still contributes exact losses.

##### `auto_block.cleanup`

`auto_block.cleanup` reports distinct IPs that await bookkeeping cleanup after a successful firewall flush. The row has no fixed capacity and is independent of the block-candidate stages.

- At startup it picks up cleanup retries that were saved earlier. After a flush it counts the entries flushed from the firewall engine before it reads the tracker.
- Cleanup also includes tracked blocks, with duplicate IPs counted once.
- Work stays in flight through store removal, threat-record cleanup and the final state-file outcome.

How age is measured:

- Cleanup waiting age starts at first observation, with `lag_basis: deferred_checkpoint`.
- Age alone does not degrade health. Cleanup retries run on the next explicit flush, without a background retry deadline.
- One minute without active operation progress reports `processing_lag`.

Retries and recovery:

- Failed cleanup whose retry survives reports `retry_failed`. An old tracker block can keep a retry even when saving its cleanup marker failed.
- Completed cleanup stays acknowledged across failed saves. A newly blocked IP creates fresh cleanup demand.
- Recovery first establishes the known block baseline. Cleanup of a later block has an exact outcome even when older cleanup history remains uncertain.

Cleanup state and snapshot failures report `state_io`.

- An unreadable tracker sets `depth_unavailable` and `dropped_lower_bound`. Speculative waiting records are not reported as measured depth.
- The last bounded batch keeps its identity for later read recovery. A subsequent unreadable flush replaces that history with its own batch.
- A readable state restores measured depth and counts confirmed unfinished work that is left without a retry source.
- An incomplete pre-flush engine snapshot marks lifetime losses as a lower bound without inventing a missing count.

##### `attackdb.events`

`attackdb.events` reports events that await persistence, including historical imports. The buffer has no fixed capacity.

- Waiting age starts at admission, independently of an event's timestamp.
- A detached batch stays in flight through writes, close and error logging. Newly arriving events stay in the waiting count.
- Processing age uses `lag_basis: operation_progress` and resets when a write returns. A progressing batch therefore does not appear stalled solely because of its total duration.
- Waiting age, or absent write progress, of one minute degrades health.
- Memory-only databases have no persistence backlog.

What counts as persisted and as lost:

- Completed JSONL records accepted by the file writer and successful database writes count as persisted. Buffered data alone does not.
- Confirmed unwritten events count as losses. That includes interrupted work left buffered or unencoded, and returned encoding failures. These losses are visible before cleanup.
- Close errors or abnormal I/O exits preserve uncertainty with `dropped_lower_bound`. They report `persistence_uncertain` for one minute, ahead of a backlog or a stalled write, as `attackdb.records` does.
- Queue health does not promise storage durability beyond the writer's result.

##### `attackdb.records`

`attackdb.records` reports distinct IP records that await a saved update or deletion. There is no fixed capacity.

What enters the queue:

- Repeated changes to one IP coalesce before the snapshot. A mutation during an active write stays separate pending work.
- A successful deletion can also satisfy a repeated deletion.
- Loaded records that need normalization and expired records that need removal enter the same queue.
- Retained scoring records are not counted as pending persistence.

How age is measured:

- Waiting age starts at the first pending change.
- The active snapshot stays in flight through writes, error logging and retry bookkeeping.
- Processing age uses `lag_basis: operation_progress`. It resets at each returned store write or delete, at the commit of their batch, or at the complete flat-file write result.
- A returned commit refreshes processing age even if every operation was refused.
- One minute without progress, or with waiting work, degrades health.

Failures and retries:

- The store commits one flush as one batch, so a failed commit retries every record and deletion in it.
- A refusal affects only that operation. A successful save cannot clear a failed deletion for the same address, or the reverse.
- Returned failures report `retry_failed` while the retry stays queued. The retry keeps its original age and is not counted as lost. Successful retries clear that condition.
- A failed shutdown flush keeps the retry in memory. The stopped background saver does not schedule another attempt, and a retry held in memory does not survive process exit.

Uncertain outcomes:

- An interrupted operation counts confirmed abandoned demand only when no pending update or deletion survives.
- Unreturned write outcomes report `persistence_uncertain` for one minute and keep `dropped_lower_bound` afterward. This includes a transaction interrupted before its callback starts, or after all its operations were refused.

##### `central.actions`

`central.actions` reports 1,024 waiting central-intelligence actions and one running action. Backlog stays visible while the signed feed refreshes. Processing time includes the action handler and its evidence delivery.

- Overflow, action failure and abandoned shutdown work count as losses.
- A protected-address refusal, or an absent firewall engine, completes the queue task without claiming that a block happened.
- Challenge tasks measure delivery to the challenge list. They do not measure its later file or firewall writes.
- Shutdown cancels feed refreshes, waits for an action that is already running and discards the remaining queue.
- Work handed in after shutdown is refused, and its loss is still counted.
- Logging does not reset loss totals.

##### `bot_verification.requests`

`bot_verification.requests` reports 256 waiting bot-identity requests and one running verification. Duplicate requests share their original waiting age. Running time includes DNS lookups and the cache write.

These count as losses: queue overflow, DNS timeouts or transient failures, failed cache or missing-PTR record writes, and abandoned shutdown requests. These remain expected outcomes: missing PTR records, unknown bot identities, and definitive positive or negative answers.

- A source with a recorded missing PTR is not queued again until its one-hour suppression lapses. Suppressed requests do not count as losses.
- The missing-PTR record still counts for a day after the lookup. Once its hour of suppression is over, the source is looked up in DNS again, but it does not get a new grace period as a pending verification.
- Queue health does not turn a resolver failure into a spoof finding.
- Shutdown cancels DNS, waits for any active cache write and discards waiting work. Late submissions are refused, pending keys are released and loss totals stay available.

#### Stored findings and incidents

##### `state.pending` and `state.pending_operations`

`state.pending` reports findings parked for the next startup, bounded to the newest 10,000 findings. The store observes existing parked work when it opens.

- Depth is the last confirmed file contents. In-flight findings include incoming appends and cleared batches still in replay.
- The bound applies to the stored batch, not to concurrent callers or an already detached replay.
- Overflow, and new findings that fail to reach storage, count as losses.
- Duplicate occurrences remain separate findings.

How age is measured:

- Waiting age starts at admission or startup observation, independently of the finding timestamp.
- Surviving findings keep their age through later appends. An evicted finding stops determining the age.
- Waiting uses `lag_basis: deferred_checkpoint`. A parked or full batch that awaits a restart does not itself report a stall.

`state.pending_operations` measures callers that wait for the state lock, and active persistence or replay. Its unit is operations, with no fixed bound. One minute waiting or without operation progress reports lag. Actual read, write and clear results advance progress, and replay stays active through dispatch.

Read, write and clear errors report `state_io`.

- Failed mutations are read back. A returned error after replacement does not imply the new findings were lost.
- Readback compares the recovered JSON payload, including internal subnet and spray-target data and its normal repair of invalid UTF-8. Repaired log text therefore does not invent uncertainty or hide overflow.
- Unreadable outcomes set `depth_unavailable` and `dropped_lower_bound`. A later read restores measured depth, while lifetime losses remain lower bounds.
- Known encoding failures and overflow are counted even when other outcomes are unknown.
- After a failed write, stored findings that cannot be told apart from those stored before keep the earlier age.
- An interrupted write or clear marks the disk state unknown.
- Interrupted replay keeps the measured disk depth but cannot claim an exact loss for a partially dispatched batch. The uncertainty reports `persistence_uncertain` for one minute.

What a parked finding stores:

- Parked findings add optional storage-only keys to the public finding fields. Subnet response and credential spray correlation thereby keep their inputs at restart.
- Subnets are in the public `cidrs` field and also keep their storage-only copy, so a daemon rolled back after a restart still replays them.
- Older parked records still replay, and older daemons ignore the added keys.
- Process-local delivery markers are cleared on read, so stored findings receive a fresh evaluation.

##### `incident.persist.waiting`, `incident.persist.active` and `incident.persist.deferred`

| Row | What it reports |
| --- | --- |
| `incident.persist.waiting` | Immutable incident snapshots that wait for the ordered writer, with no fixed waiting capacity. |
| `incident.persist.active` | The single occupied writer. |
| `incident.persist.deferred` | Coalesced bookkeeping that waits for a later mutation or an explicit flush, including shutdown. |

- A writer, or a free-slot admission, stalled for one minute reports lag.
- Failed writes and abnormal callback exits count once.
- Abandoned bulk snapshots count as waiting losses and release their ordering slots for later writes.
- A callback stays in flight until its cleanup and error logging finish.
- After a store failure, CSM keeps the transitions in memory and logs its warning.
- The oldest deferred age uses `lag_basis: deferred_checkpoint`. Age alone does not degrade health, because there is no periodic flush deadline.
- Full snapshots supersede earlier bookkeeping. Restoration and retention discard the affected markers.
- Memory-only correlators have no persistence work.

#### Notifications and delivery

##### `block_digest.records`

`block_digest.records` reports the actual buffer of watched-country block records. It is bounded to 5,000 records and drops the oldest on overflow. The buffer folds into the daily summary at each configured interval, before each summary send and at shutdown.

- Age starts when a record enters the buffer, independently of the block timestamp.
- Normal batching and a full buffer alone do not report a stall. Waiting becomes overdue one minute after the configured interval.
- A detached fold stays in flight. One minute without progress reports `processing_lag`. The row uses `lag_basis: operation_progress`.
- Records that arrive during a fold belong to the next one.
- Records merged per IP count as completed, because that merging is expected. An abandoned fold counts the records it discards as losses.
- Records kept after the collector stops report `consumer_stopped`.

The `block_digest` rows are always present, because every daemon runs the collector for the daily summary. Without `alerts.block_digest.enabled` the records buffer stays empty.

##### `block_digest.email` and `block_digest.webhook`

These rows count notifications for the configured destinations, with `capacity_unavailable`. Each eligible destination has one notification waiting before delivery starts. That covers live alerts and the daily summary, which is sent even when empty. [Summary and customer block webhooks](#summary-and-customer-block-webhooks) describes the summary and customer block payloads.

Which destinations take part:

- Default delivery follows the current alert settings at admission, at the attempt and at interrupted cleanup.
- Disabled destinations add no new waiting work or loss. Destinations that were enabled during an earlier send are still handled.
- Explicit destination selection applies only to live alerts. It keeps its error when that alert channel is disabled.
- Daily summaries use all enabled alert channels except phpanel.

Lag and losses:

- One minute waiting or active reports lag.
- A returned sink error counts one lost notification and stays in flight through error logging.
- A daily summary sink, or the summary rendering, that panics fails the same way. It is logged with the panic, so it cannot stop the daemon.
- If an operation exits without returning, its attempted delivery reports `delivery_uncertain` for one minute and keeps `dropped_lower_bound`. A remaining destination that was never attempted counts one confirmed loss.

Live delivery remains best effort. Daily summaries are retried:

- A daily summary saves its window before delivery and retries failed destinations. Successful destinations are saved separately.
- A failed destination retries after one minute, doubling up to one hour. It counts one lost notification for that summary, however often it is retried.
- Between attempts that destination keeps one waiting notification, so its row reports `backlog_lag` while the outage lasts. Switching that destination off releases it within a minute.
- When the next summary is due, a still unfinished one is dropped, logged once and counted once. The new one goes to every destination.
- A crash between remote acceptance and saving success can repeat a delivery.

##### `abuse_reporting.ingress`

`abuse_reporting.ingress` measures reports that await durable storage. Its capacity is 10,000, or the configured spool limit when that is smaller. Running time includes persistence to every configured target.

- Memory overflow, incomplete persistence and work abandoned by a worker failure count as losses. One source report counts once even when several targets fail.
- Outbound delivery can delay memory work, and that backlog stays visible.
- The queue stays open through the daemon's final finding flush. Reporter shutdown then closes admission and persists every accepted report before it closes the spool.
- A failed write does not discard unrelated waiting reports.
- Reports handed in after shutdown are refused.

This row measures the memory queue, not reports already kept on disk for retry. Normal shutdown does not count those durable reports as lost.

##### `abuse_reporting.spool`

`abuse_reporting.spool` measures durable reports per destination, with the configured spool capacity. Reports that are being sent stay in flight through the database acknowledgment.

| Case | Counted as |
| --- | --- |
| Failed admission, a discarded record, or a report the collector refuses as invalid | A loss. |
| A delivery retry, a failed acknowledgment or a normal shutdown | No loss. The report is kept. |
| An evicted or refused record | A loss only if no send was acknowledged during this process. |

An active send settles that count when it finishes. A failed retry cannot undo a prior acknowledgment. A failing destination pauses only its own reports for the rest of a pass.

How age is measured:

- `lag_basis: observed_age` means that waiting age starts when this process first sees the record. Existing records start at spool open, and retries keep that age.
- Doctor labels this as `observed_lag`, since time spent waiting before the restart is unknown.
- Waiting or running work degrades after two minutes, which allows for the normal one-minute delivery interval.
- The common full-queue and recent-loss thresholds also apply.

Two conditions belong to this row:

- `spool_io` names failed admission, read or acknowledgment operations.
- `delivery_failed` names a failed or panicking sender. It stays set while any destination failed in the last pass or is waiting for its retry deadline.

Throttling without progress stays visible here even between log warnings. These states clear when the affected operation recovers. Reopening with a smaller cap preserves existing records until the next admission applies the configured overflow policy.

##### `phpanel.spool`

`phpanel.spool` measures the durable panel webhook queue, capped at 100,000 records per state directory. In-flight work includes writes waiting to commit and deliveries awaiting database acknowledgment.

What acknowledges a finding:

- Only a 2xx response from the configured endpoint acknowledges a finding. Redirects are not followed.
- Every other failure is retried in order with backoff, except the refusals below.
- Retried findings keep their original waiting age. A failed attempt is not a lost finding while its record remains durable.

What counts as lost:

- An overflowed record counts as lost only when no send was acknowledged during this process. An active send settles that count when it finishes.
- Malformed findings, and findings the panel refuses with HTTP 400, 413 or 422, count once when removed from delivery. The next record is sent at once.
- The bounded diagnostic archive of those findings is retained history, not pending work.

A long run of refusals with nothing accepted between them looks like a panel that refuses every request. From then on refused findings stay queued and are retried as a delivery failure, until the panel accepts one. This hold survives config reloads and daemon restarts.

How age is measured:

- Waiting age uses the persisted enqueue timestamp after a restart.
- A stored record that the queue did not count when it opened is adopted when its delivery starts, with the same persisted enqueue timestamp. A retry therefore does not reset its age.
- Missing, damaged or future timestamps are timed from queue open or adoption.
- A minute of waiting or processing degrades the row.
- Delivery and database errors stay visible until the affected operation succeeds.

Disabling delivery preserves the durable backlog and the cumulative loss. Enabling it resumes the stored work. Stopped queue instances refuse late admissions.

##### `actionlog.writes`

`actionlog.writes` measures the 64 process-wide action-log write slots.

- A sink write that outlives the caller's 250ms wait budget stays in flight until the sink and any panic reporting finish.
- A batch of actions that queue behind one file lock is normal. Only a minute without the write returning degrades the row.
- A caller deadline after admission does not count as loss, since the sink may still record the action.
- Refused admission, sink errors and panics count as lost records, once per record.
- Changing or disabling the sink preserves outstanding work and cumulative loss.
- Normal writes still complete before the caller returns. When recording is saturated or stalled, a caller still waits at most its 250ms budget.

##### `events.deliveries`

`events.deliveries` aggregates live event-stream subscribers in one row, without client identities.

- Capacity sums their buffers: 64 findings per daemon stream.
- Depth counts waiting deliveries. In-flight work includes encoding, writing and flushing.
- One full subscriber can degrade this row even while others drain.
- The common one-minute lag, 30-second fullness and recent-loss thresholds apply.
- Overflow, encoding errors and failed streams count as losses. A failed stream also counts its abandoned buffered events.
- Normal request cancellation and server shutdown withdraw pending demand without adding losses.
- Cumulative loss survives subscriber removal, and an outstanding write stays visible until it returns.
- Closing the bus preserves buffered work for consumers still draining it.
- HTTP writes keep their three-second deadline. A successful delivery here means the write and flush returned, not that the remote application acknowledged it.

### Summary and customer block webhooks

The generic alert webhook gets two events of CSM's own: the [daily summary](configuration.md#daily-summary) and the [known-customer block alert](auto-response.md#known-customer-block-alert). A phpanel webhook gets neither.

Each event is one JSON object. `text` holds the email body, for chat tools, and `csm` holds the data.

#### The `daily_summary` event

```json
{
  "text": "[CSM] host.example.com - daily summary 2026-06-10\n...",
  "csm": {
    "event": "daily_summary",
    "host": "host.example.com",
    "version": "X.Y.Z",
    "summary": {
      "since": "2026-06-10T08:00:00Z",
      "due": "2026-06-11T08:00:00Z",
      "checks": {"wp_login_bruteforce": {"CRITICAL": 12}},
      "blocks": 3,
      "block_kinds": {"wp-bruteforce": 2, "netblock": 1},
      "muted": 4,
      "sources": [{"ip": "203.0.113.5", "count": 9, "country": "NL"}],
      "watched": {"total": 0, "by_country": {}, "by_category": {}}
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `csm.event` | `daily_summary`. |
| `csm.host`, `csm.version` | The host and the CSM version. |
| `summary.since` | The start of the window, in RFC 3339. |
| `summary.due` | The window's scheduled send time, in RFC 3339. |
| `summary.checks` | Summary findings counted per check, then per severity (`CRITICAL`, `HIGH`, `WARNING`). |
| `summary.blocks` | The number of applied blocks. |
| `summary.block_kinds` | Applied blocks counted by kind, such as `wp-bruteforce`, `mail-bruteforce`, `netblock`, `permanent` or `other`. |
| `summary.muted` | Summary findings of checks in `alerts.email.disabled_checks`. |
| `summary.sources` | The 10 addresses with the most summary findings: `ip`, `count`, and `country` when GeoIP knows it. |
| `summary.watched` | Watched-country blocks: `total`, `by_country` and `by_category`. It stays empty without `alerts.block_digest.enabled`. |
| `summary.customer_blocks` | The applied blocks that hit known customers, as customer block objects, at most 50. |
| `summary.customer_blocks_more` | The number of further blocks. |
| `summary.would_block` | Dry-run and observe-mode verdicts that would have blocked known customers, as customer block objects, at most 50. |
| `summary.would_block_more` | The number of further verdicts. |

`summary.customer_blocks` and `summary.customer_blocks_more` are left out when empty. So are `summary.would_block` and `summary.would_block_more`. The customer block object is described in the next section.

Each count map holds at most 512 keys. Later keys count under `other`.

#### The `customer_block` event

```json
{
  "text": "[CSM] host.example.com - automatic block hit a known customer: 203.0.113.5\n...",
  "csm": {
    "event": "customer_block",
    "host": "host.example.com",
    "version": "X.Y.Z",
    "customer_blocks": [{
      "target": "203.0.113.5",
      "reason": "SMTP brute force from 203.0.113.5",
      "check": "smtp_bruteforce",
      "customers": [{"ip": "203.0.113.5", "kind": "cpanel", "account": "alice", "at": "2026-06-10T08:15:00Z"}]
    }]
  }
}
```

`csm.event` is `customer_block`. `csm.host` and `csm.version` are as above. `csm.customer_blocks` lists the blocks of the alert. Each one is a customer block object:

| Field | Meaning |
| --- | --- |
| `target` | The blocked address or network. |
| `reason` | The block reason or, for a notice without one, its message. |
| `check` | The check that caused the block. Left out when unknown. |
| `customers` | The known customers the block covers, the most recent first. |
| `more` | The number of covered customers not listed. Left out when 0. |

Each `customers` entry is one known customer:

| Field | Meaning |
| --- | --- |
| `ip` | The customer's address. An IPv6 customer appears as its /64. |
| `kind` | `cpanel`, `webmail`, `smtp`, `imap`, `pop` or `ftp`. |
| `account` | The account the login named. Left out when the login named none. |
| `at` | The last successful login, in RFC 3339. |

The watched-country live alert, event `block_live`, keeps its own shape. There `csm.blocks` lists blocked addresses.

## GeoIP

```
GET  /api/v1/geoip               IP geolocation (?ip=&detail=1)
POST /api/v1/geoip/batch         Batch GeoIP lookup (body: {"ips":["192.0.2.1"]}, maximum 500)
```

## Threat Intelligence

```
GET  /api/v1/threat/stats        Attack stats, type breakdown, hourly trend
GET  /api/v1/threat/top-attackers Top attacking IPs with GeoIP (?limit=&spam_only=1)
GET  /api/v1/threat/ip           IP threat lookup (?ip=)
GET  /api/v1/threat/events       IP event history (?ip=&limit=)
GET  /api/v1/threat/whitelist    Whitelisted IPs
GET  /api/v1/threat/db-stats     Attack database statistics
POST /api/v1/threat/block-ip     Block IP for 24 hours
POST /api/v1/threat/block-ip-permanent Block IP with no expiry
POST /api/v1/threat/whitelist-ip       Permanent whitelist
POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist (with expiry)
POST /api/v1/threat/clear-ip           Clear IP from attack database
POST /api/v1/threat/unwhitelist-ip     Remove from whitelist
POST /api/v1/threat/bulk-action        Bulk block (24h or permanent) / whitelist across many IPs
```

### Spam evidence in threat responses

`/api/v1/threat/stats` includes three counts of records that hold only spam evidence:

| Field | Meaning |
| --- | --- |
| `mail_only_ips` | The attack database records that hold only spam evidence. |
| `mail_only_new_24h` | Those first seen in the last 24 hours. |
| `mail_evicted` | Those dropped to keep the [spam evidence budget](antispam.md#spam-evidence-budget) since the daemon started. |

In `/api/v1/threat/top-attackers`, `ip` is an IPv6 /64 in CIDR form, such as `2001:db8:1:2::/64`, for a record that holds the spam evidence of a network.

`/api/v1/threat/ip` takes an address only. Its `attack_record.spam_network` names the /64 when the spam evidence shown was recorded for the network. Equivalent IPv6 spellings use the same address record and return the canonical address. When both the address and its /64 network have spam evidence, the lookup shows whichever scores higher, and the network's on a tie.

### Blocking and bulk actions

`POST /api/v1/threat/block-ip`, the 24 hour block, returns `409 Conflict` when the address already has a permanent or longer firewall block. Unblock the address explicitly before you shorten its lifetime.

Bulk actions use `action: "block"`, `"block_permanent"`, or `"whitelist"`.

- Refused blocks are excluded from `count` and explained in `warnings`.
- Repeated canonical IPs count once.
- Permanence cannot be selected through an extra request field.

Bulk undo restores the original per-IP firewall deadlines. A later change to any target invalidates that undo action. Undo cannot restore dismissed evidence or replace the later decision.

## Firewall

```
GET  /api/v1/firewall/status         Config, blocked/allowed counts
GET  /api/v1/firewall/allowed        Whitelisted IPs
GET  /api/v1/firewall/subnets        Blocked subnets
GET  /api/v1/firewall/audit          Firewall audit log
GET  /api/v1/firewall/check          Check if IP is blocked (?ip=); admin or unban scope
POST /api/v1/block-ip                Block an IP
POST /api/v1/unblock-ip              Unblock an IP
POST /api/v1/unblock-bulk            Bulk unblock IPs
POST /api/v1/firewall/allow-ip       Allow an IP
POST /api/v1/firewall/remove-allow   Remove IP from allow list
POST /api/v1/firewall/deny-subnet    Block subnet
POST /api/v1/firewall/remove-subnet  Remove subnet block
POST /api/v1/firewall/flush          Clear all blocks
POST /api/v1/firewall/unban          Unblock IP + flush cphulk; admin or unban scope
POST /api/v1/firewall/cphulk-clear   Flush cphulk bans only
```

The audit log reports each `timestamp` as an RFC 3339 instant in UTC, and the block or allow lifetime as `duration_seconds`. Blocked addresses, subnets and allow rules carry `expires_at`, which is left out for a permanent entry.

## ModSecurity

```
GET  /api/v1/modsec/stats              WAF statistics (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/blocks             Blocked requests log, aggregated per IP, with resolved source country (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/events             WAF event details with resolved source country (read scope). Accepts ?window=1h|6h|24h, ?severity=warning|high|critical.
GET  /api/v1/modsec/rules              Loaded rules list
POST /api/v1/modsec/rules/apply        Apply the set of disabled rules and reload
GET  /api/v1/modsec/rules/escalation   Rule IDs excluded from firewall escalation, sorted
POST /api/v1/modsec/rules/escalation   Exclude one rule from escalation or turn it back on
```

`POST /api/v1/modsec/rules/escalation` takes `{"rule_id": 900112, "escalate": false}`. The rule ID must be a CSM rule (900000-900999). `escalate: false` adds the exclusion and `escalate: true` removes it. Other excluded rules are left as they are.

A failed rules reload reports `rolled_back: true` only when restoring the previous overrides succeeds. A rollback failure is reported in the response and in the audit log. Inspect the overrides before you try another reload.

## Rules & Suppressions

```
GET  /api/v1/rules/status        YAML/YARA rule counts, version
GET  /api/v1/rules/list          Rule files
GET    /api/v1/suppressions      Suppression rules
POST   /api/v1/rules/reload      Reload signature rules from disk
POST   /api/v1/suppressions      Add a suppression rule
DELETE /api/v1/suppressions      Delete a suppression rule by id
```

`POST /api/v1/suppressions` takes `{"check", "path_pattern", "reason"}`.

- The path pattern is a glob and must be valid.
- A rule that covers every path of a check hides all its findings and stops their remediation. Such a rule needs `"all_paths": true` and no `path_pattern`. An empty pattern without it returns 400.
- `check` must be a check name, not a pattern: letters, digits, `_`, `.`, `:` and `-`.
- A name that is neither a known check nor the check of a current finding is saved. The response then carries a `warning` that says the rule matches nothing yet.

## Email

```
GET  /api/v1/email/stats         Email scanning statistics
GET  /api/v1/email/forwarders    Mail forwarder inventory with destination providers and local-copy flags (read scope)
POST /api/v1/email/forwarders/delete  Delete one destination of a forwarder on cPanel hosts through uapi, as the account that owns it; takes {"source", "destination"} as the inventory lists them; 404 when the inventory has no such pair, 500 when cPanel or command execution fails, 503 when unavailable (admin scope, CSRF)
GET  /api/v1/email/deferrals     Outbound deferral rollup by provider and sending IP with reason codes and last_seen, parsed from exim_mainlog; each provider has a sample error text; lines is the number of log lines read and window_start/window_end the times of the first and last of them; one read is reused for 60 s (read scope)
GET  /api/v1/email/queue-composition  Mail queue makeup: real vs null-sender bounce backscatter, frozen count, unreadable count, oldest age, top stuck recipients; 500 when exim could not list the queue, rather than an empty queue (read scope)
POST /api/v1/email/queue/flush-backscatter  Request removal of frozen null-sender messages from the exim queue on cPanel hosts; returns the count of targeted messages no longer queued, reports incomplete verification as 500, or returns 503 when unavailable (admin scope, CSRF)
GET  /api/v1/email/queue         One page of the exim queue on cPanel hosts, oldest first, each message with why it is stuck; page (default 1), limit (default 25, max 100), filter=all|frozen|backscatter, q (a substring of the sender or of one of its first 50 undelivered recipients) (admin scope)
GET  /api/v1/email/queue/{id}    One queued message with all undelivered recipients (up to 1,000), why it is stuck and the last 20 lines of its msglog; 404 when it is not queued (admin scope)
POST /api/v1/email/queue/{id}/{action}  retry, bounce (return to sender), delete or thaw one queued message; answers the outcome the queue shows afterwards (admin scope, CSRF)
GET  /api/v1/email/held          Forward copies held by the forward guard, each with its decoded subject and size (admin scope)
POST /api/v1/email/held/{id}/release   Re-inject a held forward copy to its external recipient (admin scope, CSRF)
DELETE /api/v1/email/held/{id}   Discard a held forward copy (admin scope, CSRF)
GET  /api/v1/email/checks        Email checks the Email page shows, each with its group kind ("" = never grouped) (read scope)
GET  /api/v1/email/groups        Server-grouped action rows (kind=compromised_account|spam_outbreak|auth_failure|queue_alert|malware) with from/to/limit (read scope)
GET  /api/v1/email/overview      Mail decision totals and 15-minute chart series for from/to (default the last 24 h), antispam mode, live queue and mail-related block counts, and Stalwart's filter verdicts: totals delivered, junk, filter_rejected, discarded and unmatched, series delivered, junk, filter_rejected and discarded, and filter_rejects_seen (read scope)
GET  /api/v1/email/rejects       Recent rejected mail (time, class, sender, recipient, source IP, detail), newest first, kept 7 days; class=content (spam and malware, default)|all|<class>[,<class>...], from/to (default the last 24 h), limit (default 50, max 200); totals has the permanent rejects of every class in the range (admin scope)
GET  /api/v1/email/senders       Messages each hosting account sent in from/to (default the last 24 h), busiest first, up to 100 rows, with total, unresolved and abuse_events, the outbound abuse events relay-abuse lists for the range, counted up to 5,000 like relay-abuse, with abuse_events_truncated true when that cap cut the count, and abuse_by_account, those events counted per account they name and per kind, before any list limit (admin scope)
GET  /api/v1/email/relay-abuse   Outbound PHP-mail abuse detections (spam outbreaks, high-volume scripts/accounts) with per-site script breakdown; from/to/limit; total counts up to 5,000 and total_truncated is true when that cap cut it, while truncated is also set when only limit cut the list (read scope)
GET  /api/v1/email/rspamd       rspamd status (up|down|off), antispam mode, version and rspamd's counters since it started (scanned, learned, actions, top 8 rules), read from its controller without a password and cached 60 s; available false with a reason when they cannot be read (read scope)
GET  /api/v1/email/quarantine    Quarantined email list, each with the size of its spooled body and its subject, decoded and cleaned as on held forward copies
GET  /api/v1/email/av/status     Email AV watcher status
GET  /api/v1/email/quarantine/{id}          One quarantined message
POST /api/v1/email/quarantine/{id}/release  Release a quarantined message (admin scope, CSRF)
DELETE /api/v1/email/quarantine/{id}        Delete a quarantined message (admin scope, CSRF)
```

### Overview: Stalwart filter verdicts

For Stalwart, the overview's `totals.delivered`, `totals.junk`, `totals.filter_rejected`, `totals.discarded` and `totals.unmatched` count its own filter verdicts in the selected range.

- `unmatched` counts messages whose verdict CSM could not tie to a sending address.
- Chart points use `delivered`, `junk`, `filter_rejected` and `discarded`, and omit these keys when zero.
- `totals.rejected` and the chart's `rejected` key count rspamd decisions, not Stalwart filter rejects.

The top-level `filter_rejects_seen` is true when any retained bucket contains a Stalwart filter rejection or discard, even outside the selected range. False means no such event is retained. It does not mean the filter rejected no mail.

The Email page shows a dash and "none logged yet" for rejected mail until this flag is true. Older responses may omit the flag or the verdict counts. The page then treats the flag as false and missing counts as zero.

### Overview: counting gaps

The overview's `counting_since` begins when mail counting starts and survives restarts.

- Stops appear in `gaps`. A gap ends when counting resumes, even if loading saved counts needs a retry.
- Gap bounds round outward to whole seconds, so short stops stay visible.
- `uncounted_minutes` rounds the total gap duration to the nearest minute, with a minimum of one for any positive duration.

### Overview: queue figures

The overview reads queue depth on every request. Queue detail is refreshed at most once per minute, even if the queue empties and refills.

- An empty queue discards its previous detail.
- New mail has `detail_unavailable: true` until the next listing.
- Failed listings can reuse detail for at most ten minutes.

### Queue list

The queue list and the overview share one queue listing. It is refreshed at most once per minute, and after any queue action.

| Field | Meaning |
| --- | --- |
| `total` | The messages that match `filter` and `q`. |
| `queued`, `frozen`, `backscatter`, `oldest_seconds` | Figures for the whole queue, whatever `filter` and `q` say. `backscatter` counts null-sender messages. |
| `listed_at` | When that listing ran. These counts can therefore trail the overview's live queue size. |
| `unavailable: true` | No listing has succeeded in the last ten minutes. The list then has no items and no counts. |

A failed refresh cannot reuse an empty listing, and a positive queue count invalidates any earlier empty result. When the queue refills after an empty listing, the next list request lists the queue immediately and does not wait for the minute to pass. This happens once per refill.

Each message's `reason` (`class`, `text`, `raw`) comes from its msglog tail. A partial first line is discarded. Up to 100 reasons are cached for a minute, and the current page takes priority when older entries must be evicted. A message thawed since it froze shows `retry_wait` until its next delivery attempt.

Quoted recipient local parts stay intact, including spaces.

#### Unreadable messages and listing errors

A message that exim cannot read is listed with `unreadable` holding exim's error, and with reason class `unreadable`. Without its envelope it has no sender, recipients, size or frozen state. Only `delete` runs on it.

- The composition counts messages without envelopes only in `total` and `unreadable`, not in `real` or `bounce`.
- Backscatter flushing excludes every unreadable message. It validates the whole listing before and after removal. A targeted message that becomes unreadable still counts as queued.
- If exim prints a spool error that does not directly follow a message line, the whole listing is unavailable. This includes a missing-file error.
- Truncated entries and unrecognized output also fail. They never report an empty queue.

### Queue message actions

Message reads and actions run exim as a systemd transient unit, never inside the daemon's sandbox. Without systemd-run the message route and the actions answer 503, and exim does not run.

Each action first checks that the message is still queued. An exim "No such file or directory" reply counts as not queued only when it names the requested message ID.

| Action | Case | Answer |
| --- | --- | --- |
| Any | The message is not queued | 409 with `outcome: "gone"`. Nothing ran, unless the message left during the action. |
| `retry` | The delivery attempt has started | `attempt_started`, as soon as it has started. |
| `bounce` | The message left the queue and exim reported no error | `bounced` |
| `delete` | The message left the queue and exim reported no error | `removed` |
| `bounce`, `delete`, `thaw` | Exim reported an error and the message left anyway | 409 with `outcome: "gone"` |
| `delete` | An unreadable message and an error exit, but exim confirms the removal and the message has left the queue | `removed` |
| `delete` | A failed or interrupted delete without that confirmation, and another caller takes the message | `gone` |
| `thaw` | The queue shows the change, even if exim reported an error | `thawed` |
| `thaw` | The queue does not show the change | `unchanged` with an error |
| `thaw` | The message is not frozen | `unchanged`, without running exim -Mt |

An error with a message that left anyway happens, for example, when exim -Mrm finds the message locked by a delivery that then completes.

Every attempt is written to the UI audit log as `email_queue_<action>`, with the message ID, the outcome and any error exim reported.

### Forwarders

The `mail.forwarders.delete.v1` capability advertises the forwarder delete endpoint. A 500 can follow a delete that partly ran, so read the inventory again before you retry. A domain's default address (`*@domain`) is changed in cPanel.

### Senders and relay abuse

The senders abuse count and the relay abuse list apply the exact `from` and `to` bounds, including fractional seconds, even when requests share cached history. `from` is inclusive and `to` is exclusive. When the cached history is capped, findings outside those bounds never crowd out findings that match.

### Email groups

An email group reports `handled: true` only when all of these hold: it is an auth-failure group, its history is complete and current, and an active block covers every attacker address, either on the address itself or on a subnet that contains it.

- Missing addresses, truncated or stale history, successful logins and account sprays stay unhandled.
- Unreadable firewall state sets `blocks_unavailable: true` and leaves every group unhandled.

### Held forward copies

A release needs a recorded sender and recipient. Each must be a single mailbox without commas, whitespace or a leading dash. An explicitly empty sender is allowed for bounces. Ambiguous or missing envelope metadata causes a release error and leaves the message held, without invoking sendmail.

Release runs sendmail as a systemd transient unit with the message on its stdin, never inside the daemon's sandbox. Without systemd-run the release fails and the message stays held. The unit uses KillMode=process. The delivery that exim forks before it exits is therefore not stopped with the unit, and the message leaves at once.

Concurrent requests and interrupted releases:

- A release or delete first claims the held copy. Of concurrent requests one acts, and the others answer that the copy is not held.
- A failed release puts the copy back.
- A copy whose release or delete the daemon never finished, as when it stopped mid-release, is held again on the next 15-minute refresh, once the claim is at least five minutes old. Such a release may already have been delivered.
- Recovery never replaces another held copy in either Maildir folder, and it makes each claim visible only once.

### Deferrals

Deferrals are grouped under the provider whose MX host deferred them (Google, Microsoft and Yahoo hosts). A business domain that those providers host therefore counts under them. The recipient's domain decides when the log line names no MX or an unknown one.

### rspamd status

The rspamd status follows live health probes. Dismissing an outage finding does not change it to `up`.

- Version display strings are bounded, whether they come from the controller or from the installed program.
- A read of rspamd's controller finishes even when the request that started it goes away, so its result is cached for the other requests.
- A failed read is logged once per cache period.

## Hardening

```
GET  /api/v1/hardening           Load last hardening audit report (admin scope)
POST /api/v1/hardening/run       Run hardening audit and save report (admin scope, CSRF)
POST /api/v1/hardening/apply     Apply automatic fixes for one section, then re-run the audit (admin scope, CSRF)
POST /api/v1/hardening/undo      Undo the last apply of one fix, then re-run the audit unless refused (admin scope, CSRF)
```

A check whose fix CSM can undo carries `undo_available: true` in every hardening report reply. The undo body is `{"name": "<check name>"}`.

The undo reply holds the root worker's `result` next to the report fields, as the apply reply holds `applied`. The `result` has a message and one of three statuses: `undone`, `refused` or `failed`.

| Case | Status | What happened |
| --- | --- | --- |
| There is no record for the fix | `refused` | Nothing changed. |
| The setting changed since the apply | `refused` | Nothing changed. |
| CSM cannot put the setting back | `refused` | Nothing changed. The message says what to do instead. |
| The setting was already back to its earlier state | `undone` | Nothing changed, but CSM removed the record. |
| The service reload failed after the restore | `undone` | The reload is left for you to do by hand. |

An example of a setting CSM cannot put back is a WHM tweak value that only WHM Tweak Settings can set. After a refused undo the reply carries the saved report, and the audit is not re-run.

If the undo worker finishes but saving the recheck fails, HTTP 500 carries `error`, the fresh audit in `report`, and the worker outcome in `result`. The page displays both the outcome and the save error. Older refresh replies cannot replace the audit returned by undo.

## Scan Jobs

`csm scan --full` enqueues full-scan jobs. They run inside the daemon and persist to the store. A job is report-only unless an account-scope request sets `quarantine: true`. Server-wide jobs reject quarantine.

```
GET  /api/v1/scan-jobs              List full-scan jobs (read scope)
GET  /api/v1/scan-jobs/{id}         Job status and stored report (read scope)
GET  /api/v1/scan-jobs/{id}/findings
                                      Paginated findings for one job (?offset=&limit=, limit 500 by
                                      default and at most 5000; truncated marks more pages) (read scope)
POST /api/v1/scan-jobs              Enqueue a full-scan job (admin scope, CSRF)
POST /api/v1/scan-jobs/{id}/cancel  Cancel a queued or running job (admin scope, CSRF)
```

## Verified Bots

```
GET  /api/v1/verified-bots        Configured verified-crawler allowlist plus live verification state (admin scope)
POST /api/v1/verified-bots/apply  Validate, apply, and reload an edited verified-bots list (admin scope, CSRF)
```

## Actions

```
POST /api/v1/fix                      Apply fix for a finding
POST /api/v1/fix-bulk                 Bulk fix multiple findings
POST /api/v1/dismiss                  Dismiss one finding {key} or up to 500 {keys}, optional {contents}; returns undo_token if any were dismissed
POST /api/v1/scan-account             On-demand account scan
POST /api/v1/verify-finding           Re-check a single finding on demand (admin scope, CSRF)
POST /api/v1/quarantine-restore       Restore quarantined file
POST /api/v1/quarantine/bulk-delete   Bulk-delete quarantined files; returns count and the ids it could not delete
POST /api/v1/db-object-backup-restore Restore a dropped MySQL object from its db_object_backups record
POST /api/v1/test-alert               Send test alert through all channels
POST /api/v1/import                   Import state bundle (suppressions, whitelist)
```

### Which file a fix acts on

`fix` and `fix-bulk` act on the file that the stored finding names.

- A request may repeat that path in `file_path`. A different path is refused.
- A target is never a remediation root itself: `/home`, `/tmp`, `/var/tmp` or `/dev/shm`.
- A target is never an account's home directory.

### Reading a verify-finding answer

`verify-finding` returns the verifier verdict in `checked`, `resolved`, `demote`, and `detail`. When that verdict also changes the stored finding, `severity_change` is `demoted` or `restored`.

A `demote` verdict without `severity_change` means no stored severity changed. For example, the finding was already demoted, or a scan replaced its snapshot while verification was running. Callers must not report a state change from the verdict alone.

## Settings

```
GET  /api/v1/settings             List editable config sections
GET  /api/v1/settings/<section>   Read a config section (secrets redacted)
POST /api/v1/settings/<section>   Update a config section (safe fields reload, restart fields queue)
POST /api/v1/settings/restart     Request a daemon restart. Returns 202 with `started_at_token`
                                  for polling until the restarted daemon reports a new marker.
POST /api/v1/settings/firewall/tentative-apply  Save firewall config, restart, and arm rollback timer
GET  /api/v1/settings/firewall/rollback         Read pending rollback state
POST /api/v1/settings/firewall/confirm          Confirm tentative firewall changes
POST /api/v1/settings/firewall/revert           Revert tentative firewall changes now
```

Sections map to top-level config keys: `alerts`, `auto_response`, `challenge`, `reputation`, `performance`, `infra_ips`, `sentry`, etc.

A write persists to `csm.yaml`, re-records the integrity hash, and hot-reloads where possible. Restart-required changes are queued for `/api/v1/settings/restart`. Invalid field values return 422 and do not touch disk.

### Fields the API refuses to change

Fields marked `file_only` in the schema are shown but refused on write with a 422. These are fields that name a command, an executable, a file path, a socket or an environment variable that the daemon acts on as root. You can change them only in `csm.yaml`.

Changing `reputation.upstream.url` or `reputation.rspamd.url` has extra rules:

- The change returns 422 unless the same request enters the effective credential for that address again.
- The change is refused outright when the credential comes from an environment variable.
- A credential entered in the request must match the resulting configuration after `conf.d` merging. An overridden replacement cannot authorize sending the stored credential to another address.

### Firewall tentative apply

Firewall tentative apply is restart-class by design. It snapshots the previous config, writes the new one and restarts the daemon. It reverts automatically unless the operator confirms before the timer expires.

## Operator preferences

CSM stores per-operator state: UI density, timestamp display, default auto-refresh and saved filter views. The state is keyed server-side by the SHA-256 of the auth token. Preferences therefore follow the operator across browsers and devices, and the daemon never stores the raw credential.

The capability flag is `webui.prefs.v1`. These endpoints require admin scope, because they read or mutate operator-private UI state.

```
GET    /api/v1/prefs/user        Read this operator's UI preferences
PUT    /api/v1/prefs/user        Replace the prefs blob (CSRF on cookie sessions)
GET    /api/v1/prefs/views       List saved views; `?page=findings` filters by page
PUT    /api/v1/prefs/views       Upsert one view {page, name, params} (CSRF on cookie sessions)
DELETE /api/v1/prefs/views       Delete one view {page, name} (CSRF on cookie sessions)
```

### `GET /api/v1/prefs/user`

```json
{
  "density":       "comfortable",
  "timezone":      "local",
  "auto_refresh":  "on",
  "table_columns": { "findings-table": ["check","severity","when"] }
}
```

| Key | Values |
| --- | --- |
| `density` | `comfortable` or `compact`. |
| `timezone` | `server`, `local`, or an IANA-shaped zone string such as `Europe/Bucharest`. |
| `auto_refresh` | `on` or `off`. |

Server-side sanitization drops any other value. Unset prefs encode as empty strings, and the UI then applies the defaults `comfortable`, `local` and `on`.

### `GET /api/v1/prefs/views`

```json
{
  "items": [
    {
      "name": "Critical SSH",
      "page": "findings",
      "params": { "severity": "critical", "check": "smtp_bruteforce" },
      "updated": "2026-05-25T21:47:35Z"
    }
  ],
  "total": 1
}
```

Saved views are operator-scoped. `PUT` and `DELETE` return `"ok": true` on success.

| Limit | Value |
| --- | --- |
| Views per operator | 200 |
| The saved view collection | One 64 KiB preference blob |
| `page` and `params` keys | Simple identifiers: ASCII letters, digits, underscore, hyphen or dot, up to 64 bytes |
| Params per view | 32 |
| A param string value | 256 bytes |
| `name` | 1-80 bytes, with no control characters |

## Bulk-action undo

Three kinds of response return an `undo_token`: finding dismissals, bulk threat block and whitelist, and bulk firewall unblock. They return it when the daemon queues an inverse operation, which it keeps server-side for 30 seconds.

The UI shows a banner with the same TTL. CLI callers can act on the token through the endpoints below. Each successful undo writes an `undo_<original_action>` audit entry.

The capability flag is `webui.undo.v1`. These endpoints require admin scope, because they read or mutate operator-private action state.

```
GET  /api/v1/undo/pending    Latest pending undo entry for this operator (empty object if none)
POST /api/v1/undo/run        Consume an entry and dispatch its inverse {id}; empty id uses latest
```

A non-empty response of `GET /api/v1/undo/pending` has this shape:

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

`POST /api/v1/undo/run` returns `{ok, action, inverse, count}` on success. It returns `410 Gone` when the entry is missing, already consumed, or past its 30-second TTL.

The recognized inverse action keys are `threat_bulk_unblock`, `threat_bulk_block`, `threat_bulk_unwhitelist`, `threat_bulk_whitelist`, `firewall_bulk_reblock` and `finding_undismiss`. Other bulk actions, such as quarantine delete and generic fix, return no undo token because they have no clean inverse.

### Dismissals

A dismissal accepts at most 500 keys per request and deduplicates repeated keys.

`contents` maps a key to the `content_sha256` its row showed. The value is an empty string for a finding without one, or a string of 64 lowercase hex characters. All other values, including `null`, answer 400 before any finding is dismissed.

A key whose listed finding now carries different content is not dismissed:

| Request | Answer |
| --- | --- |
| A single key | 409. |
| A bulk request | The rest are dismissed. `refused` returns the refused keys, and `count` counts only the applied dismissals. |
| Every key refused | No `undo_token`. |

A key missing from `contents` is dismissed as before and covers the listed content.

Undo skips findings changed by a later dismissal, a successful re-check or a baseline reset. Its `count` reports only the dismissals it actually reversed. Newer scan copies remain in the current findings list.

## Finding fields

Every finding in `/api/v1/findings`, `/api/v1/events`, and the JSONL audit log carries optional correlation fields when CSM can attribute them:

| Field | Meaning |
|---|---|
| `tenant_id` | Tenant attribution from the verdict callback or panel-side webhook reply |
| `domain` | Domain associated with the event (e.g. PHP-relay scriptKey host, mailbox domain) |
| `mailbox` | Mailbox attribution (e.g. mail brute-force target, PHP-relay envelope-from) |
| `cidrs` | Offending subnets the finding names (e.g. a distributed crawl's collapsed subnets, or a mail or SMTP password spray's /24; sprays leave `source_ip` empty) |
| `relay_total` | PHP-relay trigger count for the path that fired |
| `relay_breakdown` | PHP-relay script samples that contributed to the alert, with script key, hit count, last seen time, and a bounded sample subject when available |

Fields are omitted when the daemon could not attribute them. Orchestrators should treat absence as "unknown," not "global."

JSONL and syslog audit events include `cidrs` for new findings, and for parked findings replayed after an upgrade. Existing audit records are not backfilled.

## Cleanup fields

`GET /api/v1/quarantine` also powers the file-backup list of the Cleanup page. Entries include:

| Field | Meaning |
|---|---|
| `kind` | `quarantine` or `pre_clean` |
| `live_state` | `original_missing`, `live_differs`, `original_not_file`, `archive_missing`, `archive_not_file`, or `unknown`. Byte-identical restored entries are hidden. |

`GET /api/v1/db-object-backups` returns `restored` and `restored_at` when a captured MySQL trigger, event, procedure or function backup has already been replayed.

## Incidents

`GET /api/v1/incidents/groups` is a read-scope rollup of active incidents by kind and source. A credential spray can thus render as one row per attacker, not one row per target.

- It accepts `status=active|all|open|contained|resolved|dismissed`, `kind`, `limit` and `offset`.
- `total` counts the groups, and `scanned_incidents` the incidents they came from.
- `truncated` is true when the scan cap left incidents out.

### `GET /api/v1/incidents`

Returns one page of incidents sorted by `updated_at` descending, with `items`, `total`, `offset`, `limit` and `status`.

- `limit` defaults to 50 and is at most 500.
- `status` filters by `open`, `contained`, `resolved`, `dismissed`, or `active` for open and contained. Empty means all.

### `GET /api/v1/incidents/<id>`

Returns one incident by id. 404 if not found.

### `POST /api/v1/incidents/<id>/status`

Body:

```json
{"status": "resolved", "details": "operator-marked"}
```

Status values are `open`, `contained`, `resolved` and `dismissed`.

- Closing an incident (resolved or dismissed) means that future findings for the same correlation key start a fresh incident.
- Reopening an incident binds the same key again.

Incident JSON includes `correlation_key` when CSM has a stored account, mailbox, domain, process, or remote-IP key.
