# Web UI

The Web UI is CSM's HTTPS dashboard. It updates live from the finding event stream (see [Live updates](#live-updates)) and has a dark and light theme toggle. Browser logins require administrator scope; see [Browser sessions](#browser-sessions).

## Navigation

The sidebar groups pages by operator workflow. The groups change only where a page is listed. URLs are stable.

| Group | Pages |
|-------|-------|
| Overview | Dashboard |
| Triage | Incidents, Findings (Active and History tabs) |
| Response | Firewall, Quarantine, Cleanup History, Email Security, ModSecurity, Threat Intelligence |
| Operations | Performance, Server Hardening, Audit Log |
| Configuration | Rules, ModSecurity Rules, Verified Bots, Settings |

A page has the same name in the sidebar, the browser tab and its heading. The old `/blocked` address redirects to `/firewall`.

The browser saves which sidebar groups are expanded or collapsed. On viewports under 992px the sidebar collapses into a top-bar drawer, which the hamburger button toggles.

Account detail (`/account?name=<account>`) is not in the sidebar. These places link to it:

- the finding detail
- account groups on Findings
- incident detail
- the accounts targeted in a Threat Intel lookup
- the dashboard's accounts-at-risk card

The command palette opens an account typed by name, and also lists Sessions. The header links to session management.

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/dashboard` | Triage queue, daemon status strip, Components matrix, system posture, 24h stats, accounts at risk, auto-response summary, brute-force summary and timeline charts. See [Dashboard](#dashboard). |
| **Findings** | `/findings` | Active findings with search, check and account filters, a detail panel, single and bulk actions, and an account scan. See [Findings and History](#findings-and-history). |
| **Findings > History** | `/findings?tab=history` | Paginated archive of all findings, newest first, with date range and severity filters and CSV export. See [History tab](#history-tab). |
| **Quarantine** | `/quarantine` | Every file backup: quarantined files and cleaners' pre-clean backups. Shows the type, the live state of the original path and a content preview, with restore and delete. Filters by account, detector, type and date. |
| **Cleanup History** | `/cleanup-history` | DB-object backups with preview and restore controls. File backups are on the Quarantine page. |
| **Firewall** | `/firewall` | Blocked IPs and subnets with GeoIP, bulk unblock, the whitelist and allow rules, search and the audit log, on subview tabs. See [Firewall](#firewall). |
| **ModSecurity** | `/modsec` | WAF workbench: status strip, top attackers, top rules and domains, and Blocked IPs and Events tabs. See [ModSecurity](#modsecurity). |
| **ModSecurity Rules** | `/modsec/rules` | Enable or disable CSM rules (applied with one reload) and firewall escalation exclusions. The exclusion list works even when rule management is not configured. |
| **Email Security** | `/email` | Headline numbers for the selected range, then one tab per job: queue, held mail, suspensions, rejects, senders, forwarders, provider delays and findings. See [Email Security](#email-security). |
| **Verified Bots** | `/verified-bots` | Editor for the verified-crawler allowlist (`reputation.verified_bots`): UA, reverse-DNS suffix and IP-range identities, plus auto-update posture, with apply-and-reload. Admin scope. |
| **Threat Intelligence** | `/threat` | IP lookup with scoring, GeoIP and ASN, block and whitelist actions, top attackers, attack type charts and trends. See [Threat Intelligence](#threat-intelligence). |
| **Server Hardening** | `/hardening` | On-demand hardening audit, stored report, score and remediation guidance. See [Hardening audit of the web server configuration](#hardening-audit-of-the-web-server-configuration). |
| **Incidents** | `/incident` | Correlated incident list and grouped view, with a detail panel, bulk status changes and a forensic timeline search. See [Incidents](#incidents). |
| **Rules** | `/rules` | YAML/YARA rule management, suppressions, state export/import, test alerts. |
| **Account** | `/account` | Per-account analysis: findings, quarantine and history. An on-demand account scan runs from the Findings page. See [Account](#account). |
| **Audit Log** | `/audit` | Every operator action in the Web UI and API, with the credential that acted, search, filters and export. See [Audit Log](#audit-log). |
| **Performance** | `/performance` | Server load, PHP processes, MySQL, Redis, WordPress metrics. |
| **Settings** | `/settings` | Searchable config editor with field-level validation errors, restart notices and redacted secret updates. See [Settings](#settings). |
| **Sessions** | `/sessions` | Active browser logins, individual revocation and logout of every session (confirmed first). |

### Dashboard

A finding in the triage queue opens its own detail. Each 24h severity count opens the History tab for the last 24 hours at that severity.

### Firewall

- The page has subview tabs (`?view=overview/blocks/allow/config/audit/danger`).
- `?ip=<address>` opens the lookup for that address. The lookup links to Threat Intel for the same address.
- Bulk unblock acts on the selected rows and offers an undo.
- The whitelist and the allow rules are on the Allow Rules tab.
- Destructive actions live under the Danger tab.

### ModSecurity

The page has a status strip, the Active WAF pressure summary list (top attackers by hits), a side panel with the top rules and domains, the Blocked IPs and Events tabs, and a Manage Rules link to ModSecurity Rules.

A block's detail panel shows first-seen, top URIs and sample events. It links directly to Threat Intel, the Firewall lookup and rule management.

### Incidents

The incident list and the grouped view are both filterable by every status. Bulk status changes (contained, resolved, dismissed) apply to the incidents selected on the page. The forensic timeline search takes an IP or an account.

### Account

Account views use the recorded finding owner when available, with account paths as a fallback. They also recognize resolved paths under linked account roots, including files already moved into quarantine.

### Audit Log

The log covers every operator action in the Web UI and API, including logins, logouts and session revocations. Each entry names the credential that acted. The page has search, action and date filters, URL state and export. Failed logins go to the daemon log instead.

CSM captures the audit attribution when it authorizes the action. The attribution stays available if the browser session expires or is revoked while the action runs.

### Settings

The editor is searchable and groups large sections. It shows field-level validation errors and restart notices, accepts redacted secret updates, and applies firewall changes tentatively with a rollback timer.

Commands, file paths, sockets and environment variable names are shown read-only and change only in `csm.yaml`. Changing the rspamd or upstream address requires entering its credential again.

## Findings and History

The Findings page lists active findings. It has:

- search, and filters by check and account
- a grouping toggle in the header
- a detail panel
- fix, dismiss and suppress actions on each finding
- a permanent Block for findings that report an attacker address
- sticky bulk operations (fix, dismiss, suppress)
- a modal account scan

The open finding is kept in the URL as `?key=<finding key>`, so the link reopens it.

### History tab

The History tab is a paginated archive of all findings, newest first. It has date range and severity filters and a CSV export. A page holds 25 to 200 rows (`hperpage`). `window=24h` (1 to 720 hours) shows a rolling window instead of calendar days.

### Actions on a finding

Each finding row offers up to four actions:

| Action | What it does |
|--------|--------------|
| **Fix** | Applies the automated remediation. Shown only when one exists. |
| **Re-check** | Evaluates the finding again against the live filesystem and clears it if the condition is gone. Useful after fixing something by hand instead of waiting for the next scan. |
| **Dismiss** | Stops alerts for the finding while it stays unchanged. A later scan that still finds it lists it again. Undo is offered for 30 seconds. |
| **Suppress** | Creates a rule to hide similar findings for good. |

A finding cleared by Fix or Re-check is new again when a later scan finds it, so a reinfection alerts. A detection or dismissal that arrives while Fix or Re-check runs stays in place.

### Dismissing a finding

Dismissing a finding about a file's content, such as a malware match, covers that content only:

- When the file changes, the finding alerts again as a new detection, and automatic responses can act on it.
- A scan that could not read the file does not end its dismissal.
- The "new findings" banner appears when a listed file's content changes.
- If the file changed after the page loaded, the dismissal is refused and the list refreshes with a warning.
- A bulk dismissal still dismisses the unchanged findings, and undo covers only those.

Undoing a dismissal leaves in place any dismissals, successful re-checks and baseline resets made after it.

Findings first received in real time stop alerting when dismissed, even before the next scheduled scan records them.

### Re-check

Re-check appears only when CSM can test a current condition again. Supported targets include:

- file permissions and content
- phishing and `.htaccess` files
- selected accounts and system integrity checks
- WordPress core/plugins
- CMS database rows
- administrator accounts
- database objects

Re-check uses the stored finding identity and the current host state. The browser cannot substitute a different path, row, account, or object.

Two kinds of finding have no Re-check action:

- Historical events such as login attempts, WAF blocks, and IP reputation cannot be evaluated again.
- Broad aggregates and dependency findings require a new account or full scan.

YARA Re-check compares the complete scanned content with the finding's recorded fingerprint, including large files admitted by `thresholds.full_scan_max_file_mb`. If the content is unchanged and YARA does not flag it any more, the finding clears.

Re-check fails closed: when it cannot prove the condition is gone, the finding stays.

| Case | Result |
|------|--------|
| Missing or unreadable evidence, package-manager errors, failed CMS discovery or failed database queries | The finding stays active. |
| The file's bytes changed since detection | The finding is never cleared, because a partial clean and an evasion edit look alike. |
| The replacement can be proven inert: an empty file or a comment-only stub | The finding drops to Warning instead of clearing. The original severity comes back if the file stops being inert. |

## Email Security

The page starts with headline numbers for the selected range. Each number opens the tab that explains it. Below them are the job tabs, each with a count. `?tab=` names the open tab.

| Tab | What it shows |
|-----|---------------|
| Overview | Mail decisions chart, rspamd, groups needing attention, protection. |
| Queue | Why each message is stuck, with retry, return to sender, delete and thaw. |
| Held mail | Quarantined malware and held forward copies, to release or delete. |
| Suspended | Mailboxes and accounts CSM suspended, with live status and Release. Releasing never changes the password. |
| Rejects | Up to the newest 200 rejects in the range. The tab says when the list reaches that limit. |
| Sending accounts | Mail per hosting account, or per mailbox login on a Postfix host, and abuse events. |
| Forwarders | Each forwarder and where it sends, with delete per destination. A domain's default address is changed in cPanel. |
| Provider delays | Providers and sending IPs deferring mail, and why. |
| Findings | Mail findings in the selected range. |

Some tabs and cards depend on the mail server; see [What each host shows](#what-each-host-shows).

### Search and paging

Rejects, Sending accounts and Suspended use the Held mail layout, with a search box, a row count and 25 rows per page.

| Tab | Search matches |
|-----|----------------|
| Rejects | Sender, recipient, IP or detail |
| Sending accounts | Name |
| Suspended | Mailbox, owner account or reason |

The address keeps the search. A new search starts on the first page. A refresh keeps the current page while the search and filters stay the same.

### Refresh intervals

| Data | Refreshes |
|------|-----------|
| Headline counts | Every 30 seconds |
| Queue messages and composition, held mail, rejects, sending accounts, provider delays and Findings | Every minute while their tab is open |
| The Held mail, Sending accounts and Provider delays counts | Every minute on any tab |
| The rspamd state in the header, on hosts without Stalwart's filter | Every minute on any tab |

Hidden tabs do not poll their lists.

A refresh keeps your place:

- When a refresh returns the same results, the rows on screen are left as they are.
- Changed results retain paging, sorting, selection, open details and focus for items still present.
- Pending message, bulk and firewall actions stay disabled across refreshes.

A failed refresh marks protection status as unavailable and hides stale chart data. An older response cannot overwrite newer health status or the selected outbound abuse range.

Queue actions wait up to a minute. An unreadable outcome is reported as unknown.

### Held mail ranges

A custom range on Held mail includes only items held during the selected days. The summary also identifies held items outside that range.

The other ranges have no end, so a server clock ahead of the browser cannot hide mail just held.

### Rejects and Sending accounts

Rejects and Sending accounts read the Exim main log, or the Postfix mail log on a host without Exim. Both tabs stay empty on a Stalwart host.

On Postfix:

- A send is mail accepted from a client that logged in, counted under that login.
- Mail relayed for a trusted host without a login is not counted.
- A reject whose reason cannot be told apart from text the client sent is listed under Other.

### Stalwart hosts

On a Stalwart host the Suspended tab lists the mailboxes whose sign-ins CSM stopped, and Release allows them again.

The first three Email Security cards show:

1. the mail Stalwart's spam filter did not file to Junk
2. the mail it rejected or discarded
3. the mail it filed to the Junk folder

The state line and the mail decisions chart use Stalwart's filter verdicts, independently of CSM's antispam mode. The rspamd card and the Antispam line of the Protection card are not shown, as they describe CSM's own antispam.

The Spam rejected card opens Overview and has no mode badge. It shows a dash and "none logged yet" until CSM has a retained rejection or discard, including events outside the selected range. After that, it shows the range's rejection count and the discarded count below it.

The Mail delivered card also names unmatched verdicts. Missing verdict counts from an older daemon display as zero; they never fall back to rspamd counts.

Large card counts are shortened, with the full count available in the value's tooltip.

## Threat Intelligence

The page has an IP lookup with scoring, GeoIP and ASN. `?ip=<address>` runs the lookup on load. The lookup links to Firewall for the same address.

The page has 24 hour and permanent block actions and whitelist actions, for a single address and in bulk. The whitelist itself is kept under Firewall > Allow Rules.

The page also shows top attackers, attack type charts and trends.

<a id="threat-intelligence-spam-evidence"></a>

### Spam evidence

The Spam column shows spam and ham verdict counts and the current spam score. Click its heading to sort by score.

The Spam evidence only filter requests senders with spam verdicts, including those with no attack events. The filter is kept in the URL for bookmarks and history navigation. When you switch filters, the previous rows stay unavailable for actions and export until a load succeeds.

Spam evidence about IPv6 senders is listed per /64 network. Such a row is named by the network and carries a Network badge. It differs from an address row:

- It has no checkbox and no block or whitelist buttons.
- Clicking it does not open the IP lookup.

Looking up an address inside the network shows whichever spam evidence is stronger: the address's own or the network's. On a tie the network's evidence is shown. Whenever the network's evidence is shown, the lookup names the network.

The Listing threshold badge means the spam score qualifies for the CSM IP map. It does not confirm an active listing: the feed must be configured and working, and address exclusions still apply. Spam scores remain separate from the unified threat score and firewall block status.

## What each host shows

The Web UI shows only what the host supports.

### Mail

Email Security appears when Exim, Postfix or Stalwart is detected. A mail server started after CSM shows up within five minutes.

These need cPanel and are not shown elsewhere:

- the Queue, Held mail, Forwarders and Provider delays tabs of Email Security
- the antivirus lines of the Protection card
- cPHulk actions on the Firewall page
- the dashboard's Email AV chip
- the Email AV, cPanel and webmail login, and known API token settings

The Suspended tab shows on cPanel and Stalwart hosts. [Stalwart hosts](#stalwart-hosts) lists what else changes with Stalwart.

### PHP

On a host with no PHP interpreter, these are hidden:

- the PHP Shield, WordPress, WP-Cron, XML-RPC and PHP process settings
- the Performance page's PHP cards

PHP installed after CSM starts shows them within five minutes. Hidden settings keep their values in `csm.yaml`, including when you save another field in the same section.

For PHP in containers:

- PHP-FPM or lsphp in a container counts as PHP.
- A container running only Apache with mod_php has no separate PHP process and is not found.
- The PHP Shield settings show for container PHP only when that container has the shield script at its usual path.

## Dates and time zones

Every page shows dates in the time zone chosen under Preferences: the browser's, the server's, or a named zone. Date filters pick whole days in that zone.

Changing the zone reloads the page so dates already on screen follow it, provided the browser can save and read back the preference. If browser storage is unavailable, new renders use the preference without forcing a reload.

[Clock changes and custom ranges](#clock-changes-and-custom-ranges) covers days with a clock change and custom date ranges.

## Live updates

The Web UI keeps an event stream open (`/api/v1/events`) and shows a Live indicator while it is connected. Findings are batched for up to a couple of seconds before pages update:

| Page | What a new finding does |
|------|-------------------------|
| Findings | Shows the "new findings" banner at once instead of on its next check. |
| Dashboard | Sends desktop notifications and refreshes the 24h counts and the triage queue. |
| Incidents | Reloads the current list, unless incidents are selected for a bulk change. |

While the stream is connected, the checks those pages run on a timer slow down to once a minute as a safety net. When the stream drops they return to their normal pace. Pausing auto-refresh also pauses live updates.

Desktop notifications handle findings that arrive out of order within a batch or share a timestamp, without repeating them on the next history poll.

## Refresh

The header shows when the page's data was last loaded ("Updated N ago"). The time moves when the page loads its data, on each automatic refresh and on the Refresh button. An action or a detail lookup does not change it.

The pause button appears only on pages that refresh on a timer. It pauses that refreshing in this browser.

Refresh reloads the page's data in place, keeping filters, scroll and open panels. Some pages differ:

| Page | What Refresh does |
|------|-------------------|
| A page with unsaved edits (Settings, Verified Bots, staged ModSec rule changes) | Asks before discarding them. |
| Hardening | Reloads the stored report and does not run a new audit. |
| Pages rendered by the server, such as Sessions | Reload. |
| The visible History tab | Refreshes with its current filters and page size. |

A panel that fails to load says what failed and why, with a Retry button that loads only that panel again. The panel's earlier content returns once a later load succeeds.

### Refresh while something else is loading

- Editors wait for an ongoing save or load before accepting another refresh.
- Verified Bots keeps edits made while a reload is pending.
- ModSecurity exclusion controls wait for the exclusion list to load. A failed load stays visible instead of appearing as an empty list.
- Late responses cannot replace a newer account tab, settings section, history page, or finding detail, or reopen a finding detail that was closed.

## Notifications

Success and information notices fade after five seconds. An error stays until you close it. The same error is not shown twice while it is on screen.

## Confirmations

A confirmation for an action that deletes data, blocks traffic, turns protection off or ends sessions:

- names the action on a red button, such as Delete or Block
- starts with Cancel focused, so pressing Enter does not carry the action out
- keeps focus on Cancel after the dialog finishes opening

Logging out every browser session asks first. A later text prompt uses its own normal OK button. Bulk actions keep one confirmation open at a time.

## Bulk file actions

### Which rows a bulk action reaches

Select-all and every bulk action reach only the rows the table currently shows. Rows on other pages or hidden by a search or filter are never selected or acted on. Set the page size to All to act on every row.

Quarantine selection counts and buttons are refreshed whenever the visible rows change.

### Quarantine restore and delete

A failed file restore cleans up its own destination copy while retaining the quarantined evidence. A replacement created by another writer is preserved.

Quarantine deletes large file selections in sequential batches. If a request fails, later batches are not sent. The page reports the confirmed deletion count and refreshes the list.

File restore and delete controls stay disabled until the operation and refresh finish, and Refresh waits for them.

### Restoring a quarantined mail message

A mail message quarantined from a phishing finding is listed as two files, its header and its body. Restoring either one returns the whole message to the mail queue, and Exim delivers it on its next queue run.

- The complete body is returned before the header becomes visible to Exim.
- Restore refuses an incomplete message or a conflicting queue entry and keeps the quarantine copy.
- If restore or quarantine cleanup fails, retry the same entry. Progress survives a daemon restart, and a cleanup retry does not requeue an already delivered message.
- A header quarantined on its own can be restored if its body remains in the queue.

### Limits on bulk requests

Threat Intel bulk block and whitelist actions accept up to 100 selected IPs and retain one undo action. Larger selections must be narrowed before sending.

Findings bulk fix also asks for a smaller selection when the request would exceed the API body-size limit, which includes finding details.

Findings bulk suppress creates one path rule per selected file, up to 100 files, with the file name matched literally:

- Selected findings that name no file are skipped.
- A rule for a whole check is made from one finding.
- Rules are saved one at a time. A failure stops the rest and reports how many were saved.

## Security

| Area | Protection |
|------|------------|
| Authentication | API bearer tokens in the header. Opaque server-side browser sessions in HttpOnly/Secure/SameSite=Strict cookies. |
| CSRF | HMAC-derived token bound to the browser session on cookie-authenticated POST, PUT, PATCH, and DELETE requests. A form sends it in the body, never the query string. Bearer auth skips CSRF (for API-to-API calls). |
| Headers | X-Frame-Options DENY, Content-Security-Policy, HSTS, nosniff, and the legacy XSS auditor turned off. The policy allows scripts, styles and forms from the Web UI only, and no plugins, `<base>` or framing. |
| TLS | Auto-generated self-signed certificate, renewed automatically. See [TLS certificate](#tls-certificate). |
| Rate limiting | 5 credential attempts/min per IPv4 address or IPv6 /64, and 600 requests/min for API and `/metrics` traffic. See [Rate limiting](#rate-limiting). |
| Token expiry | Dashboard, API and metrics credentials expire at their configured `expires_at` and never expire without one. Expired credentials, malformed dates and future issue times are refused. |
| Token sources | A token with `allowed_ips` is accepted only from those addresses and CIDR ranges, matched against the TCP peer. |
| Token length | Tokens shorter than 32 characters are reported as warnings at startup and by `csm validate` and `csm doctor`. They keep working. |

### TLS certificate

CSM generates a self-signed certificate and renews it automatically within 30 days of expiry. The renewed certificate is picked up without a restart. Renewal keeps the existing private key, so a failed certificate write leaves the working pair intact.

A certificate you install is never replaced. Replacing its files takes effect on the next connection. Explicitly configured certificate and key files must already exist.

### Rate limiting

- Each IPv4 address or IPv6 /64 gets 5 credential attempts/min. Login submissions and unknown bearer tokens share this limit on all authentication routes, including login GETs and unknown API paths.
- Concurrent requests share the limit.
- Valid UI and metrics tokens used outside their scope do not consume it.
- Once the budget is exhausted, CSM rejects bearer requests before checking credentials.
- API and `/metrics` traffic also has a 600 requests/min limit.

## Credential rotation

A credential expires only at its `expires_at`, a UTC RFC3339 time. A credential without `expires_at` never expires, so configurations written before these settings existed keep working.

The optional `issued_at` records when the token was generated. `expires_at` must be later.

| Credential | Expiry | Issue time |
|------------|--------|------------|
| A `webui.tokens` entry | `expires_at` | `issued_at` |
| Legacy token | `webui.auth_token_expires_at` | `webui.auth_token_issued_at` |
| Metrics token | `webui.metrics_token_expires_at` | `webui.metrics_token_issued_at` |

Integrations should:

- narrow the scope (`unban` for customer self-unblock)
- list their source addresses in `allowed_ips`
- set an `expires_at` that matches how often they rotate

The deadline applies as follows:

- Reloads and restarts preserve the deadline.
- Active event streams check the credential again before sending each event or heartbeat.
- Browser sessions and their form tokens use the credential that created the session. Expiry of another administrator's credential does not interrupt them.

### Rotating a credential

1. Replace the token with a fresh random value of at least 32 characters.
2. Update its dates.
3. Distribute it to clients through your secret manager.
4. Restart CSM after changing login or API credentials. Metrics token and date changes can be applied together with SIGHUP.

Changing a date alone is not rotation.

Package installation keeps newly generated credentials out of subprocess arguments. Rotate credentials generated by earlier packages, because local users could have observed them in process listings during installation.

### Expired credentials

An expired credential or an invalid date disables that credential and produces a warning at startup and through `csm validate` and `csm doctor`. Detection and alerting continue.

If all admin credentials expire, update the root-owned configuration locally and restart CSM to recover dashboard access.

Use `token.expires_at.v1` in the capabilities API to detect this policy.

## Browser sessions

Log in with an administrator credential from `webui.tokens` (or the migrated legacy `webui.auth_token`). Read-scope API tokens cannot create browser sessions.

The cookie contains a new random session secret. The reusable API credential never appears in it. Old token-valued cookies are rejected, so an upgrade requires a fresh login.

### Managing sessions

Use Sessions in the header (`/sessions`) to see login names, client address, browser, creation time, last activity and absolute expiry. Revoke one session or log out every browser, including your own. These operations do not rotate API credentials.

Logout uses a CSRF-protected POST. Logout and revocation accept the same browser origins as API writes (`webui.allowed_origins`). The login form does not check the origin.

### Lifetime and idle timeout

```yaml
webui:
  session_lifetime: "24h"
  session_idle_timeout: "30m"
```

Both durations require a restart.

- Lifetime must be between one second and 30 days.
- Idle timeout must be at least one second and at most the lifetime.
- Zero does not disable expiry.

Idle time means time without operator activity: page loads and API requests made within a minute of keyboard, pointer or scroll input.

| Counts as activity | Does not count |
|--------------------|----------------|
| Browser navigation to a page, which is a page load | Fetching that page on a timer |
| API requests made within a minute of keyboard, pointer or scroll input | Background polling by an open page, including metrics scrapes, HTML page fetches and event-stream connections |
| | Passive event-stream heartbeats |

The activity marker is recalculated when each API request is sent, so a dashboard left open still logs out after the idle timeout. CSM saves a session's last-activity time at intervals, not on every request, so a session can expire slightly before the idle timeout, never after it.

Streams check revocation and expiry before each event and heartbeat.

### When a session ends

- A browser session also loses access when its login credential expires.
- Every daemon restart invalidates all browser sessions.
- Token removal, rotation, name or scope changes take effect after the required restart. Log in again with a current administrator credential.
- Reauthentication creates a new session and revokes the previous one.

Operator preferences remain tied to the login credential, so a new session does not reset them.

### When a login is refused

The number of browser sessions is limited. When the limit is reached, CSM refuses new logins instead of evicting active sessions, and the login response says so. Wait for idle sessions to expire, or revoke sessions from a logged-in browser or with an admin API token (`DELETE /api/v1/sessions`).

If the session store is unavailable, browser authentication fails closed. API bearer authentication remains independent.

[Session storage](#session-storage) has the remaining rules.

MFA is a separate planned feature. See the [session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for the security principles behind opaque identifiers, expiry and revocation.

## Keyboard Shortcuts

### General

| Key | Action |
|-----|--------|
| `?` | Show shortcut help |
| `/` | Focus search input |
| `Ctrl-K / Cmd-K` | Open command palette |

### Navigate

| Key | Action |
|-----|--------|
| `g d` | Go to Dashboard |
| `g f` | Go to Findings |
| `g h` | Go to Findings > History tab |
| `g t` | Go to Threat Intel |
| `g r` | Go to Rules |
| `g b` | Go to Blocked IPs (Firewall) |

### Findings page

| Key | Action |
|-----|--------|
| `j / k` | Move selection down/up (focus moves to the row) |
| `o` / `Enter` | Open selected finding |
| `d` | Dismiss selected finding |
| `f` | Fix selected finding |

Shortcuts act on the focused finding and stay inactive while a dialog or detail panel is open. [Actions on a finding](#actions-on-a-finding) explains what Fix and Dismiss do.

### Keyboard access and focus

- Finding and incident rows, finding group headers and sortable table headers also work from the keyboard: Tab to them and press Enter or Space.
- A sorted header reports its order to screen readers.
- Closing the detail panel or a dialog returns focus to what opened it. If a refresh removes the opener, focus returns to the open detail panel or main content.
- A dialog opened from the detail panel keeps Tab and Escape to itself.

## WHM Plugin

CSM installs a WHM plugin (`addon_csm.cgi`) that redirects operators from WHM to the daemon Web UI. After the redirect, API calls are same-origin requests to the daemon.

### Accepted browser origins

API requests that carry a browser `Origin` header are accepted from:

- `https://<hostname>:<port>` (the configured `hostname` and `webui.listen` port)
- an https loopback origin such as `https://localhost:9443` over an SSH tunnel on any local port
- every origin listed in `webui.allowed_origins` (bare `https://host[:port]` entries, hot-reloadable)

Any other origin gets `403 Cross-origin request blocked`, which shows up as a read-only UI: pages load but every action fails.

A loopback origin is accepted only when it is the origin the request was sent to (its `Host`). Another local service in the same browser shares the Web UI's cookies, which ignore the port, and is refused. The `Host` header is used only for this loopback comparison; it never admits a non-loopback origin.

A preflight (`OPTIONS`) from an accepted origin is answered with the methods and request headers the API takes, so a credentialed JSON write from a listed origin goes through.

## Details

This section is reference material for edge cases.

### Static assets

Static assets use content-versioned URLs.

- Only a URL whose version matches the file being served is cached as immutable. Older or unversioned URLs must revalidate.
- Replacing a file changes its version even when its size and modification time are preserved.
- Text assets use gzip when accepted by the client, except for byte-range requests.

### Clock changes and custom ranges

- Days with a midnight clock change start at the first valid time of that day. A repeated midnight uses its first occurrence.
- Email chart hours also follow partial-hour daylight saving changes.
- Custom date links include both selected days, even when supplied in reverse order.
- Long custom ranges group adjacent days into labeled spans without dropping counts.
- Changing the range discards pending results for the previous range.

### Hardening audit of the web server configuration

Web server directive checks follow Apache quoting, section comments, continuations, and shell include patterns.

These produce warnings:

- malformed section endings
- unreadable includes
- unresolved directive names
- unsupported wildcard classes

Quotes in ignored section suffixes do not cause warnings.

Which configuration the audit reads depends on the host:

- On Apache or cPanel hosts, a configured Apache root takes precedence over default locations. A missing selected main configuration never falls back to another tree.
- Other servers skip the Apache audit when that main file is absent.

### Session storage

- The local transactional store keeps session verifiers, never raw cookie secrets.
- If a session cannot be saved, the login fails. If a revocation cannot be saved, it is not reported as successful.
- If the previous session cannot be read during reauthentication, login fails without issuing a replacement cookie or changing that session.
- Concurrent requests preserve the latest committed activity even when they arrive out of order.
- Expired sessions are removed during admission, and startup clears the session records.
- Backup exports exclude live session records, and full restores discard any session records from older archives.
