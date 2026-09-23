# Web UI

HTTPS dashboard with polling-based live updates (10s feed, 60s stats). Dark/light theme toggle.

Static assets use content-versioned URLs. Only a URL matching the served file
receives immutable caching; older or unversioned URLs must revalidate. Replacing
a file changes its version even when its size and modification time are preserved.
Text assets use gzip when accepted by the client, except for byte-range requests.

## Navigation

The sidebar groups pages by operator workflow. URLs are stable; the
groups only reorder visibility:

- **Overview** - Dashboard
- **Triage** - Incidents, Findings (Active and History tabs)
- **Response** - Firewall, Quarantine, Cleanup, Email, ModSecurity, Threat Intel
- **Operations** - Performance, Hardening, Audit
- **Configuration** - Rules, ModSec Rules, Verified Bots, Settings

Sidebar group expand/collapse state is saved in the browser. On
viewports under 992px the sidebar collapses into a top-bar drawer
toggled from the hamburger button. Account detail (`/account?name=<account>`) is
not in the sidebar; the finding detail, account groups on Findings, incident
detail, the accounts targeted in a Threat Intel lookup and the dashboard's
accounts-at-risk card link to it, and the command palette opens an account
typed by name. The palette also lists Sessions. Browser logins require administrator
scope. The header links to session management.

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/dashboard` | Triage queue, daemon status strip, Components matrix, system posture, 24h stats, recent activity, accounts at risk, auto-response summary, brute-force summary, timeline charts |
| **Findings** | `/findings` | Active findings with search, check/account filters, header grouping toggle, detail panel, fix/dismiss/suppress actions, sticky bulk operations, modal account scan |
| **Findings > History** | `/findings?tab=history` | Paginated archive of all findings with date range and severity filters, CSV export |
| **Quarantine** | `/quarantine` | Quarantined files with content preview, restore capability |
| **Cleanup** | `/cleanup-history` | File pre-clean backups and DB-object backups with preview and restore controls |
| **Firewall** | `/firewall` | Subview-tabbed page (`?view=overview/blocks/allow/config/audit/danger`; `?ip=<address>` opens the lookup for that address): blocked IPs/subnets with GeoIP, bulk unblock of selected rows (with undo), the whitelist and allow rules (Allow Rules tab), search, audit log; the lookup links to Threat Intel for the same address; destructive actions live under the Danger tab |
| **ModSecurity** | `/modsec` | WAF workbench: status strip, Active WAF pressure summary list (top attackers by hits), top rules / domains side panel, Blocked IPs / Events tabs, and a Manage Rules link to ModSec Rules. Block detail panels show first-seen, top URIs, sample events, and direct links to Threat Intel, Firewall lookup, and rule management |
| **ModSec Rules** | `/modsec/rules` | Enable or disable CSM rules (applied with one reload) and firewall escalation exclusions; the exclusion list works even when rule management is not configured |
| **Email** | `/email` | Mail queue and AV status, grouped account/auth/queue/malware findings, quarantine, senders, forwarders, provider deferrals, and PHP-relay abuse. Queue actions distinguish real mail from frozen null-sender backscatter; held external forward copies can be released or deleted without affecting the local delivery. |
| **Verified Bots** | `/verified-bots` | Editor for the verified-crawler allowlist (`reputation.verified_bots`): UA, reverse-DNS suffix, and IP-range identities, plus auto-update posture, with apply-and-reload. Admin scope |
| **Threat Intel** | `/threat` | IP lookup with scoring/GeoIP/ASN (`?ip=<address>` runs it on load), 24 hour and permanent block and whitelist actions (single and bulk), top attackers, attack type charts, trends; the lookup links to Firewall for the same address, and the whitelist itself is kept under Firewall > Allow Rules |
| **Hardening** | `/hardening` | On-demand hardening audit, stored report, score, and remediation guidance |
| **Incidents** | `/incident` | Correlated incident list with detail panel plus forensic timeline search by IP or account |
| **Rules** | `/rules` | YAML/YARA rule management, suppressions, state export/import, test alerts |
| **Account** | `/account` | Per-account analysis: findings, quarantine, history, on-demand scan |
| **Audit** | `/audit` | Every operator action in the Web UI and API, including logins, logouts and session revocations, with the credential that acted, search, action and date filters, URL state, and export. Failed logins go to the daemon log instead |
| **Performance** | `/performance` | Server load, PHP processes, MySQL, Redis, WordPress metrics |
| **Settings** | `/settings` | Searchable config editor with grouped large sections, field-level validation errors, restart notices, redacted secret updates, and firewall tentative apply with rollback timer. Commands, file paths, sockets and environment variable names are shown read-only and change only in `csm.yaml`; changing the rspamd or upstream address requires entering its credential again |
| **Sessions** | `/sessions` | Active browser logins, individual revocation and logout of every session |

Audit attribution is captured when the action is authorized and remains available
if the browser session expires or is revoked while the action runs.

Account views use the recorded finding owner when available, with account paths
as a fallback. They also recognize resolved paths under linked account roots,
including files already moved into quarantine.

## Dates and time zones

Every page shows dates in the time zone chosen under Preferences: the browser's,
the server's, or a named zone. Date filters pick whole days in that zone.
Changing the zone reloads the page so dates already on screen follow it, provided
the browser can save and read back the preference. If browser storage is
unavailable, new renders use the preference without forcing a reload.
Days with a midnight clock change start at the first valid time of that day;
a repeated midnight uses its first occurrence.

## Bulk file actions

Select-all and every bulk action reach only the rows the table currently
shows. Rows on other pages or hidden by a search or filter are never selected
or acted on; set the page size to All to act on every row.
Cleanup selection counts and buttons are refreshed whenever the visible rows change.

A failed file restore cleans up its own destination copy while retaining the
quarantined evidence. A replacement created by another writer is preserved.

Quarantine and Cleanup delete large file selections in sequential batches.
If a request fails, later batches are not sent; the page reports the confirmed
deletion count and refreshes the list. File restore and delete controls stay
disabled until the operation and refresh finish.

Threat Intel bulk block and whitelist actions accept up to 100 selected IPs
and retain one undo action. Larger selections must be narrowed before sending.
Findings bulk fix and quarantine actions also ask for a smaller selection when
the request would exceed the API body-size limit, which includes finding details.

## Security

- **Authentication** - API bearer tokens in the header; opaque server-side browser sessions in HttpOnly/Secure/SameSite=Strict cookies
- **CSRF** - HMAC-derived token bound to the browser session on cookie-authenticated POST, PUT, PATCH, and DELETE requests; a form sends it in the body, never the query string
- **Headers** - X-Frame-Options DENY, Content-Security-Policy (scripts, styles and forms from the Web UI only; no plugins, `<base>` or framing), HSTS, nosniff, and the legacy XSS auditor turned off
- **TLS** - Auto-generated self-signed certificate, renewed automatically within 30 days of expiry and picked up without a restart; a certificate you install is never replaced, and replacing its files takes effect on the next connection. Renewal keeps the existing private key, so a failed certificate write leaves the working pair intact; explicitly configured certificate and key files must already exist
- **Rate limiting** - 5 login attempts/min, 600 API and `/metrics` requests/min per IPv4 address or IPv6 /64
- **Token length** - tokens shorter than 32 characters are reported as warnings at startup and by `csm validate` and `csm doctor`; they keep working
- **Bearer auth** skips CSRF (for API-to-API calls)

## Browser sessions

Log in with an administrator credential from `webui.tokens` (or the migrated
legacy `webui.auth_token`). The cookie contains a new random session secret;
the reusable API credential never appears in it. Old token-valued cookies are
rejected, so an upgrade requires a fresh login. Read-scope API tokens cannot
create browser sessions.

Use **Sessions** in the header (`/sessions`) to see login names, client address,
browser, creation time, last activity and absolute expiry. Revoke one session
or log out every browser, including your own. These operations do not rotate
API credentials. Logout uses a CSRF-protected POST. Logout and revocation
accept the same browser origins as API writes (`webui.allowed_origins`); the
login form does not check the origin.

```yaml
webui:
  session_lifetime: "24h"
  session_idle_timeout: "30m"
```

Both durations require a restart. Lifetime must be between one second and
30 days; idle timeout must be at least one second and no longer than lifetime. Zero does
not disable expiry. Idle time means time without operator activity: page loads
and API requests made within a minute of keyboard, pointer or scroll input.
Background polling by an open page does not count, including metrics scrapes,
HTML page fetches and event-stream connections. Browser navigation to a page
counts as a page load; fetching that page on a timer does not. The activity
marker is recalculated when each API request is sent, so a dashboard left
open still logs out after the idle timeout. Activity is committed at bounded intervals, so
idle expiry can occur slightly early, never late. Passive event-stream
heartbeats do not extend the session; streams check revocation and expiry
before each event and heartbeat.

Every daemon restart invalidates all browser sessions. Token removal, rotation,
name or scope changes take effect after the required restart; log in again
with a current administrator credential. Reauthentication creates a new
session and revokes the previous one. Operator preferences remain tied to the
login credential, so a new session does not reset them.

The local transactional store keeps session verifiers, never raw cookie secrets.
Failed persistence cannot issue a login or claim successful revocation. If the
previous session cannot be read during reauthentication, login fails without
issuing a replacement cookie or changing that session. Concurrent requests
preserve the latest committed activity even when they arrive out of order.
If the session store is unavailable, browser authentication fails closed; API bearer
authentication remains independent. Session admission is bounded and refuses new
logins at capacity instead of evicting active sessions. The login response says
so; wait for idle sessions to expire, or revoke sessions from a logged-in
browser or with an admin API token (`DELETE /api/v1/sessions`). Expired sessions are removed during admission, and startup clears
the session records. Backup exports exclude live session records, and full
restores discard any session records from older archives.

MFA is a separate planned feature. See the
[session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
for the security principles behind opaque identifiers, expiry and revocation.

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
| `j / k` | Move selection down/up |
| `d` | Dismiss selected finding |
| `f` | Fix selected finding |

Each finding row offers up to four actions: **Fix** (apply the automated
remediation, shown only when one exists), **Re-check** (re-evaluate the finding
against the live filesystem and clear it if the condition is gone, useful after
fixing something by hand instead of waiting for the next scan), **Dismiss**
(stop alerts for it while it stays unchanged; a later scan that still finds it
lists it again, and undo is offered for 30 seconds), and **Suppress** (create a
rule to hide similar findings for good).

Dismissal undo preserves later dismissals, successful re-checks and baseline resets.
Findings first received in real time stop alerting when dismissed, even before
the next scheduled scan records them.

Re-check appears only when CSM can test a current condition again. Supported
targets include file permissions and content, phishing and `.htaccess` files,
selected accounts and system integrity checks, WordPress core/plugins, CMS
database rows, administrator accounts, and database objects. Re-check uses the
stored finding identity and current host state; the browser cannot substitute a
different path, row, account, or object.

The operation fails closed. Missing or unreadable evidence, package-manager
errors, failed CMS discovery, and failed database queries leave the finding
active. A file whose bytes changed since detection is never cleared either,
because a partial clean and an evasion edit look alike. When the replacement can
be proven inert, an empty file or a comment-only stub, the finding drops to
Warning instead of clearing, and the original severity comes back if the file
stops being inert. Historical events such as login attempts, WAF blocks, and IP
reputation cannot be re-evaluated and therefore have no Re-check action. Broad
aggregates and dependency findings require a new account or full scan.

## WHM Plugin

CSM installs a WHM plugin (`addon_csm.cgi`) that redirects operators from WHM to the daemon Web UI. After the redirect, API calls are same-origin requests to the daemon.

API requests that carry a browser `Origin` header are accepted from `https://<hostname>:<port>` (the configured `hostname` and `webui.listen` port), from an https loopback origin such as `https://localhost:9443` over an SSH tunnel on any local port, and from every origin listed in `webui.allowed_origins` (bare `https://host[:port]` entries, hot-reloadable). A loopback origin is accepted only when it is the origin the request was sent to (its `Host`): another local service in the same browser shares the Web UI's cookies, which ignore the port, and is refused. Any other origin gets `403 Cross-origin request blocked`, which shows up as a read-only UI: pages load but every action fails. The `Host` header is used only for this loopback comparison; it never admits a non-loopback origin.
