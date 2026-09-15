# Web UI

HTTPS dashboard with polling-based live updates (10s feed, 60s stats). Dark/light theme toggle.

## Navigation

The sidebar groups pages by operator workflow. URLs are stable; the
groups only reorder visibility:

- **Overview** - Dashboard
- **Triage** - Incidents, Findings (Active and History tabs)
- **Response** - Firewall, Quarantine, Cleanup, Email, ModSecurity, Verified Bots, Threat Intel
- **Operations** - Performance, Hardening, Rules, ModSec Rules, Audit
- **Configuration** - Settings

Sidebar group expand/collapse state is saved in the browser. On
viewports under 992px the sidebar collapses into a top-bar drawer
toggled from the hamburger button. Account detail (`/account`) is
hidden from the sidebar; it is reached from finding rows, incident
detail, and Threat Intel result panels. Browser logins require administrator
scope. The header links to session management.

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/dashboard` | Triage queue, daemon status strip, Components matrix, system posture, 24h stats, recent activity, accounts at risk, auto-response summary, brute-force summary, timeline charts |
| **Findings** | `/findings` | Active findings with search, check/account filters, header grouping toggle, detail panel, fix/dismiss/suppress actions, sticky bulk operations, modal account scan |
| **Findings > History** | `/findings?tab=history` | Paginated archive of all findings with date range and severity filters, CSV export |
| **Quarantine** | `/quarantine` | Quarantined files with content preview, restore capability |
| **Cleanup** | `/cleanup-history` | File pre-clean backups and DB-object backups with preview and restore controls |
| **Firewall** | `/firewall` | Subview-tabbed page (`?view=overview/lookup/blocks/allow/config/audit/danger`): blocked IPs/subnets with GeoIP, bulk unblock of selected rows (with undo), whitelist management, search, audit log; destructive actions live under the Danger tab |
| **ModSecurity** | `/modsec` | WAF workbench: status strip, Active WAF pressure summary list (top attackers by hits), top rules / domains side panel, and Blocked IPs / Events / Rules tabs. Block detail panels show first-seen, top URIs, sample events, and direct links to Threat Intel, Firewall lookup, and rule management |
| **ModSec Rules** | `/modsec/rules` | Per-rule management, overrides, escalation control |
| **Email** | `/email` | Mail queue and AV status, grouped account/auth/queue/malware findings, quarantine, senders, forwarders, provider deferrals, and PHP-relay abuse. Queue actions distinguish real mail from frozen null-sender backscatter; held external forward copies can be released or deleted without affecting the local delivery. |
| **Verified Bots** | `/verified-bots` | Editor for the verified-crawler allowlist (`reputation.verified_bots`): UA, reverse-DNS suffix, and IP-range identities, plus auto-update posture, with apply-and-reload. Admin scope |
| **Threat Intel** | `/threat` | IP lookup with scoring/GeoIP/ASN, top attackers, attack type charts, trends |
| **Hardening** | `/hardening` | On-demand hardening audit, stored report, score, and remediation guidance |
| **Incidents** | `/incident` | Correlated incident list with detail panel plus forensic timeline search by IP or account |
| **Rules** | `/rules` | YAML/YARA rule management, suppressions, state export/import, test alerts |
| **Account** | `/account` | Per-account analysis: findings, quarantine, history, on-demand scan |
| **Audit** | `/audit` | System-wide action log with search, action and date filters, URL state, and export |
| **Performance** | `/performance` | Server load, PHP processes, MySQL, Redis, WordPress metrics |
| **Settings** | `/settings` | Searchable config editor with grouped large sections, field-level validation errors, restart notices, redacted secret updates, and firewall tentative apply with rollback timer |
| **Sessions** | `/sessions` | Active browser logins, individual revocation and logout of every session |

## Security

- **Authentication** - API bearer tokens in the header; opaque server-side browser sessions in HttpOnly/Secure/SameSite=Strict cookies
- **CSRF** - HMAC-derived token on cookie-authenticated POST, PUT, PATCH, and DELETE requests
- **Headers** - X-Frame-Options DENY, Content-Security-Policy, HSTS, nosniff
- **TLS** - Auto-generated self-signed certificate
- **Rate limiting** - 5 login attempts/min, 600 API requests/min per IP
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
not disable expiry. Idle time means time without authenticated HTTP requests,
including dashboard polling. Activity is committed at bounded intervals, so
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
logins at capacity instead of evicting active sessions; revoke unused sessions
to make room. Expired sessions are removed during admission, and startup clears
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
(hide it; restorable), and **Suppress** (create a rule to hide similar
findings).

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

API requests that carry a browser `Origin` header are accepted from `https://<hostname>:<port>` (the configured `hostname` and `webui.listen` port), from any https loopback origin such as `https://localhost:9443` over an SSH tunnel, and from every origin listed in `webui.allowed_origins` (bare `https://host[:port]` entries, hot-reloadable). Any other origin gets `403 Cross-origin request blocked`, which shows up as a read-only UI: pages load but every action fails. The request's `Host` header is never used for this decision.
