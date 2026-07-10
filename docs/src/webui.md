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
detail, and Threat Intel result panels. Read-scope sessions hide
admin-only navigation entries such as Configuration and ModSec Rules.

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/dashboard` | Triage queue, daemon status strip, Components matrix, system posture, 24h stats, recent activity, accounts at risk, auto-response summary, brute-force summary, timeline charts |
| **Findings** | `/findings` | Active findings with search, check/account filters, header grouping toggle, detail panel, fix/dismiss/suppress actions, sticky bulk operations, modal account scan |
| **Findings > History** | `/findings?tab=history` | Paginated archive of all findings with date range and severity filters, CSV export |
| **Quarantine** | `/quarantine` | Quarantined files with content preview, restore capability |
| **Cleanup** | `/cleanup-history` | File pre-clean backups and DB-object backups with preview and restore controls |
| **Firewall** | `/firewall` | Subview-tabbed page (`?view=overview/lookup/blocks/allow/config/audit/danger`): blocked IPs/subnets with GeoIP, whitelist management, search, audit log; destructive actions live under the Danger tab |
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

## Security

- **Authentication** - Bearer token (header or HttpOnly/Secure/SameSite=Strict cookie)
- **CSRF** - HMAC-derived token on cookie-authenticated POST, PUT, PATCH, and DELETE requests
- **Headers** - X-Frame-Options DENY, Content-Security-Policy, HSTS, nosniff
- **TLS** - Auto-generated self-signed certificate
- **Rate limiting** - 5 login attempts/min, 600 API requests/min per IP
- **Bearer auth** skips CSRF (for API-to-API calls)

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

The operation fails closed. Missing or unreadable evidence, changed file bytes,
package-manager errors, failed CMS discovery, and failed database queries leave
the finding active. Historical events such as login attempts, WAF blocks, and IP
reputation cannot be re-evaluated and therefore have no Re-check action. Broad
aggregates and dependency findings require a new account or full scan.

## WHM Plugin

CSM installs a WHM plugin (`addon_csm.cgi`) that redirects operators from WHM to the daemon Web UI. After the redirect, API calls are same-origin requests to the daemon.
