# Web UI

HTTPS dashboard with polling-based live updates (10s feed, 60s stats). Dark/light theme toggle.

## Navigation

The sidebar groups pages by operator workflow. URLs are stable; the
groups only reorder visibility:

- **Overview** - Dashboard
- **Triage** - Incidents, Findings (Active and History tabs)
- **Response** - Firewall, Quarantine, Cleanup, Email, ModSecurity, Threat Intel
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
| **Email** | `/email` | Email workbench: status strip (queue, frozen, oldest, AV, group counts), grouped action rows on the left (compromised, spam outbreak, auth failure, queue, malware), Mail protection state on the right, and Findings / Auth failures / Queue / Quarantine / Senders / Forwarders / Deliverability / Outbound abuse tabs below. **Queue** breaks the spool into real mail vs null-sender bounce backscatter (frozen count, oldest age, top stuck recipients) and flushes frozen backscatter in one click without touching real or retrying mail. **Forwarders** lists cPanel forwarders -- destination provider, owner, and whether a local copy is also kept -- so off-server relays to free providers are visible at a glance; held forward copies appear here to release or delete. Enforce mode currently holds null-sender backscatter and bad-sender-IP copies before external relay while the local copy still delivers. **Deliverability** shows which providers are throttling the server, the affected sending IPs, and each provider's stated reason. **Outbound abuse** lists recent PHP-mail relay detections (spam outbreaks from one source IP across many sites, high-volume scripts or accounts) with the contributing site/script breakdown and a one-click 24h block. |
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
- **CSRF** - HMAC-derived token on all POST mutations
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

Re-check is shown only on findings whose condition CSM can re-evaluate from
current state: file-permission (world/group-writable), webshell and malware
file findings, phishing pages/kits and credential logs, `.htaccess`
directives, Exim spool messages, crontabs, outdated WordPress plugins,
WordPress core integrity, unauthorized UID 0 accounts (re-reads `/etc/passwd`),
SUID binaries in unusual locations (re-stats the setuid bit), and modified
system binaries (re-runs `rpm -V` / `debsums` / `dpkg --verify` for the
package). It resolves a finding only on confirmed evidence (the
file is gone, the bit is cleared, the directives are clean) -- never on an
ambiguous or unreadable target. Package-manager errors or unparsed output leave
the finding in place. The WordPress re-checks are heavier than the
file checks: they re-run `wp-cli` for that one site (bounded timeout) so a
just-applied update or cleanup is reflected immediately -- the plugin check runs
as the site owner and resolves when no active plugin is outdated, the core check
runs `wp core verify-checksums` and resolves only when the install is gone or
the checksum verification is clean. Other `wp-cli` errors or checksum warnings
keep the finding active for a full account scan. Database findings with a
concrete current-state target are also re-checkable: injected WordPress
options/posts, cloaked-spam post injections, siteurl/home hijacks,
Drupal/Joomla/Magento/OpenCart settings and content injections, the backdoor
magic-token user, WordPress rogue/disposable-email administrator accounts,
per-CMS administrator-account findings, and malicious or unexpected database
triggers/events/procedures/functions. Row and account re-checks re-discover the
CMS install, query the flagged row or account as root against that install's
database, and clear only when it is gone or no longer matches the detector. If
the query fails or the install cannot be located, the finding stays active.
Database-object re-checks read the current trigger/event/procedure/function body
from `INFORMATION_SCHEMA`; unexpected
objects stay active while the object exists, and malicious objects clear only
when the object is gone or its current body no longer matches the malware
classifier. Event findings, such as brute force, login history, IP reputation,
and WAF/ModSecurity blocks, reflect things that already happened and cannot be
re-evaluated from current state, so they show no Re-check button; they age out
or are dismissed. A few findings still need a full account scan and are not
re-checkable per-finding: dependency/supply-chain advisories, running
database-dump processes, database spam cleanup summaries and manual-review spam
findings, and the cross-account admin-overlap / credential-reuse aggregates --
use the account scan for those.

## WHM Plugin

CSM installs a WHM plugin (`addon_csm.cgi`) that redirects operators from WHM to the daemon Web UI. After the redirect, API calls are same-origin requests to the daemon.
