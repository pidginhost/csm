# Web UI

HTTPS dashboard with polling-based live updates (10s feed, 30s stats). Dark/light theme toggle.

## Pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/dashboard` | 24h stats, timeline chart, live feed, accounts at risk, auto-response summary, top attacked accounts |
| **Findings** | `/findings` | Active findings with search, filter by check/account, grouping, fix/dismiss/suppress actions, bulk operations, on-demand account scan |
| **Findings > History** | `/findings?tab=history` | Paginated archive of all findings with date range and severity filters, CSV export |
| **Quarantine** | `/quarantine` | Quarantined files with content preview, restore capability |
| **Firewall** | `/firewall` | Blocked IPs/subnets with GeoIP, whitelist management, search, audit log |
| **ModSecurity** | `/modsec` | WAF status, event log, active blocks |
| **ModSec Rules** | `/modsec/rules` | Per-rule management, overrides, escalation control |
| **Email** | `/email` | Email AV status, quarantined attachments, scan statistics |
| **Threat Intel** | `/threat` | IP lookup with scoring/GeoIP/ASN, top attackers, attack type charts, trends |
| **Incidents** | `/incident` | Forensic timeline correlating events by IP or account |
| **Rules** | `/rules` | YAML/YARA rule management, suppressions, state export/import, test alerts |
| **Account** | `/account` | Per-account analysis: findings, quarantine, history, on-demand scan |
| **Audit** | `/audit` | System-wide action log (block, fix, dismiss, whitelist, restore) |
| **Performance** | `/performance` | Server load, PHP processes, MySQL, Redis, WordPress metrics |

## Security

- **Authentication** — Bearer token (header or HttpOnly/Secure/SameSite=Strict cookie)
- **CSRF** — HMAC-derived token on all POST mutations
- **Headers** — X-Frame-Options DENY, Content-Security-Policy, HSTS, nosniff
- **TLS** — Auto-generated self-signed certificate
- **Rate limiting** — 5 login attempts/min, 600 API requests/min per IP
- **Bearer auth** skips CSRF (for API-to-API calls)

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `?` | Show shortcut help |
| `/` | Focus search input |
| `g d` | Go to Dashboard |
| `g f` | Go to Findings |
| `g h` | Go to Findings > History tab |
| `g t` | Go to Threat Intel |
| `g r` | Go to Rules |
| `g b` | Go to Firewall |
| `j / k` | Move selection down/up (Findings) |
| `d` | Dismiss selected finding |
| `f` | Fix selected finding |

## WHM Plugin

CSM installs a WHM plugin (`addon_csm.cgi`) that proxies the dashboard through WHM's interface. All API URLs are rewritten via the `CSM.apiUrl()` helper to support this proxy mode.
