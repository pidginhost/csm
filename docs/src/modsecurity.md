# ModSecurity Integration

CSM detects ModSecurity (WAF) on Apache, Nginx, and LiteSpeed across cPanel and plain Linux hosts. Custom rule deployment, override writes, and reload management are currently cPanel-only; other platforms still receive status, staleness, and event detection.

## Supported Web Servers

| Web server | Config candidates | Status check | Custom rule deployment |
|-----------|-------------------|--------------|------------------------|
| Apache on cPanel EA4 | `/usr/local/apache/conf/*`, `/etc/apache2/conf.d/modsec*`, `whmapi1 modsec_is_installed` | Yes | Yes (via cPanel modsec user conf) |
| Apache on Debian/Ubuntu | `/etc/apache2/mods-enabled/security2.conf`, `/etc/apache2/conf-enabled/*`, `/etc/apache2/conf.d/modsec2.conf` | Yes | No |
| Apache on RHEL/Alma/Rocky | `/etc/httpd/conf.d/mod_security.conf`, `/etc/httpd/conf.modules.d/*` | Yes | No |
| Nginx on any distro | `/etc/nginx/nginx.conf`, `/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf`, `/etc/nginx/modsec/main.conf` | Yes | No |
| LiteSpeed | `/usr/local/lsws/conf/httpd_config.xml`, `/usr/local/lsws/conf/modsec2.conf` | Yes | cPanel only |

When ModSecurity is not installed, the `waf_status` check emits a platform-specific install hint:

```
# On Ubuntu + Nginx:
Install: apt install libnginx-mod-http-modsecurity modsecurity-crs

# On Ubuntu + Apache:
Install: apt install libapache2-mod-security2 modsecurity-crs && a2enmod security2

# On AlmaLinux + Apache:
Install (requires EPEL): dnf install -y epel-release && dnf install -y mod_security

# On AlmaLinux + Nginx:
Install (requires EPEL): dnf install -y epel-release && dnf install -y nginx-mod-http-modsecurity

# On cPanel:
Install: WHM > Security Center > ModSecurity
```

Rule-staleness alerts scan both the flat CRS layout (`/usr/share/modsecurity-crs/rules/*.conf`) used by distro packages and cPanel vendor trees, including nested layouts such as `modsec_vendor_configs/VENDOR/rules/*.conf`. On cPanel, CSM maps WHM's active configuration files to their vendor trees and checks the newest artifact in each loaded tree. This honors individual configuration overrides, keeps retired trees out of the result, and prevents a fresh unloaded vendor from hiding a stale loaded one. LiteSpeed also keeps the on-disk check as a backstop while cPanel rebuilds the active configuration list and rule tree. If WHM cannot provide the mapping, and on other platforms, the check keeps the conservative oldest-artifact behavior. Update instructions are platform-specific (`apt update && apt upgrade modsecurity-crs`, `dnf upgrade modsecurity-crs`, or WHM on cPanel).

## Features

- **Custom CSM rules** - IDs 900000-900999 in `configs/csm_modsec_custom.conf` (cPanel only today)
- **Rule override management** - `SecRuleRemoveById` directives for false positive suppression
- **Escalation control** - change rule severity or action per-rule
- **Live deny escalation** - repeated ModSecurity deny events from one IP emit an escalation finding that feeds auto-response blocking. CSM-owned rules keep their existing per-rule escalation controls.
- **Disabled-scope detection** - reports domains and accounts with the engine switched off, covering both the userdata flag and the per-account and per-domain config includes used by Apache and LiteSpeed in the std and ssl trees
- **WAF event log parsing** - correlates events by IP, URI, and rule ID
- **Hot-reload** - apply changes without Apache restart (cPanel only)
- **Rule activation** - ModSecurity reads rules only when the web server starts or reloads. When CSM's installed rule sections change, for example after an upgrade or `csm install`, the daemon runs `modsec.reload_command` at startup or during its WAF check. Each rule change reloads once. Standalone `csm check` runs never reload. A failed reload raises a `waf_status` warning and is retried. Without a command, CSM only warns at startup and the rules wait for the next web server restart.

CSM checks the rule-action registry every five minutes and rebuilds it when rule
file contents change. Read failures leave the build uncached so the next check
retries. Files that were read in full but exceeded the parser's line limit are
reported without forcing unchanged files to be parsed again. Rules appended
after parsing reaches the end of a file are picked up on the next check.

The reload command runs inside CSM's systemd sandbox. Use a service-manager
command such as `systemctl reload lsws` for LiteSpeed, so the web server's service
performs the reload. Direct reload scripts inherit CSM's filesystem restrictions
and may fail. A LiteSpeed reload restarts workers and can briefly raise load.

The LiteSpeed Cache role-simulation filter covers privileged routes and writes,
including WordPress REST method overrides, when requests carry simulation cookies
with a weak hash. Ordinary public GET/HEAD crawling remains allowed. This is a
request-scoped mitigation: public reads still run under the simulated identity,
so upgrading the vulnerable plugin remains necessary.

The usual hash discriminator is 1-16 alphanumeric characters versus the fixed
plugin's 32-character hashes. Numeric equivalents are also filtered because the
vulnerable plugin compares hashes loosely; padding or exponent notation must not
turn a weak hash into an exempt one. These checks also keep public crawler reads
allowed.

The WordPress user enumeration filter blocks anonymous requests for the REST
users route, whether the route follows `wp-json/` in the path or starts at
`wp/v2/users` in the `rest_route` query parameter, in any letter case. Other
page paths and REST namespaces are left alone. Query values are matched as
already decoded by the query parser. Requests that carry an `Authorization`
header or a WordPress logged-in cookie pass, so admin screens, the editor and
Application Password clients keep working. Both are presence checks: the filter
turns away anonymous scanners, and WordPress still decides who is signed in.

The filter runs in phase 1 and does not inspect request bodies. A route supplied
only in a POST body, including with a REST method override, is outside its scope.
Sites that need to restrict the public users endpoint must enforce that policy
in WordPress. Disabling rule `900112` disables this filter for both route forms;
its helper rules only set transaction-local flags and do not block requests.

For Apache ModSecurity v2 regression validation, run
`python3 scripts/test-litespeed-modsec.py` in a disposable Debian Linux environment
with `apache2`, `libapache2-mod-security2`, `libapache2-mod-php`, and `python3`
installed. The test loads the complete shipped configuration and exercises HTTP
requests through the actual engine and PHP parser. It does not establish
LiteSpeed runtime compatibility; verify changed rules on the supported LiteSpeed
engine before deployment.

## Web UI Pages

**ModSecurity** (`/modsec`) - WAF status overview, event log, active block list, filterable by time range, minimum severity, and source country

**ModSec Rules** (`/modsec/rules`) - per-rule management:
- View the CSM rules with descriptions and hits in the last 24 hours
- Enable or disable individual rules; changes are staged and applied with one reload
- Turn firewall escalation off for a rule: the rule still denies the request, but CSM does not block the IP in the firewall
- Escalation exclusions are listed and edited here even when rule management (`modsec.rules_file`, `modsec.overrides_file`, `modsec.reload_command`) is not configured, since the daemon applies them either way

## API Endpoints

```
GET  /api/v1/modsec/stats            WAF statistics
GET  /api/v1/modsec/blocks           Blocked request log
GET  /api/v1/modsec/events           WAF event details
GET  /api/v1/modsec/rules            Loaded rules list
POST /api/v1/modsec/rules/apply      Apply the set of disabled rules and reload
GET  /api/v1/modsec/rules/escalation Rule IDs excluded from firewall escalation
POST /api/v1/modsec/rules/escalation Exclude one rule from escalation or turn it back on
```
