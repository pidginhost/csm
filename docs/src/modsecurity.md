# ModSecurity Integration

CSM detects and manages ModSecurity (WAF) on Apache, Nginx, and LiteSpeed across cPanel, plain Debian/Ubuntu, and plain AlmaLinux/Rocky/RHEL hosts. It deploys custom rules (cPanel only) and provides a web UI for rule overrides and escalation.

## Supported Web Servers

| Web server | Config candidates | Status check | Custom rule deployment |
|-----------|-------------------|--------------|------------------------|
| Apache on cPanel EA4 | `/usr/local/apache/conf/*`, `/etc/apache2/conf.d/modsec*`, `whmapi1 modsec_is_installed` | Yes | Yes (via cPanel modsec user conf) |
| Apache on Debian/Ubuntu | `/etc/apache2/mods-enabled/security2.conf`, `/etc/apache2/conf-enabled/*`, `/etc/apache2/conf.d/modsec2.conf` | Yes | Not yet (plain Linux) |
| Apache on RHEL/Alma/Rocky | `/etc/httpd/conf.d/mod_security.conf`, `/etc/httpd/conf.modules.d/*` | Yes | Not yet (plain Linux) |
| Nginx on any distro | `/etc/nginx/nginx.conf`, `/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf`, `/etc/nginx/modsec/main.conf` | Yes | Not yet (plain Linux) |
| LiteSpeed | `/usr/local/lsws/conf/httpd_config.xml`, `/usr/local/lsws/conf/modsec2.conf` | Yes | Not yet |

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

Rule-staleness alerts scan both the flat CRS layout (`/usr/share/modsecurity-crs/rules/*.conf`) used by distro packages and the per-vendor subdirectory layout used by cPanel (`/usr/local/apache/conf/modsec_vendor_configs/VENDOR/*.conf`). Update instructions are also platform-specific (`apt update && apt upgrade modsecurity-crs`, `dnf upgrade modsecurity-crs`, or WHM on cPanel).

## Features

- **Custom CSM rules** - IDs 900000-900999 in `configs/csm_modsec_custom.conf` (cPanel only today)
- **Rule override management** - `SecRuleRemoveById` directives for false positive suppression
- **Escalation control** - change rule severity or action per-rule
- **WAF event log parsing** - correlates events by IP, URI, and rule ID
- **Hot-reload** - apply changes without Apache restart (cPanel only)

## Web UI Pages

**ModSecurity** (`/modsec`) - WAF status overview, event log, active block list

**ModSec Rules** (`/modsec/rules`) - per-rule management:
- View loaded rules with descriptions
- Enable/disable individual rules
- Override rule severity or action
- Deploy custom rules

## API Endpoints

```
GET  /api/v1/modsec/stats            WAF statistics
GET  /api/v1/modsec/blocks           Blocked request log
GET  /api/v1/modsec/events           WAF event details
GET  /api/v1/modsec/rules            Loaded rules list
POST /api/v1/modsec/rules/apply      Apply custom rules
POST /api/v1/modsec/rules/escalation Change rule severity/action
```
