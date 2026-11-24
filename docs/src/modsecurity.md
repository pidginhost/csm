# ModSecurity Integration

CSM detects ModSecurity (WAF) on Apache, Nginx, and LiteSpeed across cPanel and plain Linux hosts. Every platform gets status, staleness, and event detection. Custom rule deployment, override writes, and reload management are cPanel-only.

## Supported Web Servers

| Web server | Config candidates | Status check | Custom rule deployment |
|-----------|-------------------|--------------|------------------------|
| Apache on cPanel EA4 | `/usr/local/apache/conf/*`, `/etc/apache2/conf.d/modsec*`, `whmapi1 modsec_is_installed` | Yes | Yes (via cPanel modsec user conf) |
| Apache on Debian/Ubuntu | `/etc/apache2/mods-enabled/security2.conf`, `/etc/apache2/conf-enabled/*`, `/etc/apache2/conf.d/modsec2.conf` | Yes | No |
| Apache on RHEL/Alma/Rocky | `/etc/httpd/conf.d/mod_security.conf`, `/etc/httpd/conf.modules.d/*` | Yes | No |
| Nginx on any distro | `/etc/nginx/nginx.conf`, `/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf`, `/etc/nginx/modsec/main.conf` | Yes | No |
| LiteSpeed | `/usr/local/lsws/conf/httpd_config.xml`, `/usr/local/lsws/conf/modsec2.conf` | Yes | cPanel only |

### When ModSecurity is not installed

The `waf_status` check emits an install hint for the platform:

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

## Features

| Feature | What it does |
|---------|--------------|
| Custom CSM rules | Ships rules with IDs 900000-900999 in `configs/csm_modsec_custom.conf`. cPanel only. See [CSM rules](#csm-rules). |
| Rule override management | Writes `SecRuleRemoveById` directives to suppress false positives. |
| Escalation control | Changes rule severity or action per rule. |
| Live deny escalation | Turns repeated deny events from one IP into a finding that feeds auto-response blocking. See [Deny escalation](#deny-escalation). |
| Disabled-scope detection | Reports domains and accounts with the engine switched off. See [Disabled-scope detection](#disabled-scope-detection). |
| WAF event log parsing | Correlates events by IP, URI, and rule ID. |
| Hot-reload | Applies changes without an Apache restart. cPanel only. |
| Rule activation | Reloads the web server when CSM's installed rules change. See [Rule activation](#rule-activation). |

## Rule activation

ModSecurity reads rules only when the web server starts or reloads. CSM reloads the web server for you when you set `modsec.reload_command`.

- When CSM's installed rule sections change, for example after an upgrade or `csm install`, the daemon runs `modsec.reload_command` at startup or during its WAF check.
- Each rule change reloads once.
- Standalone `csm check` runs never reload.
- A failed reload raises a `waf_status` warning and is retried.
- Without a command, CSM only warns at startup and the rules wait for the next web server restart.

### Choosing the reload command

The reload command runs inside CSM's systemd sandbox. Use a service-manager command such as `systemctl reload lsws` for LiteSpeed, so the web server's service performs the reload. Direct reload scripts inherit CSM's filesystem restrictions and may fail.

A LiteSpeed reload restarts workers and can briefly raise load.

## Deny escalation

Repeated ModSecurity deny events from one IP emit an escalation finding that feeds auto-response blocking. CSM-owned rules keep their per-rule escalation controls. CSM rules that match one specific exploit escalate on the first deny.

- First-deny escalation requires a blocking action for an exact CSM rule ID.
- Request text cannot turn a warning into a deny.
- Disabling a rule's firewall escalation excludes both new events and retained evidence from later blocking decisions.
- Existing firewall bans keep their configured expiry.

### The default exclusion for upload progress requests

CSM adds the default escalation exclusion for browser-marked upload progress requests once, including on upgrade, and keeps later operator changes. [PHP session upload-progress filter](#php-session-upload-progress-filter) explains the rule behind it.

If the saved exclusions cannot be read, CSM keeps running and blocking requests but pauses ModSecurity firewall escalation. The rules page reports the error and does not overwrite the exclusions. The next start retries the default update.

## Disabled-scope detection

CSM reports domains and accounts with the engine switched off. It covers both the userdata flag and the per-account and per-domain config includes that Apache and LiteSpeed use in the std and ssl trees.

A malware finding from a scheduled or account scan gets a context line when it is on such an account, or on a file served by such a domain. The line names the scope and the file that switches the engine off. It shows in alerts, the web UI, scan reports, webhooks and the audit log.

- CSM reads only the accounts and sites with malware findings for this.
- The line is not part of the finding's identity, and the finding keeps its severity.
- Turning the engine off or on neither re-alerts the finding nor undoes a dismissal.

## Rule staleness alerts

Rule-staleness alerts scan two layouts:

- The flat CRS layout used by distro packages, `/usr/share/modsecurity-crs/rules/*.conf`.
- cPanel vendor trees, including nested layouts such as `modsec_vendor_configs/VENDOR/rules/*.conf`.

| Host | What CSM checks |
|------|-----------------|
| cPanel, when WHM provides the mapping | CSM maps WHM's active configuration files to their vendor trees and checks the newest artifact in each loaded tree. |
| cPanel when WHM cannot provide the mapping, and other platforms | CSM judges staleness by the oldest rule artifact in the scanned directories. This is the conservative choice: a fresh rule tree that is not loaded cannot hide stale rules that are in use. |

The cPanel mapping has three effects:

- It honors individual configuration overrides.
- It keeps retired trees out of the result.
- It prevents a fresh unloaded vendor from hiding a stale loaded one.

LiteSpeed also keeps the on-disk check as a backstop while cPanel rebuilds the active configuration list and rule tree.

Update instructions are platform-specific: `apt update && apt upgrade modsecurity-crs`, `dnf upgrade modsecurity-crs`, or WHM on cPanel.

## CSM rules

### LiteSpeed Cache role-simulation filter

The LiteSpeed Cache role-simulation filter covers privileged routes and writes, including WordPress REST method overrides, when requests carry simulation cookies with a weak hash. Ordinary public GET/HEAD crawling remains allowed.

This is a request-scoped mitigation. Public reads still run under the simulated identity, so upgrading the vulnerable plugin remains necessary.

The usual hash discriminator is 1-16 alphanumeric characters versus the fixed plugin's 32-character hashes. Numeric equivalents are also filtered because the vulnerable plugin compares hashes loosely; padding or exponent notation must not turn a weak hash into an exempt one. These checks also keep public crawler reads allowed.

### WordPress user enumeration filter

The WordPress user enumeration filter blocks anonymous requests for the REST users route. It matches the route in any letter case, in both forms:

- The route follows `wp-json/` in the path.
- The route starts at `wp/v2/users` in the `rest_route` query parameter.

Other page paths and REST namespaces are left alone. Query values are matched as already decoded by the query parser.

Requests that carry an `Authorization` header or a WordPress logged-in cookie pass, so admin screens, the editor and Application Password clients keep working. Both are presence checks: the filter turns away anonymous scanners, and WordPress still decides who is signed in.

The filter has these limits:

- It runs in phase 1 and does not inspect request bodies.
- A route supplied only in a POST body, including with a REST method override, is outside its scope.
- Sites that need to restrict the public users endpoint must enforce that policy in WordPress.

Disabling rule `900112` disables this filter for both route forms. Its helper rules only set transaction-local flags and do not block requests.

### PHP session upload-progress filter

The PHP session upload-progress filter denies requests whose form field names contain PHP's default `PHP_SESSION_UPLOAD_PROGRESS` field name. The match is case-insensitive, so quoted spellings are covered. A custom `session.upload_progress.name` is outside this filter's coverage.

PHP handles that field before any script runs, which leaves the web server as the only layer that can drop the request. See [CVE Mitigations](cve-mitigations.md) for the PHP-side setting that removes the handler.

| Request | What happens |
|---------|--------------|
| GET or HEAD | It passes. |
| Another method, with both `Origin` and `Sec-Fetch-Site` absent | The first-deny escalation rule handles it. |
| Another method, marked by a browser | The separate rule handles it. That rule's escalation is off by default. |

Keep the default escalation exclusion for that browser-marked rule, to avoid browser-steered bans. See [The default exclusion for upload progress requests](#the-default-exclusion-for-upload-progress-requests). A browser whose extension or proxy strips `Origin` on a plain-HTTP request can still reach the first-deny rule.

## Web UI Pages

### ModSecurity (`/modsec`)

The page shows the WAF status overview, the event log and the active block list. You can filter by time range, minimum severity, and source country.

### ModSec Rules (`/modsec/rules`)

The page manages rules one by one:

- View the CSM rules with descriptions and hits in the last 24 hours.
- Enable or disable individual rules. Changes are staged and applied with one reload.
- Turn firewall escalation off for a rule. The rule still denies the request, but CSM does not block the IP in the firewall.

Escalation exclusions are listed and edited here even when rule management (`modsec.rules_file`, `modsec.overrides_file`, `modsec.reload_command`) is not configured, since the daemon applies them either way.

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

## Details

This section is reference material: how CSM reads ModSecurity logs and rule files, with the exact rules and known limits.

### Which error-log lines count as ModSecurity events

Live monitoring, scheduled WAF checks, and the Web UI use the same parser.

- The module marker, `ModSecurity:` or `[MODSEC]`, must follow the server's structured header directly.
- Markers inside ordinary file errors, PHP errors, or other message text do not create WAF detections.
- Standard Apache, Nginx and LiteSpeed headers are accepted. Custom headers outside those formats are ignored.
- On Apache 2.4 a line must carry ModSecurity's own module tag (`security2` or `security3`).
- Lines that another module tags, such as PHP or CGI output, and LiteSpeed PHP stderr lines are never ModSecurity events, even when their text holds a ModSecurity message.
- A LiteSpeed line must have its standard header, with the connection field directly before `[MODSEC]`.

### Where the client address comes from

ModSecurity error-log detections take the client address only from the structured prefix before `ModSecurity:` or `[MODSEC]`. Fields later in the same record cannot supply a client address.

| Log format | IPv6 handling |
|------------|---------------|
| Apache's module-qualified error prefix, including `[:error]` | The client field is `address:port`. For an unbracketed IPv6 address CSM treats the number after the last colon as the connection port, not as part of the address. |
| Legacy Apache and libmodsecurity client fields | They keep the complete IPv6 address. |
| Bracketed addresses with a port | Accepted. |
| Custom Apache logs | They must retain the module field to distinguish unbracketed IPv6 addresses with ports from bare addresses. |
| LiteSpeed IPv6 connection formats | Unsupported. Events keep an unknown client and cannot trigger an IP escalation. |

The Web UI uses the finding's recorded source address. For older findings it falls back to the raw log, reading the prefix only. It leaves the client unknown when neither is available.

### Apache 2.2-style headers

Apache 2.2-style headers without a module tag remain accepted for compatibility. They cannot distinguish ModSecurity output from a hosted site's message that starts with the same marker, so false alerts and visitor escalation remain possible with that format. Use module-tagged Apache logs to separate writers.

### File-based records are not authenticated

Header validation does not authenticate file-based records. Nginx can write literal line breaks from decoded filenames into its error log, which lets request text create an entire apparent record on a new line.

File-based real-time escalation and scheduled error-log scans remain exposed to that case. Native ModSecurity audit logs provide transaction framing for scheduled scans. Fixing real-time ingestion requires a source that preserves authenticated record boundaries rather than splitting arbitrary log bytes into lines.

### Scheduled audit scans

Scheduled audit scans read these formats:

- Native serial logs and concurrent indexes from ModSecurity 2 and libmodsecurity 3.
- libmodsecurity 3 JSON logs.

Counts use the recorded client address and the denial action or response status. Request and response content cannot select another client or cancel another client's counts. The `web_server.modsec_audit_logs` setting selects the candidate logs.

Only complete transactions within the recent line window contribute to these counts.

- The first scan, and scans after log rotation, read from the file's start to establish transaction boundaries.
- Later scans resume from the saved position.
- Large existing logs can take longer on the first scan.
- Memory use stays bounded, and incomplete writes wait for the next scan.

### Scanning error-log records instead

To scan error-log records, include the source in the `web_server.modsec_audit_logs` candidate list and identify it with `modsec_error_log` or `web_server.error_logs`. Detected platform error logs are also recognized.

- These sources count only messages starting with `Access denied with code` after the module marker.
- Request text cannot switch their interpretation to an audit index or suppress a denial.
- Other audit candidates accept native audit records only.
- Custom error-log candidates must be identified this way when upgrading.
- Changing a source's type restarts its scan, so earlier counts cannot carry across formats.

### How CSM tells a deny from a warning

LiteSpeed logs every rule match as `triggered!`, whether or not the rule denied the request. CSM therefore looks up each rule's action in the installed rule files. Apache logs say whether a request was denied and do not need the lookup.

A rule whose action is `block` does what the `SecDefaultAction` for its phase says, and `pass` when there is none, as in ModSecurity. OWASP CRS in anomaly scoring mode sets `pass`, so its detection rules count as warnings, not denies.

CSM does not follow `Include` order. A `SecDefaultAction` applies to the rules in its own directory and below, so a vendor pack's setup file governs that pack and no other.

CSM reads rule IDs, phases and actions from the rule's action argument. Text inside an operator, message or log data cannot override them. Explicit disruptive actions take precedence over inherited `block` actions.

When setup files in the applicable directory cannot be read or parsed:

- Inherited `block` actions remain blocking until CSM can resolve them.
- Explicit actions are still usable.
- Rules without a disruptive action remain unknown.

### How CSM walks rule directories

The directory walk follows symlinked packs and rule directories. Defaults follow the configured directory layout, including nested overrides. Directory cycles are reported as incomplete reads and prevent caching the result.

### Rule-action registry refresh

CSM checks the rule-action registry every five minutes and rebuilds it when rule or setup file contents change.

- Read failures leave the build uncached, so the next check retries.
- Files that were read in full but exceeded the parser's line limit are reported, without forcing unchanged files to be parsed again.
- Rules appended after parsing reaches the end of a file are picked up on the next check.

### Regression test for Apache ModSecurity v2

For Apache ModSecurity v2 regression validation, run `python3 scripts/test-litespeed-modsec.py` in a disposable Debian Linux environment with `apache2`, `libapache2-mod-security2`, `libapache2-mod-php`, and `python3` installed.

The test loads the complete shipped configuration and exercises HTTP requests through the actual engine and PHP parser. It does not establish LiteSpeed runtime compatibility. Verify changed rules on the supported LiteSpeed engine before deployment.
