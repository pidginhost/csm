# Configuration

CSM is configured via a single YAML file at `/opt/csm/csm.yaml`.

## Platform & Web Server

CSM auto-detects the host OS (Ubuntu, Debian, AlmaLinux, Rocky, RHEL, CloudLinux), control panel (cPanel, Plesk, DirectAdmin, or none), and web server (Apache, Nginx, LiteSpeed, or none) at daemon startup. The detected platform is logged as:

```
[2026-04-10 08:13:37] platform: os=ubuntu/24.04 panel=none webserver=nginx
```

The daemon then chooses the correct log paths, config candidates, and check set without any configuration from you. Verify with:

```bash
journalctl -u csm.service | grep platform:
```

### Web server overrides

For hosts with a custom layout (reverse proxy, non-standard package locations, chroot), add a `web_server:` section to `csm.yaml`. Every field is optional -- anything left blank falls back to auto-detection.

```yaml
web_server:
  type: "nginx"                          # apache | nginx | litespeed -- overrides auto-detect
  config_dir: "/etc/nginx"               # for info/diagnostics only
  access_logs:                           # tried in order until one exists
    - "/var/log/nginx/access.log"
    - "/srv/logs/nginx/access.log"
  error_logs:                            # used by ModSecurity deny watcher
    - "/var/log/nginx/error.log"
  modsec_audit_logs:
    - "/var/log/nginx/modsec_audit.log"
```

`modsec_error_log` (legacy single-path override) is still honored and takes precedence over `web_server.error_logs` for the ModSecurity watcher only:

```yaml
modsec_error_log: "/opt/myapp/logs/modsec_audit.log"
```

### Account roots (plain Linux web-scan coverage)

By default, the account-scan based checks (`perf_error_logs`, `perf_wp_config`, `perf_wp_transients`, and related) iterate `/home/*/public_html` which is the cPanel layout. On plain Ubuntu / AlmaLinux with Nginx or Apache, point CSM at your actual web roots:

```yaml
account_roots:
  - "/var/www/*/public"            # e.g. Laravel/Symfony sites
  - "/srv/http/*"                  # Arch / generic layouts
  - "/home/*/public_html"          # add if you also have cPanel-style accounts
```

Each entry is a glob pattern expanded at scan time. Non-existent matches are silently dropped. If `account_roots` is empty and CSM is not on a cPanel host, the account-scan checks return no findings (they run but find nothing, which is the correct behavior for a plain-Linux host with no configured web roots).

Today, three checks consume this: `perf_error_logs`, `perf_wp_config`, `perf_wp_transients`. The remaining account-scan checks (WordPress core integrity, phishing kit detection, htaccess tampering, fileindex, etc.) still assume the cPanel `/home/*/public_html` layout and will be migrated in a follow-up release.

## Minimal Config

```yaml
hostname: "csm.example.com"

alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    disabled_checks: []                   # optional: suppress these checks from email only
    smtp: "localhost:25"

webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: "your-secret-token"

infra_ips: ["10.0.0.0/8"]
```

## Full Reference

```yaml
hostname: "csm.example.com"

# --- Alerts ---
alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    from: "csm@csm.example.com"
    smtp: "localhost:25"
    disabled_checks: []                 # check names to keep in web/history but exclude from email
  webhook:
    enabled: false
    url: ""
    type: "slack"                       # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""                             # healthchecks.io, cronitor, dead man's switch
  max_per_hour: 10                      # default: 10

# --- Integrity ---
integrity:
  binary_hash: ""                       # auto-populated by install/rehash
  config_hash: ""                       # auto-populated by install/rehash
  immutable: false                      # prevent config changes at runtime

# --- Thresholds ---
thresholds:
  mail_queue_warn: 500                  # default: 500
  mail_queue_crit: 2000                 # default: 2000
  state_expiry_hours: 24                # default: 24
  deep_scan_interval_min: 60            # minutes between deep scans (default: 60)
  wp_core_check_interval_min: 60        # WordPress core checksum interval (default: 60)
  webshell_scan_interval_min: 30        # webshell scan interval (default: 30)
  filesystem_scan_interval_min: 30      # filesystem scan interval (default: 30)
  multi_ip_login_threshold: 3           # IPs per account before alert (default: 3)
  multi_ip_login_window_min: 60         # time window for multi-IP check (default: 60)
  plugin_check_interval_min: 1440       # WordPress plugin check interval (default: 1440)
  brute_force_window: 5000              # failed auth attempts window (default: 5000)

  # SMTP brute-force tracker (Exim mainlog, dovecot SASL on submission ports)
  smtp_bruteforce_threshold: 5            # per-IP failed auths before block (default: 5)
  smtp_bruteforce_window_min: 10          # sliding window in minutes (default: 10)
  smtp_bruteforce_suppress_min: 60        # cooldown between repeat findings (default: 60)
  smtp_bruteforce_subnet_threshold: 8     # unique IPs per /24 before subnet block (default: 8)
  smtp_account_spray_threshold: 12        # unique IPs targeting one mailbox before visibility finding (default: 12)
  smtp_bruteforce_max_tracked: 20000      # soft cap on tracked entries; oldest evicted (default: 20000)

  # Mail brute-force tracker (Dovecot direct: IMAP/POP3/ManageSieve via /var/log/maillog)
  mail_bruteforce_threshold: 5            # per-IP failed auths before block (default: 5)
  mail_bruteforce_window_min: 10          # sliding window in minutes (default: 10)
  mail_bruteforce_suppress_min: 60        # cooldown between repeat findings (default: 60)
  mail_bruteforce_subnet_threshold: 8     # unique IPs per /24 before subnet block (default: 8)
  mail_account_spray_threshold: 12        # unique IPs targeting one mailbox before visibility finding (default: 12)
  mail_bruteforce_max_tracked: 20000      # soft cap on tracked entries; oldest evicted (default: 20000)

# --- Infrastructure ---
infra_ips: []                           # management/monitoring CIDRs - never blocked

# --- State ---
state_path: "/opt/csm/state"            # bbolt DB and state files

# --- Suppressions ---
suppressions:
  upcp_window_start: "00:30"            # cPanel nightly update window start
  upcp_window_end: "02:00"              # cPanel nightly update window end
  known_api_tokens: []                  # API tokens to ignore in auth logs (e.g. ["phclient"])
  ignore_paths:                         # glob patterns to skip in filesystem scans
    - "*/cache/*"
    - "*/vendor/*"
  suppress_webmail_alerts: true         # don't alert on webmail logins
  suppress_cpanel_login_alerts: false   # don't alert on cPanel direct logins
  suppress_blocked_alerts: true         # don't alert on IPs that were auto-blocked
  trusted_countries: ["RO"]             # ISO 3166-1 alpha-2 - suppress cPanel login alerts from these

# --- Auto-Response ---
auto_response:
  enabled: false
  kill_processes: false                 # kill malicious processes
  quarantine_files: false               # move malware to quarantine
  block_ips: false                      # block attacker IPs via firewall
  block_expiry: "24h"                   # duration for temp blocks (e.g. "24h", "12h")
  enforce_permissions: false            # auto-chmod 644 world/group-writable PHP files
  block_cpanel_logins: false            # block IPs on cPanel/webmail login alerts
  netblock: false                       # auto-block /24 subnets
  netblock_threshold: 3                 # IPs from same /24 before subnet block
  permblock: false                      # promote temp blocks to permanent
  permblock_count: 4                    # temp blocks before promotion
  permblock_interval: "24h"             # window for counting temp blocks

# --- Challenge Pages ---
challenge:
  enabled: false                        # enable PoW challenge pages instead of hard block
  listen_port: 8439                     # port for challenge server (default: 8439)
  secret: ""                            # HMAC secret for tokens (auto-generated if empty)
  difficulty: 2                         # SHA-256 proof-of-work difficulty 0-5 (default: 2)

# --- PHP Shield ---
php_shield:
  enabled: false                        # watch php_events.log for PHP Shield alerts

# --- Reputation ---
reputation:
  abuseipdb_key: ""                     # AbuseIPDB API key for IP reputation lookups
  whitelist: []                         # IPs to never flag as malicious

# --- Signatures ---
signatures:
  rules_dir: "/opt/csm/rules"           # YAML signature rules directory
  update_url: ""                        # remote URL to fetch rule updates
  auto_update: false                    # auto-download rules on schedule
  update_interval: ""                   # how often to check (e.g. "24h")
  signing_key: ""                       # required for any remote rule update path; 64-char hex Ed25519 public key
  yara_forge:
    enabled: false                      # auto-fetch YARA Forge community rules
    tier: "core"                        # "core", "extended", "full" (default: "core")
    update_interval: "168h"             # how often to check for updates (default: weekly)
  disabled_rules: []                    # YARA rule names to exclude from Forge downloads
  yara_worker_enabled: false            # run YARA-X in a supervised child process (survives cgo crashes)

`signatures.signing_key` is mandatory whenever either `signatures.update_url` is set or `signatures.yara_forge.enabled` is `true`.
The value must be the hex-encoded Ed25519 public key used to verify detached `.sig` files for downloaded rule bundles.
It is not a PEM block and not a filesystem path.

If you are not operating a signed remote rule feed yet, leave `update_url` empty and keep `yara_forge.enabled: false`.

# --- Web UI ---
webui:
  enabled: true
  listen: "0.0.0.0:9443"               # address:port for HTTPS server
  auth_token: ""                        # Bearer/cookie auth token (auto-generated on install)
  tls_cert: ""                          # path to TLS certificate PEM file
  tls_key: ""                           # path to TLS private key PEM file
  ui_dir: ""                            # path to UI files on disk (default: /opt/csm/ui)

# --- Email AV ---
email_av:
  enabled: false
  clamd_socket: "/var/run/clamd.scan/clamd.sock"  # path to ClamAV daemon socket
  scan_timeout: "30s"                   # per-attachment scan timeout
  max_attachment_size: 26214400         # max single attachment size in bytes (25MB)
  max_archive_depth: 1                  # max nested archive extraction depth
  max_archive_files: 50                 # max files extracted from a single archive
  max_extraction_size: 104857600        # max total extraction size in bytes (100MB)
  quarantine_infected: true             # quarantine emails with infected attachments
  scan_concurrency: 4                   # parallel scan workers

# --- Email Protection ---
email_protection:
  password_check_interval_min: 1440     # how often to audit email passwords (default: 1440)
  high_volume_senders: []               # accounts expected to send high volume (skip rate alerts)
  rate_warn_threshold: 50               # emails per window before warning (default: 50)
  rate_crit_threshold: 100              # emails per window before critical (default: 100)
  rate_window_min: 10                   # rate check window in minutes (default: 10)
  known_forwarders: []                  # accounts that forward mail (skip rate alerts)

# --- Firewall ---
firewall:
  enabled: false

  # Open ports (IPv4)
  tcp_in: [20,21,25,26,53,80,110,143,443,465,587,993,995,2077,2078,2079,2080,2082,2083,2091,2095,2096]
  tcp_out: [20,21,25,26,37,43,53,80,110,113,443,465,587,873,993,995,2082,2083,2086,2087,2089,2195,2325,2703]
  udp_in: [53,443]
  udp_out: [53,113,123,443,873]

  # IPv6
  ipv6: false
  tcp6_in: []                           # if empty, uses tcp_in
  tcp6_out: []                          # if empty, uses tcp_out
  udp6_in: []                           # if empty, uses udp_in
  udp6_out: []                          # if empty, uses udp_out

  # Restricted ports (infra IPs only)
  restricted_tcp: [2086,2087,2325]      # WHM ports

  # Passive FTP range
  passive_ftp_start: 49152
  passive_ftp_end: 65534

  # Infra IPs for firewall rules
  infra_ips: []

  # Rate limiting
  conn_rate_limit: 30                   # new connections/min per IP
  syn_flood_protection: true
  conn_limit: 50                        # max concurrent connections per IP (0 = disabled)

  # Per-port flood protection
  port_flood:
    - port: 25
      proto: tcp
      hits: 40
      seconds: 300
    - port: 465
      proto: tcp
      hits: 40
      seconds: 300
    - port: 587
      proto: tcp
      hits: 40
      seconds: 300

  # UDP flood protection
  udp_flood: true
  udp_flood_rate: 100                   # packets per second
  udp_flood_burst: 500                  # burst allowance

  # Country blocking
  country_block: []                     # ISO country codes to block
  country_db_path: ""                   # path to MaxMind DB (uses geoip config if empty)

  # Silent drop (no logging)
  drop_nolog: [23,67,68,111,113,135,136,137,138,139,445,500,513,520]

  # IP limits
  deny_ip_limit: 30000                  # max permanent blocked IPs
  deny_temp_ip_limit: 5000              # max temporary blocked IPs

  # Outbound SMTP restriction
  smtp_block: false                     # block outgoing mail except allowed users
  smtp_allow_users: []                  # usernames allowed to send
  smtp_ports: [25,465,587]

  # Dynamic DNS
  dyndns_hosts: []                      # hostnames to resolve and whitelist periodically

  # Logging
  log_dropped: true                     # log dropped packets
  log_rate: 5                           # log entries per minute

# --- GeoIP ---
geoip:
  account_id: ""                        # MaxMind account ID
  license_key: ""                       # MaxMind license key
  editions:                             # MaxMind database editions
    - GeoLite2-City
    - GeoLite2-ASN
  auto_update: true                     # auto-update GeoIP databases (default: true when credentials set)
  update_interval: "24h"                # update check interval

# --- ModSecurity ---
modsec_error_log: ""                    # path to Apache/LiteSpeed error log for ModSec parsing
modsec:
  rules_file: ""                        # path to modsec2.user.conf
  overrides_file: ""                    # path to csm-overrides.conf
  reload_command: ""                    # command to reload web server (e.g. "/usr/sbin/apachectl graceful")

# --- Performance ---
performance:
  enabled: true
  load_high_multiplier: 1.0             # load average / CPU cores multiplier for warning (default: 1.0)
  load_critical_multiplier: 2.0         # load average / CPU cores multiplier for critical (default: 2.0)
  php_process_warn_per_user: 20         # per-user PHP process count warning (default: 20)
  php_process_critical_total_multiplier: 5  # total PHP processes / CPU cores for critical (default: 5)
  error_log_warn_size_mb: 50            # error log size warning threshold (default: 50)
  mysql_join_buffer_max_mb: 64          # MySQL join_buffer_size warning threshold (default: 64)
  mysql_wait_timeout_max: 3600          # MySQL wait_timeout warning threshold (default: 3600)
  mysql_max_connections_per_user: 10    # per-user MySQL connections warning (default: 10)
  redis_bgsave_min_interval: 900        # minimum seconds between Redis BGSAVE (default: 900)
  redis_large_dataset_gb: 4             # Redis dataset size warning threshold in GB (default: 4)
  wp_memory_limit_max_mb: 512           # WordPress memory_limit warning threshold (default: 512)
  wp_transient_warn_mb: 1               # WordPress transient data warning in MB (default: 1)
  wp_transient_critical_mb: 10          # WordPress transient data critical in MB (default: 10)

# --- Cloudflare ---
cloudflare:
  enabled: false                        # auto-whitelist Cloudflare IP ranges
  refresh_hours: 6                      # how often to refresh Cloudflare IPs (default: 6)

# --- Threat Intel ---
c2_blocklist: []                        # known C2 server IPs to block permanently
backdoor_ports: [4444,5555,55553,55555,31337]  # ports indicating backdoor activity

# --- Sentry (error reporting) ---
sentry:
  enabled: false                        # ship panics and selected errors to a Sentry server
  dsn: ""                               # Sentry project DSN
  environment: "production"             # e.g. "production", "staging"
  sample_rate: 1.0                      # 0.0 -> 1.0 (capture all errors)
  debug: false                          # SDK debug logs to stderr
```

## TLS Certificates

The Web UI serves over HTTPS. Configure TLS certificates under `webui`:

```yaml
webui:
  tls_cert: "/var/cpanel/ssl/cpanel/mycpanel.pem"   # certificate PEM file
  tls_key: "/var/cpanel/ssl/cpanel/mycpanel.pem"     # private key PEM file
```

On cPanel servers, you can reuse the cPanel self-signed certificate (both cert and key are in the same PEM file). For production, use a proper certificate from Let's Encrypt or your CA.

If `tls_cert` and `tls_key` are empty, the Web UI will not start.

## Validation

```bash
csm validate           # syntax check
csm validate --deep    # syntax + connectivity probes (SMTP, webhooks)
csm config show        # display config with secrets redacted
```

## Editing csm.yaml by hand

CSM stores a sha256 of the config in `integrity.config_hash` and
refuses to start if the on-disk file disagrees with it. This is a
tamper-detection feature. There are two supported edit workflows
depending on which fields you touch.

### Fast path: SIGHUP reload (safe fields only)

For fields tagged as hot-reload-safe (`thresholds`, `alerts`,
`suppressions`, `auto_response`, `reputation`, `email_protection`),
the daemon can accept the change without a restart:

```bash
sudo cp /opt/csm/csm.yaml /opt/csm/csm.yaml.bak-$(date +%s)

# edit /opt/csm/csm.yaml with your favourite editor

sudo systemctl reload csm
sudo journalctl -u csm -n 20 --no-pager
```

`systemctl reload` sends SIGHUP (wired via `ExecReload=` in the unit
file). The daemon re-reads the file, validates it, diffs it against
the running config, and if every change is on a field tagged
`hotreload:"safe"` it swaps the new values into
the live config and re-signs `integrity.config_hash` on disk. The
next check tick sees the new thresholds; fanotify marks are not
dropped.

The tagged-safe top-level fields are `thresholds`, `alerts`,
`suppressions`, `auto_response`, `reputation`, and
`email_protection`. Changes to their sub-keys are picked up on the
next tick by the periodic scanners, the auto-response helpers
(block/kill/quarantine/challenge/permission-fix), alert dispatch,
and the heartbeat.

Two sub-keys are exceptions. They live under a safe-tagged parent
but seed a long-lived in-memory structure at daemon startup; the
reload accepts the edit and re-signs the hash, but the running
structure keeps the old value until the next restart:

- `reputation.whitelist` -- seeded into the threat database at
  startup. The threat database exposes its own runtime API for
  adding and removing whitelist entries (via the Threat
  Intelligence page in the Web UI or the `/api/v1/threat/*`
  endpoints); those paths survive restarts because the threat
  database persists the runtime list to disk. Reloading
  `reputation.whitelist` from csm.yaml does not automatically
  propagate to the running threat database.
- `email_protection.known_forwarders` -- captured by the forwarder
  watcher at startup. No runtime API yet; send a restart if you
  edit this list.

If you change either of the above, send `systemctl restart csm`
instead of a reload. The rest of the sub-keys in every safe-tagged
section are read per-call (inside check functions, auto-response
helpers, alert dispatchers) and hot-reload cleanly on the next
tick.

Look for one of three log shapes in the journal:

- `SIGHUP: config reloaded; safe fields updated: [thresholds]` --
  success. The new values are live.
- `config_reload_restart_required: SIGHUP reload: restart-required
  fields changed: [hostname ...]; live config unchanged` -- the
  edit touched a field that cannot be hot-swapped. A Warning
  `config_reload_restart_required` finding is also emitted. Fall
  back to the restart path below.
- `config_reload_error: SIGHUP reload: parse failed ...` or
  `... validation error ...` -- the file on disk is not loadable
  or fails `csm validate`. A Critical `config_reload_error`
  finding is emitted. The live config is unchanged; fix the file
  and repeat.

### Restart path: unsafe fields

Fields not tagged `hotreload:"safe"` (the majority, including
`hostname`, `state_path`, `webui.listen`, `firewall.*`, `email_av.*`
and anything that survives only one re-init per daemon lifetime)
require a full restart. The integrity check must be re-signed first:

```bash
sudo cp /opt/csm/csm.yaml /opt/csm/csm.yaml.bak-$(date +%s)

# edit /opt/csm/csm.yaml with your favourite editor

sudo /opt/csm/csm rehash     # re-signs integrity.config_hash
sudo /opt/csm/csm validate   # syntax + value sanity
sudo systemctl restart csm
sudo systemctl status csm    # confirm active, no crash-loop
```

If the restart fails (most commonly because `rehash` was skipped),
roll back with
`sudo cp <backup> /opt/csm/csm.yaml && sudo systemctl restart csm`.
The backup carries its own matching hash so no second rehash is
needed.

### Config-management tools

Config-management workflows (Ansible, Puppet, Chef) should:

- For safe changes, notify `systemctl reload csm` instead of
  `restart`. The daemon re-signs the hash itself; no separate
  `csm rehash` step is required.
- For any change that may touch a restart-required field, run
  `csm rehash` before the restart notify fires. Or always send
  `reload` first, read the journal, and promote to `restart` only
  when the reload logs `restart-required`.
