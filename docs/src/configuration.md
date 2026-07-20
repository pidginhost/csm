# Configuration

CSM is configured via `/etc/csm/csm.yaml`, with `--config <path>` to override. Legacy installs that only have `/opt/csm/csm.yaml` keep working; packaged upgrades migrate that file into `/etc/csm/csm.yaml` and leave the old path as a compatibility link. Optional drop-in fragments under `/etc/csm/conf.d/*.yaml` are merged on top of the main file at startup; see [conf.d drop-ins](#confd-drop-ins) below.

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

By default, web-root performance checks iterate `/home/*/public_html`, which is the cPanel layout. On a plain Linux host, point CSM at the actual web roots:

```yaml
account_roots:
  - "/var/www/*/public"            # e.g. Laravel/Symfony sites
  - "/srv/http/*"                  # Arch / generic layouts
  - "/home/*/public_html"          # add if you also have cPanel-style accounts
```

Each entry is a glob pattern expanded at scan time. Non-existent matches are silently dropped. If `account_roots` is empty and CSM is not on a cPanel host, the account-scan checks return no findings (they run but find nothing, which is the correct behavior for a plain-Linux host with no configured web roots).

The setting currently covers `perf_error_logs`, `perf_wp_config`, `perf_wp_transients`, and `perf_wp_cron`, including WP-Cron remediation roots. CMS integrity, phishing, `.htaccess`, and file-index scans still use the cPanel account layout.

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
    type: "slack"                       # slack, discord, generic, phpanel
    hmac_secret: ""                     # phpanel webhook signing secret
    hmac_secret_env: ""                 # env var containing phpanel signing secret
    per_finding: false                  # phpanel sends one signed POST per finding
  heartbeat:
    enabled: false
    url: ""                             # healthchecks.io, cronitor, dead man's switch
  max_per_hour: 10                      # alert emails/hour; CRITICAL always bypasses. Code default 30; the shipped csm.yaml template sets 10
  block_digest:
    enabled: false                      # send per-country rollups for auto-blocked IPs
    countries: []                       # empty = trusted countries, then all countries
    interval: "1h"                      # digest cadence
    live: false                         # also send one alert per qualifying block
    send_on: "any"                      # any | customer
    channel: ""                         # empty = enabled alert channels; requires email or webhook enabled
    min_block: 1                        # 0 sends empty heartbeat digests
  audit_log:                            # SIEM-friendly per-finding stream
    file:
      enabled: false
      path: /var/log/csm/audit.jsonl    # default; logrotate fragment ships with the package
    syslog:
      enabled: false
      network: udp                      # udp | tcp | unix | unixgram | tls
      address: 127.0.0.1:514            # host:port, or filesystem path for unix variants
      facility: local0                  # default: local0
      tls_ca: ""                        # optional CA cert for tls transport

# --- Integrity ---
integrity:
  binary_hash: ""                       # populated by baseline/rehash
  config_hash: ""                       # populated by baseline/rehash/reload
  confd_hash: ""                        # populated by baseline/rehash/reload
  immutable: true                       # apply chattr +i to the installed binary during install/rehash

# --- Thresholds ---
thresholds:
  mail_queue_warn: 500                  # default: 500
  mail_queue_crit: 2000                 # default: 2000
  state_expiry_hours: 24                # default: 24
  deep_scan_interval_min: 60            # minutes between deep scans (default: 60)
  wp_core_check_interval_min: 60        # WordPress core checksum interval (default: 60)
  webshell_scan_interval_min: 30        # webshell scan interval (default: 30)
  filesystem_scan_interval_min: 30      # filesystem scan interval (default: 30)
  exposed_file_scan_depth: 2            # directory levels below each web docroot (default: 2, max: 10)
  multi_ip_login_threshold: 3           # IPs per account before alert (default: 3)
  multi_ip_login_window_min: 60         # time window for multi-IP check (default: 60)
  cred_stuffing_distinct_accounts: 5    # failed accounts from one IP before credential_stuffing (default: 5)
  plugin_check_interval_min: 1440       # WordPress plugin check interval (default: 1440)
  brute_force_window: 5000              # failed auth attempts window (default: 5000)
  domlog_max_files: 500                 # per-domain access logs per WP brute-force scan (default: 500)
  domlog_tail_lines: 500                # trailing lines tailed from each domlog per scan (default: 500)
  domlog_max_age_min: 30                # skip per-domain access logs untouched in this many minutes (default: 30)
  mail_log_tail_lines: 500              # trailing lines of /var/log/exim_mainlog read by the mail-per-account scanner (default: 500)
  syslog_messages_tail_lines: 200       # legacy direct-check FTP tail only; daemon FTP detection follows the log forward and ignores this setting (default: 200)
  ftp_fail_window_min: 30               # sliding window (minutes) for per-IP pure-ftpd auth-failure accumulation before ftp_bruteforce (default: 30)
  account_scan_max_files: 10000         # account and mail-domain paths per scanner cycle (default: 10000)
  # If this cap clips /home/<account>/ paths, account_scan_truncated names the affected account.
  crontab_base64_blob_max_bytes: 16384  # encoded bytes per crontab base64 candidate before decoded-content matching; must be a multiple of 4 (default: 16384)

  # Full-scan subsystem (`csm scan --full`) and rolling content coverage.
  full_scan_max_file_mb: 16            # cap on a single file scanned by a full scan, in MiB (default: 16)
  scan_job_retention: 20               # completed full-scan job records kept in the store (default: 20)
  rolling_coverage: true               # tri-state; default on. Each cycle content-scans a slice of dormant files past the mtime cap so old planted files get covered over time. Set false to disable
  dropper_detection: true              # tri-state; default on. Real-time flag for a PHP/executable created under a web docroot and unlinked before the TTL probe. Set false to disable
  dropper_unlink_ttl_sec: 300          # seconds a fresh docroot PHP/executable is tracked before the self-delete probe (default: 300, range 30-3600)

  # HTTP request flood, User-Agent spoof, and distributed HTTP detection.
  # These detectors scan the same per-vhost access-log stream as the WP
  # brute-force scanner; no extra log tailer is needed.
  #
  # http_flood_threshold: minimum per-IP request count inside the window
  # that emits http_request_flood. 0 disables the detector. The detector
  # ships disabled so operators can sample local baseline traffic first.
  # Adjust up for CDNs or CGNAT-heavy visitor pools before enabling.
  http_flood_threshold: 0              # 0 = disabled; set after sampling baseline traffic
  http_flood_window_min: 5             # rate window in minutes (default: 5)

  # http_ua_spoof_threshold: per-IP per-window count for non-browser UA
  # kinds (including claimed search-engine bots such as Googlebot/Bingbot/
  # Applebot that fail reverse-DNS confirmation) before http_ua_spoof fires.
  # A single bot-like request from a residential or mobile client no longer
  # hard-blocks it; sustained activity is required. Raise this for visitor
  # pools that legitimately send unusual User-Agents.
  http_ua_spoof_threshold: 30          # default: 30

  # xmlrpc_threshold: per-IP POST /xmlrpc.php count before xmlrpc_abuse fires
  # in access-log based detectors (a hard auto-block). WordPress sites using
  # Jetpack, the mobile app, or WooCommerce make many legitimate xmlrpc.php
  # calls, so this defaults higher than the legacy value. Set 0 to disable the
  # check entirely; an absent key uses the built-in default.
  xmlrpc_threshold: 100                # default: 100; 0 = disabled

  # http_distributed_min_ips: distinct already-abusive source IPs that hit
  # the same vhost in one scan window before a per-vhost distributed flood
  # finding fires. 0 disables the rollup for existing configs that do not
  # opt in.
  http_distributed_min_ips: 10         # sample setting; omit or set 0 to disable

  # URL scanner profile: fires http_scanner_profile for source IPs whose
  # in-window traffic is almost entirely probe-error responses spread
  # across many distinct request paths -- the shape of random-URL
  # enumeration hunting for downloadable files, exposed backups, and
  # dormant shells. Three gates must all pass: a minimum request volume,
  # a minimum error percentage, and a minimum count of distinct error
  # paths (query strings stripped, so cache-buster URLs on one missing
  # endpoint count once). A visitor following dead links, a broken image
  # hammered by one page, and a site migration all stay out of scope.
  #
  # 301 is deliberately not in the default status set: http->https and
  # www redirects make every legitimate visitor 301-heavy, and a site
  # migration redirects entire domains. Add 301 to
  # http_scanner_status_codes only on hosts where that traffic shape is
  # impossible.
  http_scanner_min_requests: 0         # volume gate; 0 = disabled (default); 30 is a safe start
  http_scanner_error_pct: 90           # min % of requests with probe-error status (default: 90)
  http_scanner_min_distinct_paths: 10  # min distinct error paths, max 512 (default: 10)
  http_scanner_status_codes: [404, 403] # statuses counted as probe errors (default: 404, 403)

  # Distributed expensive-request crawl from one ASN. The detector fires
  # only when request breadth, uncacheable volume, account share, and PHP
  # worker saturation agree. Set min_ips to 0 to disable.
  http_asn_crawl_window_min: 60
  http_asn_crawl_min_ips: 25
  http_asn_crawl_min_expensive: 250
  http_asn_crawl_min_share_pct: 50
  http_asn_crawl_high_amp_pct: 50
  http_asn_crawl_high_volume_mult: 4
  http_asn_crawl_saturation: 0          # 0 = performance.php_process_warn_per_user
  http_asn_crawl_max_prefix: 8
  http_asn_crawl_16_pref_pct: 60
  http_asn_crawl_max_tracked_ips: 20000
  http_asn_crawl_allowlist_asns: []
  http_asn_crawl_reverse_proxy_asns: [13335, 54113, 20940]

  # These three opt-in flags extend UA spoof detection to additional UA
  # classes. Leave disabled on busy shared hosts; scripting-language agents
  # and headless browsers appear on many legitimate monitoring stacks.
  http_ua_scripting_enabled: false     # flag curl/wget/python-requests/Go-http style UAs
  http_ua_headless_enabled: false      # flag Puppeteer/Playwright/PhantomJS UAs
  http_ua_empty_enabled: false         # flag requests with no UA at all

  # SMTP brute-force tracker (Exim mainlog, dovecot SASL on submission ports)
  smtp_bruteforce_threshold: 5            # per-IP failed auths before block (default: 5)
  smtp_bruteforce_window_min: 10          # sliding window in minutes (default: 10)
  smtp_bruteforce_suppress_min: 60        # cooldown between repeat findings (default: 60)
  smtp_bruteforce_subnet_threshold: 8     # unique IPs per /24 before subnet block (default: 8)
  smtp_account_spray_threshold: 12        # unique IPs targeting one mailbox before visibility finding (default: 12)
  smtp_bruteforce_max_tracked: 20000      # soft cap on tracked entries; oldest evicted (default: 20000)

  # SMTP probe-abuse tracker (raw connect-rate per IP; catches scanners that
  # never reach AUTH). Threshold sized well above any legitimate MUA usage.
  smtp_probe_threshold: 100               # per-IP connects before block (default: 100; explicit 0 disables)
  smtp_probe_window_min: 5                # sliding window in minutes (default: 5)
  smtp_probe_suppress_min: 60             # cooldown between repeat findings (default: 60)
  smtp_probe_max_tracked: 20000           # soft cap on tracked entries; oldest evicted (default: 20000)

  # Mail brute-force tracker (IMAP/POP3/ManageSieve via mail_logs source)
  mail_bruteforce_threshold: 5            # per-IP failed auths before block (default: 5)
  mail_bruteforce_window_min: 10          # sliding window in minutes (default: 10)
  mail_bruteforce_suppress_min: 60        # cooldown between repeat findings (default: 60)
  mail_bruteforce_subnet_threshold: 8     # unique IPs per /24 before subnet block (default: 8)
  mail_account_spray_threshold: 12        # unique IPs targeting one mailbox before visibility finding (default: 12)
  mail_bruteforce_max_tracked: 20000      # soft cap on tracked entries; oldest evicted (default: 20000)
  mail_brute_account_key: "builtin:dovecot-user" # builtin:dovecot-user | builtin:postfix-sasl | regex:<capture>
  modsec_escalation_hits: 3          # denies from one IP before ModSecurity escalation (default: 3)
  modsec_escalation_window_min: 10   # ModSecurity escalation window in minutes (default: 10)
  modsec_low_confidence_escalation_hits: 30 # low-confidence-only backstop (default: 30)

# --- Web server overrides ---
# Leave these empty to use auto-detected paths for the running platform.
web_server:
  type: ""                              # apache | nginx | litespeed; empty = detect
  config_dir: ""                        # optional Apache/Nginx config root
  access_logs: []                       # candidate access logs, replacing detected paths
  error_logs: []                        # candidate error logs, replacing detected paths
  modsec_audit_logs: []                 # candidate ModSecurity audit logs
  # Override the per-vhost access-log glob patterns. Empty uses the
  # auto-detected default for the panel (cPanel, Plesk, DirectAdmin,
  # bare Apache, or bare Nginx).
  domlog_globs: []
  # IPs or CIDRs whose X-Forwarded-For header is trusted for client-IP
  # extraction. Leave empty to ignore XFF and use RemoteIP as-is.
  trusted_proxies: []

# --- Infrastructure ---
infra_ips: []                           # management IPs/CIDRs/hostnames - never blocked

# --- Mail Logs ---
# Packaged releases include journald support. Custom builds need
# `make JOURNAL=1 build-yara` before `source: journal` can be selected.
mail_logs:
  source: auto                          # auto | file | journal
  file: ""                              # optional path override for file source
  units: ["postfix", "dovecot"]         # journal units for source=journal or auto fallback

# --- State ---
state_path: "/var/lib/csm/state"        # bbolt DB and state files

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
  http_asn_crawl_tempban: "24h"         # Critical ASN-crawl subnet ban duration
  max_blocks_per_hour: 50               # per-IP blocks per hour; 0/omitted uses default
  enforce_permissions: false            # auto-chmod 644 world/group-writable PHP files
  fix_wp_cron: false                    # on perf_wp_cron findings, auto-disable WP-Cron and install a per-user system cron
  http_scanner_action: "challenge"      # response for http_scanner_profile: "challenge" (default) routes to the PoW page, "block" bans the IP
  block_cpanel_logins: false            # block IPs on cPanel/webmail/FTP/API thresholded brute findings (multi-IP login, webmail/API brute, FTP brute). Single direct cPanel form logins stay audit-only regardless of this flag.
  netblock: false                       # auto-block IPv4 /24 or IPv6 /64 subnets
  netblock_threshold: 3                 # IPs from same IPv4 /24 or IPv6 /64 before subnet block
  permblock: false                      # promote temp blocks to permanent
  permblock_count: 4                    # temp blocks before promotion
  permblock_interval: "24h"             # window for counting temp blocks
  clean_database: false                 # auto-drop confirmed malicious DB objects after backup
  clean_htaccess: false                 # auto-clean .htaccess directives flagged by hardened detectors (backups under /opt/csm/quarantine/pre_clean/)
  virtual_patch_exposed_files: "off"    # off, manual CLI apply, or dry-run-gated auto apply except sample SQL
  disable_enforce_af_alg: false         # suspend periodic AF_ALG hardening re-assertion
  copy_fail_kill_process: false         # kill processes caught opening AF_ALG sockets via the live listener
  mail_auth_recovery:
    restart_enabled: false              # opt-in restart after sustained cPanel mail auth backend outage
    down_grace: "10m"                   # continuously-down duration before restart
    max_restarts_per_hour: 3            # hourly restart-attempt cap
    restart_command: "/usr/local/cpanel/scripts/restartsrv_dovecot"
  dry_run: true                         # safe default; previews IP blocks and web-exposed-file virtual patches
  verdict_callback:
    enabled: false                      # call panel before each auto-block
    url: ""                             # POST target for verdict requests
    hmac_secret: ""                     # signing secret, or use hmac_secret_env
    hmac_secret_env: ""                 # env var read at call time
    allow_unsigned: false               # true only for staged unsigned rollouts
    require_response_signature: true    # reject unsigned callback replies
    timeout_sec: 2                      # callback request timeout

  # PHP-relay auto-freeze. Off by default; only kicks in on cPanel hosts
  # where email_protection.php_relay.enabled is true. dry_run defaults to
  # true even when freeze is true, so an operator who enables freeze
  # without thinking gets a dry-run rather than a live exim -Mf storm.
  # Override at runtime with `csm phprelay dry-run on|off|reset`.
  php_relay:
    freeze: false                       # opt in to wire the exim -Mf hook into the alert pipeline
    dry_run: true                       # safe default; flip with `csm phprelay dry-run off [--persist]`
    max_actions_per_minute: 60          # rolling 60s cap on exim -Mf invocations

# --- Detection ---
detection:
  # Known-vulnerable WordPress plugin matching is default-on and alert-only.
  # Omit for the default, or set false to disable it. Allow entries suppress
  # only the exact reviewed slug and installed version.
  # vulnerable_plugin_scanning: true
  vulnerable_plugin_allow: []           # entries: <slug>@<version>, case-insensitive
  # db_object_scanning is tri-state: omit for the default (on),
  # `false` to explicitly disable. When off, the MySQL persistence
  # scanner emits no findings; the manual `csm db-clean --drop-object`
  # CLI keeps working for operator-driven cleanup.
  # db_object_scanning: true
  db_object_allowlist: []               # entries: <account>:<schema>:<type>:<name> -- suppresses db_unexpected_* warnings only
  admin_overlap_min_accounts: 2         # raise only if routine shared-admin accounts are expected on this host
  admin_overlap_trusted_emails: []       # exact reviewed admin emails that may manage multiple cPanel accounts
  admin_overlap_trusted_domains: []      # exact reviewed email domains for developer or reseller admin accounts
  # rescan_on_signature_update: true    # tri-state; omit for default-on, false to disable retroactive sweeps
  af_alg_backend: "auto"                # auto | bpf | auditd | none
  connection_tracker_backend: "auto"    # auto | bpf | legacy | none
  connection_poll_interval: 30s         # legacy connection tracker interval
  exec_monitor_backend: "auto"          # auto | bpf | legacy | none
  exec_monitor_poll_interval: 30m       # legacy process monitor interval
  sensitive_files_backend: "auto"       # auto | bpf | legacy | none
  sensitive_files_poll_interval: 5m     # sensitive-file poll/watchset refresh interval
  direct_smtp_egress:
    enabled: false                      # detect non-MTA local processes opening outbound SMTP
    backend: "auto"                     # auto | bpf | legacy | none
    dry_run: true                       # safe default for detector-scoped action
    ports: [25, 465, 587]               # destination ports to inspect
  bad_asn_outbound:
    enabled: false                      # off by default; third leg of the host_takeover chain. Needs the GeoLite2-ASN database and operator-supplied ASN lists
    blocked_asns: []                    # ASNs always treated as bad (e.g. known bulletproof hosters)
    allowed_asns: []                    # non-empty switches to allowlist mode: any destination ASN outside this set is treated as bad

# --- BPF Enforcement ---
bpf_enforcement:
  enabled: false                        # master switch for in-kernel denial
  dry_run: true                         # log intended denials, allow the connect
  direct_smtp_egress: false             # gate enforcement on direct SMTP egress matches
  verdict_callback: false               # userspace advisory callback after the BPF decision

# --- Challenge Pages ---
challenge:
  enabled: false                        # enable PoW challenge pages instead of hard block
  listen_addr: 127.0.0.1                # bind address; use 0.0.0.0 for public direct redirects
  listen_port: 8439                     # port for challenge server; must fit the TCP port range
  tls_cert: ""                          # optional HTTPS cert for direct/public challenge listener
  tls_key: ""                           # optional HTTPS key for direct/public challenge listener
  public_url: ""                        # required by webserver-integration, e.g. https://host:8439/challenge
  secret: ""                            # HMAC secret for tokens (auto-generated if empty)
  difficulty: 2                         # SHA-256 proof-of-work difficulty 0-5 (default: 2)
  trusted_proxies: []                   # IPs/CIDRs allowed to supply X-Forwarded-For
  port_gate:
    enabled: false                      # nftables gate for non-loopback challenge listener
  captcha_fallback:                     # widget for JS-disabled visitors (default off)
    provider: ""                        # "turnstile" | "hcaptcha" | "" (off)
    site_key: ""                        # public key embedded in the widget
    secret_key: ""                      # verified server-side
    timeout: 10s
  verified_session:                     # signed-cookie bypass for authenticated operators
    enabled: false
    cookie_name: csm_admin_session
    ttl: 4h
    admin_secret: ""                    # POST'd to /challenge/admin-token to mint cookie
  verified_crawlers:                    # reverse-DNS forward-confirm for search crawlers
    enabled: false
    providers: []                       # names: googlebot | bingbot
    cache_ttl: 15m

# --- PHP Shield ---
php_shield:
  enabled: false                        # watch the PHP Shield event log for alerts

# --- Reputation ---
reputation:
  abuseipdb_key: ""                     # AbuseIPDB API key for IP reputation lookups
  whitelist: []                         # IPs to never flag as malicious
  # Async PTR + forward-A verification for IPs that claim search-engine
  # bot UAs (Googlebot, Bingbot, Applebot). When an IP claims a bot UA
  # but reverse DNS does not confirm it, the request counts toward
  # http_ua_spoof. Transient DNS lookup failures fail open and are
  # retried later. Set false only if your resolver is unreliable. See
  # docs/src/auto-response.md for the always-block behavior.
  bot_verify_enabled: true              # default: true
  verified_bots: []                     # optional custom crawler identities
  # verified_bots:
  #   - name: "seranking"               # rDNS-verified crawler
  #     ua_substrings: ["serankingbacklinksbot"]
  #     rdns_suffixes: ["seranking.com"]
  #   - name: "perplexitybot"           # AI agent verified by published IP ranges
  #     ua_substrings: ["perplexitybot"]
  #     ip_ranges: ["18.97.9.96/29", "18.97.1.228/30"]
  bot_ranges:                           # built-in AI-crawler range refresh
    auto_update: true                   # default: true; restart required to change
    update_interval: "24h"              # default: 24h, minimum: 1h
  rspamd:
    enabled: false                      # include rspamd rolling history in IP reputation
    url: "http://127.0.0.1:11334"       # rspamd controller URL
    token: ""                           # controller password, or use token_env
    token_env: ""                       # env var read at query time
  upstream:
    enabled: false                      # include panel-side threat-intel cache scores
    url: ""                             # HTTPS base URL; HTTP only allowed for loopback
    token: ""                           # bearer token, or use token_env
    token_env: ""                       # env var read at query time
    cache_ttl_min: 15                   # local cache TTL for upstream scores
    timeout_sec: 5                      # upstream request timeout
  report:
    enabled: false                      # opt-in abuse report delivery; restart required
    classes: []                         # bruteforce | php_relay | credential_stuffing | bad_asn_egress
    spool_path: ""                      # default: <state_path>/abuse_reports.db
    spool_max: 10000                    # max queued reports per target
    targets:
      - name: ""                        # stable target name
        url: ""                         # HTTPS collector URL; HTTP only allowed for loopback
        transport: "hmac"               # hmac | ed25519
        node_id: ""                     # sender node ID
        key_id: ""                      # receiver key ID
        key_env: ""                     # HMAC secret or Ed25519 private key env var
        token_env: ""                   # optional bearer token env var for HMAC targets
  central:
    enabled: false                      # opt-in central scored-set consume; restart required
    set_url: ""                         # HTTPS scored-set endpoint; HTTP only for loopback
    pubkey_env: ""                      # env var with Ed25519 public key hex
    refresh_interval: 6h                # pull interval; default 6h
    action: "challenge"                 # off | challenge | block_if_local_corroborated
    block_threshold: 80                 # score needed before local corroboration can block

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
    download_url: ""                    # signed ZIP URL/template; supports {tier} and {version}
  disabled_rules: []                    # YARA rule names to exclude from Forge downloads
  # yara_worker_enabled: true           # tri-state: omit for the default (on), `false` to explicitly disable

# signatures.signing_key is mandatory whenever either signatures.update_url
# is set or signatures.yara_forge.enabled is true. It must be the hex
# Ed25519 public key used to verify detached .sig files for rule bundles.
# Remote update URLs must use HTTP or HTTPS and must not point at localhost,
# loopback, link-local, unspecified, or RFC1918 / ULA private addresses.
#
# YARA Forge upstream GitHub releases do not publish CSM detached signatures.
# To enable automatic Forge updates, mirror the ZIPs, sign each ZIP, publish
# the signature at the ZIP URL plus .sig, and set yara_forge.download_url to
# that signed mirror. Otherwise leave update_url empty and yara_forge.enabled
# false.

# --- Web UI ---
webui:
  enabled: true
  listen: "0.0.0.0:9443"               # address:port for HTTPS server
  auth_token: ""                        # Bearer/cookie auth token (auto-generated on install)
  tokens: []                            # optional scoped tokens: name/token/scope (admin or read)
  metrics_token: ""                     # optional Bearer token for /metrics only
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
  fail_mode: "open"                     # behavior when a scan cannot complete: "open" (default) delivers; "tempfail" defers so Exim retries

# --- Email Protection ---
email_protection:
  password_check_interval_min: 1440     # how often to audit email passwords (default: 1440)
  high_volume_senders: []               # accounts expected to send high volume (skip rate alerts)
  rate_warn_threshold: 50               # emails per window before warning (default: 50)
  rate_crit_threshold: 100              # emails per window before critical (default: 100)
  rate_window_min: 10                   # rate check window in minutes (default: 10)
  known_forwarders: []                  # expected plain mail forwarders

  # PHP-relay detector (cPanel only; gated by platform.IsCPanel at startup).
  # Off by default. When enabled, the daemon spawns the inotify spool
  # watcher, runs a startup spool walk, and starts the Path 2b retro scan
  # on /var/log/exim_mainlog. See docs/src/detection-realtime.md#php-relay
  # for what each path actually triggers on.
  php_relay:
    enabled: false                      # opt in to start the watcher
    rate_window_min: 5                  # Path 1 rolling window
    header_score_volume_min: 5          # Path 1: don't score until script has emitted N msgs
    absolute_volume_per_hour: 30        # Path 2 threshold per script
    account_volume_per_hour: 0          # Path 2b operator override; 0 = auto-derive from cpanel.config maxemailsperhour
    reputation_failures_per_24h: 3      # Path 3 threshold (Stage 2)
    fanout_distinct_scripts: 3          # Path 4 threshold
    fanout_distinct_recipients: 5       # Path 4 recipient-diversity gate; 0 disables only this gate
    fanout_window_min: 5                # Path 4 window
    baseline_sigma: 3.0                 # Path 5 (Stage 3)
    baseline_observation_days: 7        # Path 5 (Stage 3)
    policies_dir: "/opt/csm/policies/php_relay"  # mailer_classes.yaml + http_proxy_ranges.yaml; SIGHUP-reloadable
  cloud_relay:
    allow_users: []                     # full mailbox opt-outs for cloud-relay detection
    allow_domains: []                   # domain-wide opt-outs for cloud-relay detection

  # Email forward guard (cPanel only). Opt-in MTA-native enforcement for
  # external forward copies. Enforce mode can hold null-sender backscatter and
  # bad-sender-IP copies before they relay to an external provider, while the
  # local mailbox copy still delivers. Spam, malware, and auth-fail signals are
  # accounted in dry-run until Exim content scanning is wired. CSM is not in the
  # live mail path; an installed Exim rule can keep holding matching copies even
  # if the daemon is down. Held copies can be released or deleted from the Email page.
  forward_guard:
    enabled: false                      # master switch (default off)
    dry_run: true                       # account/log only, do not actually hold (default true)
    quarantine_retention_days: 14       # held-copy retention window
    skip_forwarders: []                 # reserved forwarder exemptions; not enforced yet
    hold_signals:                       # signal toggles, each default true
      bounce_backscatter: true          # null-sender bounce backscatter (enforceable)
      spam_flagged: true                # message flagged as spam (dry-run/accounting only)
      malware: true                     # message carries malware (dry-run/accounting only)
      bad_sender_ip: true               # originating IP has bad reputation (enforceable)
      auth_fail: true                   # sender failed SPF/DKIM/DMARC auth (dry-run/accounting only)

# --- Firewall ---
firewall:
  enabled: false

  # Open ports (IPv4). SSH (22) is intentionally absent; uncomment in
  # the YAML lists if sshd listens on 22. TCP 853 is DNS-over-TLS;
  # UDP 853 is DNS-over-QUIC.
  # 6277/24441 are DCC/Pyzor network checks used by SpamAssassin.
  tcp_in: [20,21,25,26,53,80,110,143,443,465,587,853,993,995,2077,2078,2079,2080,2082,2083,2091,2095,2096]
  tcp_out: [20,21,25,26,37,43,53,80,110,113,443,465,587,853,873,993,995,2082,2083,2086,2087,2089,2195,2325,2703]
  udp_in: [53,443,853]
  udp_out: [53,113,123,443,853,873,6277,24441]

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

  # Infra IPs/CIDRs/hostnames for firewall rules
  infra_ips: []

  # Rate limiting. SYN/conn-rate/UDP are dual-stack (IPv6 keyed per /64);
  # conn_limit is IPv4-only.
  conn_rate_limit: 200                  # new connections/min per source (CGNAT-tolerant; IPv6 per /64)
  syn_flood_protection: true            # per-source SYN flood meter (IPv6 per /64)
  conn_limit: 400                       # max concurrent connections per IPv4 source, IPv4 only (0 = disabled)

  # Per-port flood protection: rate-limit new connections per source IP and IP family.
  # Defaults are sized for a busy mail host: 600/300s = 120 new conns/min/IP,
  # which tolerates a Thunderbird/iPhone client opening 5-15 parallel sessions
  # while still capping single-IP flood storms.
  port_flood:
    - port: 25
      proto: tcp
      hits: 600
      seconds: 300
    - port: 465
      proto: tcp
      hits: 600
      seconds: 300
    - port: 587
      proto: tcp
      hits: 600
      seconds: 300

  # DoS-exempt ranges: bypass configured DoS meters and subnet auto-blocks.
  # See firewall.dos_exempt_ranges below for full details.
  dos_exempt_ranges: []                 # CIDRs or single IPs exempt from connection/mail-port meters and subnet auto-blocks; /0 and bare hostnames rejected at load
  dos_exempt_known_mail_providers: true # also exempt Google and Microsoft mail-provider egress ranges; dynamic, cached, updated every 12h (default: true)

  # UDP flood protection (per-source meter; IPv6 per /64)
  udp_flood: true
  udp_flood_rate: 100                   # packets per second
  udp_flood_burst: 500                  # burst allowance

  # Country blocking
  country_block: []                     # ISO country codes to block
  country_db_path: ""                   # path to MaxMind DB (uses geoip config if empty)

  # Silent drop (no logging)
  drop_nolog: [23,67,68,111,113,135,136,137,138,139,445,500,513,520]

  # IP limits
  deny_ip_limit: 3000                   # max permanent blocked IPs
  deny_temp_ip_limit: 500               # max temporary blocked IPs

  # Outbound SMTP restriction
  smtp_block: false                     # block outgoing mail except allowed users
  smtp_allow_users: [cpanel, mailman]   # extra outbound SMTP users; root and mailnull are always allowed
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
  wp_cron_fix:                          # tuning for the WP-Cron remediation (manual fix from the Web UI or auto_response.fix_wp_cron)
    interval_minutes: 15                # system cron frequency; default 15, clamped to [1, 60]
    php_bin: ""                         # php interpreter for the cron line; empty = auto-detect

# --- Cloudflare ---
cloudflare:
  enabled: false                        # auto-whitelist Cloudflare IP ranges
  refresh_hours: 6                      # how often to refresh Cloudflare IPs (default: 6)

# --- Threat Intel ---
c2_blocklist: []                        # known C2 server IPs to block permanently
backdoor_ports: [4444,5555,55553,55555,31337]  # ports indicating backdoor activity

# --- Update check ---
updates:
  check_enabled: true                   # notify only; CSM never downloads or applies updates
  interval: "24h"                       # release check interval
  github_api_url: ""                    # optional release API mirror or test endpoint
  package_name: "csm"                   # apt/dnf package name for package-manager fallback

# --- Incidents ---
incidents:
  auto_close:
    enabled: true                       # auto-close idle open/contained incidents
    dry_run: false                      # log decisions without writing status changes
    by_kind:
      mailbox_takeover: 24h
      mailbox_bruteforce: 24h
      credential_spray: 24h
      web_attack: 24h
      web_account_compromise: 168h
  spray_suppression:
    enabled: false                      # collapse one-source credential spray into one incident
    dry_run: true
    distinct_mailboxes: 10
    severity_escalate_at: 50
    per_check: [email_auth_failure_realtime, pam_bruteforce, credential_stuffing]
    max_tracked_ips: 10000
    block_at_severity: ""              # "" | high | critical
  auto_block:
    enabled: false                      # block source IPs from incident correlations
    block_at_severity: ""              # "" | high | critical
    kinds: []                           # empty means all non-spray kinds with remote_ip

# --- Disabled checks (skip whole categories per host) ---
# Listed finding names disable the scheduled check runner(s) that emit them,
# including sibling findings from the same runner. Realtime findings are not
# affected. Use for whole categories that don't apply to a host (e.g. WAF/web
# checks on DNS-only cPanel servers, where httpd is installed but no virtual
# hosts serve traffic).
# For email-only suppression, use `alerts.email.disabled_checks` instead.
disabled_checks: []                     # e.g. [waf_status, waf_rules, waf_detection_only]

# --- Retention (bbolt growth control) ---
retention:
  enabled: false                        # opt-in; when true, a daily sweep prunes old entries
  findings_days: 90                     # keep active findings this long (0 disables the findings sweep)
  history_days: 30                      # keep findings-history entries this long
  reputation_days: 180                  # keep IP reputation/attack entries this long
  sweep_interval: "24h"                 # how often the retention goroutine runs
  compact_min_size_mb: 128              # startup compaction floor; 0 disables auto-compaction
  compact_fill_ratio: 0.5               # compact when used_bytes / file_size drops below this

# --- Debug / diagnostics ---
debug:
  pprof_listen: ""                      # e.g. "127.0.0.1:6060"; MUST be loopback. Empty disables.
                                        # Reach it over SSH: go tool pprof http://127.0.0.1:6060/debug/pprof/heap

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

If both paths are empty, CSM generates an ECDSA self-signed certificate and key under `state_path`. Set both paths to use an operator-managed certificate. Configuring only one of the pair is invalid.

## Validation

```bash
csm validate           # syntax check
csm validate --deep    # syntax + connectivity probes (SMTP, webhooks)
csm config show        # display config with secrets redacted
```

## Editing csm.yaml by hand

CSM stores a sha256 of the main config in `integrity.config_hash` and
a separate digest of loaded drop-ins in `integrity.confd_hash`. It
refuses to start if the on-disk files disagree with those values. This
is a tamper-detection feature. There are two supported edit workflows
depending on which fields you touch.

### Fast path: SIGHUP reload (safe fields only)

For fields tagged as hot-reload-safe (`alerts`, `thresholds`,
`detection`, `suppressions`, `auto_response`, `bpf_enforcement`,
`reputation`, `email_protection`, `disabled_checks`), the daemon can
accept the change without a restart:

```bash
sudo cp /etc/csm/csm.yaml /etc/csm/csm.yaml.bak-$(date +%s)

# edit /etc/csm/csm.yaml with your favourite editor

sudo systemctl reload csm
sudo journalctl -u csm -n 20 --no-pager
```

`systemctl reload` sends SIGHUP (wired via `ExecReload=` in the unit
file). The daemon re-reads the file, validates it, diffs it against
the running config, and if every change is on a field tagged
`hotreload:"safe"` it swaps the new values into
the live config and re-signs the integrity hashes on disk. The
next check tick sees the new thresholds; fanotify marks are not
dropped.

The tagged-safe top-level fields are `alerts`, `thresholds`,
`detection`, `suppressions`, `auto_response`, `bpf_enforcement`,
`reputation`, `email_protection`, and `disabled_checks`. The Settings
API derives its restart hints from the same manifest that drives
`config.Diff`, so UI hints and SIGHUP behavior cannot drift silently.
Changes to their sub-keys are picked up on the next tick by the
periodic scanners, the auto-response helpers
(block/kill/quarantine/challenge/permission-fix), alert dispatch, and
the heartbeat.

`reputation.verified_bots` is reconciled on reload and the bot-verifier
cache is restamped when the list changes.

`reputation.bot_ranges` controls a long-lived updater goroutine and is
tagged restart-required. A reload that changes it emits
`config_reload_restart_required`; restart the daemon to change the
auto-update switch or interval.

Two sub-keys are runtime-state exceptions. They live under a safe-tagged
parent and SIGHUP accepts edits to them, but they seed long-lived
in-memory state at daemon startup. Restart the daemon if you need the
running process to use the new value:

- `reputation.whitelist` -- seeded into the threat database at
  startup. The threat database exposes its own runtime API for
  adding and removing whitelist entries (via the Threat
  Intelligence page in the Web UI or the `/api/v1/threat/*`
  endpoints); those paths survive restarts because the threat
  database persists the runtime list to disk. Reloading
  `reputation.whitelist` from csm.yaml does not automatically
  propagate to the running threat database.
- `email_protection.known_forwarders` -- captured by the forwarder
  watcher at startup and read by scheduled forwarder and mail-filter
  checks. No runtime API yet; send a restart if you edit this list.

`auto_response.mail_auth_recovery` is a restart-required sub-key under
the otherwise safe `auto_response` section. It is captured by the cPanel
mail auth backend probe at startup, so a reload that changes it emits
`config_reload_restart_required` and leaves the live config unchanged.

`alerts.block_digest` is restart-required under the otherwise safe
`alerts` section. The collector and ticker are built at startup, so a
reload that changes the digest settings emits
`config_reload_restart_required` and leaves the live config unchanged.
When `countries` is empty, the fallback to `suppressions.trusted_countries`
still follows safe reloads. Delivery uses the current email and webhook
settings. Digest output includes by-country, by-category, and by-reason
counts; WAF categories group ModSecurity escalations and high-volume WAF
attacker blocks together.

The rest of the sub-keys in every safe-tagged section are read per-call
(inside check functions, auto-response helpers, alert dispatchers) and
hot-reload cleanly on the next tick.

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
sudo cp /etc/csm/csm.yaml /etc/csm/csm.yaml.bak-$(date +%s)

# edit /etc/csm/csm.yaml with your favourite editor

sudo /opt/csm/csm rehash     # re-signs integrity hashes
sudo /opt/csm/csm validate   # syntax + value sanity
sudo systemctl restart csm
sudo systemctl status csm    # confirm active, no crash-loop
```

If the restart fails (most commonly because `rehash` was skipped),
roll back with
`sudo cp <backup> /etc/csm/csm.yaml && sudo systemctl restart csm`.
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

## conf.d drop-ins

Files matching `/etc/csm/conf.d/*.yaml` are loaded after the main config and **deep-merged** on top of it. Override with `--config-dir <path>` or `CSM_CONFIG_DIR`; the flag wins when both are set.

- **Order:** lexicographic by filename. Scalar keys in `20-overrides.yaml` override the same keys in `10-base.yaml`. Use a numeric prefix.
- **Merge semantics:** maps merge recursively; scalars replace the value from the main file; lists append in fragment order. All-scalar lists drop duplicate entries while keeping the first occurrence; structured lists such as `webui.tokens` keep every entry.
- **Trust:** override directories must be absolute, must exist, and must be owned by root or the running process. The directory and every loaded fragment must not be group- or world-writable. Safe symlinked fragments are allowed, so packaged profiles can still be linked into `/etc/csm/conf.d/`.
- **Integrity ownership:** drop-ins cannot set the `integrity` block. Integrity metadata is stored only in the main config.
- **Hash:** `integrity.config_hash` covers the main file and `integrity.confd_hash` covers loaded drop-ins. After editing a drop-in by hand, run `csm rehash` before restarting, or use `systemctl reload csm` so the daemon can re-sign after validating the merged config. Web settings saves refuse to bless a drop-in change that has not already been re-signed.
- **Use cases:** packaged integration profiles (e.g. `/usr/lib/csm/profiles/phpanel-agent.yaml` symlinked into `conf.d/`), per-host automation that should not touch the operator's `csm.yaml`, secret material rendered from a vault.

```bash
ls /etc/csm/conf.d/
# 10-phpanel-agent.yaml   20-tenant-overrides.yaml

csm validate                # validates the merged config
csm config show             # prints the merged, redacted config
csm config schema           # JSON Schema for editor / CI validation
```

`csm validate` and `csm config show` always operate on the **merged** config so you can audit the effective state without grepping fragments.

## detection.direct_smtp_egress

The direct SMTP detector's `backend` accepts `auto`, `bpf`, `legacy`, or `none`;
`ports` must contain TCP ports in the 1-65535 range. See
[Direct SMTP egress](direct-smtp-egress.md).

## bpf_enforcement

BPF enforcement requires a BPF-capable connection tracker at
runtime; `auto` falls back to legacy detection on older servers. See
[BPF enforcement](bpf-enforcement.md).

## firewall.dos_exempt_ranges

`dos_exempt_ranges` is a list of CIDRs or single IPs (/32 for IPv4, /128 for IPv6) declared by the operator. Entries are validated at startup; /0 default routes, bare hostnames, and malformed CIDRs are rejected before the daemon starts. Default: empty (no declared ranges).

`dos_exempt_known_mail_providers` (bool, default true) adds Google and Microsoft outbound mail IP ranges to the effective exempt set automatically. The ranges are sourced dynamically and cached on disk; a built-in snapshot covers startup before the first live refresh. The cache is refreshed every 12 hours.

Sources in the effective exempt set bypass the new-connection rate-limit for their IP family, the IPv4 concurrent connection-limit, and the TCP port 25/465/587 flood meters for their IP family. Subnet auto-block (spray, ASN-crawl, and netblock escalation) skips CIDRs that intersect an exempt range, and exempt IPs do not count toward the netblock threshold.

Exempt sources do not bypass: manual blocks (`csm firewall deny` or `csm firewall deny-subnet`), SYN flood protection, UDP flood protection, country blocking, and port policy. A manual block placed inside an exempt range still takes effect because blocked sets are evaluated before the DoS meters. See [Firewall - DoS-exempt ranges](firewall.md#dos-exempt-ranges).
