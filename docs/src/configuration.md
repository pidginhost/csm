# Configuration

CSM is configured via a single YAML file at `/opt/csm/csm.yaml`.

## Minimal Config

```yaml
hostname: "cluster6.example.com"

alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    smtp: "localhost:25"

webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: "your-secret-token"

infra_ips: ["10.0.0.0/8"]
```

## Full Reference

```yaml
hostname: "cluster6.example.com"

# --- Alerts ---
alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    from: "csm@cluster6.example.com"
    smtp: "localhost:25"
  webhook:
    enabled: false
    url: ""
    type: "slack"   # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""         # healthchecks.io, cronitor, dead man's switch
  max_per_hour: 10

# --- Web UI ---
webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: "your-secret-token"  # auto-generated on install

# --- Auto-Response ---
auto_response:
  enabled: false
  kill_processes: false
  quarantine_files: false
  block_ips: false
  block_expiry: "24h"
  netblock: false              # auto-block /24 subnets
  netblock_threshold: 3        # IPs from same /24 before subnet block
  permblock: false             # promote temp blocks to permanent
  permblock_count: 4           # temp blocks before promotion

# --- Firewall ---
firewall:
  enabled: false
  ipv6: false
  conn_rate_limit: 30          # new connections per minute per IP
  syn_flood_protection: true
  conn_limit: 50               # max concurrent connections per IP
  smtp_block: false            # restrict outbound SMTP to allowed users
  log_dropped: true

# --- GeoIP ---
geoip:
  account_id: ""
  license_key: ""
  editions:
    - GeoLite2-City
    - GeoLite2-ASN
  auto_update: true
  update_interval: 24h

# --- Infrastructure ---
infra_ips: []                  # management/monitoring CIDRs — never blocked

# --- Suppressions ---
suppressions:
  trusted_countries: ["US", "RO"]  # suppress cPanel login alerts from these
  upcp_window_start: "00:30"       # cPanel nightly update window
  upcp_window_end: "02:00"

# --- Signatures ---
signatures:
  rules_dir: "/opt/csm/rules"

# --- State ---
state_path: "/opt/csm/state"       # bbolt DB and state files

# --- Integrity ---
integrity:
  binary_hash: ""                   # auto-populated by install/rehash
  config_hash: ""

# --- Thresholds ---
thresholds:
  mail_queue_warn: 100
  mail_queue_crit: 500
  deep_scan_interval_min: 60       # minutes between deep scans

# --- ModSecurity ---
modsec_error_log: "/usr/local/apache/logs/error_log"
modsec:
  rules_file: "/etc/apache2/conf.d/modsec/csm_modsec_custom.conf"
  overrides_file: "/etc/apache2/conf.d/modsec/csm_overrides.conf"
  reload_cmd: "/scripts/restartsrv_httpd"

# --- Email AV ---
email_av:
  enabled: false
  clamav_socket: "/var/run/clamd.scan/clamd.sock"

# --- Email Protection ---
email_protection:
  rate_limit:
    enabled: false

# --- Reputation ---
reputation:
  abuseipdb_key: ""
  whitelist: []

# --- Challenge Pages ---
challenge:
  enabled: false
  difficulty: 4                    # SHA-256 proof-of-work difficulty

# --- PHP Shield ---
php_shield: false

# --- Performance ---
performance:
  load_warn: 10.0
  load_crit: 20.0
  php_processes_warn: 50
  php_processes_crit: 100
  swap_warn_pct: 50
```

## Validation

```bash
csm validate           # syntax check
csm validate --deep    # syntax + connectivity probes (SMTP, webhooks)
csm config show        # display config with secrets redacted
```
