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
```

## Validation

```bash
csm validate           # syntax check
csm validate --deep    # syntax + connectivity probes (SMTP, webhooks)
csm config show        # display config with secrets redacted
```
