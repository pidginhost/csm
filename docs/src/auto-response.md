# Auto-Response

When enabled, CSM automatically responds to detected threats. All actions are logged in the audit trail.

## Actions

| Action | Description |
|--------|-------------|
| **Kill processes** | Fake kernel threads, reverse shells, GSocket. Never kills root or system processes. |
| **Quarantine files** | Moves webshells, backdoors, phishing to `/opt/csm/quarantine/` with full metadata (owner, permissions, mtime). Restoreable from the web UI. |
| **Block IPs** | Adds attacker IPs to the nftables firewall with configurable expiry. Rate-limited by `auto_response.max_blocks_per_hour` (default 50/hour). |
| **Clean malware** | 7 strategies: @include removal, prepend/append stripping, inline eval removal, base64 chain decoding, chr/pack cleanup, hex injection removal, confirmed database cleanup. |
| **Drop malicious DB objects** | When `clean_database` is on, confirmed-malicious stored triggers/events/procedures/functions are dropped after a `SHOW CREATE` backup is recorded, so the drop is reversible. Detection runs regardless; the drop is gated on the operator opt-in. |
| **PHP shield** | Blocks PHP execution from uploads/tmp directories, detects webshell parameters. |
| **PAM blocking** | Instant IP block on brute force threshold breach. |
| **Subnet blocking** | Auto-blocks IPv4 /24 or IPv6 /64 when 3+ IPs from the same range attack. |
| **Permblock escalation** | Promotes temporary blocks to permanent after N repeated offenses. |
| **Auto-freeze (PHP relay)** | When the email PHP-relay detector fires (Path 1 / 2 / 4), runs `exim -Mf` against the message IDs the offending script is currently sending. Snapshots `activeMsgs` from the per-script window first, falls back to a spool walk if the snapshot was capped or if the finding is a late reputation event. Default dry-run; flip to live with `csm phprelay dry-run off`. Skips `volume_account` (per-cpuser, no scriptKey). Rate-limited to `auto_response.php_relay.max_actions_per_minute` (default 60). cPanel only. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only). |

## Configuration

```yaml
auto_response:
  enabled: true
  kill_processes: true
  quarantine_files: true
  block_ips: true
  block_expiry: "24h"         # default temp block duration
  max_blocks_per_hour: 50     # per-IP blocks per hour; 0/omitted uses default
  netblock: true              # enable subnet blocking
  netblock_threshold: 3       # IPs from same IPv4 /24 or IPv6 /64 before subnet block
  permblock: true             # promote temp blocks to permanent
  permblock_count: 4          # temp blocks before promotion

  # Response to http_scanner_profile findings: "challenge" (default)
  # routes the IP to the PoW challenge when challenge.enabled is true,
  # falling through to a firewall block when it is not; "block" always
  # hard-blocks without offering a challenge.
  http_scanner_action: "challenge"

  # SAFETY DEFAULT: dry_run defaults to TRUE when this key is absent.
  # In dry-run, BlockIP records the intended block to bbolt but does
  # NOT touch nftables. Manual operator commands (`csm firewall ...`)
  # bypass via BlockIPForce and always apply. Flip to false only after
  # verifying the policy in dry-run.
  dry_run: false

  # Advisory verdict callback. CSM POSTs each impending auto-block
  # to the panel before applying. The panel can downgrade to "allow"
  # (audit-only), attach `tenant_id` for downstream correlation, or
  # add a reason. CSM fails open on hook errors. Wire contract:
  # docs/verdict-callback-contract.md.
  verdict_callback:
    enabled: false
    url: ""                            # POST target
    hmac_secret: ""                    # signing secret, or use hmac_secret_env
    hmac_secret_env: ""
    allow_unsigned: false              # true only for staged unsigned rollouts
    require_response_signature: true   # reject unsigned callback replies
    timeout_sec: 2

  # PHP-relay auto-freeze (cPanel only). Off by default; opt in
  # explicitly. dry_run defaults to true even when freeze=true so an
  # operator who enables freeze without thinking gets a dry-run.
  php_relay:
    freeze: true                       # enable the exim -Mf hook
    dry_run: true                      # safe default; flip with `csm phprelay dry-run off`
    max_actions_per_minute: 60         # rolling 60s window cap on exim -Mf invocations
```

### Dry-run safety default

`auto_response.dry_run` defaults to `true` when the key is **absent**. This is deliberate: an operator who turns on `block_ips: true` without thinking through policy gets recorded-but-not-applied blocks. The dry-run count surfaces in `csm status --json` and `/api/v1/status` so dashboards can verify the policy before flipping live. CSM clears those records when auto-response starts or reloads in live mode, and ages out records older than a week while dry-run remains enabled.

IP auto-blocking still requires `firewall.enabled: true`. The firewall engine owns both live nftables mutations and dry-run block records; with the firewall disabled there is no engine to call, so `csm validate` warns on `auto_response.enabled: true` plus `block_ips: true`.

Verify dry-run state explicitly:

```bash
csm status --json | jq '.severities, .blocklist_size'
csm firewall status   # "Recently Blocked" entries with timestamps after the restart confirm live mode
```

To go live: set `dry_run: false`, run `csm rehash` (twice, due to the circular hash), then restart or SIGHUP-reload (the field is hot-reload-safe).

### Verdict callback (advisory)

When `verdict_callback.enabled: true`, every auto-block call POSTs a
signed JSON request to the panel before mutating nftables. CSM refuses
to start without `hmac_secret` or a non-empty `hmac_secret_env` value
unless `allow_unsigned: true` is set for a staged unsigned rollout.
Without that opt-in, an unsigned `allow` response is rejected and the
default block continues.
When a secret is configured, CSM also requires the panel to sign the
response body unless `require_response_signature: false` is set for a
staged rollout. With that opt-out, CSM still checks any echoed `nonce`
or `timestamp` when a secret is configured; a legacy response that
omits both keeps working. The panel can return `{"verdict": "block"}`
(apply), `{"verdict": "allow"}` (audit-only; CSM logs the decision and
skips nftables), or attach metadata (`tenant_id`, `note`). The callback
runs after local validation and infra-IP safety checks, and before the
dry-run gate, so panels can observe dry-run decisions too.

CSM fails open on hook errors (timeout, non-2xx, malformed body): the block continues as if the hook were disabled, or is recorded as dry-run when dry-run is active. The failure is written to the daemon log. Full request/response schema: [`docs/verdict-callback-contract.md`](https://github.com/pidginhost/csm/blob/main/docs/verdict-callback-contract.md).

### Infrastructure IP DNS guard

Hostnames listed in top-level `infra_ips` or `firewall.infra_ips` are resolved every 5 minutes and their current addresses feed the infra auto-block guard. If a hostname stops resolving, the daemon emits an `infra_ips_unresolvable` Warning finding and keeps the last known addresses protected during the grace period (default 10 min). The finding auto-clears when resolution recovers.

## Findings that always trigger IP block

When `auto_response.block_ips: true` and the firewall is enabled, the source IP is blocked for every finding in this list. The dry-run gate still applies if `dry_run: true`.

| Finding | Description |
|---------|-------------|
| `wp_login_bruteforce` | WordPress login flood via wp-login.php |
| `xmlrpc_abuse` | XML-RPC endpoint flood |
| `http_request_flood` | Per-IP HTTP request volume exceeds threshold (disabled by default; enable by setting `thresholds.http_flood_threshold > 0`) |
| `http_scanner_profile` | Random-URL probe pattern from one source IP (disabled by default; enable by setting `thresholds.http_scanner_min_requests > 0`; routed to the PoW challenge first unless `auto_response.http_scanner_action: "block"`) |
| `http_claimed_bot_unverified` | High-volume claimed crawler traffic while reverse-DNS verification is pending (routed to the PoW challenge first when challenge is enabled) |
| `http_ua_spoof` | IP spoofing a search-engine bot UA or exceeding the UA anomaly threshold (periodic; see configuration.md for opt-in flags) |
| `ftp_bruteforce` | FTP authentication flood |
| `smtp_bruteforce` | SMTP authentication flood |
| `smtp_probe_abuse` | Raw SMTP connect-rate flood before AUTH |
| `mail_bruteforce` | IMAP/POP3/ManageSieve authentication flood without matching successful mailbox activity |
| `mail_account_compromised` | Successful login from an IP that repeatedly failed auth on the same mailbox |
| `admin_panel_bruteforce` | phpMyAdmin or Joomla admin POST flood |
| `ssh_login_unknown_ip` | SSH login from an IP with no prior history |
| `ssh_login_realtime` | SSH login anomaly detected by realtime watcher |
| `c2_connection` | Outbound connection to a known C2 server |
| `ip_reputation` | IP flagged by AbuseIPDB / rspamd / upstream threat-intel |
| `local_threat_score` | IP crosses the aggregated internal attack-history threshold |
| `modsec_block_escalation` | ModSecurity deny escalation |
| `modsec_csm_block_escalation` | CSM-internal ModSecurity deny escalation |
| `waf_attack_blocked` | WAF high-volume attacker |
| `email_compromised_account` | Email account compromise indicator |
| `email_cloud_relay_abuse` | Cloud relay abuse |

Distributed HTTP flood rollups do not trigger a direct IP block because
they describe one targeted vhost, not one source IP. The per-IP findings
that feed the rollup still drive normal block decisions.

`mail_bruteforce_suspected` is also visibility only and does not feed either
auto-block path.

## Safety Guards

- Never kills root processes, system daemons, or cPanel services
- Infrastructure IPs (`infra_ips` in config) are never blocked
- Subnet blocks refuse the default route and any range that covers infrastructure, local host, allowed, or port-specific allowed IPs
- Quarantined files preserve full metadata for restoration
- Realtime signature auto-quarantine requires high confidence: category `webshell` or `dropper`, file size at least 512 bytes, and either Shannon entropy >= 5.5 or hex density > 20% with an obfuscated-execution signal. This prevents legitimate WordPress plugins from being quarantined.
- IP block rate limited by `auto_response.max_blocks_per_hour` (default 50/hour) to prevent runaway blocking
- CRITICAL alerts always bypass the email rate limit (default 30/hour)
- Trusted countries (`trusted_countries`) suppress login alerts from expected geolocations

## What CSM Detects in Real-Time

Beyond standard malware patterns, CSM detects advanced evasion techniques:

- **Fragmented function names**: attackers split `base64_decode` across variables (`$a="base"; $b="64_decode"`) to evade simple string matching
- **Appended payloads**: malicious code added to the end of large legitimate files, beyond typical scan windows. Realtime PHP checks scan the first and last 32KB, and periodic PHP content analysis scans a larger head window plus the tail.
- **Non-PHP backdoors**: Perl, Python, Bash CGI scripts in web directories (detects toolkits like LEVIATHAN)
- **SEO spam injection**: gambling/togel dofollow link injection into theme files
- **WordPress brute force**: real-time access log monitoring for wp-login.php and xmlrpc.php floods (blocks within seconds, not the 10-minute periodic scan)
- **Admin-panel brute force**: same access-log path, tracks POSTs to `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`, and Joomla `/administrator/index.php`. Emits `admin_panel_bruteforce` and auto-blocks the IP. Path matcher is intentionally tight to avoid false positives on shared hosting; Drupal and Tomcat Manager use different attack shapes and need separate detectors.
- **SMTP brute force and probes**: tails `/var/log/exim_mainlog` on cPanel and non-cPanel Exim hosts where the file exists. Emits `smtp_probe_abuse` and `smtp_bruteforce` (per-IP, auto-blocks), `smtp_subnet_spray` (per-/24, auto-blocks the whole subnet), and `smtp_account_spray` (per-mailbox, visibility only).
- **Mail brute force**: tails `/var/log/maillog` for direct IMAP, POP3, and ManageSieve auth failures. Composes with the existing geo-login monitor so `email_suspicious_geo` keeps working. Emits `mail_bruteforce`, `mail_bruteforce_suspected`, `mail_subnet_spray`, `mail_account_spray`, `mail_account_compromised`, and `mail_auth_backend_degraded`. Established good sources with a confined stale-password pattern emit the suspected advisory without auto-blocking; wider spraying and confirmed compromise still block. When the auth backend is degraded, `mail_bruteforce` and `mail_subnet_spray` auto-blocking pause until backend errors age out.
- **Mail auth backend probe (cPanel)**: independently of the log signals above, CSM opens the `cpdoveauthd` socket on a short interval. dovecot keeps answering its IMAP/POP3 ports during a cpdoveauthd outage, so cPanel's own service checks do not notice, yet every login fails regardless of password. When the probe finds the socket unreachable CSM raises `mail_auth_backend_degraded` and pauses both mail and SMTP brute-force auto-block. With `auto_response.mail_auth_recovery.restart_enabled`, CSM restarts the mail service once the backend has been continuously down past `down_grace` (default 10m, rate-limited), so a brief blip during maintenance never triggers a needless restart. Changes to mail auth recovery settings require a daemon restart.

## Dry-run precedence (Phase 4)

CSM has three independent dry_run knobs after Phase 4. Any dry_run
that is true wins; live actions require all applicable knobs to be
false.

| Layer | Knob | Default | Effect when true |
|-------|------|---------|------------------|
| Global | `auto_response.dry_run` | true | Suppress all automatic actions |
| Detector | `detection.direct_smtp_egress.dry_run` | true | Suppress detector-scoped action |
| Kernel | `bpf_enforcement.dry_run` | true | BPF program emits decision but allows traffic |

The kernel knob is consulted by the BPF program itself; the others
gate userspace action paths. All three default to true on a first
install so a configuration mistake cannot start blocking traffic.
