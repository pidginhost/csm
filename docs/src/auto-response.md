# Auto-Response

When enabled, CSM automatically responds to detected threats. All actions are logged in the audit trail.

## Actions

| Action | Description |
|--------|-------------|
| **Kill processes** | Fake kernel threads, reverse shells, GSocket. Never kills root or system processes. |
| **Quarantine files** | Moves webshells, backdoors, phishing to `/opt/csm/quarantine/` with full metadata (owner, permissions, mtime). Restoreable from the web UI. |
| **Block IPs** | Adds attacker IPs to the nftables firewall with configurable expiry. Rate-limited to 50 blocks/hour. |
| **Clean malware** | 7 strategies: @include removal, prepend/append stripping, inline eval removal, base64 chain decoding, chr/pack cleanup, hex injection removal, DB spam cleanup. |
| **PHP shield** | Blocks PHP execution from uploads/tmp directories, detects webshell parameters. |
| **PAM blocking** | Instant IP block on brute force threshold breach. |
| **Subnet blocking** | Auto-blocks /24 when 3+ IPs from the same range attack. |
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
  netblock: true              # enable subnet blocking
  netblock_threshold: 3       # IPs from same /24 before subnet block
  permblock: true             # promote temp blocks to permanent
  permblock_count: 4          # temp blocks before promotion

  # PHP-relay auto-freeze (cPanel only). Off by default; opt in
  # explicitly. dry_run defaults to true even when freeze=true so an
  # operator who enables freeze without thinking gets a dry-run.
  php_relay:
    freeze: true                       # enable the exim -Mf hook
    dry_run: true                      # safe default; flip with `csm phprelay dry-run off`
    max_actions_per_minute: 60         # rolling 60s window cap on exim -Mf invocations
```

## Safety Guards

- Never kills root processes, system daemons, or cPanel services
- Infrastructure IPs (`infra_ips` in config) are never blocked
- Quarantined files preserve full metadata for restoration
- Auto-quarantine requires high confidence: category match (webshell/backdoor/dropper) + entropy >= 4.8 or hex density > 20%. This prevents legitimate WordPress plugins from being quarantined.
- IP block rate limited to 50/hour to prevent runaway blocking
- CRITICAL alerts always bypass the email rate limit (default 30/hour)
- Trusted countries (`trusted_countries`) suppress login alerts from expected geolocations

## What CSM Detects in Real-Time

Beyond standard malware patterns, CSM detects advanced evasion techniques:

- **Fragmented function names**: attackers split `base64_decode` across variables (`$a="base"; $b="64_decode"`) to evade simple string matching
- **Appended payloads**: malicious code added to the end of large legitimate files, beyond typical scan windows. CSM scans both the first and last 32KB of every PHP file.
- **Non-PHP backdoors**: Perl, Python, Bash CGI scripts in web directories (detects toolkits like LEVIATHAN)
- **SEO spam injection**: gambling/togel dofollow link injection into theme files
- **WordPress brute force**: real-time access log monitoring for wp-login.php and xmlrpc.php floods (blocks within seconds, not the 10-minute periodic scan)
- **Admin-panel brute force**: same access-log path, tracks POSTs to `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`, and Joomla `/administrator/index.php`. Emits `admin_panel_bruteforce` and auto-blocks the IP. Path matcher is intentionally tight to avoid false positives on shared hosting; Drupal and Tomcat Manager use different attack shapes and need separate detectors.
- **SMTP brute force**: tails `/var/log/exim_mainlog` for dovecot SASL auth failures on submission ports. Emits `smtp_bruteforce` (per-IP, auto-blocks), `smtp_subnet_spray` (per-/24, auto-blocks the whole subnet), and `smtp_account_spray` (per-mailbox, visibility only).
- **Mail brute force**: tails `/var/log/maillog` for direct IMAP, POP3, and ManageSieve auth failures. Composes with the existing geo-login monitor so `email_suspicious_geo` keeps working. Emits `mail_bruteforce`, `mail_subnet_spray`, `mail_account_spray`, and `mail_account_compromised` (the last one fires when a successful login arrives from an IP that just failed auth against the same mailbox; auto-blocks with no false positives by construction).
