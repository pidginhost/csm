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
