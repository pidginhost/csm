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
- Auto-quarantine requires high confidence (category match + entropy validation)
- Block rate limited to prevent runaway blocking
