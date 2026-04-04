# Firewall (nftables)

CSM includes a native nftables firewall engine that replaces LFD and fail2ban. It uses the kernel netlink API directly via `google/nftables` — no iptables, no Perl, no shell commands.

## Features

- **Atomic ruleset** — single netlink transaction, no partial application
- **Named IP sets** with per-element timeouts (blocked, allowed, infra, country)
- **Rate limiting** — SYN flood, UDP flood, per-IP connection rate, per-port flood
- **Country blocking** via MaxMind GeoIP CIDR ranges
- **Outbound SMTP restriction** by UID (prevent spam from compromised accounts)
- **Subnet/CIDR blocking** with auto-escalation from individual IPs
- **Permanent block escalation** after repeated temp blocks
- **Dynamic DNS** hostname resolution (updated every 5 min)
- **IPv6 dual-stack** with separate sets
- **Commit-confirmed safety** — Juniper-style auto-rollback timer
- **Infra IP protection** — refuses to block infrastructure IPs
- **cphulk integration** — unblock flushes cphulk too
- **Audit trail** — JSONL log with 10MB rotation
- **State persistence** with atomic writes

## CLI Commands

```bash
# Status
csm firewall status                              # Show status and statistics
csm firewall ports                               # Show configured port rules

# Block / Allow
csm firewall deny <ip> [reason]                  # Block IP permanently
csm firewall allow <ip> [reason]                 # Allow IP (all ports)
csm firewall allow-port <ip> <port> [reason]     # Allow IP on specific port
csm firewall remove <ip>                         # Remove from blocked and allowed
csm firewall remove-port <ip> <port>             # Remove port-specific allow

# Temporary
csm firewall tempban <ip> <dur> [reason]         # Temporary block
csm firewall tempallow <ip> <dur> [reason]       # Temporary allow

# Subnets
csm firewall deny-subnet <cidr> [reason]         # Block subnet
csm firewall remove-subnet <cidr>               # Remove subnet block

# Search
csm firewall grep <pattern>                      # Search blocked/allowed IPs
csm firewall lookup <ip>                         # GeoIP + block status lookup

# Bulk operations
csm firewall deny-file <path>                    # Bulk block from file
csm firewall allow-file <path>                   # Bulk allow from file
csm firewall flush                               # Clear all dynamic blocks

# Safety
csm firewall apply-confirmed <minutes>           # Apply with auto-rollback timer
csm firewall confirm                             # Confirm applied changes
csm firewall restart                             # Reapply full ruleset

# Profiles
csm firewall profile save|list|restore <name>    # Profile management

# Audit
csm firewall audit [limit]                       # View audit log

# GeoIP
csm firewall update-geoip                        # Download country IP blocks
```

## Configuration

```yaml
firewall:
  enabled: true
  ipv6: false
  conn_rate_limit: 30          # new connections per minute per IP
  syn_flood_protection: true
  conn_limit: 50               # max concurrent connections per IP
  smtp_block: false            # restrict outbound SMTP
  log_dropped: true
```
