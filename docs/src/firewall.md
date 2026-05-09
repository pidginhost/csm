# Firewall (nftables)

CSM includes a native nftables firewall engine that replaces LFD and fail2ban. It uses the kernel netlink API directly via `google/nftables` - no iptables, no Perl, no shell commands.

## Features

- **Atomic ruleset** - single netlink transaction, no partial application
- **Named IP sets** with per-element timeouts (blocked, allowed, infra, country)
- **Rate limiting** - SYN flood, UDP flood, per-IP connection rate, per-port flood
- **Country blocking** via MaxMind GeoIP CIDR ranges
- **Outbound SMTP restriction** by UID (prevent spam from compromised accounts)
- **Subnet/CIDR blocking** with auto-escalation from individual IPs
- **Permanent block escalation** after repeated temp blocks
- **Dynamic DNS** hostname resolution (updated every 5 min) with grace-period guard against transient resolver failures
- **IPv6 dual-stack** with separate sets
- **Commit-confirmed safety** - Juniper-style auto-rollback timer
- **Infra IP protection** - refuses to block infrastructure IPs
- **Auto-response dry-run** - safety default that records intended blocks without touching nftables
- **Verdict callback** - optional advisory hook to the panel before each auto-block (allow / block / attach metadata)
- **cphulk integration** - unblock flushes cphulk too
- **Audit trail** - JSONL log with 10MB rotation
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

# Cloudflare
csm firewall cf-status                           # Show Cloudflare IP whitelist status
```

## Configuration

Firewall defaults can be edited in two places:

- **Web UI**: Settings -> Firewall section. Port lists, rate limits, flood protection, deny caps, country block, and outbound SMTP restriction are all editable. Changes are restart-class. The save endpoint warns if the WebUI listen port is missing from `tcp_in`. The `port_flood` per-port rule list is YAML-only for now.
- **YAML**: edit `/etc/csm/csm.yaml` directly. Run `csm rehash` then `systemctl restart csm`.

```yaml
firewall:
  enabled: true
  ipv6: false
  conn_rate_limit: 200         # new connections per minute per IP (CGNAT-tolerant)
  syn_flood_protection: true
  conn_limit: 400              # max concurrent connections per IP (0 = disabled)
  smtp_block: false            # restrict outbound SMTP
  log_dropped: true
  dyndns_hosts:                # resolved every 5 min into the infra set
    - "monitoring.example.com"
```

Full firewall reference: [Configuration - Firewall](configuration.md#full-reference).

## Auto-response interaction

Auto-block calls go through the firewall engine, but the engine consults two policy hooks first:

1. **`auto_response.verdict_callback`** - when enabled, the engine POSTs a signed JSON request to the panel after local validation and infra-IP safety checks. The panel can downgrade to `allow` (audit-only), attach `tenant_id` for downstream correlation, or add a note. CSM fails open on hook errors. Wire contract: [`docs/verdict-callback-contract.md`](../verdict-callback-contract.md).

2. **`auto_response.dry_run`** - when true (or absent; safety default), `BlockIP()` records the intended block to bbolt and returns success without touching nftables. Manual `csm firewall ...` operator commands bypass via `BlockIPForce` and always apply. Verify with `csm firewall status` after policy changes; "Recently Blocked" timestamps newer than the last restart confirm live mode. See [Auto-response - Dry-run safety default](auto-response.md#dry-run-safety-default).

## Infrastructure IP DNS guard

Hostnames listed in `firewall.dyndns_hosts` are resolved into the `infra_ips` set every 5 minutes so the addresses they currently point at are never auto-blocked. If a hostname stops resolving, the daemon emits an `infra_ips_unresolvable` Warning finding and keeps the **last known** addresses in the infra set during a grace period (default 10 min). This prevents a transient DNS outage from deprotecting the management plane. The finding auto-clears when resolution recovers.
