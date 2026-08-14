# Firewall (nftables)

CSM includes a native nftables firewall engine that replaces LFD and fail2ban. It uses the kernel netlink API directly via `google/nftables` - no iptables, no Perl, no shell commands.

## Features

- **Atomic ruleset** - single netlink transaction, no partial application
- **Named IP sets** with per-element timeouts (blocked, allowed, infra, country)
- **Rate limiting** - SYN flood, UDP flood, and per-IP connection rate are dual-stack (IPv6 metered per /64); per-port flood meters are dual-stack per source address; the concurrent connection limit is IPv4-only
- **Country blocking** via MaxMind GeoIP CIDR ranges
- **Outbound SMTP restriction** by UID (prevent spam from compromised accounts)
- **Subnet/CIDR blocking** with auto-escalation from individual IPs and safety guards for infra, local, and allowed addresses
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
csm firewall flush                               # Clear all blocked IPs (subnet blocks kept)

# Safety
csm firewall apply-confirmed <minutes>           # Apply with auto-rollback timer
csm firewall confirm                             # Confirm applied changes
csm firewall rollback status|confirm|revert      # Manage pending config rollback
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

### Tentative apply (rollback timer)

The Firewall section in the Web UI offers two save buttons. **Save** writes
the new config and prompts you to restart. **Apply with rollback timer**
writes the new config, restarts the daemon, and starts a timer (default 5
minutes, range 1-30). If you do not click **Confirm** before the timer
expires, the daemon restores the previous config and restarts again. This
protects against locking yourself out by, for example, removing the WebUI
port from `tcp_in`.

When the Web UI is unreachable (firewall mistuned, daemon broken), use the
CLI escape hatch:

```
csm firewall rollback status
csm firewall rollback confirm
csm firewall rollback revert
```

Rollback state survives daemon restarts (the snapshot is persisted in
bbolt). On startup the daemon checks for a pending rollback: if the
deadline has already passed it restores the previous config and restarts;
otherwise it rearms the timer for the remaining window.

```yaml
firewall:
  enabled: true
  ipv6: false                  # false = ALL IPv6 traffic bypasses the firewall; CSM raises a finding on dual-stack hosts
  conn_rate_limit: 200         # new connections per minute per source (IPv6 per /64; 0 = disabled; null = default)
  syn_flood_protection: true   # per-source SYN flood meter (IPv6 per /64)
  conn_limit: 400              # max concurrent connections per IPv4 source (0 = disabled)
  smtp_block: false            # restrict outbound SMTP
  log_dropped: true
  dyndns_hosts:                # resolved every 5 min and whitelisted
    - "monitoring.example.com"
```

Full firewall reference: [Configuration - Firewall](configuration.md#full-reference).

## Auto-response interaction

Auto-block calls require `firewall.enabled: true` because they go through the firewall engine. The engine consults two policy hooks first:

1. **`auto_response.verdict_callback`** - when enabled, the engine
   POSTs a signed JSON request to the panel after local validation and
   infra-IP safety checks. When a secret is configured, CSM rejects
   unsigned callback replies by default. The panel can downgrade to
   `allow` (audit-only), attach `tenant_id` for downstream correlation,
   or add a note. CSM fails open on hook errors. Wire contract:
   [`docs/verdict-callback-contract.md`](https://github.com/pidginhost/csm/blob/main/docs/verdict-callback-contract.md).

2. **`auto_response.dry_run`** - when true (or absent; safety default), `BlockIP()` records the intended block to bbolt and returns success without touching nftables. Manual `csm firewall ...` operator commands bypass via `BlockIPForce` and always apply. Verify with `csm firewall status` after policy changes; "Recently Blocked" timestamps newer than the last restart confirm live mode. See [Auto-response - Dry-run safety default](auto-response.md#dry-run-safety-default).

Subnet blocks refuse the default route and any range that contains an
infrastructure IP, a resolved infra hostname, a local host address, a
full-IP allow, or a port-specific allow. Remove the allow or narrow the
CIDR before applying the block.

### Allowlist precedence

The nftables input chain accepts `infra_ips` first, then drops
`blocked_ips`, then accepts `allowed_ips`. Because the drop is evaluated
before the `allowed_ips` accept, an allowlisted IP that lands in
`blocked_ips` would still be dropped. The same applies to port-specific
allows, because those rules are evaluated after `blocked_ips` too. To keep
operator allows effective, the auto-block path refuses to add an IP to
`blocked_ips` when it is on `allowed_ips` (set by `csm firewall allow`), has
a port-specific allow (`csm firewall allow-port`), or is in a verified-bot
range (built-in or `reputation.verified_bots`). Precedence:

- **`infra_ips`** - hard protect. Never blocked by anything, auto or
  manual; subnet blocks containing one are refused.
- **`allowed_ips`, port-specific allows, and verified-bot ranges** - soft
  allow. The auto-block path skips them, but an explicit operator deny
  (`csm firewall deny`, Web UI manual block) still applies, because operator
  commands go through `BlockIPForce` and bypass the soft-allow gate.

## Lockout warnings

Config validation warns when an enabled firewall would cut off the management
plane. `csm doctor`, daemon startup, and the Web UI save path all run the same
checks, and the Web UI returns each warning once:

- The enabled Web UI port is missing from `tcp_in`, or from an explicit
  `tcp6_in` override when IPv6 filtering is enabled. An empty `tcp6_in`
  inherits `tcp_in`.
- A `restricted_tcp` entry also appears in an effective public TCP allow list,
  but no `infra_ips` are configured. The restricted list only filters public
  accepts; it does not open ports itself. Matching ports are therefore
  reachable only through the port-agnostic infrastructure-IP accept rule, and
  with no infrastructure addresses they are reachable from nowhere.

These stay warnings and never block a save or a start: fronting the Web UI with
a reverse proxy or reaching it over a VPN are legitimate reasons to leave the
port out of `tcp_in`.

One more warning compares the policy against the host instead of against the
config, so it runs in `csm doctor`, `csm validate --deep`, and the Web UI
firewall save rather than on every load:

- sshd listens on a port that `tcp_in` (or an explicit `tcp6_in`) does not
  allow. The shipped `tcp_in` leaves 22 out, because many hosts move sshd, so a
  host that never moved it loses SSH on the first apply. Every `Port` directive
  counts, including ones in `Include`d drop-ins under `/etc/ssh/sshd_config.d/`,
  and a port named in `restricted_tcp` with `infra_ips` set is treated as a
  deliberate infra-only listener. `AddressFamily` and `ListenAddress` limit
  the check to the IP families sshd exposes, and loopback-only listeners do
  not count because the inbound firewall always accepts loopback traffic.
  Hosts with no sshd config get no warning.

## Value validation

Unlike the warnings above, these are errors, because the value cannot do what
the operator meant:

- Ports outside 1-65535 in any port list, including `drop_nolog` and the
  passive FTP range, and a passive FTP range that ends before it starts.
- `country_block` entries that are not two-letter ISO codes.
- `port_flood` entries with an out-of-range port, a protocol other than `tcp`
  or `udp`, or a non-positive hit count or window.

Two enums elsewhere get the same treatment because their consumers fall back to
a default branch rather than failing: `reputation.central.action` (an
unrecognised value became a challenge policy) and
`incidents.*.block_at_severity`, which accepts only `high` or `critical` and
silently disabled incident blocking on anything else.

## Infrastructure IP DNS guard

Hostnames listed in top-level `infra_ips` or `firewall.infra_ips` are resolved every 5 minutes and their current addresses feed the infra auto-block guard. If a hostname stops resolving, the daemon emits an `infra_ips_unresolvable` Warning finding and keeps the last known addresses protected during the grace period (default 10 min). This prevents a transient DNS outage from deprotecting the management plane. The finding auto-clears when resolution recovers.

## DoS-exempt ranges

Operators can declare IP ranges that bypass the new-connection rate meter for their IP family, the IPv4 concurrent connection-limit, and mail-port flood meters, preventing false-positive throttling and subnet auto-blocks for carrier CGNAT pools or mail-provider egress. Configure under `firewall.dos_exempt_ranges` (your own CIDRs) and `firewall.dos_exempt_known_mail_providers` (adds Google and Microsoft mail ranges, on by default). See [Configuration - firewall.dos_exempt_ranges](configuration.md#firewalldos_exempt_ranges).

### What exempt sources bypass

Sources in the exempt set skip three categories of metering:

- **Connection rate-limit** - the new-connection rate meter (configured via `conn_rate_limit`) does not apply for the source's IP family.
- **Concurrent connection-limit** - the IPv4 concurrent connection cap (`conn_limit`) does not apply.
- **Mail-port flood meters** - the `port_flood` rules on TCP 25, 465, and 587 do not apply for the source's IP family.

Subnet auto-block (spray, ASN-crawl, and netblock escalation) also skips any subnet block whose CIDR intersects an exempt range, and exempt IPs are excluded from the per-subnet threshold count so they cannot push a subnet over the netblock limit. Auto-response subnet blocks whose range falls inside an exempt range are removed automatically at daemon startup and at the start of each auto-block cycle. Manually created IP and subnet blocks are never pruned, even if they fall inside an exempt range.

### What exempt sources do not bypass

The following protections remain in force regardless of exempt status:

- **Manual blocks** - `csm firewall deny <ip>` and `csm firewall deny-subnet <cidr>` go through `BlockIPForce`, which bypasses the exempt check. An IP or range that is both exempt and manually blocked is still dropped.
- **SYN flood protection** - the SYN flood meter is not affected by the exempt set.
- **UDP flood protection** - the UDP flood meter is independent of the exempt set.
- **Country blocking** - country CIDR blocks apply unconditionally.
- **Port policy** - `tcp_in`, `tcp_out`, and `restricted_tcp` port rules are not modified.

The rule ordering that makes this work: the nftables input chain evaluates `blocked_ips` (and subnet blocks) before the DoS-meter rules. So a manual block inside an exempt range still drops the traffic -- the block is hit before the meter that exempt sources bypass.

### Dynamic mail-provider ranges

When `dos_exempt_known_mail_providers` is true (the default), the daemon resolves Google and Microsoft outbound mail ranges at startup and pushes them into the firewall exempt sets before the first rule application. The ranges are discovered from the providers' published SPF records (the Google and Microsoft mail SPF roots), so they track provider changes without a CSM update. They are cached on disk so the previous set is available immediately on subsequent starts. A built-in snapshot is used if the cache is missing or the first live refresh has not completed. The cache is refreshed every 12 hours; if a refresh fails or the nftables reapply fails, the previous overlay is preserved unchanged.
