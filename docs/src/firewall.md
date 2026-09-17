# Firewall (nftables)

CSM includes a native nftables firewall engine that replaces LFD and fail2ban. It writes rules through the kernel netlink API directly via `google/nftables`. Integrity monitoring reads the installed structure with the `nft` command.

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

## Storage contract preparation

The durable firewall action service is implemented and tested through engine injection. Production activation, reader cutover, migration, restore, downgrade and operator recovery interfaces remain open.

Firewall actions record the actor, source, linked finding or incident, and complete before and after state before changing the kernel. Pending intent is separate from committed state. Recovery verifies target identity and expiry before recording an outcome; it does not blindly replay a mutation. Repeated request IDs reuse the original action and admission accounting. Audit delivery retries use the same action ID. Typed undo checks that the affected targets still match the recorded result.

Proven outcomes are retained for undo and review, bounded two ways. The
retention sweep drops delivered outcomes older than the findings-history
setting, and a hard cap on retained outcomes and on their total size applies
even when sweeps stay off. The size cap includes retained audit evidence.
Existing journals are indexed on their first retention operation. Pending
actions and outcomes whose audit has not been delivered are never dropped.
The newest outcome also survives the hard cap even if it alone exceeds it.
Hourly scan counters keep only the newest windows. Scan admission refuses
pruned windows after a backward clock correction, preserving budget safety.
Deleting an outcome ends the undo window for that action.

When an action cannot be proven, for example because the kernel did not answer
in time, its outcome stays uncertain and the engine refuses further firewall
changes rather than guess. The daemon retries recovery at startup and on its
maintenance tick, which settles the outcome as soon as the kernel can answer.
`csm firewall actions` shows what is waiting and why. If the kernel can never
prove it, an operator inspects the host and records the answer with
`csm firewall actions resolve`, which takes `applied` or `rejected` and an
optional note. Kernel evidence wins over the operator: if recovery can prove
the outcome at that moment, the proven one is recorded and the operator's
answer is not used. The decision and its note reach the action log.

Startup recovery runs before applying the firewall. If startup fails, pending
actions remain available for automatic recovery and operator resolution. After
resolving them, restart the daemon to retry firewall setup. A storage error
while saving kernel evidence stops resolution; it never permits an operator
assertion to replace that evidence. Failure to refresh committed state is also
reported, even when the outcome was saved.

Applying an action writes only the entries that change, so the kernel write
for one block does not grow with the size of the blocked set. Large removals
use bounded messages within the same atomic update. Ranged sets are written
whole because their start and end markers move together. If the kernel already
expired an entry the action meant to remove, the set is rewritten instead, and
both paths end at the same state.

Firewall state storage provides complete snapshot reads and revision-checked
replacement using the existing database. Reads preserve expired entries,
original timestamps, explicit provenance, duplicate allow entries and collection
order. An uninitialized store, corrupt data or a failed read returns an error
without usable state. Rejected or rolled-back writes preserve the previous
snapshot and revision. An error after the transaction body succeeds reports an
uncertain commit; callers must reconcile stored state before retrying and must
not assume rollback or confirmed durability. Legacy bucket edits invalidate a
committed snapshot instead of silently changing its revision. The contract does
not activate runtime cutover.

Firewall storage metrics separate write wait from transaction
duration and expose read time, pending writes, failures and snapshot batch size
using fixed labels. Repeatable benchmarks exercise competing writers and local
snapshot copying. Backup restore and downgrade compatibility require the later
migration stage.

## Mutation failures

Subnet blocks refuse ranges overlapping loopback or link-local scopes, plus
unspecified individual addresses and default routes. Other ranges beginning
at zero, such as `0.0.0.0/8`, remain blockable. These refusals are recorded as
refused in the action log, like single-address refusals. Refusing a permanent
promotion leaves the prior temporary block and its expiry unchanged.

WAF attacker reports for link-local addresses stay visible but advise
investigating the traffic source instead of a block CSM would refuse.

Integrity checks compare live rule structure with the snapshot captured after
CSM last applied the firewall. Editing or rehashing configuration alone never
approves a changed ruleset. A failed snapshot capture reports a monitoring gap;
after correcting `nft` availability, re-apply the firewall to restore its
baseline. Dynamic set membership does not affect this comparison.

Firewall changes persist their intent before changing kernel rules. A failed
atomic kernel transaction restores the previous state. Failed writes and
rollbacks return errors without success audit records; expiry cleanup logs the
failure and retries on a later pass. DNS refreshes also retry failed removals.
Removing one allow source preserves any other active source for that address.

An unconfirmed-durability error means the replacement is visible on disk but
storage did not confirm its survival across power loss. For kernel changes,
CSM attempts to restore the previous state before returning the error. A
failed rollback is reported as well. Correct the storage problem, inspect the
saved state and live rules, and repeat the intended operation or run
`csm firewall restart` to apply the saved state. Do not treat an error as a
successful rule change.

Port-specific allow additions and removals update saved state only. Run
`csm firewall restart` to apply them to the kernel; the command acknowledgement
states that a reload is required.

## Clearing a stale local threat score

Run `csm firewall forget <ip>` as root against the running daemon to clear one
address's accumulated local threat score. It accepts exactly one IPv4 or IPv6
address, including equivalent IPv6 spellings; CIDRs and extra arguments are
rejected. There is no dry-run option.

The command clears equivalent stored spellings together and reports their
highest score and total event count. Blocks, allow lists, whitelists and raw
event history remain intact. New findings immediately
start a fresh scoring record, even if they arrive while the command runs.
This does not suppress findings about the host's own address.

Persistence is attempted immediately but remains best effort: a success reply
confirms removal from memory, not durability across a restart. Check the daemon
logs for attack database write failures if an old score returns after restart.

Attack statistics and event queries use the daemon's state database or its
configured attack database directory. If neither is available, they do not
read event files from the working directory.

## Startup failures

Overlapping, nested, duplicate, and adjacent ranges are merged for the kernel,
including IPv4 and IPv6 ranges ending at the last address. This applies to
infrastructure, country, Cloudflare, DoS exemption, and blocked subnet sets.
Stored subnet entries keep their own source and expiry; removing or expiring
one entry rebuilds the remaining coverage in an atomic transaction. Default
routes remain forbidden as subnet blocks to prevent operator lockout.

CSM tries to initialize and apply an enabled firewall up to three times, with
one-second and two-second delays between attempts. Each attempt builds a fresh
atomic transaction. A failed apply keeps the previous kernel rules in place.
The retry delays stop when the daemon shuts down.

If all attempts fail, CSM continues monitoring but reports degraded health.
`/api/v1/status` and `csm status --json` expose
`automation.firewall_enabled: true`, `firewall_managed: false`, and
`firewall_startup_error`. The error remains available for the lifetime of that
process. `csm doctor` reports a failed firewall check and a recovery step.

Inspect `journalctl -u csm.service`, correct the reported configuration or
nftables permissions problem, and restart `csm.service`. A successful startup
clears the error and enables the firewall-dependent services. Disabling the
firewall deliberately does not degrade health.

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
csm firewall apply-confirmed <minutes>           # Apply the firewall block from csm.yaml with auto-rollback timer
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

Rollback state survives daemon restarts (the snapshot and its firewall
configuration are persisted in the state directory). On startup the daemon
checks for a pending rollback: if the deadline has already passed it restores
the previous config and restarts; otherwise it restores the running firewall
configuration and rearms the timer for the remaining window. Backup and store
export omit this transient state, so restoring an archive cannot re-arm an old
confirmation window.

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

### Egress

`tcp_out` is default-drop as well and ends in a TCP reset, so a host whose
policy omits a port it dials does not lock an operator out; it goes silent.
Every heartbeat, finding delivery or intel lookup fails at once with
"connection refused", which reads like the far end being down, while the host
looks healthy locally. The same validation pass therefore warns when an
enabled firewall's outbound policy would refuse a connection the daemon
itself needs:

- The port of every enabled outbound endpoint in the config is checked
  against `tcp_out`: `alerts.email.smtp`, `alerts.webhook.url`,
  `alerts.heartbeat.url`, `alerts.audit_log.syslog.address` (tcp and tls
  transports), `auto_response.verdict_callback.url`, `reputation.rspamd.url`,
  `reputation.upstream.url`, `reputation.report.targets[].url`,
  `reputation.central.set_url`, `signatures.update_url`,
  `signatures.yara_forge.download_url`, `sentry.dsn` and
  `updates.github_api_url`. HTTP endpoints use their explicit numeric port,
  or the scheme default when the port is omitted. SMTP and TCP/TLS syslog
  addresses also accept TCP service names, matching their dialers. Disabled
  features are skipped, and so are loopback destinations, which the output
  chain accepts ahead of any port rule.
- Port 443 is checked once for the built-in HTTPS endpoints (threat feeds,
  AbuseIPDB, MaxMind, YARA Forge, AI-crawler range feeds, release check),
  because dropping it silences all of them at once.
- Every port under `firewall.required_tcp_out` is checked. That list is a
  declaration, never added to the policy: a conf.d fragment owned by an
  integration can state the ports its service needs, and `csm doctor`
  reports when the effective policy drops one instead of the operator
  discovering it from a silent node. The check runs against the merged
  `tcp_out`, so any config layer that permits the port satisfies the
  declaration.

On a restricted output chain, `smtp_block` installs per-user accepts for the
mail ports ahead of the port rules, and those ports never get a port rule of
their own. The daemon runs as root, so its alert mail is not warned about when
`tcp_out` omits a port that `smtp_block` still lets root reach. A port
declared for another service still warns under `smtp_block`, because a port
declaration cannot prove that service's user is allowed. When IPv6 is managed,
an explicit `tcp6_out` is checked separately; an empty one inherits `tcp_out`,
and the single warning covers both families. When only the IPv6 lists are set,
IPv4 egress is accepted wholesale and the warning names `tcp6_out`. A literal
IPv4 or IPv6 destination is checked only against its own family.

This catches the daemon's own egress and whatever has been declared. It does
not see what an arbitrary third-party process on the host dials; an agent
that ships its own conf.d fragment should declare its ports under
`required_tcp_out` there.

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

## Incident auto-block escalation

An incident-driven block used to be requested once per incident and never
again. The block it applied expired after `auto_response.block_expiry`, but the
marker saying "already blocked" did not, so an attacker who kept going past the
expiry was never blocked a second time while the incident stayed open and kept
collecting evidence.

A block is now re-requested whenever the previous one has lapsed and the
incident is still active and still receiving qualifying findings, and each
request lasts longer than the last:

| block | lifetime |
|-------|----------|
| first | `auto_response.block_expiry` (24h by default) |
| second | 7 days |
| third and later | permanent |

A permanent block is never re-requested. Closing an incident, by an operator or
by the stale-incident sweep, resets the ladder, so a later recurrence starts at
the bottom rather than inheriting a months-old episode. Concurrent findings
still collapse into one firewall call, and a declined or dry-run request is not
recorded, so it can retry.

The ladder survives restarts and quiet intervals while the incident remains
active. Closing the incident, manually or automatically, resets it; a pending
block callback cannot restore the old ladder after that close.

The incident view carries a Block button whenever the incident has one
unambiguous source address. Mixed-source or truncated timelines without an
address in the correlation key do not offer a block target. The button asks
for confirmation, blocks permanently, notes the block on the incident timeline as
`operator_block`, and settles the ladder so the automatic hand-off does not
re-request a block for an address the operator just blocked.

The block API accepts an optional `incident_id`. An invalid, unknown, or
address-mismatched incident ID does not prevent the firewall block, but does
not change the incident. Refreshing an existing temporary block does not
advance the escalation rung. Blocks recorded on closed incidents remain audit
actions without restarting the ladder.

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
