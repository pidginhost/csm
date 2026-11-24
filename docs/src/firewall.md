# Firewall (nftables)

CSM includes a native nftables firewall that replaces LFD and fail2ban. It writes rules straight to the kernel through the netlink API, using `google/nftables`. Integrity monitoring reads the installed structure with the `nft` command. The firewall is off until you set `firewall.enabled: true`.

## Turning it on

1. Set `firewall.enabled: true`, in `/etc/csm/csm.yaml` or in the Web UI. See [Configuration](#configuration).
2. Check that `tcp_in` lists the ports you manage the host through, such as the sshd port. The shipped list leaves out SSH port 22. Run `csm doctor` to see the [lockout warnings](#lockout-warnings).
3. Apply the change. After a YAML edit, run `csm rehash` and `systemctl restart csm`. In the Web UI, **Apply with rollback timer** restarts the daemon and undoes the change unless you confirm it. See [Tentative apply](#tentative-apply-rollback-timer).
4. Run `csm firewall status` to check the result.

Automatic IP blocks from [auto-response](auto-response.md) need the firewall on. See [Auto-response interaction](#auto-response-interaction).

## Features

| Feature | What it does |
|---------|--------------|
| **Atomic ruleset** | Applies the ruleset in a single netlink transaction, so it is never partly applied. |
| **Named IP sets** | Keeps blocked, allowed, infra and country addresses in named sets with per-element timeouts. |
| **IPv4 options drop** | Drops inbound IPv4 TCP packets that carry IP options. See [IPv4 options drop](#ipv4-options-drop). |
| **Rate limiting** | Meters SYN floods, UDP floods, connection rate and concurrent connections. See [Rate limits](#rate-limits). |
| **Country blocking** | Blocks country CIDR ranges downloaded by `csm firewall update-geoip`. |
| **Outbound SMTP restriction** | Restricts outbound SMTP by UID, to prevent spam from compromised accounts. |
| **Local port locks** | Lets only listed users and root open new connections to a port on this host. See [Local port locks](#local-port-locks). |
| **Subnet/CIDR blocking** | Blocks whole ranges, with automatic escalation from individual IPs and safety guards for infra, local and allowed addresses. |
| **Permanent block escalation** | Makes a block permanent after repeated temp blocks. |
| **Dynamic DNS** | Resolves hostnames every 5 min, with a grace-period guard against transient resolver failures. |
| **IPv6 dual-stack** | Filters IPv6 with separate sets. |
| **Commit-confirmed safety** | Rolls a change back on a Juniper-style timer unless you confirm it. |
| **Infra IP protection** | Refuses to block infrastructure IPs. |
| **Auto-response dry-run** | A safety default that forecasts eligible IP blocks and keeps bounded examples without applying them. |
| **Verdict callback** | An optional advisory hook to the panel before each auto-block (allow / block / attach metadata). |
| **cphulk integration** | An unblock flushes cphulk too. |
| **Mail spray history** | Unblock, allow, undoing a block and flush also clear the released addresses' mail login spray history and failure counts. |
| **Audit trail** | A JSONL log with 10MB rotation. |
| **State persistence** | Saves state with atomic writes. |

### IPv4 options drop

CSM drops inbound IPv4 TCP packets with IP options before conntrack, NAT to containers and every accept. This closes the CVE-2026-98432 trigger on unpatched kernels. Set `drop_ipv4_options: false` only for workloads that need IP options, such as CIPSO labels.

### Rate limits

| Meter | Coverage |
|-------|----------|
| SYN flood, UDP flood and per-IP connection rate | Dual-stack. IPv6 is metered per /64. |
| Per-port flood meters | Dual-stack, per source address. |
| Concurrent connection limit | IPv4-only. |

## Configuration

You can edit the firewall settings in two places:

- In the Web UI, under Firewall in Settings. Port lists, rate limits, flood protection, deny caps, country block and outbound SMTP restriction are all editable there. Changes are restart-class: they take effect after a restart. The save endpoint warns if the WebUI listen port is missing from `tcp_in`. The `port_flood` per-port rule list is YAML-only.
- In YAML, by editing `/etc/csm/csm.yaml` directly. Then run `csm rehash` and `systemctl restart csm`.

```yaml
firewall:
  enabled: true
  ipv6: false                  # false = ALL IPv6 traffic bypasses the firewall; CSM raises a finding on dual-stack hosts
  conn_rate_limit: 200         # new connections per minute per source (IPv6 per /64; 0 = disabled; null = default)
  syn_flood_protection: true   # per-source SYN flood meter (IPv6 per /64)
  conn_limit: 400              # max concurrent connections per IPv4 source (0 = disabled)
  drop_ipv4_options: true      # drop inbound IPv4 TCP carrying IP options (default: true)
  smtp_block: false            # restrict outbound SMTP
  log_dropped: true
  dyndns_hosts:                # resolved every 5 min and whitelisted
    - "monitoring.example.com"
```

Full firewall reference: [Configuration - Firewall](configuration.md#full-reference).

### Passive FTP range

When `passive_ftp_start` and `passive_ftp_end` are both unset, CSM decides by host whether to open TCP 49152-65534 for passive FTP data connections:

| Host | Passive FTP range |
|------|-------------------|
| cPanel hosts | Open |
| Hosts with pure-ftpd, proftpd or vsftpd installed. This includes Plesk's ProFTPD and Debian's MySQL, PostgreSQL and LDAP Pure-FTPd packages. | Open |
| Other hosts | Closed |

Explicit values take precedence. Set both endpoints to `0` to keep the range closed.

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

Port-specific allow additions and removals (`allow-port`, `remove-port`) update saved state only. Run `csm firewall restart` to apply them to the kernel. The command acknowledgment states that a reload is required.

## Applying changes with a rollback timer

A wrong firewall setting can lock you out of the host. CSM has two rollback timers that undo a change unless you confirm it: one for config saved in the Web UI, and one for `csm firewall apply-confirmed`. They are separate and use different commands.

### Tentative apply (rollback timer)

The Firewall section in the Web UI offers two save buttons. **Save** writes the new config and prompts you to restart. **Apply with rollback timer** writes the new config, restarts the daemon, and starts a timer. The default is 5 minutes and the range is 1-30.

If you do not click **Confirm** before the timer expires, the daemon restores the previous config and restarts again. This protects against locking yourself out by, for example, removing the WebUI port from `tcp_in`.

When the Web UI is unreachable (firewall mistuned, daemon broken), use the CLI escape hatch:

```
csm firewall rollback status
csm firewall rollback confirm
csm firewall rollback revert
```

Rollback state survives daemon restarts: the snapshot and its firewall configuration are saved in the state directory. On startup the daemon checks for a pending rollback:

- If the deadline has passed, it restores the previous config and restarts.
- Otherwise it restores the running firewall configuration and rearms the timer for the remaining window.

Backup and store export omit this transient state, so restoring an archive cannot re-arm an old confirmation window.

### CLI confirmation window

`csm firewall apply-confirmed <minutes>` applies the firewall settings from disk and starts a rollback timer. `csm firewall confirm` accepts the current ruleset and engine configuration and cancels that timer.

If the timer runs out, CSM rolls back. A normal rollback restores the saved engine configuration first. It then restores the ruleset and the saved blocks of the moment the window opened.

While confirmation is pending, CSM refuses `csm firewall restart` and another `apply-confirmed`, and says what settles the window. Waiting helps only while the rollback is scheduled and can restore the saved configuration. `csm status` and `csm doctor` show a pending window, when it rolls back and why it cannot settle by itself.

This CLI window is separate from the Web UI config rollback above, which uses `csm firewall rollback status|confirm|revert`.

#### Temporary blocks when the window ends

When the window ends, CSM retimes temporary blocks from readable saved state. This includes IPv6 blocks when a restart during the window had disabled IPv6 filtering. A retiming failure logs a warning and releases the hold, so restored timers may still outlast the displayed expiry. Older windows with no saved block snapshot keep their restored timers.

#### If the saved configuration cannot be read

If startup cannot read the saved engine configuration, rollback still restores the kernel ruleset and state, but the window stays pending. You end it in one of two ways:

| You want to | Do this |
|-------------|---------|
| Keep the current state | Inspect the current ruleset and configuration, then run `csm firewall confirm`. Confirmation accepts the current configuration. It does not recover the unreadable settings. |
| Recover the saved settings | Repair the saved configuration and restart the daemon. CSM restores the settings and rebuilds the ruleset with the current blocks. The window ends only once that rebuild applies. |

Removing the saved configuration does not end a recorded window.

Restarts behave as follows while such a window is pending:

- Once the ruleset restore is recorded, later restarts keep the blocks added since. They do not restore the window's start again.
- A missing, truncated or mismatched record makes the next restart restore again.
- An empty or corrupt marker is recorded like any other.
- After such a ruleset-only rollback, a restart applies the configured settings, so the old kernel ruleset does not survive a reboot.

Confirmation or rollback can report a leftover snapshot cleanup error after ending the window. Fix that cleanup error before starting another window.

## Allowlist precedence

The firewall checks an inbound packet in this order:

1. While `drop_ipv4_options` is on, inbound IPv4 TCP packets with IP options are dropped in prerouting, before any of the rules below, infra included. Hosts that support the key report the `firewall.drop_ipv4_options.v1` capability.
2. The nftables input chain accepts `infra_ips`.
3. It accepts each `tcp_in_allow` source on its declared port. This accept sits ahead of the blocked address, blocked subnet and country rules.
4. It drops sources matched by `blocked_ips` and the blocked subnets.
5. It accepts `allowed_ips` and port-specific allows.
6. It drops sources matched by the country rules.

The drop in step 4 comes before the accept in step 5. An allowlisted address that lands in `blocked_ips` would still be dropped, and so would an address with a port-specific allow. To keep operator allows effective, the automatic block path refuses to add an address to `blocked_ips` when the address:

- is on `allowed_ips`, set by `csm firewall allow`;
- has a port-specific allow, set by `csm firewall allow-port`;
- is in a verified-bot range, built-in or from `reputation.verified_bots`.

That gives three levels of protection:

| Entry | Level | What it means |
|-------|-------|---------------|
| `infra_ips` | Hard protect | Never blocked by anything, automatic or manual. Subnet blocks that contain one are refused. |
| `tcp_in_allow` sources | Firm, one port | A block of that source, automatic or manual, takes effect on every other port and never on the declared one. To cut a source off, remove it from the entry. See [firewall.tcp_in_allow](configuration.md#firewalltcp_in_allow). |
| `allowed_ips`, port-specific allows and verified-bot ranges | Soft allow | The automatic block path skips them. An explicit operator deny (`csm firewall deny`, Web UI manual block) still applies. |

Operator commands use a forced block (`BlockIPForce` in the code) that bypasses the soft-allow check.

### Operator block lifetimes

An operator block carries the lifetime the operator chose.

| Action | Lifetime |
|--------|----------|
| `csm firewall deny` | Never expires. |
| Web UI permanent block | Never expires. |
| Web UI 24 hour block | Expires in the firewall and takes its threat-database evidence with it, so the address does not keep scoring as malicious after the block is gone. |

The Web UI 24 hour action refuses to shorten a permanent or longer block. Unblock explicitly before changing its lifetime.

Undo of a bulk block or unblock restores each original deadline, including permanent blocks, and never extends an expired block. A later operator decision supersedes the older undo action.

### Targets CSM refuses to block

CSM refuses these targets as a safety measure:

| Block | Refused targets |
|-------|-----------------|
| Single address | Loopback, unspecified, link-local, multicast and the limited broadcast address. |
| Subnet | The default route, and the unspecified or broadcast address as an individual address. |
| Subnet | A range that overlaps loopback, link-local or multicast ranges. |
| Subnet | A range that overlaps infrastructure addresses (resolved infra hostnames included), host interface addresses, full-IP allows or port-specific allows. |

The default route is forbidden to prevent operator lockout. The kernel drops multicast and limited-broadcast sources before the input chain. Other ranges that contain the unspecified or broadcast address, such as `0.0.0.0/8` or `240.0.0.0/4`, remain blockable.

When an allow makes CSM refuse a subnet block, remove the allow or narrow the CIDR before applying the block.

CSM records every one of these safety refusals as refused in the action log, for subnets as for single addresses. Invalid targets and storage or kernel errors remain failures. [How refusals are handled](#how-refusals-are-handled) has the finer rules.

## Auto-response interaction

Automatic blocks go through the firewall engine, so they need `firewall.enabled: true`. Before it applies one, the engine consults two policy hooks: the verdict callback and the dry-run switch.

### Verdict callback

When `auto_response.verdict_callback` is enabled, the engine POSTs a signed JSON request to the panel. It does so after local validation and the infra-IP safety checks. The panel can:

- downgrade the block to `allow`, which leaves an audit record only;
- attach `tenant_id` for downstream correlation;
- add a note.

When a secret is configured, CSM rejects unsigned callback replies by default. CSM fails open on hook errors. In dry run, admission also asks the panel about each block it forecasts. Admission is the part of auto-response that decides whether an automatic block goes ahead.

The wire contract is in [verdict callback contract](verdict-callback-contract.md).

### Dry run

When `auto_response.dry_run` is true or absent (the safety default), the automatic block call, `BlockIP()`, skips the automatic IP mutation. Manual firewall block commands bypass dry run. Target protections still apply.

When admission forecasts blocks in dry run, it keeps a limited number of them as examples of what it would have blocked. A forecast becomes an example only if it was saved and passed the capacity checks. A dry-run outcome from the older blocking path alone does not guarantee an example.

After a policy change, check `automation.auto_response_dry_run` in `csm status --json` while the daemon is running. Manual blocks also appear in the firewall's block list and audit log. See [Auto-response - Dry-run safety default](auto-response.md#dry-run-safety-default).

## Incident auto-block escalation

An incident can request a block more than once. CSM requests a new block whenever the previous one has lapsed and the incident is still active and still receiving qualifying findings. An attacker who keeps going past the expiry is blocked again, and each request lasts longer than the last:

| block | lifetime |
|-------|----------|
| first | `auto_response.block_expiry` (24h by default) |
| second | 7 days |
| third and later | permanent |

A permanent block is never re-requested. Concurrent findings still collapse into one firewall call. A declined or dry-run request is not recorded, so it can retry.

### Lifetimes under admission

The lifetimes in the table are what the older blocking path applies. Admission follows its own rules:

- It caps new temporary lifetimes at `auto_response.block_expiry`, live and in dry-run forecasts.
- Shorter requests stay short.
- A retry keeps an earlier attempt's absolute expiry, even after the cap is lowered.
- It does not turn a non-positive lifetime into a permanent block.
- A block that admission applied is never promoted to a permanent block while it stands.

### When the ladder resets

The ladder survives restarts and quiet intervals while the incident remains active.

Closing the incident resets the ladder, whether an operator closes it or the stale-incident sweep does. A later recurrence starts at the bottom and does not inherit a months-old episode. A pending block callback cannot restore the old ladder after that close.

### Blocking from the incident view

The incident view carries a Block button whenever the incident has one unambiguous source address. Mixed-source or truncated timelines without an address in the correlation key do not offer a block target.

The button asks for confirmation and blocks permanently. It notes the block on the incident timeline as `operator_block`. It also settles the ladder, so the automatic hand-off does not re-request a block for an address the operator just blocked.

### Blocking through the API

The block API accepts an optional `incident_id`.

- An invalid, unknown or address-mismatched incident ID does not prevent the firewall block, but does not change the incident.
- Refreshing an existing temporary block does not advance the escalation rung.
- Blocks recorded on closed incidents remain audit actions and do not restart the ladder.

## Lockout warnings

Config validation warns when an enabled firewall would cut off the management plane. These are warnings and never block a save or a start. Fronting the Web UI with a reverse proxy or reaching it over a VPN are legitimate reasons to leave the port out of `tcp_in`.

`csm doctor`, daemon startup and the Web UI save path all run the Web UI port and restricted port checks below. The Web UI returns each warning once. The sshd check runs in fewer places; see its section.

### Web UI port not open

CSM warns when the enabled Web UI port is missing from `tcp_in`. With IPv6 filtering enabled it also warns when the port is missing from an explicit `tcp6_in` override. An empty `tcp6_in` inherits `tcp_in`.

A port opened to at least one usable source in `tcp_in_allow` does not warn.

### Restricted port reachable from nowhere

CSM warns when a `restricted_tcp` entry also appears in an effective public TCP allow list, but no `infra_ips` are configured.

The restricted list only filters public accepts. It does not open ports itself. Matching ports are therefore reachable only through the port-agnostic infrastructure-IP accept rule, and with no infrastructure addresses they are reachable from nowhere.

A port with a usable `tcp_in_allow` source stays reachable from that source and is left out of the warning.

### sshd port not open

CSM warns when sshd listens on a port that `tcp_in`, or an explicit `tcp6_in`, does not allow. The shipped `tcp_in` leaves 22 out because many hosts move sshd. A host that never moved it loses SSH on the first apply.

This warning compares the policy against the host, not against the config. It therefore runs in `csm doctor`, `csm validate --deep` and the Web UI firewall save, and not on every load.

The check reads the sshd configuration as follows:

- Every `Port` directive counts, including ones in `Include`d drop-ins under `/etc/ssh/sshd_config.d/`.
- A port named in `restricted_tcp` with `infra_ips` set is treated as a deliberate infra-only listener.
- A port opened to listed sources in `tcp_in_allow` is treated as deliberate too, unless none of its sources renders a rule.
- `AddressFamily` and `ListenAddress` limit the check to the IP families sshd exposes.
- Loopback-only listeners do not count, because the inbound firewall always accepts loopback traffic.
- Hosts with no sshd config get no warning.

### Egress

`tcp_out` is default-drop as well and ends in a TCP reset. A host whose policy omits a port it dials does not lock an operator out. It goes silent: every heartbeat, finding delivery or intel lookup fails at once with "connection refused". That reads like the far end being down, while the host looks healthy locally.

The same validation pass therefore warns when an enabled firewall's outbound policy would refuse a connection the daemon itself needs. It checks three groups of ports.

#### Configured outbound endpoints

CSM checks the port of every enabled outbound endpoint in the config against `tcp_out`:

- `alerts.email.smtp`
- `alerts.webhook.url`
- `alerts.heartbeat.url`
- `alerts.audit_log.syslog.address` (tcp and tls transports)
- `auto_response.verdict_callback.url`
- `reputation.rspamd.url`
- `reputation.upstream.url`
- `reputation.report.targets[].url`
- `reputation.central.set_url`
- `signatures.update_url`
- `signatures.yara_forge.download_url`
- `sentry.dsn`
- `updates.github_api_url`

HTTP endpoints use their explicit numeric port, or the scheme default when the port is omitted. SMTP and TCP/TLS syslog addresses also accept TCP service names, matching their dialers.

Disabled features are skipped. So are loopback destinations, which the output chain accepts ahead of any port rule.

#### Built-in HTTPS endpoints

Port 443 is checked once for the built-in HTTPS endpoints: threat feeds, AbuseIPDB, MaxMind, YARA Forge, AI-crawler range feeds and the release check. Dropping it silences all of them at once.

#### Declared ports

Every port under `firewall.required_tcp_out` is checked. That list is a declaration and is never added to the policy. A conf.d fragment owned by an integration can state the ports its service needs. `csm doctor` then reports when the effective policy drops one, and the operator does not have to discover it from a silent node.

The check runs against the merged `tcp_out`, so any config layer that permits the port satisfies the declaration.

This catches the daemon's own egress and whatever has been declared. It does not see what an arbitrary third-party process on the host dials. An agent that ships its own conf.d fragment should declare its ports under `required_tcp_out` there.

#### Mail ports under `smtp_block`

On a restricted output chain, `smtp_block` installs per-user accepts for the mail ports ahead of the port rules, and those ports never get a port rule of their own.

- The daemon runs as root, so its alert mail gets no warning when `tcp_out` omits a port that `smtp_block` still lets root reach.
- A port declared for another service still warns under `smtp_block`, because a port declaration cannot prove that service's user is allowed.

#### IPv6 egress

- When IPv6 is managed, an explicit `tcp6_out` is checked separately. An empty one inherits `tcp_out`, and the single warning covers both families.
- When only the IPv6 lists are set, IPv4 egress is accepted wholesale and the warning names `tcp6_out`.
- A literal IPv4 or IPv6 destination is checked only against its own family.

## Value validation

Unlike the warnings above, these are errors, because the value cannot do what the operator meant:

- A port outside 1-65535 in any port list, including `drop_nolog` and the passive FTP range.
- A passive FTP range that ends before it starts.
- A `country_block` entry that is not a two-letter ISO code.
- A `port_flood` entry with an out-of-range port, a protocol other than `tcp` or `udp`, or a non-positive hit count or window.

Two enums elsewhere get the same treatment, because the code that reads them falls back to a default branch on an unrecognized value and does not fail:

- `reputation.central.action`. Without the check, an unrecognized value becomes a challenge policy.
- `incidents.*.block_at_severity`, which accepts only `high` or `critical`. Without the check, anything else silently disables incident blocking.

## Local port locks

`firewall.local_port_locks` limits which local users may open new TCP connections to a port on this host. Each entry is `PORT:user,user`. Root is always allowed. Other users get a connection reset. Connections to other hosts on the same port and connections already open are not affected.

```yaml
firewall:
  local_port_locks:
    - "8080:www-data,stalwart"
```

Use it for a service that trusts what local clients tell it, such as a mail server that takes the webmail client's address from a forwarded header. List only users that run no site code: a PHP pool running as a listed user can connect too.

A user name that does not exist is reported at startup and skipped. The port stays locked to the others.

The status page and `csm doctor` read the locked ports from the running daemon after successful installation. Unapplied changes, failed replacements, and live rules that do not match the installation do not count as protection.

## Infrastructure IP DNS guard

Hostnames listed in top-level `infra_ips` or `firewall.infra_ips` are resolved every 5 minutes. Their current addresses feed the guard that keeps infrastructure addresses out of automatic blocks.

If a hostname stops resolving, the daemon keeps the last known addresses protected. It raises one `infra_ips_unresolvable` Warning when a lookup fails more than 10 minutes after the last success. If no lookup has succeeded, it counts from the first failure. On recovery, the daemon protects the returned addresses and can warn again on a later outage.

## DoS-exempt ranges

You can declare IP ranges that bypass three DoS meters: the new-connection rate meter for their IP family, the IPv4 concurrent connection limit and the mail-port flood meters. This prevents false-positive throttling and subnet auto-blocks for carrier CGNAT pools or mail-provider egress.

| Key | Ranges |
|-----|--------|
| `firewall.dos_exempt_ranges` | Your own CIDRs. |
| `firewall.dos_exempt_known_mail_providers` | Google and Microsoft mail ranges. On by default. |

See [Configuration - firewall.dos_exempt_ranges](configuration.md#firewalldos_exempt_ranges).

### What exempt sources bypass

Sources in the exempt set skip three categories of metering:

| Meter | What an exempt source skips |
|-------|-----------------------------|
| **Connection rate-limit** | The new-connection rate meter (configured via `conn_rate_limit`) does not apply for the source's IP family. |
| **Concurrent connection-limit** | The IPv4 concurrent connection cap (`conn_limit`) does not apply. |
| **Mail-port flood meters** | The `port_flood` rules on TCP 25, 465, and 587 do not apply for the source's IP family. |

Subnet auto-block (spray, ASN-crawl, and netblock escalation) respects the exempt set too:

- It skips any subnet block whose CIDR intersects an exempt range.
- It leaves exempt IPs out of the per-subnet threshold count, so they cannot push a subnet over the netblock limit.
- It removes auto-response subnet blocks whose range falls inside an exempt range. This happens at daemon startup and at the start of each auto-block cycle, but only while IP auto-response is live. Dry run leaves them in place.

Manually created IP and subnet blocks are never pruned, even if they fall inside an exempt range.

### What exempt sources do not bypass

These protections remain in force regardless of exempt status:

| Protection | Why it still applies |
|------------|----------------------|
| **Manual blocks** | `csm firewall deny <ip>` and `csm firewall deny-subnet <cidr>` go through `BlockIPForce`, which bypasses the exempt check. An IP or range that is both exempt and manually blocked is still dropped. |
| **SYN flood protection** | The SYN flood meter is not affected by the exempt set. |
| **UDP flood protection** | The UDP flood meter is independent of the exempt set. |
| **Country blocking** | Country CIDR blocks apply unconditionally. |
| **Port policy** | `tcp_in`, `tcp_out`, and `restricted_tcp` port rules are not modified. |

Rule order makes this work. The nftables input chain evaluates `blocked_ips` and subnet blocks before the DoS-meter rules. A manual block inside an exempt range therefore still drops the traffic: the packet hits the block before it reaches the meter that exempt sources bypass.

### Dynamic mail-provider ranges

When `dos_exempt_known_mail_providers` is true (the default), the daemon resolves Google and Microsoft outbound mail ranges at startup. It pushes them into the firewall exempt sets before the first rule application.

CSM discovers the ranges from the providers' published SPF records (the Google and Microsoft mail SPF roots), so they track provider changes without a CSM update.

- The ranges are cached on disk, so the previous set is available immediately on subsequent starts.
- A built-in snapshot is used if the cache is missing or the first live refresh has not completed.
- The cache is refreshed every 12 hours.
- If a refresh fails or the nftables reapply fails, the previous overlay is preserved unchanged.

## Stalwart bans

On a host whose mail server is Stalwart, Stalwart keeps its own list of banned addresses. CSM lifts Stalwart's automatic bans of one address when that address is:

- unblocked or allowed in CSM, or its block is undone;
- unbanned from a hosting panel;
- allowed through a hostname in `dyndns_hosts` or `infra_ips`. An allow through a hostname counts the same as an operator allow.

CSM does this through the Stalwart API key from `csm stalwart setup`. The lift runs in the background, so the unblock never waits on Stalwart.

| Entry in Stalwart | What CSM does |
|-------------------|---------------|
| A ban Stalwart made on its own, for failed logins, failed recipients, loitering or port scans | Lifts it and writes it to the [action log](action-log.md) as `operate.clear_stalwart_ban`. |
| A block made by hand in Stalwart, or a ban with any other reason | Leaves it. The daemon log says so. |

A flush and a subnet removal leave Stalwart's list alone.

### When a lift fails

A lift that fails is written to the daemon log, which names the address Stalwart may still refuse. It is also written to the action log when it got as far as the delete.

Every unblock ends with Stalwart reloading its ban list, also when no ban was left to lift. Unblocking the address again therefore retries a ban that Stalwart still lists, and finishes a lift whose reload did not happen. Until then Stalwart can keep enforcing a ban that is gone from its list.

## Clearing a stale local threat score

Run `csm firewall forget <ip>` as root against the running daemon to clear one address's accumulated local threat score.

The command accepts exactly one IPv4 or IPv6 address, including equivalent IPv6 spellings. It rejects CIDRs and extra arguments. There is no dry-run option.

The command clears equivalent stored spellings together and reports their highest score and total event count. Forgetting an IPv6 address also forgets the spam evidence of its /64 network, and the reply names that network.

Blocks, allow lists, whitelists and raw event history remain intact.

New findings immediately start a fresh scoring record, even if they arrive while the command runs. The command does not suppress findings about the host's own address.

Persistence is attempted immediately but remains best effort. A success reply confirms removal from memory, not durability across a restart. Check the daemon logs for attack database write failures if an old score returns after restart.

Attack statistics and event queries use the daemon's state database or its configured attack database directory. If neither is available, they do not read event files from the working directory.

## Ruleset integrity check

Integrity checks compare the live rule structure with the snapshot CSM captured after it last applied the firewall. Dynamic set membership does not affect this comparison.

Editing or rehashing configuration alone never approves a changed ruleset.

A failed snapshot capture reports a monitoring gap. After correcting `nft` availability, re-apply the firewall to restore its baseline.

## Startup failures

### The firewall does not apply

CSM tries to initialize and apply an enabled firewall up to three times, with one-second and two-second delays between attempts. Each attempt builds a fresh atomic transaction. A failed apply keeps the previous kernel rules in place. The retry delays stop when the daemon shuts down.

If all attempts fail, CSM continues monitoring but reports degraded health:

- `/api/v1/status` and `csm status --json` expose `automation.firewall_enabled: true`, `firewall_managed: false`, and `firewall_startup_error`. The error remains available for the lifetime of that process.
- `csm doctor` reports a failed firewall check and a recovery step.

To recover, inspect `journalctl -u csm.service`, correct the reported configuration or nftables permissions problem, and restart `csm.service`. A successful startup clears the error and enables the firewall-dependent services.

Disabling the firewall deliberately does not degrade health.

### The state file cannot be read

If the firewall state file cannot be read at startup, CSM sets it aside and starts without it:

1. It renames the file to `state.json.unreadable-<UTC time>` in the same directory, with a numbered suffix if needed, before anything can replace it.
2. It starts without the blocked and allowed addresses the file held.
3. It raises a Critical `firewall_state_unreadable` finding. This startup alert bypasses the finding queue and finding suppression rules.
4. `csm doctor` fails its `firewall state` check, naming the kept file, until the next restart. `automation.firewall_state_set_aside` carries the same path.

Review the kept file and add back the entries that must stay.

If the file cannot be renamed or synced, startup fails without retrying, even if installing the base rules also fails. What happens next:

- A running CSM ruleset stays in place with its blocks.
- After a reboot, CSM installs its base rules without saved blocks, allows or port exceptions.
- The failed engine does not adopt replacement state or resume management when storage becomes readable. Correct the storage problem before restarting CSM.

A running engine behaves differently from a starting one. It keeps its known state across an unreadable rewrite, including failed saves, and writes that state back when storage accepts a later save.

<a id="mutation-failures"></a>

## When a firewall change fails

Firewall changes save their intent before they change kernel rules. A failed atomic kernel transaction restores the previous state.

- Failed writes and rollbacks return errors and write no success audit record.
- Expiry cleanup logs the failure and retries on a later pass.
- DNS refreshes also retry failed removals.

Do not treat an error as a successful rule change.

### Unconfirmed durability

An unconfirmed-durability error means the replacement is visible on disk, but storage did not confirm that it survives a power loss. For kernel changes, CSM attempts to restore the previous state before it returns the error. A failed rollback is reported as well.

To recover:

1. Correct the storage problem.
2. Inspect the saved state and live rules.
3. Repeat the intended operation, or run `csm firewall restart` to apply the saved state.

### Actions with an uncertain outcome

Sometimes CSM cannot prove whether an action took effect, for example because the kernel did not answer in time. The outcome then stays uncertain, and the engine refuses further firewall changes rather than guess.

The daemon retries recovery at startup and on its maintenance tick. That settles the outcome as soon as the kernel can answer. `csm firewall actions` shows what is waiting and why.

If the kernel can never prove the outcome, inspect the host and record the answer with `csm firewall actions resolve`. It takes `applied` or `rejected` and an optional note. The decision and its note reach the action log.

Kernel evidence wins over the operator. If recovery can prove the outcome at that moment, CSM records the proven outcome and does not use the operator's answer.

Startup recovery runs before CSM applies the firewall. If startup fails, pending actions remain available for automatic recovery and operator resolution. After resolving them, restart the daemon to retry firewall setup.

Two errors can appear while you resolve an action:

- A storage error while saving kernel evidence stops resolution. It never permits an operator assertion to replace that evidence.
- A failure to refresh committed state is reported, even when the outcome was saved.

## Details

This section is reference material: exact rules, edge cases and rare failure modes.

### How refusals are handled

- Protected targets are refused before timed-block lifetime checks.
- Subnet dry-runs validate the target before reporting a proposed block.
- Manual requests also record safety refusals when durable action tracking is enabled.
- Refusing a permanent promotion leaves the prior temporary block and its expiry unchanged.
- Legacy entries for protected addresses survive reloads and can still be unblocked.
- WAF attacker reports for link-local addresses stay visible. They advise investigating the traffic source, not a block that CSM would refuse.

### Allow sources

Removing one allow source preserves any other active source for that address.

### How ranges are merged

CSM merges overlapping, nested, duplicate and adjacent ranges for the kernel, including IPv4 and IPv6 ranges ending at the last address. This applies to the infrastructure, country, Cloudflare, DoS exemption and blocked subnet sets.

Stored subnet entries keep their own source and expiry. Removing or expiring one entry rebuilds the remaining coverage in an atomic transaction.

### Blocks held back at startup

The admission ledger is the record admission keeps of each automatic response attempt. Before CSM restores blocks at startup, it asks the ledger about every block that an automatic response attempt wrote. The same check runs after a confirmation window restores its saved blocks.

| Attempt recorded in the ledger | What CSM does with the block |
|--------------------------------|------------------------------|
| Still running | Marks the block unverified and holds it back from the kernel. |
| Ended unknown | Marks the block unverified and holds it back from the kernel. |
| Ended unknown and was later found expired and absent | Marks the block unverified, holds it back, then removes it from the saved state. |
| Failed | Marks the block unverified, holds it back, then removes it from the saved state. |

Saving can fail at either step:

- If the unverified mark cannot be saved, the block still stays out of the kernel, but views can list it until a later save succeeds.
- If the removal cannot be saved, the block stays held back and the next start removes it.

Firewall views omit a held-back block once its mark is saved. Firewall and threat views omit unverified addresses, including duplicate spellings. When firewall state exists, threat views use it alone for block status. Legacy tracking entries cannot make held-back blocks appear enforced.

#### If the ledger cannot be read

A ledger that is missing its admission queue state counts as unreadable. With an unreadable ledger:

- Eligible blocks are restored as before, and existing unverified marks are kept.
- None of those automatic blocks is evicted to make room for a new one.
- `csm doctor` warns until a restart reads the ledger. `automation.firewall_ledger_error` carries the reason.

### Replacement at the temporary limit

When the set of temporary blocks is full, a new block can replace an existing one. Which blocks it may replace depends on who asks and on the origin each block recorded.

New timed automatic blocks record their origin explicitly. Operator blocks and operator undo do not acquire that origin from their reason text. Older unstamped rows keep unknown origin.

| New block | What it may replace |
|-----------|---------------------|
| Automatic | Only blocks that recorded an automatic origin. It never replaces an operator's temporary block or a block of unknown origin, and is refused when only those remain. |
| Automatic, through admission | A block that recorded its origin, when the new block has a higher priority. Never a block of unknown origin. |
| Operator | Blocks that recorded an automatic origin, and also an operator's temporary block or a block of unknown origin. |

An automatic alias of an operator block keeps that operator protection and the longer lifetime.

Blocks that an automatic response attempt wrote are never evicted to make room, whether the ledger can be read or not. An operator block that finds the temporary limit reached only because of them is added above the limit.

#### What counts toward the limit

In the rules below, a row is a block in the saved state and an element is its entry in the kernel's blocked set.

- Rows of an address family without a blocked set neither fill the temporary limit nor become replacement victims. Turning off IPv6 filtering therefore does not make saved IPv6 blocks refuse a new temporary block.
- Checking the limit does not remove blocks.
- Dry runs and allowed verdicts keep existing blocks, even when the limit would require a replacement.

At the temporary limit, replacement uses the same live set image as the limit count:

- A saved row without an element in the live set cannot free a slot.
- When no replaceable row has an element, the new block is refused.
- If a complete image cannot be read, the saved rows remain the fallback.
- The element must belong to the address's own family. An IPv4-mapped key in the IPv6 set does not prove that an IPv4 block is present.

### The firewall clock

Temporary IP blocks use a firewall clock that counts elapsed time and never moves backward.

- Setting the system clock back does not add that step to block lifetimes.
- A forward step can shorten restored blocks.
- While the firewall clock leads system time, new blocks show expiry times that much later. Elapsed time alone does not close the lead, but a later clock correction can.
- The journal reports the first lead greater than one second once per firewall start.

#### The clock checkpoint

`lease.json`, beside the state file, stores the firewall clock reading, boot identity and time since boot. CSM attempts to save it after each successful ruleset install. It also saves it before a new temporary block changes state or kernel rules.

| Start | Where the clock resumes |
|-------|-------------------------|
| Restart on the same boot | No earlier than the saved time plus the time elapsed since that checkpoint. |
| After a reboot | No earlier than the saved time alone. A reboot supplies no proof of elapsed time from the previous boot. |

The current wall clock and the admission ledger's saved clock can move the resumed time forward.

| Checkpoint problem | Result |
|--------------------|--------|
| The checkpoint is unreadable or damaged | CSM logs a warning. Restoration uses the remaining clock bounds. |
| A save fails after ruleset installation | CSM warns and does not remove those rules. |
| A save fails before a new temporary block | CSM refuses that block with an error. |

Older CSM versions ignore the checkpoint. If system time still trails the firewall clock at downgrade, saved temporary blocks can be restored for longer by that remaining lead.

### Storage contract preparation

The durable firewall action service is implemented and tested through engine injection. Production activation, reader cutover, migration, restore, downgrade and operator recovery interfaces remain open.

#### What an action records

- Before it changes the kernel, a firewall action records the actor, the source, the linked finding or incident, and the complete before and after state.
- Pending intent is separate from committed state.
- Recovery verifies target identity and expiry before it records an outcome. It does not blindly replay a mutation.
- Repeated request IDs reuse the original action and its admission accounting.
- Audit delivery retries use the same action ID.
- Typed undo checks that the affected targets still match the recorded result.

#### Mail login spray blocks

Mail login spray blocks keep their eviction priority through restart, durable batches and undo. Undo restores the original expiry. An operator replacement does not inherit the spray classification. Undoing an unblock restores the block, not the spray history the unblock cleared.

#### How long outcomes are kept

CSM retains proven outcomes for undo and review, bounded two ways:

- The retention sweep drops delivered outcomes older than the findings-history setting.
- A hard cap on retained outcomes and on their total size applies even when sweeps stay off. The size cap includes retained audit evidence.

Some outcomes are exempt:

- Pending actions and outcomes whose audit has not been delivered are never dropped.
- The newest outcome also survives the hard cap, even if it alone exceeds it.

Deleting an outcome ends the undo window for that action. Existing journals are indexed on their first retention operation.

Hourly scan counters keep only the newest windows. After a backward clock correction, scan admission refuses pruned windows, which preserves budget safety.

#### Kernel writes

Applying an action writes only the entries that change, so the kernel write for one block does not grow with the size of the blocked set. Large removals use bounded messages within the same atomic update.

Ranged sets are written whole because their start and end markers move together. If the kernel already expired an entry the action meant to remove, the set is rewritten instead. Both paths end at the same state.

#### State storage

Firewall state storage provides complete snapshot reads and revision-checked replacement using the existing database.

- Reads preserve expired entries, original timestamps, explicit provenance, duplicate allow entries and collection order.
- An uninitialized store, corrupt data or a failed read returns an error without usable state.
- Rejected or rolled-back writes preserve the previous snapshot and revision.
- An error after the transaction body succeeds reports an uncertain commit. Callers must reconcile stored state before retrying and must not assume rollback or confirmed durability.
- Legacy bucket edits invalidate a committed snapshot and do not silently change its revision.
- The contract does not activate runtime cutover.

#### Metrics and benchmarks

Firewall storage metrics separate write wait from transaction duration. They expose read time, pending writes, failures and snapshot batch size using fixed labels.

Repeatable benchmarks exercise competing writers and local snapshot copying. Backup restore and downgrade compatibility require the later migration stage.
