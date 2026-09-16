# Auto-Response

When enabled, CSM automatically responds to detected threats. All actions are logged in the audit trail.

## Actions

| Action | Description |
|--------|-------------|
| **Kill processes** | Fake kernel threads, reverse shells, GSocket. Never kills root or system processes. |
| **Quarantine files** | Moves webshells, backdoors, phishing to `/opt/csm/quarantine/` with full metadata (owner, permissions, mtime). Restoreable from the web UI. |
| **Block IPs** | Adds attacker IPs to the nftables firewall with configurable expiry. Rate-limited by `auto_response.max_blocks_per_hour` (default 50/hour). |
| **Clean supported malware** | Applies bounded PHP and `.htaccess` cleaners with pre-clean backups. Database cleanup has a separate opt-in. |
| **Drop malicious DB objects** | When `clean_database` is on, confirmed-malicious stored triggers/events/procedures/functions are dropped after a `SHOW CREATE` backup is recorded, so the drop is reversible. Detection runs regardless; the drop is gated on the operator opt-in. |
| **PHP shield** | Blocks PHP execution from uploads/tmp directories and inspects directly executed `wp-content` scripts for request-fed command sinks and packed eval loaders. |
| **PAM blocking** | Instant IP block when one address breaches `thresholds.pam_bruteforce_threshold` failures inside `pam_bruteforce_window_min` minutes, or fails against `cred_stuffing_distinct_accounts` distinct accounts. |
| **Subnet blocking** | Auto-blocks IPv4 /24 or IPv6 /64 when 3+ IPs from the same range attack. |
| **Permblock escalation** | Promotes temporary blocks to permanent after N repeated offenses. |
| **Auto-freeze (PHP relay)** | On cPanel, freezes active Exim messages attributed to a high-confidence PHP-relay finding. It has its own dry-run control and action-rate limit. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only). |

### Process termination

CSM opens a kernel process handle before verifying ownership, executable, start
time, or the file referenced by a process. It checks that the captured process
is still alive after verification and sends the signal through that handle.
An exited process cannot redirect the signal to a replacement with the same PID.
Automatic and manual malware termination reject root credentials, including
effective and saved root IDs. The separate opt-in AF_ALG reaction requires the
current credentials and executable to match its recorded event.

Safe signaling needs `pidfd_send_signal` (Linux 5.1). Where `pidfd_open`
(Linux 5.3) is absent -- EL8 and CloudLinux 8 ship 4.18 kernels without it --
CSM pins the target through its `/proc/<pid>` directory descriptor, which
`pidfd_send_signal` accepts and which refers to the same kernel process. Both
paths reject a recycled PID; CSM never falls back to numeric PID signaling.
On a kernel without `pidfd_send_signal`, or when service restrictions deny the
call, termination stays disabled: `csm doctor` reports `process termination
supported` as failed and the health status becomes `degraded` whenever
`auto_response.kill_processes` is enabled, so an inoperative protection is
visible before an incident needs it. Each health snapshot probes this capability
again, so transient resource failures clear once signaling becomes available.
Automatic termination failures are logged while the original detection remains.
Manual kill-and-quarantine reports a termination failure even if the file was
successfully quarantined; inspect both the process and recovery entry before
retrying. Manual request cancellation is checked before sending a signal.

### Automatic file response limits

Realtime quarantine, scheduled quarantine, PHP cleaning and automatic `.htaccess`
cleaning share one rolling-hour budget. `auto_response.max_file_actions_per_hour`
caps host-wide attempts (default 50), `max_file_actions_per_account_per_hour` caps
attempts for one account (default 10), and `max_file_action_failures_per_hour`
pauses these responses after repeated failures (default 3). Zero or an omitted
key uses the default; negative values and values above 10000 are rejected.

Each attempt is reserved before touching the file. Successful, failed and
interrupted attempts all consume capacity. Reservations live in
`<state_path>/file-response.json` and survive configuration reloads and daemon
restarts. Entries expire one hour after admission. A backwards clock adjustment
keeps future-dated reservations charged until their window has passed.

Account budgets come from the target's account-home path, not finding text.
Paths outside recognized account homes share an unknown-account budget. One
account reaching its limit does not stop other accounts unless the host or
failure limit is also reached. Automatic directory and special-file quarantine
is refused because one directory move can affect an unbounded number of files.
Manual remediation remains available after reviewing the original detection.

A busy safety lock refuses that attempt without waiting behind another file
operation. Unreadable, incomplete or unwritable safety state also refuses
mutations. The original detections remain visible and a deduplicated
`auto_response_paused` warning reports the cause. Account-limit notices are
grouped at host scope so a fault across many accounts cannot flood the alert
budget. A pause does not create a retry job; new eligible detections can act
after capacity returns. Review outstanding findings and recovery evidence before
manual remediation. Do not delete safety state to clear a pause; repair storage
faults and let reservations expire.

Duplicate detections of one path share a single response attempt in each batch.
Within one daemon run, alert delivery does not repeat a file response already
evaluated by a scan or admitted to the realtime safety gate, including budget
refusals. A realtime detection rejected using sampled content remains eligible
for full-file validation during delivery. The original findings still reach
alerts and history; a new detection can be evaluated again.
Findings still queued at shutdown retain the existing restart replay behavior:
the next daemon run evaluates them again under the same persisted limits.

A failed PHP cleaner leaves the file and any pre-clean backup for manual review.
It no longer escalates to whole-file quarantine. A cleaner that recognizes no
injection or declines an unsupported target refuses the file instead of failing.
Sources that change or disappear before mutation are also refusals, including
socket replacements and parent paths replaced after quarantine copying. These
attempts still use capacity but do not count toward the failure pause. Read,
write, backup and durability errors still count as failures. Quarantine and
cleaners retain their descriptor-based identity checks, and automatic actions
revalidate the file after saving the reservation. Opening a replacement special
file cannot block response processing.

Manual full scans leave cleaner refusals for review instead of reporting a
failed remediation. `csm clean` also distinguishes a refusal from an action
failure; both return a nonzero exit status when the file was not cleaned.

These limits use the existing `enabled`, `quarantine_files` and `clean_htaccess`
opt-ins. Observe mode still forbids automatic changes. `dry_run` continues to
control IP blocking and web-exposed-file virtual patches; it does not preview
file quarantine or cleaning. Other response families have their own controls.

### Restoring quarantined files

Regular-file quarantine and pre-clean backups write and sync the private content
copy, metadata, and directory entries before removing or changing the original.
Directory quarantine syncs the tree and metadata before moving it on the same
filesystem. A directory move across filesystems is refused and leaves the source
in place. Storage failures do not count as successful remediation.

New quarantine and pre-clean sidecars record the original modification time,
owner, group, permissions, and size. Restore reapplies the saved attributes to
the opened destination before syncing it. Linux preserves modification times at
the precision supported by the destination filesystem. An ownership or timestamp
failure keeps the recovery evidence and reports an error.

Older sidecars may use `quarantine_at`; listing and restore also read that
historical spelling. Entries without a saved quarantine date sort last. Older
entries have no recorded original modification time, so restore leaves the new
file's modification time in place instead of treating the archive's timestamp
as the original. Some older access-file cleanup backups also lack trustworthy
ownership and permission data; check those attributes when restoring them.

Configured account roots participate in manual remediation and restore. Set up
[service write access](custom-account-roots.md) for roots outside the packaged
grants before enabling these operations.

Web UI restore refuses symbolic links in destination directories and does not
replace an existing file or directory. If a destination changes during restore,
CSM reports a conflict and retains the quarantine entry. Check the original
location before retrying; a failed or interrupted file restore can leave a
partial file in the directory that was opened for restoration. CSM keeps this
file because removing it could discard a concurrent replacement.

Restore syncs the replacement and its containing directory before deleting
quarantine evidence. A failure after a move or unlink reports partial completion
and retains recovery metadata where possible. Inspect both the original and
quarantine locations named in the error before retrying; a copy may already be
restored while quarantine cleanup remains incomplete. These guarantees depend
on the filesystem and storage device honoring sync requests.

Virtual-patch rollback uses the same directory confinement. It replaces or
removes the access file only when the saved content, owner, and permissions
still match, preserving later customer edits.

Virtual-patch backups are reused only when their content and saved attributes,
including modification time, match. A later edit with identical bytes but a new
modification time gets a separate recovery point.

Rollback isolates displaced entries in a private directory. If another writer
changes the destination, CSM preserves the live replacement and reports any
retained recovery directory in the error. Check that directory beneath the
original destination or quarantine location before retrying. If another writer
moves a restored directory, CSM cannot recover it from its old name and will
not substitute a different entry into quarantine.

## Configuration

```yaml
auto_response:
  enabled: true
  kill_processes: true
  quarantine_files: true
  max_file_actions_per_hour: 50
  max_file_actions_per_account_per_hour: 10
  max_file_action_failures_per_hour: 3
  block_ips: true
  block_expiry: "24h"         # positive temp block duration; omitted defaults to 24h
  max_blocks_per_hour: 50     # per-IP blocks per hour; 0/omitted uses default
  netblock: true              # enable subnet blocking
  netblock_threshold: 3       # IPs from same IPv4 /24 or IPv6 /64 before subnet block; minimum 2
  permblock: true             # promote temp blocks to permanent
  permblock_count: 4          # temp blocks before promotion; minimum 2
  permblock_interval: "24h"   # positive counting window; omitted defaults to 24h

  # Response to http_scanner_profile findings: "challenge" (default)
  # routes the IP to the PoW challenge when challenge.enabled is true,
  # falling through to a firewall block when it is not; "block" always
  # hard-blocks without offering a challenge.
  http_scanner_action: "challenge"

  # Deny HTTP access to confirmed exposed files with reversible .htaccess
  # rules. off: alert only; manual: `csm virtual-patch --apply`; auto:
  # apply confirmed findings except warning-only sample SQL when dry_run is false.
  virtual_patch_exposed_files: "off"

  # SAFETY DEFAULT: dry_run defaults to TRUE when this key is absent.
  # In dry-run, BlockIP records the intended block to bbolt but does
  # NOT touch nftables. Manual operator commands (`csm firewall ...`)
  # bypass via BlockIPForce and always apply. Flip to false only after
  # verifying the policy in dry-run.
  dry_run: true

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

### Exposed-file virtual patches

Each applied deny keeps a rollback copy under `/opt/csm/quarantine/pre_clean/`. Re-applying the same rollback state reuses that copy; content, ownership, permissions, or remove-versus-replace changes keep separate restore points.

All-in-One WP Migration rewrites the access file inside `wp-content/ai1wm-backups`, so CSM also denies only `.wpress` filenames from the parent `wp-content` access file. It does not add parent-wide `.zip` or `.gz` rules because those extensions can be legitimate downloads elsewhere under `wp-content`.

### Dry-run safety default

`auto_response.dry_run` defaults to `true` when the key is **absent**. This is deliberate: an operator who turns on `block_ips: true` without reviewing policy gets recorded-but-not-applied blocks. The dry-run count surfaces in `csm status --json` and `/api/v1/status` so dashboards can verify the policy before flipping live. CSM clears those records when auto-response starts or reloads in live mode, and ages out records older than a week while dry-run remains enabled.

This setting is not a universal simulation mode. It gates automatic firewall and related network enforcement paths plus web-exposed-file virtual patches. File quarantine, cleanup, permission changes, and process termination are controlled by their individual `auto_response` flags. Leave those flags off while evaluating block policy.

IP auto-blocking still requires `firewall.enabled: true`. The firewall engine owns both live nftables mutations and dry-run block records; with the firewall disabled there is no engine to call, so `csm validate` warns on `auto_response.enabled: true` plus `block_ips: true`.

Verify dry-run state explicitly:

```bash
csm status --json | jq '.severities, .blocklist_size'
csm firewall status   # "Recently Blocked" entries with timestamps after the restart confirm live mode
```

To go live: set `dry_run: false`, then run `systemctl reload csm`. The field is hot-reload-safe, and a successful reload validates and re-signs the config. For a planned restart instead, run `csm rehash` once before restarting.

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

When `auto_response.block_ips: true` and the firewall is enabled, qualifying findings in this list block the source IP. Per-row severity and challenge exceptions apply. The dry-run gate still applies if `dry_run: true`. Suppression rules do not stop these blocks; allowlist an address to exempt it.

Suppression rules also leave incident auto-blocking, credential-spray containment and central threat responses active. With database response enabled, suppression stops database cleanup and session revocation while keeping session IP blocking eligible. Suppress the action's own check type to mute its notification; this does not disable enforcement.

Incidents and central threat responses receive new findings, including suppressed findings and checks that do not notify operators. Duplicate observations within a batch count once. Cross-account correlation uses only unsuppressed sources, and its derived alerts can be muted with their own suppression rules without removing them from enforcement.

| Finding | Description |
|---------|-------------|
| `wp_login_bruteforce` | WordPress login flood via wp-login.php |
| `xmlrpc_abuse` | XML-RPC endpoint flood |
| `http_request_flood` | Per-IP HTTP request volume exceeds threshold (disabled by default; enable by setting `thresholds.http_flood_threshold > 0`) |
| `http_scanner_profile` | Random-URL probe pattern from one source IP (disabled by default; enable by setting `thresholds.http_scanner_min_requests > 0`; routed to the PoW challenge first unless `auto_response.http_scanner_action: "block"`) |
| `http_claimed_bot_unverified` | High-volume claimed crawler traffic while reverse-DNS verification is pending (routed to the PoW challenge first when challenge is enabled) |
| `http_ua_spoof` | IP exceeding the UA anomaly threshold, including confirmed search-engine bot UA spoofing (periodic; see configuration.md for opt-in flags) |
| `ftp_bruteforce` | FTP authentication flood |
| `smtp_bruteforce` | SMTP authentication flood |
| `smtp_probe_abuse` | Raw SMTP connect-rate flood before AUTH |
| `mail_bruteforce` | IMAP/POP3/ManageSieve authentication flood without matching successful mailbox activity |
| `mail_account_compromised` | Successful login from an IP that repeatedly failed auth on the same mailbox. Only Critical findings block; the established multi-mailbox High advisory is visibility only |
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

Successful cPanel, FTP, webmail and PAM login audit events and authenticated
File Manager writes do not trigger direct blocks or challenges. Incidents
containing only these audit events cannot request a block, even when they
retain a higher severity from an older version. Independent attack evidence
can still justify a response.

`block_cpanel_logins` gates cPanel multi-IP logins, API authentication failures,
webmail brute force and realtime FTP authentication failures. This includes
webmail challenge routing, since an unanswered challenge can become a block.

Queued block candidates are checked against the current check policy and
login-blocking setting before retrying. Legacy queue entries without a check
identity are discarded on upgrade; new eligible findings can queue them again.
Existing firewall blocks and permanent evidence are not removed by this change.

Distributed HTTP flood rollups do not trigger a direct IP block because
they describe one targeted vhost, not one source IP. The per-IP findings
that feed the rollup still drive normal block decisions.

`http_asn_crawl` is also handled separately because one finding can carry several offending CIDRs rather than one source IP. Only Critical findings with confirmed PHP worker saturation can tempban those CIDRs, using `auto_response.http_asn_crawl_tempban`. Dry-run and subnet safety guards still apply.

`mail_bruteforce_suspected` and the established multi-mailbox High form of
`mail_account_compromised` are visibility only. They do not feed direct,
incident, or spray auto-blocking. A separate blockable finding can still block
the same source.

Every auto-response block source - scan findings, challenge-timeout
escalations, central-intel corroborated blocks, and incident spray
containment - records the same evidence: a temporary threat-DB row, a
blocked-IPs tracker entry, an `auto_block` finding visible to the block
digest and alerting, and a step toward permanent-block escalation.
Challenge, central, and incident blocks are not limited by
`auto_response.max_blocks_per_hour`; that budget applies to scan-driven
blocks only.

The resulting `auto_block` findings are output evidence, not new local
corroboration for central intelligence or incident correlation. They are
deduplicated before the digest, attack database, history, and alert sinks
receive them.

## Safety Guards

- Never kills root processes, system daemons, or cPanel services
- Infrastructure IPs (`infra_ips` in config) are never blocked
- Subnet blocks refuse the default route and any range that covers infrastructure, local host, allowed, or port-specific allowed IPs
- Quarantined files preserve full metadata for restoration
- Every regular file is copied from its verified open descriptor into a private quarantine inode before the detected name is removed. Other hard links are reported after removal; a file swapped into the detected path is reported as a refused remediation, with the captured copy kept as evidence and the replacement left untouched
- Realtime signature auto-quarantine requires high confidence: category `webshell` or `dropper`, file size at least 512 bytes, and either Shannon entropy >= 5.5 or hex density > 20% with an obfuscated-execution signal. This prevents legitimate WordPress plugins from being quarantined.
- IP block rate limited by `auto_response.max_blocks_per_hour` (default 50/hour) to prevent runaway blocking
- CRITICAL alerts and threat-intel reputation sightings always bypass the operator email/webhook rate limit (default 30/hour)
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
- **Mail brute force**: tails `/var/log/maillog` for direct IMAP, POP3, and ManageSieve auth failures. Composes with the existing geo-login monitor so `email_suspicious_geo` keeps working. Emits `mail_bruteforce`, `mail_bruteforce_suspected`, `mail_subnet_spray`, `mail_account_spray`, `mail_account_compromised`, and `mail_auth_backend_degraded`. Established good sources with a confined stale-password pattern emit the suspected advisory without auto-blocking. A compromise finding from an IP established on at least two other mailboxes stays visible as High without auto-blocking. Wider spraying and compromise without that standing still block. When the auth backend is degraded, `mail_bruteforce` and `mail_subnet_spray` auto-blocking pause until backend errors age out.
- **Mail auth backend probe (cPanel)**: independently of the log signals above, CSM opens the `cpdoveauthd` socket on a short interval. dovecot keeps answering its IMAP/POP3 ports during a cpdoveauthd outage, so cPanel's own service checks do not notice, yet every login fails regardless of password. When the probe finds the socket unreachable CSM raises `mail_auth_backend_degraded` and pauses both mail and SMTP brute-force auto-block. With `auto_response.mail_auth_recovery.restart_enabled`, CSM restarts the mail service once the backend has been continuously down past `down_grace` (default 10m, rate-limited), so a brief blip during maintenance never triggers a needless restart. Changes to mail auth recovery settings require a daemon restart.

## Network dry-run precedence

Three settings combine for direct-SMTP BPF enforcement. Any applicable
dry-run value that is true wins; live network denial requires all three
to be false.

| Layer | Knob | Default | Effect when true |
|-------|------|---------|------------------|
| Auto-response | `auto_response.dry_run` | true | Record automatic block decisions without applying firewall denial |
| Detector | `detection.direct_smtp_egress.dry_run` | true | Suppress detector-scoped action |
| Kernel | `bpf_enforcement.dry_run` | true | BPF program emits decision but allows traffic |

The kernel knob is consulted by the BPF program itself; the others
gate userspace action paths. All three default to true on a first
install so a configuration mistake cannot start blocking traffic.
