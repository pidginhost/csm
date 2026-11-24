# Auto-Response

CSM can act on what it detects: block an attacking address, quarantine a malicious file, stop a malicious process, or suspend a compromised mailbox. Auto-response is off until you enable it, and automatic IP blocks then start in dry run. Every action is recorded in the audit trail and the [action log](action-log.md).

## Turning it on

1. Set `auto_response.enabled: true` and the switch for each action you want, such as `block_ips`, `quarantine_files` or `kill_processes`. See [Configuration](#configuration).
2. For IP blocking, also set `firewall.enabled: true`.
3. Leave `dry_run: true` at first and watch what CSM would block. See [Dry-run safety default](#dry-run-safety-default).
4. Set `dry_run: false` and run `systemctl reload csm`.

Dry run covers automatic IP blocks, exposed-file virtual patches and mailbox suspension. File quarantine, cleaning and process termination act as soon as their switch is on, so leave those switches off while you evaluate the block policy. [Observe mode](observe-mode.md) forbids every automatic change.

## Actions

| Action | What it does |
|--------|--------------|
| **Kill processes** | Stops fake kernel threads, reverse shells, GSocket, loops that write back a file CSM removed, and shell loops a web request left running. Never kills root or system processes. See [Process termination](#process-termination). |
| **Quarantine files** | Moves webshells, backdoors and phishing files to `/opt/csm/quarantine/`, keeping owner, permissions and mtime. Restore from the Web UI. See [File quarantine and cleaning](#file-quarantine-and-cleaning). |
| **Block IPs** | Adds attacker addresses to the nftables firewall for a set time. See [IP blocks](#ip-blocks). |
| **Clean supported malware** | Removes injected code from PHP and `.htaccess` files after saving a backup. Database cleanup has a separate opt-in. |
| **Drop malicious DB objects** | With `clean_database` on, drops confirmed-malicious stored triggers, events, procedures and functions. A `SHOW CREATE` backup is saved first, so the drop can be reversed. Detection runs either way. |
| **PHP shield** | Blocks PHP execution from uploads and tmp directories. Inspects directly executed `wp-content` scripts for request-fed command sinks and packed eval loaders. |
| **PAM blocking** | Blocks an address at once after too many failed SSH logins. See [PAM blocking](#pam-blocking). |
| **Subnet blocking** | Blocks an IPv4 /24 or IPv6 /64 after several of its addresses were blocked. See [Subnet blocking](#subnet-blocking). |
| **Permblock escalation** | Makes a temporary block permanent after `permblock_count` repeated offenses within `permblock_interval`. |
| **Suspend mailbox** | After confirmed credential abuse, suspends the mailbox's logins and outgoing mail through cPanel. See [Mailbox suspension](#mailbox-suspension). |
| **Auto-freeze (PHP relay)** | On cPanel, freezes active Exim messages attributed to a high-confidence PHP-relay finding. It has its own dry-run control and rate limit. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only). |

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
  # max_blocks_per_hour omitted: 50 scan blocks an hour, admission ceiling 1000
  netblock: true              # enable subnet blocking
  netblock_threshold: 3       # IPs from same IPv4 /24 or IPv6 /64 before subnet block; minimum 2
  netblock_window: "168h"     # blocked IPs count this far back, expired blocks included; omitted defaults to 168h
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
  # Automatic IP blocks do not touch nftables. Admission keeps bounded
  # examples of successful capacity predictions, not every attempted block.
  # Manual operator commands (`csm firewall ...`) bypass dry-run and apply.
  # Flip to false only after verifying the policy in dry-run.
  dry_run: true

  # Advisory verdict callback. CSM POSTs each impending auto-block
  # to the panel before applying. The panel can downgrade to "allow"
  # (audit-only), attach `tenant_id` for downstream correlation, or
  # add a reason. CSM fails open on hook errors. Wire contract:
  # verdict-callback-contract.md in this book.
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

The full key list is in [Configuration](configuration.md).

## Dry-run safety default

`auto_response.dry_run` is `true` when the key is absent. An operator who turns on `block_ips` without reviewing the policy gets a record of what would be blocked, and no block.

Dry run is not a simulation mode for everything:

| Covered by `dry_run` | Not covered |
|----------------------|-------------|
| Automatic IP and subnet blocks and related network enforcement | File quarantine and cleaning |
| Exposed-file virtual patches in `auto` mode | Permission fixes |
| Mailbox suspensions and account mail holds | Process termination |

The actions in the right column follow their own `auto_response` switches. Manual commands such as `csm firewall ...` always apply.

IP blocking needs `firewall.enabled: true`. With the firewall off nothing can apply a block, so `csm validate` warns when `auto_response.enabled` and `block_ips` are both on.

### What you see in dry run

With the firewall on and outside observe mode, CSM forecasts each automatic block: would it fit the hourly ceiling and the temporary block set, given the blocks and forecasts before it? Status, `csm doctor` and the findings history show the forecast, with at most one summary a minute. `csm status --json` and `/api/v1/status` report how many forecast examples are stored. Whether each forecast block would have fitted is shown separately, in the forecast section of the status output.

A forecast is not a block. [Dry-run forecasts](#dry-run-forecasts) explains how the forecast models capacity.

### Checking the state

```bash
csm status --json | jq '.severities, .blocklist_size'
csm firewall status   # "Recently Blocked" entries with timestamps after the restart confirm live mode
```

### Going live

Set `dry_run: false`, then run `systemctl reload csm`. The key can be reloaded without a restart, and a successful reload validates the config and records its new hash. If you plan a restart instead, run `csm rehash` once before restarting.

When CSM goes live it purges the stored dry-run examples in the background. Status reports stale examples until the purge is complete. A daemon that starts live with examples left over purges them the same way. While dry run stays on, examples older than a week are dropped.

## IP blocks

CSM has two ways to apply an automatic block. Admission is the current one: it decides whether a block goes ahead by checking where the address came from, the hourly ceiling and the free room in the temporary block set. In dry run it records a forecast and applies nothing. An older blocking path still handles permanent blocks, mail spray blocks and a few fallbacks. [How admission decides a block](#how-admission-decides-a-block) has the full rules.

### Findings that always trigger IP block

With `auto_response.block_ips: true` and the firewall on, the findings below block their source address. Some rows block only at Critical severity or send the address to the challenge first; the row says so. In dry run the block is forecast, not applied.

| Finding | Description |
|---------|-------------|
| `wp_login_bruteforce` | WordPress login flood via wp-login.php |
| `xmlrpc_abuse` | XML-RPC endpoint flood |
| `email_php_form_relay` | A client that made hosted sites mail many outside addresses through their forms. Responses, retries included, need `email_protection.php_relay.ip_recipient_mode: enforce`. Goes to the PoW challenge first when challenge is enabled. |
| `http_request_flood` | Per-IP HTTP request volume over the threshold. Off by default; set `thresholds.http_flood_threshold` above 0 to enable. |
| `http_scanner_profile` | Random-URL probe pattern from one source IP. Off by default; set `thresholds.http_scanner_min_requests` above 0 to enable. Goes to the PoW challenge first unless `auto_response.http_scanner_action: "block"`. |
| `http_claimed_bot_unverified` | High-volume traffic claiming to be a crawler while reverse-DNS verification is pending. Goes to the PoW challenge first when challenge is enabled. |
| `http_ua_spoof` | IP over the UA anomaly threshold, including confirmed search-engine bot UA spoofing. Periodic; see [Configuration](configuration.md) for the opt-in flags. |
| `ftp_bruteforce` | FTP authentication flood |
| `smtp_bruteforce` | SMTP authentication flood. An address that fails only on mailboxes it has login standing on gets an advisory instead. |
| `smtp_probe_abuse` | Raw SMTP connect-rate flood before AUTH |
| `mail_bruteforce` | IMAP/POP3/ManageSieve authentication flood without matching successful mailbox activity. An address that fails only on mailboxes it has login standing on gets an advisory instead. |
| `mail_account_compromised` | Successful login from an IP that repeatedly failed auth on the same mailbox, or a mail login after the address failed on two or more mailboxes including a different one, or on a mailbox that does not exist. Only Critical findings block. High advisories are visibility only, including a login to a mailbox the address had login standing on before the failures. |
| `admin_panel_bruteforce` | phpMyAdmin or Joomla admin POST flood |
| `ssh_login_unknown_ip` | SSH login from an IP with no prior history, whether the realtime watcher or the periodic scan saw it first |
| `c2_connection` | Outbound connection to a known C2 server |
| `ip_reputation` | IP flagged by AbuseIPDB, rspamd or upstream threat intel |
| `modsec_block_escalation` | ModSecurity deny escalation |
| `modsec_csm_block_escalation` | CSM-internal ModSecurity deny escalation |
| `waf_attack_blocked` | WAF high-volume attacker |
| `email_compromised_account` | Email account compromise indicator |
| `email_cloud_relay_abuse` | Cloud relay abuse |

### What does not block

- Successful cPanel, FTP, webmail and PAM login audit events and authenticated File Manager writes never block or challenge directly. An incident made only of these events cannot request a block, even if it kept a higher severity from an older version. Independent attack evidence can still justify a response.
- `block_cpanel_logins` gates cPanel multi-IP logins, API authentication failures, webmail brute force and realtime FTP authentication failures. It also gates webmail challenge routing, because an unanswered challenge can become a block.
- A distributed HTTP flood rollup does not block. It describes one targeted vhost, not one source IP. The per-IP findings behind it still block normally.
- `http_asn_crawl` is handled separately, because one finding can carry several CIDRs. Only Critical findings with confirmed PHP worker saturation can tempban those CIDRs, using `auto_response.http_asn_crawl_tempban`. Dry run and the subnet safety guards still apply.
- `mail_bruteforce_suspected` and the High forms of `mail_account_compromised` are visibility only. They feed no direct, incident or spray blocking. A separate blockable finding can still block the same source. `mail_bruteforce_suspected` also reports SMTP, IMAP and POP password sprays while spray detection runs in observe mode.
- Central intelligence and incident blocking act on an address only when a finding names it as an attacker. The remote end of an outbound connection, a customer login, and advisories such as ModSecurity warnings or visitors of a mail-sending script do not count, even when another finding raised the incident's severity. A listed command-and-control server is blocked only by the C2 connection check, when `block_ips` is on.

Queued block candidates are checked against the current check policy and the login-blocking setting before each retry. On upgrade, old queue entries that name no check are dropped; a new eligible finding can queue the block again. Existing firewall blocks and permanent evidence stay.

### Suppression rules and blocking

A suppression rule hides an alert. It does not stop enforcement:

- The findings in the table above still block. To exempt an address, add it to the allowlist.
- Incident blocking, credential-spray containment and central threat responses stay active. They receive suppressed findings and findings from checks that send no notification. Duplicate observations in one batch count once.
- With database response enabled, a suppression does stop database cleanup and session revocation. The notice listing the session addresses is still sent.
- To mute an action's notification, suppress the action's own check type. The action still runs.
- Cross-account correlation uses only unsuppressed sources. Its derived alerts can be muted with their own suppression rules and stay in enforcement.

### What every block records

Blocks come from four sources: scan findings, challenges that timed out, central intelligence that local evidence corroborated, and incident spray containment. Each applied block records the same evidence:

- a temporary row in the threat database
- an entry in the blocked-IPs tracker
- an `auto_block` finding, visible to the block digest and to alerts
- one step toward a permanent block

A block that admission applied is never promoted to a permanent block while it stands. Its offense still counts toward a later block of the address.

All four sources block only while `auto_response.enabled` and `block_ips` are on. With either off, an expired challenge just leaves the challenge list. A reload of these switches applies before the next block attempt, including later entries of a challenge-timeout batch. An incident whose block these switches refused stays visible, without a failed-block warning.

The `auto_block` findings are a result, not new evidence: central intelligence and incident correlation do not count them as local corroboration. They are deduplicated before the digest, attack database, history and alerts receive them. Only an applied block marks its address as auto-blocked in the attack database. A dry-run "would be blocked" warning does not.

Blocks, challenges and the Web UI Block button use the structured address the check supplied, never an address quoted in the finding's message. A challenge notice keeps the address sent to the challenge, so daily summaries count it among their source addresses.

### Hourly limit

`auto_response.max_blocks_per_hour` caps automatic IP blocks. One key sets two limits:

| Limit | Applies to | Key omitted or 0 |
|-------|-----------|------------------|
| Admission ceiling | Every IP block admission applies: scan, challenge, central and incident blocks | 1000 |
| Older scan budget | Scan-driven blocks on the older blocking path | 50 |

An explicit value sets both. The admission ceiling is clamped to 20000.

- Packaged configs used to set 50. That value keeps the ceiling at 50 until you remove the key. `csm doctor` warns about a configured ceiling below 1000.
- Busy shared hosts reach a few hundred automatic blocks in their busiest hour. A ceiling of 200 can hold blocks back for over an hour.
- On upgrade, a host that used the former default of 2000 adopts 1000 when the key is omitted or zero. An explicit value keeps its meaning.
- Status and `csm doctor` show the ceiling and where it comes from.

Changing the ceiling:

- A new value applies on reload. A Web UI settings save applies moments later. If applying it fails, admission pauses and retries until it succeeds.
- A new ceiling never clears recent spend or grants fresh credit. If the blocks of the last hour exceed the new ceiling, admission waits for them to age out.
- A restart does not grant a fresh hour either. At its first start admission imports the current hour's block count. If that count cannot be read, it starts without saved credit.

### PAM blocking

CSM blocks an address at once when either is true:

- it reaches `thresholds.pam_bruteforce_threshold` failed SSH logins within `pam_bruteforce_window_min` minutes
- it fails SSH logins on `cred_stuffing_distinct_accounts` different accounts

Only a successful SSH login clears those failures. Failures from other PAM services never block.

### Subnet blocking

With `netblock: true`, CSM blocks a whole IPv4 /24 or IPv6 /64 when `netblock_threshold` addresses of that range (default 3) were blocked within `netblock_window` (default 7 days).

Addresses that count:

- Every currently blocked address, whatever its age, including operator and permanent blocks.
- A block that has ended, if its latest observed start is inside the window and it did not already count toward an earlier subnet block.

Addresses that do not count:

- An address you whitelisted or cleared, including by bulk whitelist. CSM forgets it.
- IPv4 addresses blocked for a mail login spray. IPv6 spray blocks do count toward their /64, because one /64 is treated as one source.
- A saved spray block that is missing from the kernel.
- An address on `c2_blocklist`, whatever finding asked for the block. A listed command-and-control server is where local processes connect, not a source of attacks. Other blocked addresses in its subnet still count. Such an address never counts toward a permanent block either.

An operator block that goes away and returns starts fresh history once CSM has seen it gone.

CSM reads the spray classification from the firewall state, so a missing or stale scan tracker cannot turn IPv4 spray blocks into range evidence. If block metadata cannot be read, subnet escalation waits while single-address blocks continue.

Subnet blocks refuse the default route and any range that covers infrastructure, local host, allowed or port-specific allowed addresses.

The subnet history is pruned hourly. If its file cannot be read, CSM leaves it untouched and counts only the addresses blocked right now until the file is repaired or removed. Status and `csm doctor` report the failure. Clear, whitelist and flush actions report a failed history cleanup so you can retry.

### Mail login spray blocks

In enforce mode a spray block lasts `thresholds.mail_spray_block_expiry` (30 days by default), not `block_expiry`. An address already blocked keeps its current expiry.

- A block that combines a spray finding with another finding for the address, such as a WAF or per-IP brute-force finding, is a normal block. It lasts `block_expiry` and uses the scan budget.
- When the temporary block set is full, the spray block that ends soonest is evicted first. An operator's temporary block is never evicted for an automatic one.
- CSM remembers a blocked address until one spray memory window after its block ends. One failed login from it in that time, on any mailbox, blocks it again for the spray length. That includes a failure logged just before an authentication outage is detected. An IPv6 address blocked on failures counted across its /64 stays subject to re-blocking until that address itself is released.

Spray blocks have their own hourly budget, the same size as the scan budget:

- CSM reserves credit before the firewall attempt. An uncertain result keeps the credit. A confirmed non-block releases it.
- When the spray budget is full, spray retries wait. Other scan blocks keep their own budget.
- Waiting spray retries hold at most half of the retry queue and give way to other retries when the queue fills. Deferred retries follow the same limits.
- One warning an hour names the budgets that are full at that moment, and says when retries were dropped because the spray share of the queue was full.
- A failed spray reservation defers spray blocks and reports a warning. Other scan blocks continue.

What clears an address's spray history:

| Action | Effect |
|--------|--------|
| Operator unblock, or an undo that removes a block | Clears the re-block and the failure history of the address, or for IPv6 of its /64. SMTP, IMAP and POP failure counts restart across all address spellings. Pending SMTP rejections are discarded, so a delayed reply cannot restore old spray evidence. Login trust and cracked-password records stay. |
| Allow or temporary allow | The same, even when the address holds no block. This includes the allow CSM adds for an address a `dyndns_hosts` or `infra_ips` hostname resolves to. |
| Self-service unban through the panel API with an unban-scope token | Lifts the block and its re-block. Keeps the failure history and counts, so renewed spraying is blocked again on the usual rules. |
| Admin token or browser session on the same API route | Full operator release. |
| Flush | Clears the spray history, per-address failure counts and pending rejections of every address. |

A failed firewall release returns an error and clears no threat state. Authentication outage guards remain active after a release or flush.

### Known-customer block alert

When an automatic block applies to an address that logged in successfully as a customer in the last 30 days (cPanel, webmail, SMTP, IMAP or POP), CSM alerts you at once. It sends one email and the generic alert webhook as event `customer_block`, with the blocks under `csm.customer_blocks`. See the [API reference](api.md#summary-and-customer-block-webhooks).

The alert is the false-positive check of automatic blocking. It is never an exemption: the block stands for its configured length.

The alert names:

- the address, the block reason and the check that caused it
- the customer's login kind, account or mailbox, and last login time
- the command that lifts the block: `csm firewall remove <ip>` for an address, `csm firewall remove-subnet <cidr>` for a range

An IPv6 customer is named by its /64. A subnet block or netblock that covers known customers sends one message with their count and the five most recent.

An allow rule (`csm firewall allow <ip>`) trusts the address on every port. It does not pass a blocked range, but CSM never blocks a range over an allowed address.

Which blocks alert:

- Every applied block counts: scan blocks, permanent promotions, challenge timeouts, central intelligence and incident blocks.
- A customer whose own login caused the block is left out, also when the block comes later than its cause. A mail account compromise names that address and account in its own Critical alert. When earlier address blocks escalate to a range block, its count and examples include only the remaining customers.
- A login with stolen credentials also makes an address known. The alert can therefore show the block of an attacker who holds a customer's password, which is worth seeing too.

How it is delivered:

- Each applied block sends at most one message. A later new block of the same address sends another.
- A promotion to a permanent block is named in its block's message when both reach CSM together. A promotion that arrives apart from its block sends a message of its own.
- The block's notice still goes to the daily summary, which lists the block with its customers. A failed alert still reaches you that way.
- The alert replaces the live watched-country alert for the same block. The block still counts in the watched-country section of the daily summary.
- It does not spend the hourly alert budget, goes out with `alerts.block_digest` off and ignores `alerts.block_digest.channel`.
- A phpanel webhook does not receive it.
- Dry-run and observe-mode verdicts that would have blocked a known customer are listed in the [daily summary](configuration.md#daily-summary) instead.

### Verdict callback (advisory)

With `verdict_callback.enabled: true`, CSM POSTs a signed JSON request to the panel before each automatic block. The panel answers:

| Reply | Effect |
|-------|--------|
| `{"verdict": "block"}` | CSM applies the block. |
| `{"verdict": "allow"}` | Audit only. CSM logs the decision and leaves nftables alone. |

Either reply can carry metadata (`tenant_id`, `note`). The full schema is in the [Verdict callback contract](verdict-callback-contract.md).

Signing:

- CSM refuses to start without `hmac_secret` or a non-empty `hmac_secret_env` value, unless `allow_unsigned: true` is set for a staged unsigned rollout. Without that opt-in, an unsigned `allow` reply is rejected and the block continues.
- With a secret configured, the panel must sign the reply body, unless `require_response_signature: false` is set for a staged rollout. With that opt-out CSM still checks any echoed `nonce` or `timestamp`. A legacy reply that omits both keeps working.

Errors: CSM fails open. On a timeout, a non-2xx status or a malformed body, local admission continues, still subject to dry run and capacity. An error proves neither a block nor a forecast example. The failure is written to the daemon log.

The callback runs after local validation and the infrastructure-IP checks, and before the dry-run gate, so the panel sees dry-run decisions too. In dry run:

- With the firewall on and outside observe mode, admission asks for each locally eligible block attempt, with `CSM auto-block: <check>` as the reason. It sends up to four requests at a time and uses the configured `allow_unsigned` and `require_response_signature` settings.
- An `allow` ends that forecast without a block.
- A full block set still sends a request when a lower-priority automatic block could be replaced or an equal-priority forecast block rotated out. Pending requests hold no slots. Admission checks capacity again after each answer, so competing requests cannot reuse one slot.
- The v1 request has no dry-run field. Forecast examples and summaries are bounded, and promotions the forecast does not support are not simulated. After a reload CSM asks the panel again and does not reuse earlier answers.

Do not expect exactly two requests per block. Until admission decides blocks, a panel can receive an additional request for the same automatic block. Local refusals, existing effects, capacity waits, coalescing and retries all change the count.

### Infrastructure IP DNS guard

Addresses in top-level `infra_ips` and `firewall.infra_ips` are never blocked automatically. Hostnames in those lists are resolved every 5 minutes.

If a hostname stops resolving, CSM raises an `infra_ips_unresolvable` Warning and keeps the last known addresses protected for the grace period (10 minutes by default). The finding clears by itself when resolution recovers.

## Process termination

CSM evaluates each eligible finding for termination once, whether a scan or alert delivery sees it first. A refused or failed attempt is not retried when the same finding reaches alert delivery. Realtime findings are evaluated too. A new detection, or a finding replayed from storage, gets a fresh evaluation.

### Signaling the right process

CSM never signals a bare PID number. It takes a kernel handle on the process, verifies the owner, executable, start time and referenced file, confirms the process is still alive, and sends the signal through the handle. If the process exits and its PID is reused, the new process is not touched.

Automatic and manual malware termination refuse a process with root credentials, including effective and saved root IDs. The separate opt-in AF_ALG reaction requires the current credentials and executable to match its recorded event.

### Kernel support

Safe signaling needs `pidfd_send_signal` (Linux 5.1). EL8 and CloudLinux 8 ship 4.18 kernels without `pidfd_open` (Linux 5.3). There CSM pins the target through its `/proc/<pid>` directory descriptor, which `pidfd_send_signal` accepts and which refers to the same kernel process. Both ways reject a recycled PID.

On a kernel without `pidfd_send_signal`, or when service restrictions deny the call, termination stays disabled. With `auto_response.kill_processes` on, `csm doctor` then reports `process termination supported` as failed and the health status becomes `degraded`, so you see the gap before an incident needs it. Each health snapshot probes again, so a transient resource failure clears by itself.

### When termination fails

- An automatic failure is logged. The original detection remains.
- Manual kill-and-quarantine reports a termination failure even if the file was quarantined. Inspect both the process and the recovery entry before retrying.
- A cancelled manual request is honored before any signal is sent.

### Shells left running by a web request

A shell a web request left running (`detached_web_process`) is stopped every time it is seen. Only shells are stopped. Any other process a web request left running, including a non-shell parent of a shell, stays a Warning for review.

When CSM stops such a shell a second time within 24 hours for the same account, or the same user outside an account, it raises `detached_web_process_respawn` once a day. Something keeps starting it, most likely a PHP file that requests still run. For a hosting account CSM also queues a malware scan of the account. That scan quarantines and cleans only what automatic quarantine would at that moment, within the same safety limits. Its report shows what it quarantined, cleaned or refused.

Stopping never backs off: a shell that keeps coming back is stopped every time. CSM tracks up to 4096 owners and forgets them when it restarts. Past that number, a new owner's shells are still stopped but not escalated until a tracked owner has gone a day without a stop.

## File quarantine and cleaning

### Limits

Realtime quarantine, scheduled quarantine, PHP cleaning and automatic `.htaccess` cleaning share one rolling-hour budget:

| Key | Limits | Default |
|-----|--------|---------|
| `auto_response.max_file_actions_per_hour` | Attempts on the whole host | 50 |
| `max_file_actions_per_account_per_hour` | Attempts for one account | 10 |
| `max_file_action_failures_per_hour` | Failures before these responses pause | 3 |

Zero or an omitted key uses the default. Negative values and values above 10000 are rejected.

How the budget is counted:

- Each attempt is reserved before CSM touches the file. Successful, failed and interrupted attempts all use capacity.
- Reservations live in `<state_path>/file-response.json`. They survive config reloads and daemon restarts and expire one hour after they were made. If the clock is set backwards, future-dated reservations stay charged until their hour has passed.
- The account comes from the file's account-home path, not from the finding text. Paths outside recognized account homes share one unknown-account budget.
- One account reaching its limit does not stop other accounts, unless the host or failure limit is reached too.
- A slow file action does not hold up other actions. An action in progress counts against the failure limit until its result is saved, so concurrent failures cannot pass the limit.

CSM refuses the action when the budget state is busy, unreadable, incomplete or unwritable.

Automatic quarantine of a directory or a special file is always refused, because one directory move can affect any number of files. Manual remediation stays available after you review the detection.

When responses pause:

- The original detections stay visible. A deduplicated `auto_response_paused` warning reports the cause.
- Account-limit notices are grouped for the whole host, so a fault across many accounts cannot flood the alert budget.
- A pause creates no retry job. New eligible detections can act once capacity returns.
- Review the outstanding findings and recovery evidence before remediating by hand.
- Do not delete the budget state to clear a pause. Repair the storage fault and let the reservations expire.

These limits apply under the existing `enabled`, `quarantine_files` and `clean_htaccess` switches. `dry_run` does not preview file quarantine or cleaning.

### What is quarantined automatically

Two kinds of Critical realtime PHP finding are sent for a file response immediately, within the limits above: request data that reaches an execution primitive, and executable PHP that unwraps and runs encoded content.

For these, and for whole-file malware the cleaner identifies, quarantine holds an exclusive Linux lease on the open file until the file is removed. It refuses while another process has the file open or is running it, and when the content or the path identity changes. Other quarantines take no lease, so they can still move a file that is open or running.

These matches stay for review and are never moved automatically: comment-only matches, URL-only droppers, filename-only checks, tail-window matches and YARA-only findings.

Realtime signature quarantine also needs high confidence; see [Safety guards](#safety-guards).

Quarantine copies exactly the file size it verified and checks the file again before removing it. A file that changed in between is restored and its copy discarded. If the name was recreated meanwhile, the error names the private directory that holds the changed file.

### Repeat detections

- Duplicate detections of one unchanged file share a single realtime response attempt. A different file planted at the same path is eligible again.
- Within one daemon run, alert delivery does not repeat a file response that a scan already evaluated or the realtime gate already admitted, budget refusals included.
- A realtime detection rejected on sampled content stays eligible for full-file validation during delivery.
- The original findings still reach alerts and history. A new detection can be evaluated again.
- Findings still queued at shutdown are evaluated again by the next daemon run, under the same saved limits.

Findings saved at shutdown for the next start keep their offending subnets and targeted accounts, so subnet response and credential-spray correlation still work after the restart. Findings saved by an older version replay without that data. The subnets also appear in the public `cidrs` field.

Saved reputation findings keep their intelligence source and expiry. If an expiry cannot be saved, only that intelligence metadata is dropped. The finding and the rest of the batch are still saved and replayed. There is no setting for this.

### Refusals and failures

A quarantine or cleaning attempt ends in one of three ways:

| Result | When | Counts toward the failure pause |
|--------|------|-------------------------------|
| Done | The file was quarantined or cleaned | No |
| Refused | The file changed or disappeared before the change. This includes a socket swapped in and a parent path replaced after the quarantine copy. For a cleaner, also: it recognizes no injection or declines an unsupported target. | No, but it uses capacity |
| Failed | A read, write, backup or durability error | Yes |

A failed PHP cleaner leaves the file and any pre-clean backup for manual review. It does not fall back to whole-file quarantine.

Automatic actions check the file again after reserving budget. A special file swapped into the path cannot stall response processing.

Manual full scans leave cleaner refusals for review and do not report them as failed remediation. `csm clean` also tells a refusal from a failure. Both return a nonzero exit status when the file was not cleaned.

`csm clean --preview` runs the same cleaner without a backup or a write and prints the change as a unified diff:

- The header names the SHA-256 of the file before and after. These are the digests the action log records when the clean is applied.
- File names and content are escaped for the terminal.
- A preview over the display limit fails without writing.
- Integrations can check for `response.preview_diff.v1` in the capabilities list.

Automatic permission fixes dismiss the original finding after a successful fix, or after confirming the unsafe permission is already gone. A confirmation alone does not report a permission change.

### WordPress files

WordPress core, plugin and theme files are cleaned in place, with three exceptions:

| Case | What CSM does |
|------|---------------|
| Cleaning would leave nothing of a file that sends no page output | Quarantines the whole file. A stub would lose the same content, and quarantine keeps it for a restore. |
| Cleaning would erase the file's page output | Leaves the file untouched for review. |
| The WordPress core release, or the wordpress.org plugin release, that the site runs does not ship the file | The file was planted. CSM quarantines it. |

Page output is any text outside PHP code, including short and echo tags.

CSM trusts the release a site names only when its `version.php`, or the plugin's `<slug>.php` main file, is that release's own copy, and only from the checksums the realtime file monitor has cached. A plugin whose main file has another name stays with the cleaner.

Whole-file quarantine rechecks the original content under the same protection as other verified file responses. A changed file stays in place. `csm clean` refuses a file it would leave empty.

### Files written back after removal

When CSM quarantines or cleans a file, it clears the alert state it kept for that file. If the file is detected there again, the finding is reported as new, not held back as a repeat. Dismissals remain in effect.

CSM also remembers, for seven days, the content each quarantine or clean took away. A process that writes the same bytes back to the same path raises `removed_file_restored_realtime` (Critical). With `quarantine_files` on, CSM repeats what it did before: it quarantines the file again, or cleans it again.

What counts as the file coming back:

- Any restore of the same bytes, including the account's own through SSH, cPanel or FTP. A stolen login replays a payload the same way.
- Removed files are watched whatever their extension.

What does not:

- A restore from the Web UI quarantine page. To keep a file, restore it from there.
- CSM's own writes and official WordPress release files.
- A file cleaned with `csm clean` from the command line. It is not remembered.
- A file that no longer holds the removed bytes. CSM checks before repeating the response, so a later replacement is never removed.

The finding says how the bytes came back: an SSH, cPanel, cron or FTP session, a web request, a terminal, or a process detached under init. Sessions take precedence over PHP workers in the ancestry, so running PHP from cron or a terminal does not make it a web request. Incomplete ancestry is reported as untraceable.

The finding also gives the expiry time of the current removal. Each successful removal starts a new seven-day window, so repeated restores can extend it. A restored `.htaccess` is cleaned only when `clean_htaccess` is on.

The daemon keeps this memory across restarts, in a private file it owns. A damaged or unsafe file is logged and ignored, and detection carries on without it.

#### Stopping the process that wrote the file back

With `kill_processes` on, CSM also stops the process that wrote the file back, together with its parent processes of the same account, parents first, so a loop cannot start another writer.

It does so only when those processes trace back to the web server or run detached under init, the shape of a loop a webshell leaves behind. These are left running, and the file is still handled:

- a PHP worker that serves the site, unless it wrote the file itself
- a process with a terminal
- a process started from an SSH, cPanel or cron session, or with such a session anywhere above a PHP worker
- any process whose ancestry CSM cannot read in full
- root processes, always

The processes are named when the write is seen. Each is checked again through a kernel process handle just before the signal, as in [Signaling the right process](#signaling-the-right-process).

### Restoring quarantined files

Restore a file from the Web UI quarantine page. Restore puts back the content together with the saved modification time, owner, group and permissions.

What restore refuses:

- A symbolic link in a destination directory.
- An existing file or directory at the destination. Restore never replaces one.
- A destination that changes during the restore. CSM reports a conflict and keeps the quarantine entry.

When a restore fails or is interrupted:

- Check the original location before retrying. A partial file can remain in the directory that was opened for the restore. CSM keeps it, because removing it could discard a file someone else wrote there meanwhile.
- A failure after a move or unlink reports partial completion and keeps the recovery metadata where it can. Inspect both the original and the quarantine locations named in the error. A copy may already be restored while the quarantine cleanup is incomplete.
- An ownership or timestamp failure keeps the recovery evidence and reports an error.

Custom account roots take part in manual remediation and restore. Set up [service write access](custom-account-roots.md) for roots outside the packaged grants before using these operations.

Older quarantine entries:

- Entries without a saved quarantine date sort last. Entries that use the old `quarantine_at` spelling are still listed and restored.
- Older entries have no recorded original modification time. Restore leaves the new file's modification time in place.
- Some older access-file cleanup backups lack trustworthy ownership and permission data. Check those attributes when you restore them.

[Quarantine and restore durability](#quarantine-and-restore-durability) lists the storage guarantees.

### Exposed-file virtual patches

`virtual_patch_exposed_files` denies HTTP access to confirmed exposed files with reversible `.htaccess` rules. `off` only alerts, `manual` applies with `csm virtual-patch --apply`, and `auto` applies confirmed findings when `dry_run` is false, except warning-only sample SQL.

A preview comes from `csm virtual-patch` without `--apply`, or from `auto` mode in dry run. It writes nothing and shows each access-file change as a unified diff:

- Each diff header names the SHA-256 of the file before and after. The after digest is the one the rollback copy expects.
- Later changes to the same file start from the previous planned change.
- The local command shows context. Automatic alerts show only the proposed deny rules and mask any existing line that needs a final newline.
- A file that cannot be shown as text fails the preview.

Each applied deny keeps a rollback copy under `/opt/csm/quarantine/pre_clean/`. Applying the same rollback state again reuses that copy. A change in content, ownership, permissions, modification time, or between remove and replace, keeps a separate restore point. A later edit with identical bytes but a new modification time therefore gets its own.

Rollback replaces or removes the access file only when the saved content, owner and permissions still match, so later customer edits are preserved. It uses the same directory confinement as restore.

All-in-One WP Migration rewrites the access file inside `wp-content/ai1wm-backups`. CSM therefore also denies `.wpress` filenames, and only those, from the parent `wp-content` access file. It adds no parent-wide `.zip` or `.gz` rules, because those can be legitimate downloads elsewhere under `wp-content`.

## Mailbox suspension

After confirmed credential abuse, CSM suspends the mailbox's logins and outgoing mail through cPanel. Suspension follows `auto_response.enabled` and dry run.

Set `auto_response.suspend_mailboxes: false` to keep every finding and incident without suspending mailboxes. Account holds for a domain are unaffected.

### When a mailbox is suspended

| Evidence | Response |
|----------|----------|
| A login after brute force (Critical `mail_account_compromised`) | One sign of compromise. After a few failures it suspends the mailbox only together with another sign. After at least `mail_bruteforce_threshold` failures on that mailbox the password was guessed, and this sign alone suspends the mailbox. |
| Several signs for one mailbox | Suspended with a single Critical `email_mailbox_compromise` finding. See [Mailbox Compromise Evidence](detection-realtime.md#mailbox-compromise-evidence). |
| The mailbox is caught sending abuse | Always suspended. |
| A login by the cPanel account's own username | Names no mailbox. After `mail_bruteforce_threshold` failures CSM holds the account's outgoing mail, since that password also opens cPanel and every mailbox. A Critical `email_mailbox_response` finding says what was done. After fewer failures it only alerts. |

Account logins older than the mailbox evidence retention period do not trigger holds.

### What CSM does

CSM tries to suspend both the mailbox's logins and its outgoing mail. Either success stops the escalation. A partial suspension names the restriction that succeeded and does not claim both.

The account-wide outgoing mail hold is the fallback when both fail, when no account owns the domain, or when the target is a bare domain. Evidence that includes no sending never falls back to the account hold.

- If cPanel cannot report the mailbox state, CSM suspends anyway and records the suspension as its own. Sending evidence can still fall back to an account hold.
- Restrictions and holds that were applied outside CSM are not offered for release.
- Each attempted suspension or hold is recorded in the action log with its quoted release command. Dry run writes one planned-action record and runs no command. Disabled auto-response writes none.
- If CSM cannot save an applied hold, the response finding sends staff to the action log and a manual release on the mail server.

CSM runs `/usr/local/cpanel/bin/uapi` as a transient systemd service outside the daemon's filesystem sandbox. Hosts without a usable `systemd-run` run it directly. Each call has a time limit, the JSON result decides success, and mailbox names are always passed as literal arguments. WHM holds and releases also check the JSON API result before reporting success.

### Suspensions per hour

On login evidence, CSM suspends at most three mailboxes of one hosting account in any rolling hour. Mailboxes no hosting account owns share their domain's allowance.

- A mailbox caught sending abuse is always suspended. It still counts toward the hour, including during concurrent login responses.
- New sending evidence triggers a response even if an earlier login-only incident was held back.
- Past the limit CSM leaves the mailbox open, reports that it would have suspended it, and raises one Critical `email_mailbox_suspension_paused` finding for the account in that hour. The notice includes mailboxes held back by redirect evidence in the same batch.
- A released suspension still counts during that hour. Suspending the same mailbox again uses no extra slot.
- Stalwart aliases count as the mailbox they resolve to. A reassigned address counts as a new mailbox.
- Account holds and alias changes do not reset the counts. Counts survive a daemon restart.

### Releasing a mailbox or account

After you resolve the credential abuse, release the mailbox or account on the Email page, Suspended tab. The tab lists every suspension and hold CSM made, with its live state in cPanel.

- A suspension lifted directly in cPanel shows as released outside CSM.
- An incomplete or unreadable status stays unknown. A delayed status reply cannot release a newer suspension.
- Release undoes the recorded restrictions. It never changes a password.
- Evidence captured before the release cannot suspend the mailbox again.
- Cleanup failures are reported so you can retry the release.

Releasing an account hold delivers the mail cPanel held. Delete spam from the Queue tab first; the confirmation says so.

The action log keeps the release commands, quoted for the shell. For example:

```bash
/usr/local/cpanel/bin/uapi '--user=account' Email unsuspend_login 'email=alice%40example.com'
```

and the matching `unsuspend_outgoing` command. The address is URI-encoded because uapi decodes its values.

## Mail auth backend recovery (cPanel)

CSM opens the `cpdoveauthd` socket on a short interval. During a `cpdoveauthd` outage dovecot keeps answering on its IMAP and POP3 ports, so cPanel's own service checks notice nothing, yet every login fails whatever the password.

When the socket is unreachable, CSM raises `mail_auth_backend_degraded` and pauses automatic blocking for both mail and SMTP brute force, so customers are not blocked for the outage.

With `auto_response.mail_auth_recovery.restart_enabled`, CSM restarts the mail service once the backend has been down without a break for `down_grace` (10 minutes by default). Restarts are rate-limited, and a short interruption during maintenance does not trigger one. Changes to the mail auth recovery settings need a daemon restart.

The log-based outage signals are described in [Real-time detection](detection-realtime.md#mail-auth-brute-force-tracker).

## Network dry-run precedence

Three settings combine for direct-SMTP BPF enforcement. If any of them is true, traffic is not denied. Live network denial needs all three set to false.

| Layer | Key | Default | Effect when true |
|-------|-----|---------|------------------|
| Auto-response | `auto_response.dry_run` | true | Records automatic block decisions without applying firewall denial |
| Detector | `detection.direct_smtp_egress.dry_run` | true | Suppresses the detector's own action |
| Kernel | `bpf_enforcement.dry_run` | true | The BPF program reports its decision and allows the traffic |

The BPF program reads the kernel key itself. The other two gate actions in the daemon. All three default to true on a first install, so a configuration mistake cannot start blocking traffic.

## Safety guards

Processes:

- CSM never kills root processes, system daemons or cPanel services.

Addresses:

- Infrastructure IPs (`infra_ips` and `firewall.infra_ips`) are never blocked or sent to the challenge page.
- A block of an address that recently logged in as a customer is alerted at once and never exempted.
- Failed mail logins confined to mailboxes an address regularly logs in to raise an advisory, not a block. See [login standing](detection-realtime.md#login-standing).
- Subnet blocks refuse the default route and any range that covers infrastructure, local host, allowed or port-specific allowed IPs.
- IP blocks are limited by `auto_response.max_blocks_per_hour`: 1000 an hour for admission and 50 an hour for the older scan budget, by default.

Files:

- Quarantined files keep their full metadata for restoration.
- Every regular file is copied from its verified open descriptor into a private quarantine copy before the detected name is removed. Other hard links are reported after removal. A file swapped into the detected path is reported as a refused remediation: the captured copy is kept as evidence and the replacement is left untouched.
- Realtime signature quarantine needs high confidence: category `webshell` or `dropper`, a file of at least 512 bytes, and either Shannon entropy of 5.5 or more, or hex density over 20% with an obfuscated-execution signal. This keeps legitimate WordPress plugins out of quarantine.

Alerts:

- Critical alerts and threat-intel reputation sightings always bypass the operator email and webhook rate limit (30 an hour by default). Lower-severity findings batched with them still count against it.
- Attacks CSM blocked or challenged, and its applied block and challenge notices, go to the daily summary, not to alert email and the generic webhook. An attack is alerted immediately when its block failed, is still queued or ran in dry run. So are a block of a Cloudflare-covered address and the web attacks from it.
- Trusted countries (`trusted_countries`) suppress login alerts from expected locations.

The detections behind these actions are described in [Real-time detection](detection-realtime.md).

## Details

The sections below are reference material for edge cases. You do not need them to run auto-response.

### How admission decides a block

Every automatic block the blocking code selects is handed to admission. What admission does with it depends on the mode:

| Mode | What happens |
|------|--------------|
| Live: `dry_run` false, firewall on, outside observe mode | Admission applies the block itself, within the hourly ceiling and the free slots of the temporary block set. |
| Dry run | Admission forecasts the block. |
| Firewall disabled, or observe mode | Admission previews the block. Nothing is applied. |
| Firewall engine starting or unavailable | Queued live blocks wait. New responses stay on the older blocking path. |

A refusal is final. The older blocking path does not apply a block that admission refused, and neither does a queued retry of the same finding. Independent evidence for the same address keeps its own response. A challenge whose evidence was refused keeps that refusal, so its timeout follows the same rule.

Status, `csm doctor` and the findings history show the results. Forecast endings add no per-attempt row to the [action log](action-log.md).

#### Blocks that stay on the older path

- Permanent blocks, mail spray blocks, and derived blocks (challenge timeouts, central intelligence and incident blocks) that ask for longer than `auto_response.block_expiry`. They stay there even when their evidence was refused, with one exception: a `forged_client` refusal and a final rewrite refusal hold for every block lifetime, including permanent incident escalation. Longer derived blocks still never block a known CDN edge or a client behind a trusted proxy.
- A block refused only because admission could not take new work at all.
- A block refused because the web server rewrote the client address from a proxy header, in one of two cases: Apache, while CSM has never trusted its current web peer-log reader; or nginx reading a proxy header, in a configuration CSM reads whole and without PROXY protocol.

A rewrite refusal is final, and nothing goes to the older path, in these cases:

- On LiteSpeed. It also applies proxy headers to requests from the host itself, so any local user can choose the address it logs.
- With a log format that writes request data where CSM reads the client, even when the same configuration also enables proxy-header rewriting.
- With a detected nginx `proxy_protocol` source, for queued retries and permanent blocks too. Only sources covered by `web_server.trusted_proxies` can pass verification. The shipped CDN ranges alone never authorize a PROXY protocol address.

`csm doctor` tells these final refusals from the Apache and nginx header-only exception.

#### When the block set is full

Work the temporary block set has no room for waits as `set_full` until a slot frees.

- Of the slots that operator, unknown and subnet blocks leave, a fifth is kept for direct or corroborated attacks.
- Automatic blocks from the older path occupy general slots.
- A set without a size limit counts as 10000 entries.
- A Critical local attack, or one with direct compromise or independently corroborated evidence, may take the general slot of an older automatic block that recorded its origin.

#### Responses you turned off

With the firewall on, a queued response that the current policy disables ends as `disabled`, without a withheld alert. That also happens when its evidence expires before a restart or config reload. Turning the response back on needs a new eligible observation. Ended work is not replayed.

### Which addresses can be blocked

A block is only as good as the address it targets. Admission refuses a block when it cannot be sure the address is the real attacker.

#### Evidence needs a trusted address source

- Admission checks how each finding's address was read. It compares that with the address sources the check declares and with the check's current policy. It does this when evidence is created and every time stored evidence is used.
- A check without a trusted address source cannot produce evidence. This rules out PHP relay findings, whose client address comes from a mail header a local account can forge. In dry run these findings cannot produce a successful forecast.
- Each response target is bound to its evidence. Only the mail subnet and ASN crawl entries may widen one address to a containing prefix. Queue requests, retained candidates and reservations repeat the check, so a response queued earlier cannot bypass it.
- A log reader that starts in the middle of a line still passes the rest of that line to the checks, but the fragment cannot supply evidence. Complete lines after it are unaffected.

#### Sources that supply evidence

`auto_response.dry_run` decides whether admission forecasts these blocks or applies them.

- Scheduled cPanel, ModSecurity audit, per-site and central access log scans supply evidence from complete records with a verified address source and a server time. Rereading a record does not refresh its time or count as independent evidence. Unfinished or ambiguous records supply nothing.
- SMTP password sprays read from Postfix mail logs supply evidence.
- ModSecurity observations expire with the denial's recent-log window.
- The startup Exim history scan names the newest counted send of the account it reports, with Exim's full timestamp and zone, as the realtime mail log reader does. An invalid zone supplies no observation. When the realtime cloud relay window is full, it still keeps the address of the current send.
- An IP reputation finding supplies evidence only with a local sighting: a record whose log parser read the address, dated by the server within the last 24 hours. An HTTP or cPanel sighting never uses an address listed in `web_server.trusted_proxies` or `challenge.trusted_proxies`. The normal freshness check still applies.
- The scheduled command-and-control connection scan supplies evidence for established IPv4 connections this server opened. See below.

Command-and-control connection details:

- CSM names each connection by its socket during the current boot, and reports both endpoints and the socket owner.
- The first-seen time survives a restart when the state save completed. Listener changes and overlapping scans do not refresh it.
- Socket inodes can be reused between scans. Such a report keeps the earlier time. Lost first-seen state can make a forecast conflict with retained evidence.
- A connection on a local port that also listens still alerts but supplies no evidence, because the socket table does not show which side connected.
- Without a socket identity the alert still shows but supplies no evidence.
- Connections still waiting for a reply, and those in the IPv6 socket table, are not reported.
- Blocking the address drops its replies. It does not stop data this server sends to it.

#### Clients behind a proxy

An HTTP finding whose counts or bot-majority decision use forwarded addresses names a client behind a trusted proxy. That includes mixed direct and forwarded traffic. The firewall cannot reach such a client, so the finding is refused as unreachable.

How CSM reads the forwarded header:

- The client is the first untrusted address reached from the right of the header.
- An address in `web_server.trusted_proxies` or `challenge.trusted_proxies` is never read as the client. This is true even when CSM ignores the header that proxy sent, because the proxy address is this server's own or because CSM could not read this server's addresses.
- An address of this host is never trusted as a proxy.
- CSM refuses a header over 4 KiB, or a walk that must read more than 32 hops, the client included. Hops left of the client never count.
- Periodic scans keep a bounded tail of complete addresses. Padding to the left of a retained client does not hide its count. A missing or unreadable right end, or a tail that holds only trusted proxies, names no client and is not counted.

Known CDN and website-firewall edges are refused as `proxy_peer`:

- This applies to HTTP, cPanel and IP reputation findings, whether or not `cloudflare.enabled` is set.
- An edge is an address in the Cloudflare, QUIC.cloud and Sucuri ranges CSM ships. A replacement `http_proxy_ranges.yaml` does not change them.
- When the ASN database names it, a network in `thresholds.http_asn_crawl_reverse_proxy_asns` is an edge too.
- The refusal does not apply to SSH, FTP or mail session peers.

#### When the web server rewrites the logged address

A web server can replace the client address in its log with one taken from a proxy header. CSM then cannot trust that log by itself. New HTTP findings are refused as `rewritten_log`, and access-log lines are not IP reputation sightings. cPanel access lines still are, even when the same address also appears in a rewritten web log.

CSM treats the log as rewritten when it finds any of these, or when it cannot read the configuration files completely:

| Web server | Setting |
|------------|---------|
| Apache | `RemoteIPHeader`; `RemoteIPProxyProtocol On`; a loaded or configured mod_cloudflare, including `DenyAllButCloudFlare`; mod_rpaf with `RPAF_Enable On` or `RPAFenable On` |
| nginx | `set_real_ip_from` |
| LiteSpeed | Use Client IP in Header, in its own configuration or, on cPanel, the Apache configuration it loads |
| Any | An access log format that writes request data into the first client token |

A mod_rpaf that is disabled or only loaded does not count as a rewrite.

These access logs carry no original-peer field CSM reads. The separate [web peer log](detection-realtime.md#web-peer-log-and-forged-client-addresses) supplies the connecting peer, and with it CSM can verify each address.

#### Verifying an address with the web peer log

Where the web server rewrites client addresses, CSM checks each one against the web peer log:

| What the peer log shows | Response |
|-------------------------|----------|
| The address connected for itself | Blocked, as on a host without a proxy |
| A client behind a trusted proxy or a known CDN edge | Challenged only |
| An address that a different connecting peer supplied | Refused as `forged_client` |

Timing rules:

- Verification uses the request time in the access or ModSecurity log, including delayed reads and scheduled scans. A request without a valid log time stays unverified.
- The peer log must show a direct connection from the address in the request's second or within the forward-skew window after it. Direct visits at other times do not count.
- Before an address counts as connected for itself, CSM reads the peer log again about two seconds after it read the finding. A peer line the web server flushed after its access line still decides.
- Reputation sightings use the same check. Findings read together share one wait. A finding without a valid read time stays unverified. A refusal that is already final does not wait.
- Once CSM has trusted a peer-log reader, losing that trust keeps unverified addresses refused until the daemon restarts. It does not bring back blocking on the older path.

nginx needs no peer log when all of these hold. Its web findings are then blocked as on a direct host.

- `real_ip_header` is set at `http` scope, and every server and location uses that same header.
- For `CF-Connecting-IP`, every `set_real_ip_from` lies in Cloudflare's ranges. Other edges and proxies may pass on a client's own `CF-Connecting-IP`, so that header counts only from Cloudflare.
- For `proxy_protocol`, every source lies in `web_server.trusted_proxies`. Code that customers run on a shared edge can open connections from the edge's own addresses and write any PROXY header.
- No source can reach a loopback, unspecified or host address, including through IPv4-mapped IPv6.
- The whole configuration tree is readable, all includes included, and no used log format has request data in the client field.

nginx stays unverified with unresolved hostnames or variables, the default `X-Real-IP` header, or conflicting per-server or per-location headers. For each verification admission uses the current `web_server.trusted_proxies` and reads the host addresses afresh; a failed address lookup refuses verification. Without a loaded CSM configuration, only Cloudflare's header and ranges can qualify.

#### When CSM reads the web server configuration

CSM reads the configuration when admission starts, at the start of every reload attempt and Web UI settings save, and every 10 minutes. A settings save refreshes this state before applying its changes, including a save that fails or needs a restart.

`web_server.config_dir` selects the Apache or nginx root, including the Apache tree that cPanel LiteSpeed uses. LiteSpeed XML stays at its standard location. The main file is:

| Platform | Main file |
|----------|-----------|
| Debian Apache | `apache2.conf` |
| RHEL or cPanel Apache | `conf/httpd.conf`. A cPanel root ending in `conf` already names that directory. |
| nginx | `nginx.conf` |

If the selected Apache main file is absent, the state is unknown, even if a default tree exists elsewhere.

Limits of this check:

- Files on disk can differ from what the web server loaded until it reloads.
- A setting in any virtual host applies to the whole host.
- Responses already queued are not checked again.

#### Log format rules

CSM reads every log format in use, to see whether request data can end up where it reads the client address. When it cannot prove a format safe, the state is unknown and the log is treated as rewritten. A valid format that no `CustomLog`, `GlobalLog`, `TransferLog` or nginx `access_log` uses does not count.

All web servers:

- Leading whitespace and extra spaces after cPanel's `splitlogs` virtual-host field cannot hide the client token.
- A leading quote, brace or other non-address character guards normally escaped output. Brackets do not guard a request value, because scheduled scans accept bracketed IPv6 peers, with or without ports.

Apache:

- Format nicknames ignore case, including the `TransferLog` default.
- A definition in another virtual host or an unrelated conditional section cannot hide a log's inline or common-format fallback.
- With `HostnameLookups On` in any scope, `%h` counts as a request value, because it then logs the client's unverified reverse DNS name.
- The built-in `CLF` nickname is also checked after piped logging removes its leading field.
- An `ErrorLogFormat` that writes a request value before an unconditional message, in any output record, counts too. A message that shares its field with another placeholder does not protect later request values, because that field may disappear.
- A nonempty `expr=` condition does not change how its format is read.
- A `${...}` variable that starts a log target leaves the state unknown, except Debian's `${APACHE_LOG_DIR}/`. The exception does not apply when `Define` or `UnDefine` can change the variable, including inside a macro.
- Section suffixes are ignored only where Apache accepts them. A rewrite directive found beside a parsing gap still counts as active.

Apache state is unknown with:

- unresolved configuration variables in log formats, format names or server names, or ones that could make or hide a piped log target
- unsupported format handlers, or blank server names
- custom time formats that can write a line break
- unproven time formats, or process, port and duration arguments, in or before the field CSM reads
- empty logging conditions, including whitespace-only expressions
- malformed legacy-module arguments
- malformed closing tags, or comments on closing tags, for read-time conditions such as `IfModule`
- Cloudflare trusted-proxy hostnames or variables, when CSM cannot establish another active rewrite. Only Apache can resolve those values.

Apache mod_macro, inside a `<Macro>`:

- A parameter in a log format, format name, piped log target, module name or directive name leaves the state unknown. That includes a parameter that spells `ServerName`.
- A parameter later in a log file path, or in a server name, is harmless.
- A macro parameter that starts a log target leaves the state unknown.
- Quoted macro names and parameters keep their boundaries.

LiteSpeed:

- Formats with unsupported escapes, modifiers, handlers or ambiguous brace arguments are unknown, in both native XML and cPanel Apache configuration.

nginx:

- HTTP and stream format namespaces are checked separately. Stream byte counts, session duration and transport protocol remain server values in the stream namespace.
- A log selects the first previously declared format with the same name, ignoring ASCII case. Later case variants do not count as used formats.
- Unresolved names and malformed log declarations leave the state unknown.
- Entries inside maps are values, including entries read from included files.
- With `escape=none`, any request variable can start another log record, even after the normal client field or a quote.
- Binary address variables have unknown output framing.
- Empty server-name, hostname and port fields cannot hide a following request value.
- User-defined variables do not inherit trust from a name that looks built in.
- Original-peer variable names and stream server names stay unproven, because their availability depends on the installed modules and version, and captures or scripts can supply request values under those names. CSM applies this caution even when the variables come from nginx itself.

### Dry-run forecasts

A forecast answers one question: would this block have fitted? It never becomes a block. A restart, or going back into dry run, starts a new session and restores nothing from the stored examples.

What the example count means:

- CSM stores a bounded number of examples of successful capacity predictions, not every attempted block.
- The count includes older examples until they are pruned or purged.
- It is not a count of unique addresses, and not the number of blocks that would be active now.
- Lost examples and incomplete comparisons appear in status.

How the forecast models capacity:

- It fills the temporary block set as live admission will. Of the slots that operator, unknown and subnet blocks leave, a fifth is kept for direct or corroborated attacks. A set without a size limit is modelled as 10000 entries.
- In forecasts and previews, each new automatic lifetime, challenges included, is capped at `auto_response.block_expiry`. Longer requests are cut and shorter ones stay short.
- A retry keeps its first absolute expiry, even after you configure a lower cap. Blocking on the older path keeps its own lifetimes.

When the modelled set is full:

- A forecast block may take the place of a lower-priority one, as live admission would. That is an earlier forecast block of a lower class or severity, or an automatic block from the older path that recorded its origin.
- A new attack may rotate out an earlier forecast block of the same class and severity once that block has held its slot for 30 minutes, as long as it stays within the part of the set its kind of block may use.
- An address whose forecast block was replaced or rotated out cannot rotate again before that block's expiry.
- If an address returns after the forecast replaced its earlier block, its new forecast block lasts only until the earlier block would have ended. A return with too little time left for a firewall block is refused, with no forecast charge and no stored example.

### Quarantine and restore durability

These guarantees depend on the filesystem and storage device honoring sync requests.

Quarantine:

- For a regular file, quarantine and pre-clean backup write and sync the private content copy, the metadata and the directory entries before the original is removed or changed.
- Directory quarantine syncs the tree and metadata before moving it on the same filesystem. A directory move across filesystems is refused and leaves the source in place.
- A storage failure never counts as a successful remediation.
- New quarantine and pre-clean records store the original modification time, owner, group, permissions and size.

Restore:

- Restore applies the saved attributes to the opened destination before syncing it. Linux keeps modification times at the precision the destination filesystem supports.
- Restore can verify the destination even after the saved permissions remove all read access. The restored file keeps those permissions, including a mode that grants no access to anyone.
- Restore syncs the replacement and its directory before deleting the quarantine evidence.

When a restore is rolled back:

- CSM moves displaced entries into a private directory.
- If another writer changes the destination, CSM keeps the live replacement and names any retained recovery directory in the error. Check that directory beneath the original destination or quarantine location before retrying.
- If another writer moves a restored directory, CSM cannot recover it from its old name and will not put a different entry into quarantine in its place.
