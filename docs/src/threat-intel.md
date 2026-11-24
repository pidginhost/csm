# Threat Intelligence

CSM tracks, scores and correlates attacks. It records them per IP address in a local attack database, then combines that record with external feeds and GeoIP data into one verdict for the address. The free public feeds need no API key; AbuseIPDB, Rspamd and an upstream cache take part once you configure them. [Abuse reporting](#abuse-reporting) to a central database or a private collector is off by default.

## Attack Database

The attack database provides:

- Per-IP event tracking: brute force, reconnaissance, reputation and authenticated activity.
- A local score built from attack volume, attack types and targeted accounts. CSM uses it to rank addresses and in the unified verdict. The score never raises a finding or a block on its own.
- A top attackers leaderboard.

An alert about a cPanel service subdomain keeps the logged address as unverified context. That address stays separate from per-IP reputation and attack history.

### Authenticated activity

Successful cPanel, FTP, webmail and PAM login audit events, and authenticated File Manager writes, stay in event history and account counts as `auth_success` (Authenticated Activity). They add no event-volume or multi-account score. Multi-IP login and authentication-failure signals keep their own scoring.

### Mail evidence

The attack database keeps mail login attacks and spam/ham verdicts in a separate mail section. These rules apply to it:

- Equivalent IPv4 and IPv6 spellings of an address share one record.
- Invalid sender addresses are ignored.
- Spam and ham verdicts do not change the local threat score or add attack events.
- A ham verdict only updates an existing record.
- Spam and ham verdicts about an IPv6 sender are recorded per /64 network, not per address.

A record that holds only spam evidence is dropped once that evidence has faded, or sooner to keep the [50,000-record spam evidence budget](antispam.md#spam-evidence-budget). CSM checks the budget when a verdict is recorded, using that verdict's observation time. Startup can load more records until then.

[Spam evidence](antispam.md#spam-evidence) has the details. [How mail evidence fades](#how-mail-evidence-fades) lists the decay rules.

## IP Intelligence

CSM combines several sources into a unified verdict for an address:

| Source | Data |
|--------|------|
| Local attack DB | Event count, types, score |
| AbuseIPDB | External reputation (if API key configured) |
| Rspamd | Per-IP rolling history (if controller access configured) |
| Upstream HTTP cache | Panel-side shared score (if `reputation.upstream` configured) |
| Permanent blocklist | Operator-managed persistent blocks |
| Free public feeds | Spamhaus DROP, blocklist.de, CINS Army |
| Firewall state | Currently blocked/allowed status |
| GeoIP | Country, city, ASN, ISP |
| RDAP | Network name, organization (cached 24h) |

The verdict is one of clean, suspicious, malicious or blocked.

### Free public feeds

CSM loads cached Spamhaus DROP, blocklist.de and CINS Army data at startup and refreshes it daily. A failed download keeps that feed's previous data. These lists add to local evidence and need no AbuseIPDB key.

CSM does not fetch Spamhaus EDROP, because Spamhaus merged it into DROP. An old `<state_path>/threat_db/spamhaus-edrop.txt` cache is ignored and you can delete it. Existing firewall blocks, whitelists and findings are unchanged.

### Pluggable sources

Each threat-intel source answers a lookup by IP with a score and a reason. CSM queries every enabled source in parallel, applies a weight per source, and produces the unified verdict above.

In the code, a source implements a small `Source` interface. Adding a source means implementing the interface and registering it. No existing source code changes.

CSM ships three sources of this kind: AbuseIPDB, Rspamd and the upstream HTTP cache.

#### AbuseIPDB

Set `reputation.abuseipdb_key` to use this external IP reputation feed. CSM caps the uncached lookups in each cycle. Before it sends requests it reserves them against a daily quota that is kept in the state store.

While the quota is exhausted, CSM raises a `reputation_quota_exhausted` Warning. See [Coverage warnings](#coverage-warnings).

#### Rspamd

The `reputation.rspamd.*` keys read per-IP rolling-history signals from the local rspamd controller. CSM scores them this way:

- Delivered ham dilutes the score.
- Temporary deferrals are neutral.
- Definitive spam actions count against the sender.

CSM reads the token named by `token_env` from the process environment at query time. Changing the external environment requires a daemon restart; see [credential rotation](credential-rotation.md).

#### Upstream HTTP cache

The `reputation.upstream.*` keys point CSM at a shared panel-side cache of AbuseIPDB or proprietary scores. This is useful in fleets. Each agent answers from a bounded local cache (`cache_ttl_min`, default 15 m), so the agents do not hammer the upstream once per agent.

After repeated upstream failures CSM temporarily opens a circuit breaker. The breaker fails open: lookups go ahead without the upstream score. While it is open, CSM lets only one cooldown probe through at a time.

Use HTTPS for remote panels. Plain HTTP is accepted only for loopback. The wire contract is in [Upstream threat-intel contract](upstream-threat-intel-contract.md).

### Coverage warnings

Two Warning findings tell you that threat-intel coverage is degraded:

| Finding | Raised when |
|---------|-------------|
| `reputation_quota_exhausted` | The AbuseIPDB quota is exhausted: the daily budget is used up, or CSM is backing off after an API 429 or 402 answer. |
| `threat_feed_stale` | Free threat feeds that CSM downloaded earlier have not refreshed in over 7 days. |

A condition that persists stays visible in Findings. Alert email and the webhook send each warning once. History records a reminder at most once a day, including across daemon restarts. These coverage warnings never trigger reputation scoring or blocks.

### Verified crawlers

`reputation.bot_verify_enabled` verifies claimed crawler User-Agents with static IP ranges first, then strict forward-confirmed reverse DNS.

#### Built-in crawlers

| Crawlers | How CSM verifies them |
|----------|-----------------------|
| Googlebot, Bingbot, Applebot | A shipped IP-range snapshot first, then reverse DNS as the fallback. |
| DuckDuckBot, Amazonbot, the Facebook and Meta crawlers, Brave, the SERanking backlink bot | Reverse DNS only. |
| GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, ClaudeBot | Published IP ranges. See [Crawlers that publish IP ranges](#crawlers-that-publish-ip-ranges). |

#### Crawlers that publish IP ranges

GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot and ClaudeBot are recognized out of the box. Their published IP ranges ship as an embedded snapshot, and an auto-updater refreshes them from the vendor endpoints.

The auto-updater is configured under `reputation.bot_ranges`:

- It is on by default.
- It makes outbound HTTPS requests.
- Its interval is configurable.
- A change to its settings requires a restart.

CSM validates fetched ranges with the same over-broad and non-public guards as operator entries. When a fetch fails, the embedded snapshot is the trusted fallback.

Anthropic publishes one combined feed for ClaudeBot, Claude-User and Claude-SearchBot, and documents IP-list verification rather than reverse DNS. CSM therefore verifies ClaudeBot by address from that feed. The legacy `anthropic.com` reverse-DNS suffix is kept only as a fallback.

`csm update-bot-ranges` refreshes these ranges on demand, in the same way as `csm update-geoip`. It fetches the vendor feeds, writes the on-disk snapshot, and asks the running daemon to apply them without a restart.

The auto-updater and the manual command both export metrics under the `csm_botranges_*` names: refresh success and failure, prefix count per crawler, and the last successful refresh time.

#### Adding your own crawlers

`reputation.verified_bots` adds operator-defined crawler identities. Each identity has a `name`, `ua_substrings`, and one verification method:

| Method | Rule |
|--------|------|
| `rdns_suffixes` | The source IP must forward-confirm under a registrable domain. Public suffixes and shared-hosting suffixes are rejected. A PTR-only match is not trusted. |
| `ip_ranges` | The source IP must fall in one of the published CIDRs. Over-broad or non-public ranges are rejected. |

Use `ip_ranges` for crawlers such as GPTBot and PerplexityBot that publish address ranges instead of crawler reverse DNS. All checks run at config load and on reload.

#### While reverse DNS is unresolved

Reverse-DNS verification is asynchronous. When CSM accepts a new verification job, it treats the source as pending for a short, bounded time, the pending window. Time spent waiting in the queue counts toward it. In that window, high-volume traffic from the source can be sent to the proof-of-work challenge when the challenge is enabled.

The ordinary flood and scanner controls apply instead in these cases:

- The verification queue is full.
- The worker is stopped.
- The identity is unsupported.
- The pending window has expired.

The result of a lookup decides what happens next:

| Result | Treatment |
|--------|-----------|
| A cached positive | The source receives the normal verified-crawler exemption. |
| A confirmed negative | The source remains eligible for spoof detection. |
| A DNS failure, missing reverse DNS, or a failed cache write | Verification stays unresolved. None of these proves a spoofed identity. |

An unresolved verification delays retries, and a retry does not renew pending treatment. [Crawler verification retries](#crawler-verification-retries) has the exact rules.

## Abuse Reporting

`reputation.report` can send minimized confirmed-abuse reports to a central database or a private collector. It is off by default.

- A report carries only the source address, the class, a count and the time.
- You list the classes to send in `reputation.report.classes`. An empty list keeps reporting off.
- Remote targets must use HTTPS. Plain HTTP is accepted only for loopback collectors.
- CSM reads keys and target wiring at daemon startup, so changes to this block require a restart.
- The central abuse database accepts `ed25519` targets only. Its report URL ends in `/report` and its scored-set URL in `/decisions`.

The request format is in the [Abuse Report Contract](abuse-report-contract.md).

### Reported findings

Each class covers these checks. Only Critical findings are reported, except `bad_asn_egress` and `spam`, which report High findings too.

| Class | Checks |
|---|---|
| `bruteforce` | `pam_bruteforce`, `wp_login_bruteforce`, `xmlrpc_abuse`, `ftp_bruteforce`, `smtp_bruteforce`, `mail_bruteforce`, `admin_panel_bruteforce` |
| `credential_stuffing` | `credential_stuffing` |
| `php_relay` | `email_php_relay_abuse` |
| `bad_asn_egress` | `bad_asn_outbound` |
| `spam` | `mail_spam_source` |

### The spam class

With `spam` in `reputation.report.classes`, a node raises `mail_spam_source` for a sender that rspamd keeps rejecting and that has sent it no clean mail recently. The node then reports that sender.

- The class needs `email_protection.antispam.enabled`. Turning either one on or off takes a restart.
- Antispam nodes in dry run count their verdicts too.
- The finding never blocks or challenges the sender on the reporting node.
- Nodes accept `spam` entries in downloaded central lists.

#### Shared mail services

Shared mail services are never reported: Google, Microsoft, Amazon SES, SendGrid, Mailgun, Brevo, Yahoo and iCloud. CSM reads their sending hosts from each provider's published SPF records and refreshes the list in the background. Spam reports wait while that list cannot be loaded.

When a refresh has failed and the list is not current, CSM raises a `shared_senders_stale` Warning. It stays in Findings until the list is current again. Alert email and the webhook send it once. History records a reminder at most once a day, including across daemon restarts.

#### Sender history

CSM keeps sender history across restarts. If that history cannot be read at startup, spam source detection stays off for that run and the daemon log says why. A restart turns it back on once the state database can be read.

### Set up the central abuse database

1. On the node, generate a key pair:

   ```bash
   csm report enroll
   ```

   It prints a 64-byte private key as 128 hex characters and a 32-byte public key as 64 hex characters.
2. Put the private key in the CSM environment file described in [credential rotation](credential-rotation.md#configure-a-systemd-environment-file), for example as `CSM_REPORT_KEY`. The private key is a secret: never paste it into a ticket or chat.
3. Give only the public key to the central operator. The operator approves the node and returns its `node_id` and `key_id`, the report and scored-set URLs, and the central public key.
4. Add the central public key, encoded as 64 hex characters, to the same environment file, for example as `CSM_CENTRAL_PUBKEY`.
5. Configure the target. The `central` block is optional; [Acting on the central list](#acting-on-the-central-list) describes it.

   ```yaml
   reputation:
     report:
       enabled: true
       classes: [bruteforce, credential_stuffing, php_relay, bad_asn_egress]
       targets:
         - name: central
           url: https://abuse.example.net/report
           transport: ed25519
           node_id: "<node_id from the operator>"
           key_id: "<key_id from the operator>"
           key_env: CSM_REPORT_KEY
     central:
       enabled: true
       set_url: https://abuse.example.net/decisions
       pubkey_env: CSM_CENTRAL_PUBKEY
       auth_target: central
       action: challenge
   ```

6. Restart CSM: `systemctl restart csm.service`.

To rotate the node key, run `csm report enroll` again and have the central operator register the new public key. Then update `key_id` and the environment file, and restart CSM.

### Acting on the central list

`reputation.central` pulls the database's signed list of scored addresses. Its `action` key decides what CSM does with a listed address:

| Setting | What CSM does |
|---------|---------------|
| `action: challenge` | When this node raises a qualifying attacker finding of its own for an address on the central list, CSM adds the address to the challenge list. [Protected addresses](#protected-addresses) are skipped. |
| `action: block_if_local_corroborated` | CSM attempts a block instead once the central score reaches `reputation.central.block_threshold`. Below that score it still uses the challenge path. |
| `action: off` | CSM pulls the list without taking central-driven actions. |

Central data alone never blocks. An `ip_reputation` match also comes from outside data, not from what this node saw. It never counts as the local finding that either action needs.

The challenge path requires `challenge.enabled: true`, an active firewall and a working [challenge setup](challenge.md).

A live block also requires all of these, and it remains subject to the normal block protections:

- An active firewall.
- `auto_response.enabled: true`.
- `auto_response.block_ips: true`.
- `auto_response.dry_run: false`.

In dry run, CSM records what would have been blocked.

### Signed downloads

`auth_target` names the report target whose node key signs each download of the central list. The central abuse database refuses unsigned downloads.

- The target must use `transport: ed25519`.
- The target's URL must share scheme, host and port with `set_url`, so a signed request never goes to another host.
- Signed downloads work with `reputation.report.enabled: false`. Keep the target configured even when the node does not send reports.
- Leave `auth_target` unset only for a central service that serves the list without signatures.

`csm validate` refuses the configs below, and CSM will not start with one of them. The settings page refuses the same changes.

- An `auth_target` that names no target, or several.
- A target that is not Ed25519, or that lacks `node_id`, `key_id` or `key_env`.
- A `set_url` on another origin.

If the target's key is unset or invalid, CSM starts with the central consumer off and logs one line naming `reputation.central.auth_target`. It never falls back to unsigned downloads while `auth_target` is set.

If the service refuses a download, CSM keeps its last verified list and tries again at the next refresh. It logs `central-intel: pull unauthorized; check node enrollment, node clock and reputation.central.auth_target`. Each successful refresh logs `central-intel: refresh complete (version=N)`.

### Send to a private collector

Use `transport: hmac` with a shared secret. You choose `node_id` and `key_id`; the collector uses them to find the secret. Set the named secret and the optional token in CSM's [environment file](credential-rotation.md#configure-a-systemd-environment-file) and restart CSM. CSM uses the secret as raw string bytes and does not hex-decode it.

```yaml
reputation:
  report:
    enabled: true
    classes: [bruteforce, credential_stuffing]
    targets:
      - name: collector
        url: https://collector.example.net/csm/report
        transport: hmac
        node_id: web-01
        key_id: k1
        key_env: CSM_COLLECTOR_SECRET
        token_env: CSM_COLLECTOR_TOKEN   # optional bearer token
```

The collector must implement the [Abuse Report Contract](abuse-report-contract.md).

#### Several targets

CSM queues one copy of a report per target, so one node can report to the central database and a private collector at the same time.

Give each target a unique, stable `name`. Duplicate names select only the last usable target. CSM discards a target's queued reports on the next delivery pass in these cases:

- You remove the target.
- You rename the target.
- A key error makes the target unusable at startup.

The `spool_max` capacity is shared across all targets, not reserved per collector. Overflow drops the oldest entries across that shared queue.

### Check delivery

When reporting starts successfully, the log shows `abuse-reporting: enabled for 1 target(s), 4 class(es)` with your counts.

CSM skips a target, with a log line, when the target has one of these faults:

- A missing field.
- A remote URL that is not HTTPS.
- An unknown transport.
- An unusable key.

Reporting stays off when no usable targets or valid classes remain, or when its spool cannot be opened.

Failed deliveries are logged as `reporting: delivery incomplete`. The `abuse_reporting.ingress` and `abuse_reporting.spool` entries in [protection queue health](api.md#protection-queue-health) show waiting and lost reports.

### Delivery and retries

Reports wait in a durable queue and are delivered once a minute.

| Case | What CSM does |
|------|---------------|
| The target is down, throttling, or refuses the node | Keeps that target's reports queued in order and retries a minute later. Other targets keep receiving theirs. |
| The target answers HTTP 429 with `Retry-After`, in seconds or as an HTTP date | Retries after that wait instead, up to an hour. |
| The target throttles but still accepts reports | Logs nothing. |
| The target keeps throttling without accepting any report | Doubles the delay on each attempt up to a minute, or the requested wait if longer. Warns at most once a minute per target. |
| The collector refuses a report as invalid (HTTP 422) | Drops the report and counts it as lost, because it would be refused again. |

A target refuses the node, for example, before the node is approved or when the node's clock is wrong.

### Protected addresses

Reporting and central intelligence actions share the [address protection checks](abuse-report-contract.md#what-csm-reports). These cover literal infrastructure IPs/CIDRs and crawler IP ranges, not infrastructure hostname resolution or rDNS crawler results. For NAT64 and 6to4 sources, protection of either the original IPv6 address or its embedded IPv4 address applies.

## Web UI

The **Threat Intel** page (`/threat`) provides:

- IP lookup with composite scoring.
- Two separate block actions per IP: a 24 hour block and a confirmed permanent block. Each works on one address or on a selection of attackers.
- Top attackers with GeoIP enrichment.
- An attack type breakdown chart.
- An hourly trend chart.
- Whitelist management, permanent and temporary.

### The two block actions

| Action | Threat evidence it records |
|--------|----------------------------|
| 24 hour block | Evidence that expires with the firewall block. A mistaken block of a customer address stops counting against it once the block lapses. |
| Permanent block | Evidence that stays until an operator clears it. |

An address can lose its block and still hold permanent evidence. The lookup says so, because that address is flagged again the next time it is seen.

The 24 hour action refuses to shorten an existing permanent or longer firewall block. Unblock explicitly before changing that lifetime. Bulk requests skip those addresses and report warnings.

Existing permanent threat evidence remains until cleared. Feed updates do not remove a timed operator record before its expiry.

### Bulk undo

Bulk undo restores each prior firewall lifetime. For a timed block it uses the original deadline.

- Expired blocks stay expired.
- A later block, clear or whitelist decision invalidates the older undo action.
- Only successful firewall reversals restore the corresponding threat evidence.

### Infrastructure and private addresses

When CSM starts, it drops the attack records of addresses inside the top-level `infra_ips` list. An internal host that you list after it was recorded then stops ranking as an attacker. Only addresses and CIDRs count; hostnames and `firewall.infra_ips` do not. Event history is kept.

The actions treat private addresses this way:

- Unblock & Clear accepts private addresses, for an internal host that is not in `infra_ips`.
- Whitelist and allow actions refuse private addresses and point to `infra_ips` instead.
- Clear and whitelist remove the attack record under every equivalent spelling of the address, such as an IPv4-mapped form.

## API Endpoints

```
GET  /api/v1/threat/stats            Attack stats and type breakdown
GET  /api/v1/threat/top-attackers    Top attacking IPs with GeoIP
GET  /api/v1/threat/ip               IP threat lookup
GET  /api/v1/threat/events           IP event history
GET  /api/v1/threat/whitelist        Whitelisted IPs
GET  /api/v1/threat/db-stats         Attack database statistics
POST /api/v1/threat/block-ip         Block IP for 24 hours
POST /api/v1/threat/block-ip-permanent  Block IP with no expiry
POST /api/v1/threat/whitelist-ip     Permanent whitelist
POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist
POST /api/v1/threat/clear-ip         Clear from attack DB
POST /api/v1/threat/unwhitelist-ip   Remove from whitelist
```

## Details

This section is reference material: exact rules and rare cases.

### Scores recorded under older classifications

`file_upload` remains readable for historical records. No current check produces it.

CSM does not rewrite existing scores that were recorded under older classifications, because aggregated login counts cannot distinguish ordinary logins from multi-IP alerts. For a confirmed false positive, follow [Clearing a stale local threat score](firewall.md#clearing-a-stale-local-threat-score). That operation preserves historical events. It does not remove firewall or permanent-blocklist entries; review those separately.

### How mail evidence fades

- Verdict weights decay from their observation times, including when older verdicts arrive after newer ones.
- A verdict with no observation time uses the current time.
- A spam verdict refreshes the record's activity time.
- Remaining ham weight keeps a spam-only record until both spam and ham evidence have faded, but never past the 90-day limit since the last spam verdict or finding. The spam evidence budget can drop the record sooner.
- Retained mail evidence survives a restart with its original counts and observation times.

### Crawler verification retries

A missing PTR record is stored in the state database:

- It suppresses further DNS lookups for one fixed hour, including across restarts. Scans do not extend that hour.
- After the hour, DNS retries resume. The record remains as attempt history for a day, so a restart or in-memory eviction cannot grant fresh pending treatment.
- Records older than a day are removed as new ones are written. CSM attempts this cleanup at most once an hour, including after a failed cleanup.
- A definitive verification result replaces that history.

The record is not a verdict. It grants neither the verified-crawler exemption nor pending treatment, and it never counts as a spoof.

`csm store reset-bot-verify` and a `verified_bots` change clear these records together with the cached results.

### Crawler verification attempt history

Attempt history is bounded, and CSM does not run lookups it cannot track.

- When the history is full, a new source can replace a completed entry once that entry's initial cooldown has passed. A retry does not make the cooldown longer.
- Live jobs and newly granted pending windows keep their history.
- If no entry can be replaced, CSM refuses to admit the new job until capacity becomes available.
- An evicted or expired source with no persisted missing-PTR record can receive another pending window. The initial cooldown prevents continuous renewal under churn.
- An expired entry stays while its job is still running. After the job completes, the entry stays until its retry delay has passed.
