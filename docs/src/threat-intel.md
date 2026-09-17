# Threat Intelligence

CSM tracks, scores, and correlates attacks using a local attack database enriched with external feeds and GeoIP data.

## Attack Database

- Per-IP event tracking (brute force, webshell upload, phishing, C2, WAF block)
- Local scoring from attack volume, types and targeted accounts
- Auto-block on reputation threshold
- Top attackers leaderboard

Successful cPanel, FTP, webmail and PAM login audit events, and authenticated
File Manager writes, remain in event history and account counts as
`auth_success` (Authenticated Activity). They add no event-volume or
multi-account score. Multi-IP login and authentication-failure signals keep
their existing scoring.

`file_upload` remains readable for historical records; no current check
produces it. Existing scores recorded under older classifications are not
rewritten because aggregated login counts cannot distinguish ordinary logins
from multi-IP alerts. For a confirmed false positive, follow
[Clearing a stale local threat score](firewall.md#clearing-a-stale-local-threat-score).
That operation preserves historical events and does not remove firewall or
permanent-blocklist entries; review those separately.

## IP Intelligence

Combines multiple sources into a unified verdict:

| Source | Data |
|--------|------|
| Local attack DB | Event count, types, score |
| AbuseIPDB | External reputation (if API key configured) |
| Rspamd | Per-IP rolling history (if controller access configured) |
| Upstream HTTP cache | Panel-side shared score (if `reputation.upstream` configured) |
| Permanent blocklist | Operator-managed persistent blocks |
| Firewall state | Currently blocked/allowed status |
| GeoIP | Country, city, ASN, ISP |
| RDAP | Network name, organization (cached 24h) |

**Verdicts:** clean, suspicious, malicious, blocked

### Pluggable sources

Threat-intel sources implement a small `Source` interface (lookup-by-IP returning a score + reason). The aggregator queries every enabled source in parallel, applies per-source weighting, and produces the unified verdict above. Adding a new source means implementing the interface and registering it; no existing source code changes.

Currently shipped:

- **AbuseIPDB** (`reputation.abuseipdb_key`) - external IP reputation feed. CSM caps uncached lookups per cycle and reserves store-backed daily quota before sending requests. While the quota is exhausted (daily budget or an API 429/402 backoff) CSM emits a `reputation_quota_exhausted` Warning so the degraded coverage is visible; a `threat_feed_stale` Warning fires when previously downloaded free threat feeds have not refreshed in over 7 days. Persistent conditions remain visible in Findings but send at most one reminder per day, including across daemon restarts; these coverage warnings never trigger reputation scoring or blocks.
- **Rspamd** (`reputation.rspamd.*`) - per-IP rolling-history signals from the local rspamd controller. Delivered ham dilutes the score, temporary deferrals are neutral, and definitive spam actions count against the sender. Token resolution reads `token_env` from the process environment at query time. Changing the external environment requires a daemon restart; see [credential rotation](credential-rotation.md).
- **Upstream HTTP cache** (`reputation.upstream.*`) - shared panel-side cache of AbuseIPDB or proprietary scores. Useful in fleets: agents pay a bounded local cache hit (`cache_ttl_min`, default 15 m) instead of hammering the upstream once per agent. CSM temporarily opens a fail-open circuit breaker after repeated upstream failures and lets only one cooldown probe through at a time. Use HTTPS for remote panels; plain HTTP is accepted only for loopback. Wire contract: [`docs/upstream-threat-intel-contract.md`](https://github.com/pidginhost/csm/blob/main/docs/upstream-threat-intel-contract.md).

### Verified crawlers

`reputation.bot_verify_enabled` verifies claimed crawler User-Agents
with static IP ranges first, then strict forward-confirmed reverse DNS.
`reputation.verified_bots` adds operator-defined crawler identities with
`name`, `ua_substrings`, and one verification method: `rdns_suffixes` or
`ip_ranges`. With `rdns_suffixes` the source IP must forward-confirm under
a registrable domain (public suffixes and shared-hosting suffixes are
rejected; a PTR-only match is not trusted). With `ip_ranges` the source IP
must fall in one of the published CIDRs -- this is for crawlers such as
GPTBot and PerplexityBot that publish address ranges instead of crawler
reverse DNS. Over-broad or non-public ranges are rejected. All
checks run at config load and on reload.

Built-in rDNS verification covers Googlebot, Bingbot, Applebot, DuckDuckBot,
Amazonbot, the Facebook and Meta crawlers, Brave, and the SERanking backlink
bot. Googlebot, Bingbot, and Applebot also match a shipped IP-range snapshot
first and fall back to reverse DNS; DuckDuckBot, Amazonbot, Facebook/Meta,
Brave, and SERanking are rDNS-only.

Reverse-DNS verification is asynchronous. A newly admitted verification job
receives a short, bounded pending window, including time spent waiting in the
queue. High-volume traffic in that window can route to the proof-of-work
challenge when it is enabled. A full queue, stopped worker, unsupported
identity, or expired pending window uses the ordinary flood and scanner
controls instead.

DNS failures, missing reverse DNS, and failed cache writes do not prove a
spoofed identity. They leave verification unresolved, delay retries, and do
not renew pending treatment on each retry. Attempt history is bounded. When
it is full, new sources can replace completed entries after their initial
cooldown; retries cannot extend that reservation. Live jobs and newly granted
pending windows keep their history. If no entry can be replaced, admission is
refused until capacity becomes available instead of running untracked lookups.
Evicted or expired sources without a persisted missing-PTR record can receive
another pending window, but the initial cooldown prevents continuous renewal
under churn. Expiry preserves live jobs and their retry delay after completion.
A missing PTR suppresses further DNS lookups for one fixed hour in the state
database, including across restarts. Scans do not extend that hour. After it
lapses, DNS retries resume, but the record remains as attempt history for a
day, so a restart or in-memory eviction cannot grant fresh pending treatment.
Records older than that are removed as new ones are written. Cleanup is
attempted at most once an hour, including after a failed cleanup. A definitive
verification result replaces that history. The record is not a verdict: it
grants neither the verified-crawler exemption nor pending treatment, and it
never counts as a spoof. `csm store reset-bot-verify` and a `verified_bots`
change clear these records together with the cached results.
A confirmed negative remains eligible for spoof detection. A cached positive
receives the normal verified-crawler exemption.

GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot and ClaudeBot are recognized
out of the box: their published IP ranges ship as an embedded snapshot and are
refreshed from the vendor endpoints by an auto-updater (`reputation.bot_ranges`,
default on, outbound HTTPS, configurable interval; restart required for setting
changes). Fetched ranges are validated with the same over-broad and non-public
guards as operator entries, and the embedded snapshot is the trusted fallback
when a fetch fails. Anthropic publishes one combined feed for ClaudeBot,
Claude-User and Claude-SearchBot and documents IP-list verification rather than
reverse DNS, so CSM verifies ClaudeBot by address from that feed; the legacy
`anthropic.com` reverse-DNS suffix is kept only as a fallback.

`csm update-bot-ranges` refreshes these ranges on demand (mirroring
`csm update-geoip`): it fetches the vendor feeds, writes the on-disk snapshot,
and asks the running daemon to apply them without a restart. The auto-updater
and the manual command both export metrics -- refresh success/failure, prefix
count per crawler, and the last successful refresh time -- under the
`csm_botranges_*` names.

## Abuse Reporting

`reputation.report` can send minimized confirmed-abuse reports to a central
database or private collector. It is off by default. Remote targets must use
HTTPS; plain HTTP is accepted only for loopback collectors. Keys and target
wiring are read at daemon startup, so changes to this block require a restart.

## Web UI

The **Threat Intel** page (`/threat`) provides:
- IP lookup with composite scoring
- Two separate block actions per IP: a 24 hour block and a confirmed
  permanent block, singly or over a selection of attackers
- Top attackers with GeoIP enrichment
- Attack type breakdown chart
- Hourly trend chart
- Whitelist management (permanent and temporary)

A 24 hour block records threat evidence that expires with the firewall
block, so a mistaken block of a customer address stops counting against it
once the block lapses. A permanent block records evidence that stays until
an operator clears it. When an address is no longer blocked but still holds
permanent evidence, the lookup says so, because that address is flagged
again the next time it is seen.

The 24 hour action refuses to shorten an existing permanent or longer
firewall block. Unblock explicitly before changing that lifetime. Bulk
requests skip those addresses and report warnings. Existing permanent
threat evidence remains until cleared; feed updates do not remove a timed
operator record before its expiry.

Bulk undo restores each prior firewall lifetime, using the original deadline
for timed blocks. Expired blocks stay expired, and a later block, clear, or
whitelist decision invalidates the older undo action. Only successful
firewall reversals restore the corresponding threat evidence.

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
