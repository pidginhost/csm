# Threat Intelligence

CSM tracks, scores, and correlates attacks using a local attack database enriched with external feeds and GeoIP data.

## Attack Database

- Per-IP event tracking (brute force, webshell upload, phishing, C2, WAF block)
- Threat score calculation with temporal decay (older attacks weighted less)
- Auto-block on reputation threshold
- Top attackers leaderboard

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

- **AbuseIPDB** (`reputation.abuseipdb_key`) - external IP reputation feed. CSM caps uncached lookups per cycle and reserves store-backed daily quota before sending requests.
- **Rspamd** (`reputation.rspamd.*`) - per-IP rolling-history signals from the local rspamd controller. Token resolves from `token_env` at query time so rotation does not require a daemon restart.
- **Upstream HTTP cache** (`reputation.upstream.*`) - shared panel-side cache of AbuseIPDB or proprietary scores. Useful in fleets: agents pay a bounded local cache hit (`cache_ttl_min`, default 15 m) instead of hammering the upstream once per agent. CSM temporarily opens a fail-open circuit breaker after repeated upstream failures and lets only one cooldown probe through at a time. Use HTTPS for remote panels; plain HTTP is accepted only for loopback. Wire contract: [`docs/upstream-threat-intel-contract.md`](../upstream-threat-intel-contract.md).

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

Reverse-DNS verification is asynchronous, so on the first request from a
crawler IP (or right after an upgrade clears the verification cache) the
result is not yet known. During that window a high-volume crawler that
trips a flood or scanner-profile threshold is routed to the proof-of-work
challenge rather than hard-blocked: a real crawler ignores the challenge
but is recognized on the next pass once verification resolves, while a host
merely spoofing a crawler User-Agent cannot solve it. Once verification
fails outright, the spoofer is hard-blocked. When the challenge subsystem
is disabled, the claimed bot is hard-blocked during the window instead.

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
- Top attackers with GeoIP enrichment
- Attack type breakdown chart
- Hourly trend chart
- Whitelist management (permanent and temporary)

## API Endpoints

```
GET  /api/v1/threat/stats            Attack stats and type breakdown
GET  /api/v1/threat/top-attackers    Top attacking IPs with GeoIP
GET  /api/v1/threat/ip               IP threat lookup
GET  /api/v1/threat/events           IP event history
GET  /api/v1/threat/whitelist        Whitelisted IPs
GET  /api/v1/threat/db-stats         Attack database statistics
POST /api/v1/threat/block-ip         Block IP permanently
POST /api/v1/threat/whitelist-ip     Permanent whitelist
POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist
POST /api/v1/threat/clear-ip         Clear from attack DB
POST /api/v1/threat/unwhitelist-ip   Remove from whitelist
```
