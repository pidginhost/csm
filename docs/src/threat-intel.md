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
- **Upstream HTTP cache** (`reputation.upstream.*`) - shared panel-side cache of AbuseIPDB or proprietary scores. Useful in fleets: agents pay a local cache hit (`cache_ttl_min`, default 15 m) instead of hammering the upstream once per agent. Use HTTPS for remote panels; plain HTTP is accepted only for loopback. Wire contract: [`docs/upstream-threat-intel-contract.md`](../upstream-threat-intel-contract.md).

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
