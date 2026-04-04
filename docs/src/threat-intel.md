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
| Permanent blocklist | Operator-managed persistent blocks |
| Firewall state | Currently blocked/allowed status |
| GeoIP | Country, city, ASN, ISP |
| RDAP | Network name, organization (cached 24h) |

**Verdicts:** clean, suspicious, malicious, blocked

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
