# MCP endpoint (read-only)

CSM can expose what it knows about a server to an LLM support agent through the [Model Context Protocol](https://modelcontextprotocol.io/). The endpoint is off by default. It is read-only: no tool can block, unblock, fix, scan, quarantine or change settings.

The endpoint is meant for agents that verify support tickets about the server ("is my IP blocked", "why does this account have findings", "is mail stuck"). It answers at `/mcp` on the Web UI listener, with credentials of its own.

## Enable it

1. Add an `mcp` block with at least one token to the configuration. The Web UI must be enabled, because its listener serves the endpoint.
2. Run `csm validate` to check the block.
3. Restart the daemon (`systemctl restart csm`). The endpoint is wired at startup.

```yaml
webui:
  enabled: true           # the endpoint is served by the Web UI listener
mcp:
  enabled: true
  tokens:
    - name: "support-agent"
      token: "<64 random hex characters>"
      issued_at: "2026-11-02T10:00:00Z"
      allowed_ips: ["198.51.100.0/24"]
```

The endpoint shares the Web UI's TLS certificate, port and firewall exposure. Limit who reaches it with the token's `allowed_ips`.

### What `csm validate` checks

| Configuration | Result |
| --- | --- |
| `mcp.enabled` without `webui.enabled` | Refused. |
| No usable token | Refused. |
| A token that is also a Web UI or metrics token | Refused. |
| A short token | Warning. |

## Tokens

Tokens are bearer credentials with the same dates and source restriction as `webui.tokens`. They have no scope, because there is only one: read-only.

A Web UI token or browser session never opens `/mcp`, and an MCP token opens nothing else.

| Request | Result |
| --- | --- |
| A known credential sent to the wrong endpoint | Refused, without spending the guess budget. |
| A known credential used outside its dates or addresses | Refused, without spending the guess budget. |
| An unknown token | Refused, and it draws on the guess budget. |

The guess budget is the one Web UI login and API token guesses use. It allows five failed attempts per minute per client (IPv4 address or IPv6 /64). After that the client is refused for a minute.

## Request limits

- `/mcp` counts toward the API request rate limit.
- Up to four tool calls run at once.
- Each request, a whole batch included, has 30 seconds. A read still running at that deadline keeps one of the four tool-call slots until it finishes.

## Transport

The endpoint uses the MCP Streamable HTTP transport with JSON-RPC 2.0, and it is stateless:

```bash
curl -sk https://server.example.com:9443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"csm_lookup_ip","arguments":{"ip":"203.0.113.9"}}}'
```

- Only `POST /mcp` is served. `GET` answers 405 (no server-initiated stream), and there is no session id to keep.
- The protocol versions are `2025-06-18`, `2025-03-26` and `2024-11-05`. `initialize` answers the client's version when it is one of those.
- The methods are `initialize`, `ping`, `tools/list`, `tools/call` and `notifications/initialized` (202, no body).
- `resources/list` and `prompts/list` answer empty lists.
- Batches of up to 20 requests are answered as a batch.
- A request body is limited to 1 MiB.
- A tool answer larger than 4 MiB is refused with a message asking for `limit`, `offset` or a filter.

A browser `Origin` header must pass the same check as on the API. It must be the configured Web UI origin, an entry in `webui.allowed_origins`, or a loopback origin that matches the request host.

This is a client configuration for an agent runtime that takes a URL and a header:

```json
{
  "mcpServers": {
    "csm-web01": {
      "url": "https://web01.example.com:9443/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Tools

Every tool carries `readOnlyHint: true`. The endpoint answers each tool by dispatching a `GET`, in-process, to one route from a fixed allowlist of API reads. That is why no tool can change anything.

- A tool answers the route's JSON as text content.
- The route's own error (`400`, `404`, `503`) is returned as a tool error with the API message, so the agent can read it.
- Lists keep the API shape `{items, total, truncated}`.
- A tool takes only the arguments its route reads.

### Composite tools

| Tool | Reads |
| --- | --- |
| `csm_overview` | hostname, platform, version, `status`, `health`, `capabilities` |
| `csm_lookup_ip` | `firewall/check`, the `blocked-ips` entry, `threat/ip`, `geoip` for one address |
| `csm_config_summary` | non-secret configuration facts from an explicit field list: mode, platform, Web UI listen address, enabled protections, auto-response limits, brute-force thresholds. Token values, keys, DSNs and URLs are never read |

### Route tools

There is one route tool per API read. The tool's description names the route.

| Area | Tools |
| --- | --- |
| Daemon | `csm_status`, `csm_health`, `csm_capabilities`, `csm_components`, `csm_challenge_stats`, `csm_scan_jobs`, `csm_scan_job` |
| Findings | `csm_findings`, `csm_findings_enriched`, `csm_finding_detail`, `csm_history`, `csm_stats`, `csm_stats_trend`, `csm_stats_timeline` |
| Response | `csm_blocked_ips`, `csm_quarantine`, `csm_db_object_backups`, `csm_audit` |
| Accounts and incidents | `csm_accounts`, `csm_account`, `csm_incident_timeline`, `csm_incidents`, `csm_incident_groups`, `csm_incident` |
| Mail | `csm_email_stats`, `csm_email_quarantine`, `csm_email_av_status`, `csm_email_checks`, `csm_email_groups`, `csm_email_overview`, `csm_email_rejects`, `csm_email_senders`, `csm_email_rspamd`, `csm_email_relay_abuse`, `csm_email_forwarders`, `csm_email_deferrals`, `csm_email_queue_composition`, `csm_email_queue`, `csm_email_held` |
| Host | `csm_performance`, `csm_hardening` |
| Threat and rules | `csm_threat_stats`, `csm_threat_top_attackers`, `csm_threat_ip`, `csm_threat_events`, `csm_threat_db_stats`, `csm_threat_whitelist`, `csm_rules_status`, `csm_rules_list` |
| WAF and firewall | `csm_modsec_stats`, `csm_modsec_blocks`, `csm_modsec_events`, `csm_modsec_rules`, `csm_firewall_status`, `csm_firewall_allowed`, `csm_firewall_audit`, `csm_firewall_subnets`, `csm_firewall_check`, `csm_firewall_rollback`, `csm_geoip` |

### What is not reachable

These are left out on purpose:

- The findings event stream.
- CSV and state exports.
- Settings, sessions, preferences and undo.
- The verified-bots editor.
- Every `POST`, `PUT`, `PATCH` and `DELETE` route.
- The reads that return content, not metadata: quarantined file previews, queued message headers and the SQL of backed-up database objects.

The allowlist is tested against the public route registrations, so a route added to it must be a documented `GET` read.

### Tools that touch the live host

Some reads touch the live host, not CSM's store:

| Tool | What it does on the host |
| --- | --- |
| `csm_email_stats` and `csm_email_queue` | Run the MTA queue tools. |
| `csm_firewall_check` | Asks cPHulk on cPanel. |
| `csm_accounts` | Walks account directories. |
| `csm_performance` | Samples `/proc`. |

## Logging

| Event | Daemon log line |
| --- | --- |
| A tool call | One `mcp tool call` line with the token name, tool, peer, HTTP status of the underlying route, outcome and duration, and the arguments cut to one line. |
| An authentication failure | `mcp: refused token` with the credential name, when known, and the peer. |

Reads are not written to the Web UI audit log, which records actions only.

The capability `mcp.readonly.v1` in `GET /api/v1/capabilities` advertises that the build carries the endpoint. Whether the endpoint is enabled is a matter of configuration.
