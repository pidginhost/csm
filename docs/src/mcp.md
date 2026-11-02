# MCP endpoint (read-only)

CSM can expose what it knows about a server to an LLM support agent through
the [Model Context Protocol](https://modelcontextprotocol.io/). The endpoint
is off by default, answers at `/mcp` on the Web UI listener with credentials
of its own, and is read-only by construction: every tool is answered by
dispatching a `GET` to one route from a fixed allowlist of API reads,
in-process, so no tool can block, unblock, fix, scan, quarantine or change
settings. It is meant for agents that verify support tickets about the
server ("is my IP blocked", "why does this account have findings", "is mail
stuck").

## Enable it

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

Restart the daemon (`systemctl restart csm`); the endpoint is wired at
startup. `csm validate` checks the block: it refuses `mcp.enabled` without
`webui.enabled`, a configuration without a usable token, and a token that is
also a Web UI or metrics token, and warns about short tokens.

The endpoint shares the Web UI's TLS certificate, port and firewall
exposure. Limit who reaches it with the token's `allowed_ips`.

Tokens are bearer credentials with the same dates and source restriction as
`webui.tokens`, without a scope: there is only one, read-only. A Web UI token
or browser session never opens `/mcp`, and an MCP token opens nothing else.
A known credential sent to the wrong endpoint, or used outside its dates
or addresses, is refused without spending the guess budget below.
Unknown tokens draw on the same budget as Web UI login and API token
guesses: five failed attempts per minute per client (IPv4 address or IPv6
/64), after which the client is refused for a minute. `/mcp` also counts
toward the API request rate limit. Up to four tool calls run at once and
each request, a whole batch included, has 30 seconds. A read still running
at the deadline keeps its slot until it finishes.

## Transport

The MCP Streamable HTTP transport, JSON-RPC 2.0, stateless:

```bash
curl -sk https://server.example.com:9443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"csm_lookup_ip","arguments":{"ip":"203.0.113.9"}}}'
```

- `POST /mcp` only. `GET` answers 405 (no server-initiated stream);
  there is no session id to keep.
- Protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05`; `initialize`
  answers the client's version when it is one of those.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`,
  `notifications/initialized` (202, no body). `resources/list` and
  `prompts/list` answer empty lists. Batches of up to 20 requests are
  answered as a batch.
- A request body is limited to 1 MiB. A tool answer larger than 4 MiB is
  refused with a message asking for `limit`, `offset` or a filter.
- A browser `Origin` header must pass the same check as on the API: the
  configured Web UI origin, an entry in `webui.allowed_origins`, or a
  loopback origin that matches the request host.

A client configuration for an agent runtime that takes a URL and a header:

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

Every tool carries `readOnlyHint: true`. A tool answers the route's JSON as
text content; the route's own error (`400`, `404`, `503`) is returned as a
tool error with the API message, so the agent can read it. Lists keep the
API shape `{items, total, truncated}`; a tool takes only the arguments its
route reads.

Composite tools:

| Tool | Reads |
| --- | --- |
| `csm_overview` | hostname, platform, version, `status`, `health`, `capabilities` |
| `csm_lookup_ip` | `firewall/check`, the `blocked-ips` entry, `threat/ip`, `geoip` for one address |
| `csm_config_summary` | non-secret configuration facts from an explicit field list: mode, platform, Web UI listen address, enabled protections, auto-response limits, brute-force thresholds. Token values, keys, DSNs and URLs are never read |

Route tools, one per API read (the description names the route):

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

Not reachable, on purpose: the findings event stream, CSV and state exports,
settings, sessions, preferences, undo, the verified-bots editor, every
`POST`, `PUT`, `PATCH` and `DELETE` route, and the reads that return content
rather than metadata: quarantined file previews, queued message headers and
the SQL of backed-up database objects. The allowlist is tested against
the public route registrations, so a route added to it must be a documented
`GET` read.

Some reads touch the live host rather than CSM's store: `csm_email_stats`
and `csm_email_queue` run the MTA queue tools, `csm_firewall_check` asks
cPHulk on cPanel, `csm_accounts` walks account directories and
`csm_performance` samples `/proc`.

## Logging

Each tool call writes one daemon log line, `mcp tool call`, with the token
name, tool, peer, HTTP status of the underlying route, outcome and duration,
and the arguments cut to one line. Authentication failures log
`mcp: refused token` with the credential name, when known, and peer. Reads
are not written to the Web UI audit log, which records actions only.

The capability `mcp.readonly.v1` in `GET /api/v1/capabilities` advertises
that the build carries the endpoint; whether it is enabled is a matter of
configuration.
