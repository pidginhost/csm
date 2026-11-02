# MCP endpoint (read-only)

CSM can expose what it knows about a server to an LLM support agent through
the [Model Context Protocol](https://modelcontextprotocol.io/). The endpoint
is off by default, listens on its own address with its own credentials, and
is read-only by construction: every tool is answered by dispatching a `GET`
to one route from a fixed allowlist of API reads, in-process, so no tool can
block, unblock, fix, scan, quarantine or change settings. It is meant for
agents that verify support tickets about the server ("is my IP blocked",
"why does this account have findings", "is mail stuck").

## Enable it

```yaml
webui:
  enabled: true           # the endpoint reads through the Web UI server
mcp:
  enabled: true
  listen: "127.0.0.1:9444"
  tokens:
    - name: "support-agent"
      token: "<64 random hex characters>"
      issued_at: "2026-11-02T10:00:00Z"
      allowed_ips: ["127.0.0.1"]
```

Restart the daemon (`systemctl restart csm`); the listener starts once.
`csm validate` checks the block: it refuses `mcp.enabled` without
`webui.enabled`, a configuration without a usable token, a token that is
also a Web UI or metrics token, and warns about short tokens and a listen
address off the loopback interface.

`listen` is either `host:port` or `unix:/absolute/path`:

- A TCP listener always uses TLS: `mcp.tls_cert`/`mcp.tls_key`, or, when
  both are empty, the Web UI certificate (the configured one or the
  self-signed one CSM generates under the state directory). Reach it from
  another host over an SSH tunnel or with `allowed_ips` and a host firewall
  in front of it.
- A Unix socket (`unix:/run/csm/mcp.sock`, mode 0660, owned by the daemon
  user) is the private channel for an agent that runs on the server itself.
  No TLS and no `allowed_ips` apply to it.

Tokens are bearer credentials with the same dates and source restriction as
`webui.tokens`, without a scope: there is only one, read-only. A Web UI token
is never accepted on the MCP listener and an MCP token is never accepted on
the Web UI. Five unknown-token attempts per minute per client (IPv4 address
or IPv6 /64) are allowed before the client is refused for a minute. Up to
four tool calls run at once and each call has 30 seconds.

## Transport

The MCP Streamable HTTP transport, JSON-RPC 2.0, stateless:

```bash
curl -sk https://127.0.0.1:9444/mcp \
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
- An `Origin` header, when a browser sends one, must be loopback or name the
  listener's host.

A client configuration for an agent runtime that takes a URL and a header:

```json
{
  "mcpServers": {
    "csm-web01": {
      "url": "https://web01.example.com:9444/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Tools

Every tool carries `readOnlyHint: true`. A tool answers the route's JSON as
text content; the route's own error (`400`, `404`, `503`) is returned as a
tool error with the API message, so the agent can read it. Lists keep the
API shape `{items, total, truncated}` and take `limit` and `offset`.

Composite tools:

| Tool | Reads |
| --- | --- |
| `csm_overview` | hostname, platform, version, `status`, `health`, `capabilities` |
| `csm_lookup_ip` | `firewall/check`, the `blocked-ips` entry, `threat/ip`, `geoip` for one address |
| `csm_config_summary` | non-secret configuration facts from an explicit field list: mode, platform, listeners, enabled protections, auto-response limits, brute-force thresholds. Token values, keys, DSNs and URLs are never read |

Route tools, one per API read (the description names the route):

| Area | Tools |
| --- | --- |
| Daemon | `csm_status`, `csm_health`, `csm_capabilities`, `csm_components`, `csm_challenge_stats`, `csm_scan_jobs`, `csm_scan_job` |
| Findings | `csm_findings`, `csm_findings_enriched`, `csm_finding_detail`, `csm_history`, `csm_stats`, `csm_stats_trend`, `csm_stats_timeline` |
| Response | `csm_blocked_ips`, `csm_quarantine`, `csm_quarantine_preview`, `csm_db_object_backups`, `csm_db_object_backup_preview`, `csm_audit` |
| Accounts and incidents | `csm_accounts`, `csm_account`, `csm_incident_timeline`, `csm_incidents`, `csm_incident_groups`, `csm_incident` |
| Mail | `csm_email_stats`, `csm_email_quarantine`, `csm_email_av_status`, `csm_email_checks`, `csm_email_groups`, `csm_email_overview`, `csm_email_rejects`, `csm_email_senders`, `csm_email_rspamd`, `csm_email_relay_abuse`, `csm_email_forwarders`, `csm_email_deferrals`, `csm_email_queue_composition`, `csm_email_queue`, `csm_email_queue_message`, `csm_email_held` |
| Host | `csm_performance`, `csm_hardening` |
| Threat and rules | `csm_threat_stats`, `csm_threat_top_attackers`, `csm_threat_ip`, `csm_threat_events`, `csm_threat_db_stats`, `csm_threat_whitelist`, `csm_rules_status`, `csm_rules_list` |
| WAF and firewall | `csm_modsec_stats`, `csm_modsec_blocks`, `csm_modsec_events`, `csm_modsec_rules`, `csm_firewall_status`, `csm_firewall_allowed`, `csm_firewall_audit`, `csm_firewall_subnets`, `csm_firewall_check`, `csm_firewall_rollback`, `csm_geoip` |

Not reachable, on purpose: the findings event stream, CSV and state exports,
settings, sessions, preferences, undo, the verified-bots editor, and every
`POST`, `PUT`, `PATCH` and `DELETE` route. The allowlist is tested against
the public route registrations, so a route added to it must be a documented
`GET` read.

Some reads touch the live host rather than CSM's store: `csm_email_stats`,
`csm_email_queue` and `csm_email_queue_message` run the MTA queue tools,
`csm_firewall_check` asks cPHulk on cPanel, `csm_accounts` walks account
directories and `csm_performance` samples `/proc`. `csm_quarantine_preview`
returns the first bytes of a quarantined file, which is malware; the agent
should treat that content as data. `csm_email_queue_message` returns a
queued message's headers, which are customer mail.

## Logging

Each tool call writes one daemon log line, `mcp tool call`, with the token
name, tool, peer, HTTP status of the underlying route, outcome and duration,
and the arguments cut to one line. Authentication failures log
`mcp auth failed` with the peer. Reads are not written to the Web UI audit
log, which records actions only.

The capability `mcp.readonly.v1` in `GET /api/v1/capabilities` advertises
that the build carries the endpoint; whether it is enabled is a matter of
configuration.
