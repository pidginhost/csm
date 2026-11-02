package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Dispatcher serves one allowlisted API read in-process. webui.Server's
// ReadOnly dispatcher is the implementation; it always sends GET and
// refuses every path outside its table with an error.
type Dispatcher interface {
	Dispatch(ctx context.Context, path string, query url.Values, peer string) (status int, contentType string, body []byte, err error)
	Routes() []string
}

// param describes one query parameter a tool accepts. Values are passed to
// the route as given; the route validates them as it does for any client.
type param struct {
	name, kind, desc string
	required         bool
}

var (
	pLimit    = param{"limit", "integer", "Maximum number of items to return.", false}
	pOffset   = param{"offset", "integer", "Number of items to skip (paging).", false}
	pFrom     = param{"from", "string", "Start of the range: a calendar date YYYY-MM-DD (server time zone) or an RFC 3339 instant.", false}
	pTo       = param{"to", "string", "End of the range: a calendar date (inclusive) or an RFC 3339 instant (exclusive).", false}
	pSeverity = param{"severity", "string", "Severity filter: CRITICAL, HIGH or WARNING.", false}
	pSearch   = param{"search", "string", "Free-text filter on the message.", false}
	pChecks   = param{"checks", "string", "Comma-separated check names to include.", false}
	pIP       = param{"ip", "string", "IPv4 or IPv6 address.", true}
	pAccount  = param{"account", "string", "Hosting account (system user) name.", false}
	pHours    = param{"hours", "integer", "Window in hours.", false}
)

// tool is one MCP tool backed by a route, or by a composite function that
// calls several routes through the same dispatcher.
type tool struct {
	name, title, desc string
	route             string
	params            []param
	composite         func(ctx context.Context, s *Server, args map[string]string, peer string) (any, error)
}

// routeTools is the one-tool-per-route table. Names say what the tool reads;
// descriptions name the route so a reader can cross-check docs/src/api.md.
var routeTools = []tool{
	{name: "csm_status", title: "Daemon status", desc: "Full health snapshot of the CSM daemon: version, uptime, watchers, severity counts, store and firewall health, queues, admission ledger, security posture. GET /api/v1/status.", route: "/api/v1/status"},
	{name: "csm_health", title: "Daemon health", desc: "Daemon liveness: fanotify, log watchers, loaded rules, uptime. GET /api/v1/health.", route: "/api/v1/health"},
	{name: "csm_capabilities", title: "Build capabilities", desc: "Feature tokens this build and host support. GET /api/v1/capabilities.", route: "/api/v1/capabilities"},
	{name: "csm_components", title: "Component matrix", desc: "Watcher and component attachment, event and upstream freshness state. GET /api/v1/components.", route: "/api/v1/components"},
	{name: "csm_challenge_stats", title: "Challenge routing stats", desc: "Challenge-page routing activity: pending, escalated, routed by check, recent routes. GET /api/v1/challenge/stats.", route: "/api/v1/challenge/stats"},
	{name: "csm_scan_jobs", title: "Scan jobs", desc: "Queued, running and finished full-scan jobs. GET /api/v1/scan-jobs.", route: "/api/v1/scan-jobs"},
	{name: "csm_scan_job", title: "Scan job detail", desc: "One scan job by id. GET /api/v1/scan-jobs/{id}.", route: "/api/v1/scan-jobs/{id}", params: []param{{"id", "string", "Scan job id.", true}}},
	{name: "csm_findings", title: "Active findings", desc: "Current active findings. GET /api/v1/findings.", route: "/api/v1/findings"},
	{name: "csm_findings_enriched", title: "Enriched findings", desc: "Active findings with GeoIP, account, fix availability and the evidence address auto-block acts on. Ordered by severity then newest when limit is set. GET /api/v1/findings/enriched.", route: "/api/v1/findings/enriched", params: []param{pLimit}},
	{name: "csm_finding_detail", title: "Finding detail", desc: "One finding with first/last seen, related audit actions and related history. GET /api/v1/finding-detail.", route: "/api/v1/finding-detail", params: []param{{"check", "string", "Check name of the finding.", true}, {"message", "string", "Finding message.", false}, {"key", "string", "Finding key, when known.", false}}},
	{name: "csm_history", title: "Finding history", desc: "Paginated finding history with filters. GET /api/v1/history.", route: "/api/v1/history", params: []param{pLimit, pOffset, pFrom, pTo, pSeverity, pSearch, pChecks, {"scope", "string", "email limits results to the email checks.", false}}},
	{name: "csm_stats", title: "24h stats", desc: "24h severity counts, auto-response summary and accounts with active high or critical findings. GET /api/v1/stats.", route: "/api/v1/stats"},
	{name: "csm_stats_trend", title: "30-day trend", desc: "Daily severity counts for the last 30 days. GET /api/v1/stats/trend.", route: "/api/v1/stats/trend"},
	{name: "csm_stats_timeline", title: "24h timeline", desc: "Hourly severity counts for the last 24 hours. GET /api/v1/stats/timeline.", route: "/api/v1/stats/timeline"},
	{name: "csm_blocked_ips", title: "Blocked IPs", desc: "Addresses CSM blocked, with reason, origin and expiry. GET /api/v1/blocked-ips.", route: "/api/v1/blocked-ips"},
	{name: "csm_quarantine", title: "Quarantined files", desc: "Quarantined files with metadata. GET /api/v1/quarantine.", route: "/api/v1/quarantine"},
	{name: "csm_db_object_backups", title: "DB object backups", desc: "MySQL triggers, events, procedures and functions CSM removed and backed up. GET /api/v1/db-object-backups.", route: "/api/v1/db-object-backups"},
	{name: "csm_accounts", title: "Hosting accounts", desc: "Accounts a server-wide scan covers. GET /api/v1/accounts.", route: "/api/v1/accounts"},
	{name: "csm_account", title: "Account detail", desc: "One account's findings, quarantine and history. GET /api/v1/account.", route: "/api/v1/account", params: []param{{"name", "string", "Account (system user) name.", true}}},
	{name: "csm_audit", title: "UI audit log", desc: "Newest operator actions taken through the Web UI and API, with actor. GET /api/v1/audit.", route: "/api/v1/audit"},
	{name: "csm_incident_timeline", title: "Incident timeline", desc: "Timeline of findings and actions for an address or account over a window. GET /api/v1/incident.", route: "/api/v1/incident", params: []param{{"ip", "string", "Address to follow.", false}, pAccount, pHours}},
	{name: "csm_incidents", title: "Incidents", desc: "Correlated incidents (open, contained, resolved). GET /api/v1/incidents.", route: "/api/v1/incidents", params: []param{pLimit, pOffset, {"status", "string", "Status filter.", false}, pSeverity}},
	{name: "csm_incident_groups", title: "Incident groups", desc: "Incidents grouped for the dashboard. GET /api/v1/incidents/groups.", route: "/api/v1/incidents/groups"},
	{name: "csm_incident", title: "Incident detail", desc: "One incident by id. GET /api/v1/incidents/{id}.", route: "/api/v1/incidents/{id}", params: []param{{"id", "string", "Incident id.", true}}},
	{name: "csm_email_stats", title: "Mail stats", desc: "Mail queue size and mail protection counters. Runs the MTA queue count. GET /api/v1/email/stats.", route: "/api/v1/email/stats"},
	{name: "csm_email_quarantine", title: "Mail quarantine", desc: "Messages the email antivirus quarantined. GET /api/v1/email/quarantine.", route: "/api/v1/email/quarantine", params: []param{pLimit, pOffset}},
	{name: "csm_email_av_status", title: "Email AV status", desc: "Email antivirus engine and watcher state. GET /api/v1/email/av/status.", route: "/api/v1/email/av/status"},
	{name: "csm_email_checks", title: "Email check names", desc: "Check names that belong to mail protection. GET /api/v1/email/checks.", route: "/api/v1/email/checks"},
	{name: "csm_email_groups", title: "Mail finding groups", desc: "Mail findings grouped by mailbox and kind over a range. GET /api/v1/email/groups.", route: "/api/v1/email/groups", params: []param{pFrom, pTo, pLimit}},
	{name: "csm_email_overview", title: "Mail overview", desc: "Mail protection overview over a range. GET /api/v1/email/overview.", route: "/api/v1/email/overview", params: []param{pFrom, pTo}},
	{name: "csm_email_rejects", title: "Mail rejects", desc: "Rejected inbound mail over a range. GET /api/v1/email/rejects.", route: "/api/v1/email/rejects", params: []param{pFrom, pTo, pLimit, pOffset}},
	{name: "csm_email_senders", title: "Mail senders", desc: "Outbound sender profiles over a range. GET /api/v1/email/senders.", route: "/api/v1/email/senders", params: []param{pFrom, pTo, pLimit, pOffset}},
	{name: "csm_email_rspamd", title: "rspamd stats", desc: "Antispam engine statistics from rspamd. GET /api/v1/email/rspamd.", route: "/api/v1/email/rspamd"},
	{name: "csm_email_relay_abuse", title: "Relay abuse", desc: "Authenticated relay abuse over a range. GET /api/v1/email/relay-abuse.", route: "/api/v1/email/relay-abuse", params: []param{pFrom, pTo, pLimit}},
	{name: "csm_email_forwarders", title: "Mail forwarders", desc: "Forwarders and filters audit with summary. GET /api/v1/email/forwarders.", route: "/api/v1/email/forwarders", params: []param{pAccount, pLimit, pOffset}},
	{name: "csm_email_deferrals", title: "Mail deferrals", desc: "Deferred delivery summary. GET /api/v1/email/deferrals.", route: "/api/v1/email/deferrals"},
	{name: "csm_email_queue_composition", title: "Mail queue composition", desc: "What the mail queue holds, by sender and class. GET /api/v1/email/queue-composition.", route: "/api/v1/email/queue-composition"},
	{name: "csm_email_queue", title: "Mail queue", desc: "Messages in the MTA queue. Reads the live queue. GET /api/v1/email/queue.", route: "/api/v1/email/queue", params: []param{{"filter", "string", "Queue filter.", false}, pLimit, pOffset}},
	{name: "csm_email_held", title: "Held forward copies", desc: "Forward copies the forward guard is holding. GET /api/v1/email/held.", route: "/api/v1/email/held", params: []param{pLimit, pOffset}},
	{name: "csm_performance", title: "Performance", desc: "Performance findings and a host resource sample. GET /api/v1/performance.", route: "/api/v1/performance"},
	{name: "csm_hardening", title: "Hardening report", desc: "Last stored hardening audit report. GET /api/v1/hardening.", route: "/api/v1/hardening"},
	{name: "csm_threat_stats", title: "Threat stats", desc: "Attack database totals. GET /api/v1/threat/stats.", route: "/api/v1/threat/stats"},
	{name: "csm_threat_top_attackers", title: "Top attackers", desc: "Most active attacking addresses. GET /api/v1/threat/top-attackers.", route: "/api/v1/threat/top-attackers", params: []param{pLimit, pHours}},
	{name: "csm_threat_ip", title: "Threat record for IP", desc: "Everything CSM recorded about one address: attacks, reputation, block state. GET /api/v1/threat/ip.", route: "/api/v1/threat/ip", params: []param{pIP}},
	{name: "csm_threat_events", title: "Attack events", desc: "Recent attack events with filters. GET /api/v1/threat/events.", route: "/api/v1/threat/events", params: []param{{"ip", "string", "Address filter.", false}, pLimit, pHours, {"type", "string", "Event type filter.", false}}},
	{name: "csm_threat_db_stats", title: "Threat DB stats", desc: "Threat database sizes and freshness. GET /api/v1/threat/db-stats.", route: "/api/v1/threat/db-stats"},
	{name: "csm_threat_whitelist", title: "Whitelist", desc: "Addresses on the runtime whitelist. GET /api/v1/threat/whitelist.", route: "/api/v1/threat/whitelist"},
	{name: "csm_rules_status", title: "Rules status", desc: "Signature rule set status and update state. GET /api/v1/rules/status.", route: "/api/v1/rules/status"},
	{name: "csm_rules_list", title: "Rules list", desc: "Loaded signature rules. GET /api/v1/rules/list.", route: "/api/v1/rules/list", params: []param{pLimit, pOffset, pSearch}},
	{name: "csm_modsec_stats", title: "ModSecurity stats", desc: "WAF event totals. GET /api/v1/modsec/stats.", route: "/api/v1/modsec/stats"},
	{name: "csm_modsec_blocks", title: "ModSecurity blocks", desc: "Addresses blocked from WAF correlation. GET /api/v1/modsec/blocks.", route: "/api/v1/modsec/blocks"},
	{name: "csm_modsec_events", title: "ModSecurity events", desc: "Recent WAF events. GET /api/v1/modsec/events.", route: "/api/v1/modsec/events", params: []param{pLimit, {"ip", "string", "Address filter.", false}}},
	{name: "csm_modsec_rules", title: "ModSecurity rules", desc: "Bundled WAF rule configuration and per-domain coverage. GET /api/v1/modsec/rules.", route: "/api/v1/modsec/rules"},
	{name: "csm_firewall_status", title: "Firewall status", desc: "nftables engine state: enabled, managed, sets, counts. GET /api/v1/firewall/status.", route: "/api/v1/firewall/status"},
	{name: "csm_firewall_allowed", title: "Firewall allow list", desc: "Addresses allowed through the firewall. GET /api/v1/firewall/allowed.", route: "/api/v1/firewall/allowed"},
	{name: "csm_firewall_audit", title: "Firewall audit", desc: "Firewall change audit log. GET /api/v1/firewall/audit.", route: "/api/v1/firewall/audit", params: []param{pLimit}},
	{name: "csm_firewall_subnets", title: "Firewall subnets", desc: "Denied subnets. GET /api/v1/firewall/subnets.", route: "/api/v1/firewall/subnets"},
	{name: "csm_firewall_check", title: "Firewall check IP", desc: "Whether one address is blocked, by what and until when, including cPHulk. GET /api/v1/firewall/check.", route: "/api/v1/firewall/check", params: []param{pIP}},
	{name: "csm_firewall_rollback", title: "Firewall rollback", desc: "Pending timed firewall configuration rollback, if any. GET /api/v1/settings/firewall/rollback.", route: "/api/v1/settings/firewall/rollback"},
	{name: "csm_geoip", title: "GeoIP lookup", desc: "Country, ASN and organisation of an address from the local GeoIP database. GET /api/v1/geoip.", route: "/api/v1/geoip", params: []param{pIP}},
}

// compositeTools answer a support question in one call by reading several
// routes through the same dispatcher.
var compositeTools = []tool{
	{name: "csm_overview", title: "Server overview", desc: "One-call picture of this server: hostname, platform, CSM version and mode, daemon status, health and capabilities.", composite: overview},
	{name: "csm_lookup_ip", title: "Look up an IP", desc: "Everything about one address in one call: firewall block state, blocked-list entry, threat record and GeoIP.", params: []param{pIP}, composite: lookupIP},
	{name: "csm_config_summary", title: "Configuration summary", desc: "Non-secret configuration facts: mode, platform, listeners, which protections are enabled, thresholds that explain blocks. Secrets are never read.", composite: configSummary},
}

// toolTable builds the name -> tool map and the descriptors sent by
// tools/list, keeping only route tools the dispatcher serves.
func toolTable(d Dispatcher) (map[string]tool, []toolDescriptor) {
	served := map[string]bool{}
	if d != nil {
		for _, r := range d.Routes() {
			served[r] = true
		}
	}
	byName := map[string]tool{}
	var descriptors []toolDescriptor
	add := func(t tool) {
		byName[t.name] = t
		descriptors = append(descriptors, toolDescriptor{
			Name:        t.name,
			Description: t.desc,
			InputSchema: inputSchema(t.params),
			Annotations: toolAnnotations{Title: t.title, ReadOnlyHint: true, IdempotentHint: true},
		})
	}
	for _, t := range routeTools {
		if !served[t.route] {
			continue
		}
		add(t)
	}
	for _, t := range compositeTools {
		add(t)
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Name < descriptors[j].Name })
	return byName, descriptors
}

func inputSchema(params []param) map[string]any {
	props := map[string]any{}
	var required []string
	for _, p := range params {
		props[p.name] = map[string]any{"type": p.kind, "description": p.desc}
		if p.required {
			required = append(required, p.name)
		}
	}
	schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// decodeArguments turns the JSON arguments into strings the routes read as
// query values. Only declared parameters are accepted; a number is
// formatted as the route expects.
func decodeArguments(t tool, raw json.RawMessage) (map[string]string, error) {
	args := map[string]string{}
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	}
	var given map[string]any
	if err := json.Unmarshal(raw, &given); err != nil {
		return nil, fmt.Errorf("arguments must be an object: %v", err)
	}
	declared := map[string]param{}
	for _, p := range t.params {
		declared[p.name] = p
	}
	for name, v := range given {
		p, ok := declared[name]
		if !ok {
			return nil, fmt.Errorf("unknown argument %q", name)
		}
		switch val := v.(type) {
		case nil:
			continue
		case string:
			if len(val) > 1024 {
				return nil, fmt.Errorf("argument %q is longer than 1024 characters", name)
			}
			args[name] = val
		case float64:
			if p.kind == "integer" {
				args[name] = strconv.FormatInt(int64(val), 10)
			} else {
				args[name] = strconv.FormatFloat(val, 'f', -1, 64)
			}
		case bool:
			args[name] = strconv.FormatBool(val)
		default:
			return nil, fmt.Errorf("argument %q must be a scalar", name)
		}
	}
	for _, p := range t.params {
		if p.required && args[p.name] == "" {
			return nil, fmt.Errorf("argument %q is required", p.name)
		}
	}
	return args, nil
}

// errRouteFailed carries the API's own error message for a non-2xx answer.
type errRouteFailed struct {
	status  int
	message string
}

func (e *errRouteFailed) Error() string {
	return fmt.Sprintf("%s (HTTP %d)", e.message, e.status)
}

// read dispatches one route and decodes its JSON answer. A non-2xx status
// becomes errRouteFailed with the API's error text; a cut response is an
// error asking the caller to narrow the query.
func (s *Server) read(ctx context.Context, route string, args map[string]string, peer string) (json.RawMessage, error) {
	path := route
	query := url.Values{}
	for name, val := range args {
		if name == "id" && strings.Contains(route, "{id}") {
			if val == "" || strings.ContainsAny(val, "/?#%") {
				return nil, errors.New("id must be a single path segment")
			}
			path = strings.Replace(route, "{id}", url.PathEscape(val), 1)
			continue
		}
		query.Set(name, val)
	}
	status, ctype, body, err := s.dispatcher.Dispatch(ctx, path, query, peer)
	if err != nil {
		if isTruncated(err) {
			return nil, fmt.Errorf("response too large for one call; narrow it with limit, offset or a filter")
		}
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, &errRouteFailed{status: status, message: apiErrorMessage(body, status)}
	}
	if !strings.HasPrefix(ctype, "application/json") || !json.Valid(body) {
		return nil, fmt.Errorf("route %s answered %q, not JSON", route, ctype)
	}
	return json.RawMessage(body), nil
}

// isTruncated recognises a dispatcher size cut by the Truncated method the
// webui error carries, without importing that package.
func isTruncated(err error) bool {
	var t interface{ Truncated() bool }
	return errors.As(err, &t) && t.Truncated()
}

func apiErrorMessage(body []byte, status int) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return "request failed"
}

// callTool runs one tool and returns the MCP result. Route failures are
// tool errors (isError), never JSON-RPC errors, so the model can read them.
func (s *Server) callTool(ctx context.Context, name string, raw json.RawMessage, peer string) (toolResult, int, error) {
	t, ok := s.tools[name]
	if !ok {
		return toolResult{}, 0, fmt.Errorf("unknown tool %q", name)
	}
	args, err := decodeArguments(t, raw)
	if err != nil {
		return toolResult{}, 0, err
	}
	var out any
	if t.composite != nil {
		out, err = t.composite(ctx, s, args, peer)
	} else {
		out, err = s.read(ctx, t.route, args, peer)
	}
	if err != nil {
		var rf *errRouteFailed
		if errors.As(err, &rf) {
			return errorResult(rf.message), rf.status, nil
		}
		return errorResult(err.Error()), 0, nil
	}
	text, err := json.Marshal(out)
	if err != nil {
		return toolResult{}, 0, err
	}
	return textResult(string(text)), http.StatusOK, nil
}

// overview reads status, health and capabilities and adds host facts.
func overview(ctx context.Context, s *Server, _ map[string]string, peer string) (any, error) {
	out := map[string]any{
		"hostname": s.hostname,
		"version":  s.version,
		"platform": s.platform,
	}
	for key, route := range map[string]string{
		"status":       "/api/v1/status",
		"health":       "/api/v1/health",
		"capabilities": "/api/v1/capabilities",
	} {
		body, err := s.read(ctx, route, nil, peer)
		if err != nil {
			out[key+"_error"] = err.Error()
			continue
		}
		out[key] = body
	}
	return out, nil
}

// lookupIP reads the four address routes; a route that fails reports its
// error next to the others instead of failing the whole lookup.
func lookupIP(ctx context.Context, s *Server, args map[string]string, peer string) (any, error) {
	ip := args["ip"]
	out := map[string]any{"ip": ip}
	for key, route := range map[string]string{
		"firewall": "/api/v1/firewall/check",
		"threat":   "/api/v1/threat/ip",
		"geoip":    "/api/v1/geoip",
	} {
		body, err := s.read(ctx, route, map[string]string{"ip": ip}, peer)
		if err != nil {
			out[key+"_error"] = err.Error()
			continue
		}
		out[key] = body
	}
	if body, err := s.read(ctx, "/api/v1/blocked-ips", nil, peer); err != nil {
		out["blocked_error"] = err.Error()
	} else {
		out["blocked"] = blockedEntryFor(body, ip)
	}
	return out, nil
}

// blockedEntryFor picks the blocked-ips item for ip, or null.
func blockedEntryFor(body json.RawMessage, ip string) any {
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return nil
	}
	for _, item := range list.Items {
		if v, _ := item["ip"].(string); v == ip {
			return item
		}
	}
	return nil
}

func configSummary(_ context.Context, s *Server, _ map[string]string, _ string) (any, error) {
	if s.configSummary == nil {
		return nil, errors.New("configuration summary not available")
	}
	return s.configSummary(), nil
}
