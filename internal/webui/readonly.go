package webui

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ReadOnlyRoute is one GET route the read-only dispatcher can reach. The
// table is the whole surface: a path that is not listed cannot be served,
// whatever the caller sends.
type ReadOnlyRoute struct {
	// Pattern is the http.ServeMux pattern, with {id} where the public
	// mux takes a path value or a prefix.
	Pattern string
	handler http.HandlerFunc
}

// readOnlyRoutes lists every API read the MCP endpoint may dispatch. Keep
// it to GET handlers that answer JSON; TestReadOnlyRoutesAreRegisteredReads
// checks each one against the public route registrations.
func (s *Server) readOnlyRoutes() []ReadOnlyRoute {
	return []ReadOnlyRoute{
		{"/api/v1/status", s.apiStatus},
		{"/api/v1/health", s.apiHealth},
		{"/api/v1/capabilities", s.apiCapabilities},
		{"/api/v1/components", s.apiComponents},
		{"/api/v1/challenge/stats", s.apiChallengeStats},
		{"/api/v1/scan-jobs", s.apiScanJobsList},
		{"/api/v1/scan-jobs/{id}", s.apiScanJobsRouter},
		{"/api/v1/findings", s.apiFindings},
		{"/api/v1/findings/enriched", s.apiFindingsEnriched},
		{"/api/v1/finding-detail", s.apiFindingDetail},
		{"/api/v1/history", s.apiHistory},
		{"/api/v1/stats", s.apiStats},
		{"/api/v1/stats/trend", s.apiStatsTrend},
		{"/api/v1/stats/timeline", s.apiStatsTimeline},
		{"/api/v1/blocked-ips", s.apiBlockedIPs},
		{"/api/v1/quarantine", s.apiQuarantine},
		{"/api/v1/db-object-backups", s.apiDBObjectBackups},
		{"/api/v1/accounts", s.apiAccounts},
		{"/api/v1/account", s.apiAccountDetail},
		{"/api/v1/audit", s.apiUIAudit},
		{"/api/v1/incident", s.apiIncident},
		{"/api/v1/incidents", s.apiIncidentList},
		{"/api/v1/incidents/groups", s.apiIncidentGroups},
		{"/api/v1/incidents/{id}", s.apiIncidentShow},
		{"/api/v1/email/stats", s.apiEmailStats},
		{"/api/v1/email/quarantine", s.apiEmailQuarantineList},
		{"/api/v1/email/av/status", s.apiEmailAVStatus},
		{"/api/v1/email/checks", s.apiEmailChecks},
		{"/api/v1/email/groups", s.apiEmailGroups},
		{"/api/v1/email/overview", s.apiEmailOverview},
		{"/api/v1/email/rejects", s.apiEmailRejects},
		{"/api/v1/email/senders", s.apiEmailSenders},
		{"/api/v1/email/rspamd", s.apiEmailRspamd},
		{"/api/v1/email/relay-abuse", s.apiEmailRelayAbuse},
		{"/api/v1/email/forwarders", s.apiEmailForwarders},
		{"/api/v1/email/deferrals", s.apiEmailDeferrals},
		{"/api/v1/email/queue-composition", s.apiEmailQueueComposition},
		{"/api/v1/email/queue", s.apiEmailQueueList},
		{"/api/v1/email/held", s.apiEmailHeldList},
		{"/api/v1/performance", s.apiPerformance},
		{"/api/v1/hardening", s.apiHardening},
		{"/api/v1/threat/stats", s.apiThreatStats},
		{"/api/v1/threat/top-attackers", s.apiThreatTopAttackers},
		{"/api/v1/threat/ip", s.apiThreatIP},
		{"/api/v1/threat/events", s.apiThreatEvents},
		{"/api/v1/threat/db-stats", s.apiThreatDBStats},
		{"/api/v1/threat/whitelist", s.apiThreatWhitelist},
		{"/api/v1/rules/status", s.apiRulesStatus},
		{"/api/v1/rules/list", s.apiRulesList},
		{"/api/v1/modsec/stats", s.apiModSecStats},
		{"/api/v1/modsec/blocks", s.apiModSecBlocks},
		{"/api/v1/modsec/events", s.apiModSecEvents},
		{"/api/v1/modsec/rules", s.apiModSecRules},
		{"/api/v1/firewall/status", s.apiFirewallStatus},
		{"/api/v1/firewall/allowed", s.apiFirewallAllowed},
		{"/api/v1/firewall/audit", s.apiFirewallAudit},
		{"/api/v1/firewall/subnets", s.apiFirewallSubnets},
		{"/api/v1/firewall/check", s.apiFirewallCheck},
		{"/api/v1/settings/firewall/rollback", s.apiFirewallRollbackStatus},
		{"/api/v1/geoip", s.apiGeoIPLookup},
	}
}

// ReadOnlyDispatcher serves the read-only route table in-process. It holds
// a private ServeMux with nothing but those routes, each behind getOnly,
// and builds every request itself with the GET method, so no caller input
// can select a method or a route outside the table.
type ReadOnlyDispatcher struct {
	routes   *http.ServeMux
	patterns []string
	maxBody  int
}

// ReadOnlyMaxBody caps one dispatched response. Larger answers are cut and
// reported as truncated; callers narrow the query with the route's own
// limit and filter parameters.
const ReadOnlyMaxBody = 4 << 20

// ErrReadOnlyRoute is returned for a path outside the read-only table.
var ErrReadOnlyRoute = errors.New("not a read-only route")

// ReadOnly returns the dispatcher for this server. It is safe to call once
// the server is constructed; the handlers read the same live wiring the
// HTTPS listener uses.
func (s *Server) ReadOnly() *ReadOnlyDispatcher {
	d := &ReadOnlyDispatcher{routes: http.NewServeMux(), maxBody: ReadOnlyMaxBody}
	for _, route := range s.readOnlyRoutes() {
		d.routes.Handle(route.Pattern, getOnly(route.handler))
		d.patterns = append(d.patterns, route.Pattern)
	}
	sort.Strings(d.patterns)
	return d
}

// Routes lists the patterns the dispatcher serves, sorted.
func (d *ReadOnlyDispatcher) Routes() []string {
	return append([]string(nil), d.patterns...)
}

// Serves reports whether path (without a query) is inside the table. A
// pattern with {id} matches one non-empty path segment in its place.
func (d *ReadOnlyDispatcher) Serves(path string) bool {
	if path == "" || strings.Contains(path, "?") || strings.Contains(path, "..") {
		return false
	}
	for _, pattern := range d.patterns {
		if readOnlyPatternMatches(pattern, path) {
			return true
		}
	}
	return false
}

func readOnlyPatternMatches(pattern, path string) bool {
	prefix, _, wild := strings.Cut(pattern, "{id}")
	if !wild {
		return pattern == path
	}
	rest, ok := strings.CutPrefix(path, prefix)
	return ok && rest != "" && !strings.Contains(rest, "/")
}

// Dispatch serves GET path?query to the matching read-only handler and
// returns the status, content type and body it wrote. peer is recorded as
// the request's RemoteAddr for handlers and logs that name the caller. A
// path outside the table answers ErrReadOnlyRoute without touching any
// handler.
func (d *ReadOnlyDispatcher) Dispatch(ctx context.Context, path string, query url.Values, peer string) (int, string, []byte, error) {
	if !d.Serves(path) {
		return 0, "", nil, ErrReadOnlyRoute
	}
	target := &url.URL{Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.RemoteAddr = peer
	req.Header.Set("Accept", "application/json")
	rec := &readOnlyRecorder{header: http.Header{}, status: http.StatusOK, limit: d.maxBody}
	d.routes.ServeHTTP(rec, req)
	body := rec.body.Bytes()
	if rec.truncated {
		return rec.status, rec.header.Get("Content-Type"), body, errReadOnlyTruncated{}
	}
	return rec.status, rec.header.Get("Content-Type"), body, nil
}

// errReadOnlyTruncated reports a response cut at ReadOnlyMaxBody. Callers
// in other packages recognise it through its Truncated method.
type errReadOnlyTruncated struct{}

func (errReadOnlyTruncated) Error() string {
	return "response larger than the read-only dispatch limit"
}

// Truncated marks the error as a size cut rather than a handler failure.
func (errReadOnlyTruncated) Truncated() bool { return true }

// readOnlyRecorder captures a handler's answer in memory, up to limit.
type readOnlyRecorder struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	limit     int
	truncated bool
}

func (r *readOnlyRecorder) Header() http.Header { return r.header }

func (r *readOnlyRecorder) WriteHeader(status int) { r.status = status }

func (r *readOnlyRecorder) Write(p []byte) (int, error) {
	room := r.limit - r.body.Len()
	if room <= 0 {
		r.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		r.body.Write(p[:room])
		r.truncated = true
		return len(p), nil
	}
	return r.body.Write(p)
}

// Flush satisfies handlers that stream; the recorder is already in memory.
func (r *readOnlyRecorder) Flush() {}
