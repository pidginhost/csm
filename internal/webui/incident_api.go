package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

type timelineEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`     // "finding", "action", "block"
	Severity  int    `json:"severity"` // 0=info, 1=high, 2=critical
	Summary   string `json:"summary"`
	Details   string `json:"details,omitempty"`
	Source    string `json:"source"` // "history", "audit", "firewall"
}

const incidentTimelineEventLimit = 200

func (s *Server) handleIncident(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "incident.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

func (s *Server) apiIncident(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	account := r.URL.Query().Get("account")
	if ip == "" && account == "" {
		writeJSONError(w, "ip or account parameter is required", http.StatusBadRequest)
		return
	}

	hours := queryInt(r, "hours", 72)
	if hours > 720 {
		hours = 720
	} // max 30 days
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	var events []timelineEvent

	// Build search terms
	var searchTerms []string
	if ip != "" {
		searchTerms = append(searchTerms, ip)
	}
	if account != "" {
		searchTerms = append(searchTerms, "/home/"+account+"/", account)
	}

	dedup := make(map[string]struct{})
	dedupKey := func(t time.Time, summary string) string {
		return t.UTC().Format(time.RFC3339Nano) + "|" + summary
	}
	matchesHistoryQuery := func(f alert.Finding) bool {
		matched := false
		for _, term := range searchTerms {
			if strings.Contains(f.Message, term) || strings.Contains(f.Details, term) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}

		summary := f.Check + ": " + f.Message
		key := dedupKey(f.Timestamp, summary)
		if _, seen := dedup[key]; seen {
			return false
		}
		dedup[key] = struct{}{}
		return true
	}

	// Search newest-first and stop once the timeline has enough matching
	// history rows. Busy hosts can retain large 30-day windows, so response
	// size alone is not a safe bound for the read path.
	allHistory := s.store.SearchHistorySince(cutoff, incidentTimelineEventLimit, matchesHistoryQuery)
	for _, f := range allHistory {
		summary := f.Check + ": " + f.Message
		events = append(events, timelineEvent{
			Timestamp: f.Timestamp.Format(time.RFC3339),
			Type:      "finding",
			Severity:  int(f.Severity),
			Summary:   summary,
			Details:   f.Details,
			Source:    "history",
		})
	}

	// Fold in events from the incident correlator. The finding history
	// bucket rotates aggressively on busy hosts so a Critical incident
	// from two days ago may have no surviving history row, but the
	// incident object still carries the full timeline. Walk every
	// incident, match by RemoteIP for IP queries or by Account / Mailbox /
	// Domain for account queries, and emit each matching timeline event.
	if s.incidentCorrelator != nil {
		for _, inc := range s.incidentCorrelator.Snapshot() {
			incMatches := incidentMatchesAccount(inc, account)
			for _, ev := range inc.Timeline {
				if ev.Time.Before(cutoff) {
					continue
				}
				match := false
				if ip != "" && ev.RemoteIP == ip {
					match = true
				}
				if !match && incMatches {
					match = true
				}
				if !match {
					continue
				}
				summary := ev.Check
				if ev.Message != "" {
					if summary != "" {
						summary += ": "
					}
					summary += ev.Message
				}
				key := dedupKey(ev.Time, summary)
				if _, seen := dedup[key]; seen {
					continue
				}
				dedup[key] = struct{}{}
				events = append(events, timelineEvent{
					Timestamp: ev.Time.Format(time.RFC3339),
					Type:      "finding",
					Severity:  int(inc.Severity),
					Summary:   summary,
					Details:   "From incident " + inc.ID + " (" + string(inc.Kind) + ", " + string(inc.Status) + ")",
					Source:    "incident:" + inc.ID,
				})
			}
		}
	}

	// Search UI audit log
	auditEntries := readUIAuditLog(s.cfg.StatePath, 500)
	for _, a := range auditEntries {
		if a.Timestamp.Before(cutoff) {
			continue
		}
		matched := false
		for _, term := range searchTerms {
			if strings.Contains(a.Target, term) || strings.Contains(a.Details, term) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		events = append(events, timelineEvent{
			Timestamp: a.Timestamp.Format(time.RFC3339),
			Type:      "action",
			Severity:  0,
			Summary:   a.Action + ": " + a.Target,
			Details:   a.Details,
			Source:    "audit",
		})
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp > events[j].Timestamp
	})

	if len(events) > incidentTimelineEventLimit {
		events = events[:incidentTimelineEventLimit]
	}

	writeJSON(w, map[string]interface{}{
		"events":        events,
		"total":         len(events),
		"query_ip":      ip,
		"query_account": account,
		"hours":         hours,
	})
}

// incidentMatchesAccount reports whether an incident's identity fields
// match the account search term. Empty account never matches so an
// IP-only query does not pull in unrelated incidents.
func incidentMatchesAccount(inc incident.Incident, account string) bool {
	if account == "" {
		return false
	}
	return inc.Account == account || inc.Mailbox == account || inc.Domain == account
}

// maxIncidentPageSize caps the page size a client may request so a
// misbehaving consumer cannot OOM the daemon by asking for the whole
// world in one round-trip. The web UI's default page size is well
// below this; the ceiling exists for defense in depth.
const maxIncidentPageSize = 500

// defaultIncidentPageSize is applied when the client requests a paged
// shape (any of limit/offset/status set) but does not pass an explicit
// limit. Tuned to fit comfortably on one screen.
const defaultIncidentPageSize = 50

// apiIncidentList serves GET /api/v1/incidents.
//
// Default (no query parameters): returns the full Snapshot as a bare
// JSON array, preserving the wire shape the existing API consumers
// (phpanel, SIEM tooling) decode against.
//
// When the client passes any of ?limit=, ?offset=, ?status=, the
// response switches to an envelope: {"items":[...], "total":N,
// "offset":N, "limit":N, "status":"..."}. Servers that pass the
// envelope must always include all five fields so the client can
// render an accurate page header without a second probe.
//
// status accepts the four spec values (open/contained/resolved/dismissed)
// plus the UI-only convenience "active" that means
// open+contained. An empty string means all statuses. Anything else is
// rejected with 400 Bad Request rather than silently widening to all,
// which would hide a typo like ?status=opn.
func (s *Server) apiIncidentList(w http.ResponseWriter, r *http.Request) {
	if s.incidentCorrelator == nil {
		writeJSON(w, []incident.Incident{})
		return
	}

	q := r.URL.Query()
	hasPagingParams := q.Has("limit") || q.Has("offset") || q.Has("status")

	if !hasPagingParams {
		writeJSON(w, s.incidentCorrelator.Snapshot())
		return
	}

	statusParam := q.Get("status")
	statuses, err := parseIncidentStatusFilter(statusParam)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	limit := queryInt(r, "limit", defaultIncidentPageSize)
	if limit <= 0 {
		limit = defaultIncidentPageSize
	}
	if limit > maxIncidentPageSize {
		limit = maxIncidentPageSize
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	items, total := s.incidentPage(statuses, offset, limit)
	writeJSON(w, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
		"status": statusParam,
	})
}

// parseIncidentStatusFilter validates the status query parameter and
// returns the set of statuses it expands to. Empty input means "all";
// "active" is the UI-only convenience for open+contained.
func parseIncidentStatusFilter(s string) ([]incident.Status, error) {
	switch s {
	case "":
		return nil, nil
	case "active":
		return []incident.Status{incident.StatusOpen, incident.StatusContained}, nil
	case string(incident.StatusOpen),
		string(incident.StatusContained),
		string(incident.StatusResolved),
		string(incident.StatusDismissed):
		return []incident.Status{incident.Status(s)}, nil
	}
	return nil, fmt.Errorf("invalid status %q", s)
}

// incidentPage returns a status-filtered page. The "active" filter
// expands to open+contained and is handled by the correlator in one
// sorted pass so pagination stays stable across statuses.
func (s *Server) incidentPage(statuses []incident.Status, offset, limit int) ([]incident.Incident, int) {
	return s.incidentCorrelator.SnapshotPageStatuses(statuses, offset, limit)
}

// apiIncidentShow serves GET /api/v1/incidents/<id>. 404 if not found.
func (s *Server) apiIncidentShow(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || s.incidentCorrelator == nil {
		http.NotFound(w, r)
		return
	}
	inc, ok := s.incidentCorrelator.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, inc)
}

// apiIncidentStatus serves POST /api/v1/incidents/<id>/status. Body
// {"status": "resolved", "details": "..."}.
func (s *Server) apiIncidentStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	id = strings.TrimSuffix(id, "/status")
	id = strings.Trim(id, "/")
	var body struct {
		Status  string `json:"status"`
		Details string `json:"details"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if s.incidentCorrelator == nil {
		http.Error(w, "incidents not enabled", http.StatusServiceUnavailable)
		return
	}
	if err := s.incidentCorrelator.SetStatus(id, incident.Status(body.Status), body.Details); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// apiIncidentRouter dispatches /api/v1/incidents/<id>[...] sub-paths.
// POST .../status -> apiIncidentStatus; GET .../<id> -> apiIncidentShow.
func (s *Server) apiIncidentRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/status") {
		s.apiIncidentStatus(w, r)
		return
	}
	s.apiIncidentShow(w, r)
}
