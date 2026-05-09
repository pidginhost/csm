package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

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

	// Search finding history
	allHistory, _ := s.store.ReadHistory(3000, 0)
	for _, f := range allHistory {
		if f.Timestamp.Before(cutoff) {
			continue
		}
		matched := false
		for _, term := range searchTerms {
			if strings.Contains(f.Message, term) || strings.Contains(f.Details, term) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		events = append(events, timelineEvent{
			Timestamp: f.Timestamp.Format(time.RFC3339),
			Type:      "finding",
			Severity:  int(f.Severity),
			Summary:   f.Check + ": " + f.Message,
			Details:   f.Details,
			Source:    "history",
		})
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

	// Limit to 200 events
	if len(events) > 200 {
		events = events[:200]
	}

	writeJSON(w, map[string]interface{}{
		"events":        events,
		"total":         len(events),
		"query_ip":      ip,
		"query_account": account,
		"hours":         hours,
	})
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

// incidentPage executes one or more SnapshotPage calls (one per status
// in the filter) and stitches them into a single page. The "active"
// filter expands to two statuses; the daemon-side primitive only
// accepts one at a time, so the handler folds them. Items are
// re-sorted by UpdatedAt descending across the union and the page
// bounds are applied last so offset/limit semantics match the
// single-status case.
func (s *Server) incidentPage(statuses []incident.Status, offset, limit int) ([]incident.Incident, int) {
	if len(statuses) == 0 {
		return s.incidentCorrelator.SnapshotPage("", offset, limit)
	}
	if len(statuses) == 1 {
		return s.incidentCorrelator.SnapshotPage(statuses[0], offset, limit)
	}
	var merged []incident.Incident
	total := 0
	for _, st := range statuses {
		// Pull every record for this status; the union is small enough
		// that paging per-status before merging would discard records
		// the caller's offset still wants.
		page, n := s.incidentCorrelator.SnapshotPage(st, 0, 0)
		merged = append(merged, page...)
		total += n
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].UpdatedAt.After(merged[j].UpdatedAt)
	})
	if offset >= len(merged) {
		return []incident.Incident{}, total
	}
	end := len(merged)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return merged[offset:end], total
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
