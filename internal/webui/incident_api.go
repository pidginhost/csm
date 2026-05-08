package webui

import (
	"encoding/json"
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

// apiIncidentList serves GET /api/v1/incidents. Returns an array of
// incidents (open, contained, resolved, dismissed) newest first.
func (s *Server) apiIncidentList(w http.ResponseWriter, _ *http.Request) {
	if s.incidentCorrelator == nil {
		writeJSON(w, []incident.Incident{})
		return
	}
	writeJSON(w, s.incidentCorrelator.Snapshot())
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
