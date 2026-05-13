package webui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/incident"
)

// incidentGroupsDefaultLimit / Max bound how many group rows the UI
// receives. A typical busy production host emits ~12 attacker-IP rows;
// the cap of 200 leaves headroom for the long tail without unbounded
// payload size.
const (
	incidentGroupsDefaultLimit = 50
	incidentGroupsMaxLimit     = 200
)

// apiIncidentGroups handles GET /api/v1/incidents/groups. Buckets the
// in-memory incident snapshot by (kind, source) and returns rolled-up
// group rows. Read-scope eligible; never mutates state.
func (s *Server) apiIncidentGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()

	limit := queryInt(r, "limit", incidentGroupsDefaultLimit)
	if limit <= 0 || limit > incidentGroupsMaxLimit {
		limit = incidentGroupsDefaultLimit
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	filter := incident.GroupFilter{
		Kind:      incident.Kind(strings.TrimSpace(q.Get("kind"))),
		Offset:    offset,
		MaxGroups: limit,
	}

	switch strings.ToLower(strings.TrimSpace(q.Get("status"))) {
	case "", "active":
		// Default surface: open + contained, the UI's primary tab.
		filter.StatusSet = []incident.Status{incident.StatusOpen, incident.StatusContained}
	case "all":
		// No status filter; the operator wants the full picture.
	case string(incident.StatusOpen),
		string(incident.StatusContained),
		string(incident.StatusResolved),
		string(incident.StatusDismissed):
		filter.StatusSet = []incident.Status{incident.Status(q.Get("status"))}
	default:
		writeJSONError(w, "unknown status: "+strconv.Quote(q.Get("status")), http.StatusBadRequest)
		return
	}

	if s.incidentCorrelator == nil {
		writeJSON(w, incident.GroupsResponse{Groups: []incident.Group{}})
		return
	}
	resp := incident.BuildGroups(s.incidentCorrelator.Snapshot(), filter)
	writeJSON(w, resp)
}
