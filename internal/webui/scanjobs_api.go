package webui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// apiScanJobsList handles GET /api/v1/scan-jobs.
// Returns all scan-job records, newest-first.
func (s *Server) apiScanJobsList(w http.ResponseWriter, _ *http.Request) {
	db := store.Global()
	if db == nil {
		writeJSONError(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	jobs, err := db.ListScanJobs()
	if err != nil {
		writeJSONError(w, "failed to list scan jobs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if jobs == nil {
		jobs = []store.ScanJobRecord{}
	}
	writeJSON(w, map[string]any{"jobs": jobs})
}

// apiScanJobsRouter handles /api/v1/scan-jobs/{id} and
// /api/v1/scan-jobs/{id}/findings.
//
//   - GET /api/v1/scan-jobs/{id}          → job detail
//   - GET /api/v1/scan-jobs/{id}/findings → paginated findings
//
// Only GET is accepted; other methods return 405.
func (s *Server) apiScanJobsRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	db := store.Global()
	if db == nil {
		writeJSONError(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}

	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/scan-jobs/")
	if tail == "" {
		writeJSONError(w, "scan job id required", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(tail, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	switch sub {
	case "":
		s.apiScanJobDetail(w, r, db, id)
	case "findings":
		s.apiScanJobFindings(w, r, db, id)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// apiScanJobDetail handles GET /api/v1/scan-jobs/{id}.
func (s *Server) apiScanJobDetail(w http.ResponseWriter, _ *http.Request, db *store.DB, id string) {
	rec, ok, err := db.GetScanJob(id)
	if err != nil {
		writeJSONError(w, "failed to get scan job: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSONError(w, "scan job not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"job": rec})
}

// apiScanJobFindings handles GET /api/v1/scan-jobs/{id}/findings.
// Query params: offset (default 0), limit (default 0 = all).
func (s *Server) apiScanJobFindings(w http.ResponseWriter, r *http.Request, db *store.DB, id string) {
	offset := parseQueryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	limit := parseQueryInt(r, "limit", 0)
	if limit < 0 {
		limit = 0
	}

	findings, total, err := db.ListScanJobFindings(id, offset, limit)
	if err != nil {
		writeJSONError(w, "failed to list findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if findings == nil {
		findings = []alert.Finding{}
	}
	writeJSON(w, map[string]any{
		"job_id":   id,
		"findings": findings,
		"total":    total,
		"offset":   offset,
		"limit":    limit,
	})
}

// parseQueryInt parses a query parameter as int. Returns def on missing or
// non-numeric values.
func parseQueryInt(r *http.Request, key string, def int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}
