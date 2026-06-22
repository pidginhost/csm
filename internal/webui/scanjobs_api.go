package webui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

// ScanJobController is the subset of the daemon's ScanJobManager the WebUI
// needs to enqueue and cancel full-scan jobs. The daemon injects a concrete
// *ScanJobManager via SetScanJobs; nil until wired (POST endpoints → 503).
type ScanJobController interface {
	Enqueue(scope, target string, opts checks.AccountScanOptions, quarantine bool) (string, error)
	Cancel(id string) error
}

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

// scanJobEnqueueBody is the JSON request body for POST /api/v1/scan-jobs.
type scanJobEnqueueBody struct {
	Scope          string `json:"scope"`
	Target         string `json:"target"`
	RespectIgnores bool   `json:"respect_ignores"`
	Quarantine     bool   `json:"quarantine"`
}

// apiScanJobsEnqueue handles POST /api/v1/scan-jobs.
// Requires admin auth + CSRF (enforced by the mux registration).
func (s *Server) apiScanJobsEnqueue(w http.ResponseWriter, r *http.Request) {
	if s.scanJobs == nil {
		writeJSONError(w, "scan job manager not available", http.StatusServiceUnavailable)
		return
	}

	var body scanJobEnqueueBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	opts := checks.AccountScanOptions{
		MaxFiles:       0,
		ForceContent:   true,
		ForceFileIndex: true,
		RespectIgnores: body.RespectIgnores,
		MaxFileBytes:   checks.FullScanMaxFileBytes(s.cfg),
	}

	switch body.Scope {
	case "account":
		if body.Target == "" || !control.ValidScanAccountTarget(body.Target) {
			writeJSONError(w, "invalid or missing account target", http.StatusBadRequest)
			return
		}
		id, err := s.scanJobs.Enqueue("account", body.Target, opts, body.Quarantine)
		if err != nil {
			msg := "enqueue failed: " + err.Error()
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "queue is full") {
				status = http.StatusConflict
			}
			writeJSONError(w, msg, status)
			return
		}
		writeJSON(w, map[string]any{"job_id": id, "state": "queued"})

	case "all":
		if body.Quarantine {
			writeJSONError(w, "quarantine is not supported with scope \"all\"", http.StatusBadRequest)
			return
		}
		id, err := s.scanJobs.Enqueue("all", "all", opts, false)
		if err != nil {
			msg := "enqueue failed: " + err.Error()
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "queue is full") {
				status = http.StatusConflict
			}
			writeJSONError(w, msg, status)
			return
		}
		writeJSON(w, map[string]any{"job_id": id, "state": "queued"})

	default:
		writeJSONError(w, "unsupported scope: must be \"account\" or \"all\"", http.StatusBadRequest)
	}
}

// apiScanJobsCancel handles POST /api/v1/scan-jobs/{id}/cancel.
// The path arriving here is everything after /api/v1/scan-jobs/, e.g.
// "sj-abc123/cancel". The tail must end exactly in "/<id>/cancel".
// Requires admin auth + CSRF (enforced by the mux registration).
func (s *Server) apiScanJobsCancel(w http.ResponseWriter, r *http.Request) {
	if s.scanJobs == nil {
		writeJSONError(w, "scan job manager not available", http.StatusServiceUnavailable)
		return
	}

	// Path: /api/v1/scan-jobs/{id}/cancel
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/scan-jobs/")
	if !strings.HasSuffix(tail, "/cancel") {
		writeJSONError(w, "not found", http.StatusNotFound)
		return
	}
	id := strings.TrimSuffix(tail, "/cancel")
	if id == "" {
		writeJSONError(w, "scan job id required", http.StatusNotFound)
		return
	}

	if err := s.scanJobs.Cancel(id); err != nil {
		msg := err.Error()
		status := http.StatusConflict
		if strings.Contains(msg, "not found") {
			status = http.StatusNotFound
		}
		writeJSONError(w, "cancel failed: "+msg, status)
		return
	}
	writeJSON(w, map[string]any{"job_id": id, "state": "canceling"})
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
