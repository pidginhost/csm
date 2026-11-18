package webui

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// apiHardening returns the last stored audit report (GET).
func (s *Server) apiHardening(w http.ResponseWriter, _ *http.Request) {
	db := store.Global()
	if db == nil {
		writeJSON(w, &store.AuditReport{})
		return
	}
	report, err := db.LoadHardeningReport()
	if err != nil {
		writeJSONError(w, "failed to load report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, report)
}

// apiHardeningRun runs the audit, stores the result, and returns it (POST only).
func (s *Server) apiHardeningRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusConflict)
		return
	}
	defer s.releaseScan()

	// The audit can outlast the server's WriteTimeout; extend, never shorten.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(longRequestTimeout))

	report := checks.RunHardeningAudit(s.liveCfg())
	s.auditLog(r, "hardening_run", "server", "hardening audit run")

	if db := store.Global(); db != nil {
		if err := db.SaveHardeningReport(report); err != nil {
			writeJSONError(w, "audit completed but failed to save report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// The fresh report, with the action's ok flag next to its fields.
	writeJSON(w, struct {
		OK bool `json:"ok"`
		*store.AuditReport
	}{true, report})
}

// apiHardeningApply applies the automatic fixes for one section of the
// hardening report, then re-runs the audit so the page shows the result
// (POST only). Body: {"category": "ssh", "names": ["ssh_use_dns"]}; an
// empty names list applies every fixable check in the section.
func (s *Server) apiHardeningApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Category string   `json:"category"`
		Names    []string `json:"names"`
	}
	if err := decodeJSONBodyLimited(w, r, 1<<14, &req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !slices.Contains(checks.HardeningCategories, req.Category) {
		writeJSONError(w, "unknown hardening category", http.StatusBadRequest)
		return
	}

	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusConflict)
		return
	}
	defer s.releaseScan()

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(longRequestTimeout))

	cfg := s.liveCfg()
	fixes, err := checks.ApplyHardening(cfg, req.Category, req.Names)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var appliedNames, failedNames []string
	for _, f := range fixes {
		switch f.Status {
		case "applied":
			appliedNames = append(appliedNames, f.Name)
		case "failed":
			failedNames = append(failedNames, f.Name)
		}
	}
	if len(appliedNames) > 0 || len(failedNames) > 0 {
		details := "applied: " + strings.Join(appliedNames, ", ")
		if len(failedNames) > 0 {
			details += "; failed: " + strings.Join(failedNames, ", ")
		}
		s.auditLog(r, "hardening_apply", req.Category, details)
	}

	// Recheck: the page shows the state after the change, not before.
	report := checks.RunHardeningAudit(cfg)
	if db := store.Global(); db != nil {
		if err := db.SaveHardeningReport(report); err != nil {
			writeJSONError(w, "fixes applied but failed to save the recheck: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if fixes == nil {
		fixes = []checks.HardeningFixResult{}
	}
	writeJSON(w, struct {
		OK      bool                        `json:"ok"`
		Applied []checks.HardeningFixResult `json:"applied"`
		*store.AuditReport
	}{true, fixes, report})
}

// handleHardening renders the hardening audit page.
func (s *Server) handleHardening(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "hardening.html", nil)
}
