package webui

import (
	"net/http"
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

	// Extend write deadline for this long-running request
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(3 * time.Minute))

	report := checks.RunHardeningAudit(s.cfg)

	if db := store.Global(); db != nil {
		if err := db.SaveHardeningReport(report); err != nil {
			writeJSONError(w, "audit completed but failed to save report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, report)
}

// handleHardening renders the hardening audit page.
func (s *Server) handleHardening(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "hardening.html", nil)
}
