package webui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/systemdrun"
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
// empty names list applies every fixable check in the section. The fixes
// run in a root worker outside the daemon's sandbox, which leaves the files
// they change read-only.
func (s *Server) apiHardeningApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := checks.ReadHardeningApplyRequest(r.Body)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusConflict)
		return
	}
	defer s.releaseScan()

	cfg := s.liveCfg()
	apply := s.hardeningApply
	if apply == nil {
		apply = checks.RunHardeningApplyWorker
	}
	// A closed browser tab must not stop a worker half-way through.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), checks.HardeningApplyWorkerTimeout+time.Minute)
	defer cancel()
	// The final audit can take the same time as a standalone audit.
	workerDeadline, _ := ctx.Deadline()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(workerDeadline.Add(longRequestTimeout))
	fixes, err := apply(ctx, cfg, req)
	if errors.Is(err, systemdrun.ErrUnavailable) {
		s.auditLog(r, "hardening_apply", req.Category, "not started: "+err.Error())
		writeJSONError(w, "Applying fixes needs systemd-run, so nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.auditLog(r, "hardening_apply", req.Category, hardeningApplyDetails(fixes, err))

	// Recheck: the page shows the state after the change, not before. A
	// failed worker may have changed some files, so it rechecks too.
	report := checks.RunHardeningAudit(cfg)
	if db := store.Global(); db != nil {
		if saveErr := db.SaveHardeningReport(report); saveErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to save the recheck: %w", saveErr))
		}
	}
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, struct {
			Error  string             `json:"error"`
			Report *store.AuditReport `json:"report"`
		}{"Hardening apply: " + err.Error() + ". The audit was re-run.", report})
		return
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

// hardeningApplyDetails is the audit log line for one apply.
func hardeningApplyDetails(fixes []checks.HardeningFixResult, err error) string {
	var appliedNames, failedNames []string
	for _, f := range fixes {
		switch f.Status {
		case "applied":
			appliedNames = append(appliedNames, f.Name)
		case "failed":
			failedNames = append(failedNames, f.Name)
		}
	}
	details := "applied: " + strings.Join(appliedNames, ", ")
	if len(failedNames) > 0 {
		details += "; failed: " + strings.Join(failedNames, ", ")
	}
	if err != nil {
		details += "; error: " + err.Error()
	}
	return details
}

// handleHardening renders the hardening audit page.
func (s *Server) handleHardening(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "hardening.html", nil)
}
