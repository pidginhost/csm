package webui

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// apiHardening returns the last stored audit report (GET).
func (s *Server) apiHardening(w http.ResponseWriter, _ *http.Request) {
	report, err := savedHardeningReport()
	if err != nil {
		writeJSONError(w, "failed to load report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, report)
}

// savedHardeningReport is the last stored audit with the current cautions
// and undo records.
func savedHardeningReport() (*store.AuditReport, error) {
	db := store.Global()
	if db == nil {
		return &store.AuditReport{}, nil
	}
	report, err := db.LoadHardeningReport()
	if err != nil {
		return nil, err
	}
	checks.AnnotateHardeningCautions(report.Results)
	markHardeningUndo(report.Results)
	return report, nil
}

// hardeningUndoNames lists the fixes the root worker kept an undo record
// for. Tests replace it.
var hardeningUndoNames = checks.HardeningUndoNames

// markHardeningUndo flags the results whose fix has an undo record. The
// daemon only lists the root worker's directory. When that fails, the page
// offers no Undo and the reason goes to the log.
func markHardeningUndo(results []store.AuditResult) {
	names, err := hardeningUndoNames()
	if err != nil {
		log.Printf("webui: listing hardening undo records: %v", err)
	}
	for i := range results {
		results[i].UndoAvailable = slices.Contains(names, results[i].Name)
	}
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
	markHardeningUndo(report.Results)

	// The fresh report, with the action's ok flag next to its fields.
	writeJSON(w, struct {
		OK bool `json:"ok"`
		*store.AuditReport
	}{true, report})
}

// apiHardeningApply applies the automatic fixes for one section of the
// hardening report, then re-runs the audit so the page shows the result
// (POST only). Body: {"category": "ssh", "names": ["ssh_use_dns"]}; an
// empty names list applies only uncautioned fixes in the section. The fixes
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
	ctx, cancel := hardeningWorkerContext(w, r)
	defer cancel()
	fixes, err := apply(ctx, cfg, req)
	if errors.Is(err, systemdrun.ErrUnavailable) {
		s.auditLog(r, "hardening_apply", req.Category, "not started: "+err.Error())
		writeJSONError(w, "Applying fixes needs systemd-run, so nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.auditLog(r, "hardening_apply", req.Category, hardeningApplyDetails(fixes, err))

	// A failed worker may have changed some files, so it rechecks too.
	report, err := recheckHardening(cfg, err)
	if err != nil {
		writeHardeningRecheckError(w, "Hardening apply", err, report)
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

// apiHardeningUndo undoes the last apply of one fix (POST only). Body:
// {"name": "ssh_use_dns"}. The root worker puts back what it recorded when
// it applied the fix, and refuses when the setting changed since. The audit
// is re-run unless the undo was refused, which changes nothing.
func (s *Server) apiHardeningUndo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := checks.ReadHardeningUndoRequest(r.Body)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Apply and undo change the same files and records.
	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusConflict)
		return
	}
	defer s.releaseScan()

	cfg := s.liveCfg()
	undo := s.hardeningUndo
	if undo == nil {
		undo = checks.RunHardeningUndoWorker
	}
	ctx, cancel := hardeningWorkerContext(w, r)
	defer cancel()
	res, err := undo(ctx, cfg, req.Name)
	if errors.Is(err, systemdrun.ErrUnavailable) {
		s.auditLog(r, "hardening_undo", req.Name, "not started: "+err.Error())
		writeJSONError(w, "Undoing a fix needs systemd-run, so nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.recordHardeningUndo(r, req.Name, res, err)

	var report *store.AuditReport
	if err == nil && res.Status == "refused" {
		if report, err = savedHardeningReport(); err != nil {
			writeJSONError(w, "Undo refused: "+res.Message+" The saved report failed to load: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if report, err = recheckHardening(cfg, err); err != nil {
		writeHardeningRecheckError(w, "Hardening undo", err, report)
		return
	}
	writeJSON(w, struct {
		OK     bool                      `json:"ok"`
		Result checks.HardeningFixResult `json:"result"`
		*store.AuditReport
	}{true, res, report})
}

// recordHardeningUndo writes the action log record and the UI audit log
// entry for one undo. The worker runs outside the daemon and has no action
// log of its own.
func (s *Server) recordHardeningUndo(r *http.Request, name string, res checks.HardeningFixResult, err error) {
	actor, _ := s.requestActor(r)
	rec := actionlog.Record{Op: "operate.undo_hardening", Actor: actionlog.WebUI, ActorDetail: actor, Target: name}
	details := res.Status + ": " + res.Message
	switch {
	case err != nil:
		rec.Result, rec.Error = actionlog.Failed, err.Error()
		details = "error: " + err.Error()
	case res.Status == "undone":
		rec.Result = actionlog.Applied
	case res.Status == "refused":
		rec.Result, rec.Error = actionlog.Refused, res.Message
	default:
		rec.Result, rec.Error = actionlog.Failed, res.Message
	}
	actionlog.Write(rec)
	s.auditLog(r, "hardening_undo", name, details)
}

// hardeningWorkerContext lets a root worker run to the end when the browser
// goes away, and keeps the reply open for the worker and the audit after it.
func hardeningWorkerContext(w http.ResponseWriter, r *http.Request) (context.Context, context.CancelFunc) {
	// A closed browser tab must not stop a worker half-way through.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), checks.HardeningApplyWorkerTimeout+time.Minute)
	// The final audit can take the same time as a standalone audit.
	workerDeadline, _ := ctx.Deadline()
	_ = http.NewResponseController(w).SetWriteDeadline(workerDeadline.Add(longRequestTimeout))
	return ctx, cancel
}

// recheckHardening re-runs and saves the audit after a worker ran, so the
// page shows the state after the change, not before. A failed save is
// joined to err.
func recheckHardening(cfg *config.Config, err error) (*store.AuditReport, error) {
	report := checks.RunHardeningAudit(cfg)
	if db := store.Global(); db != nil {
		if saveErr := db.SaveHardeningReport(report); saveErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to save the recheck: %w", saveErr))
		}
	}
	markHardeningUndo(report.Results)
	return report, err
}

// writeHardeningRecheckError answers a worker or save failure with the
// rechecked report, which the page shows in place of the old one.
func writeHardeningRecheckError(w http.ResponseWriter, what string, err error, report *store.AuditReport) {
	writeJSONStatus(w, http.StatusInternalServerError, struct {
		Error  string             `json:"error"`
		Report *store.AuditReport `json:"report"`
	}{what + ": " + err.Error() + ". The audit was re-run.", report})
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
