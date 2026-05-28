package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall/rollback"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/obs"
)

// apiFirewallTentativeApply handles POST /api/v1/settings/firewall/tentative-apply.
// Body shape mirrors the regular settings POST plus an optional
// timeout_min field (1..30, default 5). The handler runs the same
// change validation as the normal save path, snapshots the previous
// csm.yaml bytes into bbolt, writes the new file, and triggers a
// daemon restart. The rollback manager arms an in-process timer; if
// the operator does not POST /confirm before the deadline the daemon
// restores the snapshot and restarts itself.
func (s *Server) apiFirewallTentativeApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mgr := rollback.Global()
	if mgr == nil {
		writeJSONError(w, "rollback manager not available", http.StatusServiceUnavailable)
		return
	}
	if mgr.Status().Pending {
		writeJSONError(w, "a firewall rollback is already pending; confirm or revert first", http.StatusConflict)
		return
	}

	section, ok := LookupSettingsSection("firewall")
	if !ok {
		writeJSONError(w, "firewall section not registered", http.StatusInternalServerError)
		return
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		writeJSONError(w, "If-Match header required", http.StatusBadRequest)
		return
	}

	var body struct {
		Changes    map[string]json.RawMessage `json:"changes"`
		TimeoutMin int                        `json:"timeout_min"`
	}
	if err := decodeJSONBodyLimited(w, r, 256*1024, &body); err != nil {
		writeJSONError(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}

	diskBytes, err := os.ReadFile(s.cfg.ConfigFile) // #nosec G304 -- operator-supplied config path
	if err != nil {
		writeJSONError(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, err := config.LoadBytes(diskBytes)
	if err != nil {
		writeJSONError(w, "parse config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk.ConfigFile = s.cfg.ConfigFile
	if disk.Integrity.ConfigHash != ifMatch {
		writeJSONError(w, "config changed on disk, reload", http.StatusPreconditionFailed)
		return
	}

	clone := *disk
	if disk.Firewall != nil {
		fw := *disk.Firewall
		clone.Firewall = &fw
	}

	yamlChanges, errs := buildChangeSet(section, &clone, body.Changes)
	if len(errs) > 0 {
		writeValidationErrors(w, errs)
		return
	}
	validationResults := append(config.Validate(&clone), config.ValidateDeepSection(&clone, section.ID)...)
	fieldErrors, warnings := splitValidationResults(validationResults)
	if len(fieldErrors) > 0 {
		writeValidationErrors(w, fieldErrors)
		return
	}
	warnings = append(warnings, firewallLockoutWarnings(&clone)...)

	edited, err := config.YAMLEdit(diskBytes, yamlChanges)
	if err != nil {
		writeJSONError(w, "yaml edit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Stage rollback BEFORE the on-disk write so a crash between the two
	// leaves the snapshot recoverable: if there is no new file on disk
	// yet, the snapshot is a no-op revert. The reverse order would let
	// the daemon come back to the new config with no rollback record and
	// no way to undo without operator intervention.
	timeout := time.Duration(body.TimeoutMin) * time.Minute
	st, err := mgr.Apply(diskBytes, edited, timeout, extractClientIP(r))
	if err != nil {
		writeJSONError(w, "stage rollback: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := integrity.SignAndSavePreserving(s.cfg.ConfigFile, edited, &clone, disk.Integrity.BinaryHash); err != nil {
		// Best-effort cleanup: the snapshot is now misleading because
		// the on-disk file never changed. Drop it so the operator does
		// not see a phantom pending rollback in the UI.
		_ = mgr.Confirm()
		writeJSONError(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditLog(r, "settings-tentative-apply", "firewall", auditDetailsFor(section, body.Changes))

	// Defer the restart so the response flushes first; otherwise the
	// client sees a connection reset and cannot read the rollback ETA
	// it needs to drive the countdown banner.
	s.scheduleDaemonRestart(250 * time.Millisecond)

	writeJSON(w, map[string]interface{}{
		"status":           "tentative-apply issued",
		"warnings":         warnings,
		"rollback":         st,
		"new_etag":         clone.Integrity.ConfigHash,
		"applied":          changedFieldList(body.Changes, section),
		"requires_restart": true,
	})
}

// changedFieldList returns the dotted YAML paths of the keys in changes
// scoped to the section. Used in the response so the UI knows which
// fields to highlight as pending.
func changedFieldList(changes map[string]json.RawMessage, section SettingsSection) []string {
	out := make([]string, 0, len(changes))
	for k := range changes {
		if k == "" {
			out = append(out, section.YAMLPath)
			continue
		}
		out = append(out, section.YAMLPath+"."+k)
	}
	return out
}

// apiFirewallRollbackStatus returns the pending rollback record, if any.
// Read endpoint, no CSRF; safe to poll for the countdown banner.
func (s *Server) apiFirewallRollbackStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := rollback.Global()
	if mgr == nil {
		writeJSON(w, rollback.Status{})
		return
	}
	writeJSON(w, mgr.Status())
}

// apiFirewallRollbackConfirm handles POST .../confirm. Drops the snapshot;
// the new config stays.
func (s *Server) apiFirewallRollbackConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := rollback.Global()
	if mgr == nil {
		writeJSONError(w, "rollback manager not available", http.StatusServiceUnavailable)
		return
	}
	if !mgr.Status().Pending {
		writeJSONError(w, "no pending rollback", http.StatusConflict)
		return
	}
	if err := mgr.Confirm(); err != nil {
		writeJSONError(w, "confirm: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "settings-rollback-confirm", "firewall", "")
	writeJSON(w, map[string]string{"status": "confirmed"})
}

// apiFirewallRollbackRevert handles POST .../revert. Restores the
// snapshot to disk and triggers a daemon restart. Returns 200 with the
// pre-revert status; the actual restart happens on a goroutine so the
// response can flush.
func (s *Server) apiFirewallRollbackRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := rollback.Global()
	if mgr == nil {
		writeJSONError(w, "rollback manager not available", http.StatusServiceUnavailable)
		return
	}
	if !mgr.Status().Pending {
		writeJSONError(w, "no pending rollback", http.StatusConflict)
		return
	}
	s.scheduleRollbackRevert(mgr, 30*time.Second)
	s.auditLog(r, "settings-rollback-revert", "firewall", "")
	writeJSON(w, map[string]string{"status": "revert issued"})
}

// scheduleDaemonRestart fires restartDaemon after delay in a supervised
// goroutine. The select on pruneDone lets the goroutine exit cleanly if
// the server begins shutdown during the pre-restart delay, so an
// operator-initiated stop is not chased by a phantom restart.
func (s *Server) scheduleDaemonRestart(delay time.Duration) {
	obs.SafeGo("webui-tentative-apply-restart", func() {
		select {
		case <-s.pruneDone:
			return
		case <-time.After(delay):
		}
		if _, err := s.restartDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "webui: tentative-apply restart failed: %v\n", err)
		}
	})
}

// scheduleRollbackRevert runs the revert in a supervised goroutine with
// a hard timeout. If shutdown already started before the worker runs, it
// does not begin a new revert; once started, the revert owns its restart
// context so the restart it triggers cannot cancel itself via Shutdown.
func (s *Server) scheduleRollbackRevert(mgr *rollback.Manager, timeout time.Duration) {
	obs.SafeGo("webui-rollback-revert", func() {
		select {
		case <-s.pruneDone:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := mgr.Revert(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "webui: rollback revert failed: %v\n", err)
		}
	})
}
