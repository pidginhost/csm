package webui

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

func (s *Server) apiSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.store.LoadSuppressions()
		if rules == nil {
			rules = []state.SuppressionRule{}
		}
		writeJSON(w, rules)

	case http.MethodPost:
		var req struct {
			Check       string `json:"check"`
			PathPattern string `json:"path_pattern"`
			// AllPaths is the explicit opt-in for a rule without a path
			// pattern, which hides every finding of the check and stops its
			// remediation.
			AllPaths bool   `json:"all_paths"`
			Reason   string `json:"reason"`
		}
		if err := decodeJSONBodyLimited(w, r, 32*1024, &req); err != nil || req.Check == "" {
			writeJSONError(w, "check field is required", http.StatusBadRequest)
			return
		}
		req.PathPattern = strings.TrimSpace(req.PathPattern)
		switch {
		case req.PathPattern == "" && !req.AllPaths:
			writeJSONError(w, "path_pattern is required; set all_paths to suppress every finding of this check", http.StatusBadRequest)
			return
		case req.PathPattern != "" && req.AllPaths:
			writeJSONError(w, "path_pattern and all_paths are mutually exclusive", http.StatusBadRequest)
			return
		case req.PathPattern != "":
			if _, err := filepath.Match(req.PathPattern, ""); err != nil {
				writeJSONError(w, "path_pattern is not a valid glob: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		id := newSuppressionID()

		err := s.store.UpdateSuppressions(func(rules []state.SuppressionRule) ([]state.SuppressionRule, error) {
			return append(rules, state.SuppressionRule{
				ID:          id,
				Check:       req.Check,
				PathPattern: req.PathPattern,
				Reason:      req.Reason,
				CreatedAt:   time.Now(),
			}), nil
		})
		if err != nil {
			writeJSONError(w, "failed to save suppression: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scope := "pattern: " + req.PathPattern
		if req.AllPaths {
			scope = "all paths"
		}
		s.auditLog(r, "suppress", req.Check, scope)
		writeJSON(w, map[string]string{"status": "created", "id": id})

	case http.MethodDelete:
		var req struct {
			ID string `json:"id"`
		}
		if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.ID == "" {
			writeJSONError(w, "id is required", http.StatusBadRequest)
			return
		}

		err := s.store.UpdateSuppressions(func(rules []state.SuppressionRule) ([]state.SuppressionRule, error) {
			var filtered []state.SuppressionRule
			for _, rule := range rules {
				if rule.ID != req.ID {
					filtered = append(filtered, rule)
				}
			}
			return filtered, nil
		})
		if err != nil {
			writeJSONError(w, "failed to save suppressions: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "unsuppress", req.ID, "removed suppression rule")
		writeJSON(w, map[string]string{"status": "deleted"})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
