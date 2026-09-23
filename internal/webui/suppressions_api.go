package webui

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/state"
)

// suppressionCheckName matches the check names findings carry. A rule
// matches a finding's check exactly, so a glob or free text would be saved
// as a rule that matches nothing.
var suppressionCheckName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)

// knownCheck reports whether name is a registered check or the check of a
// current finding. Checks from other subsystems may be missing from the
// registry, so an unknown name is a warning, not an error.
func (s *Server) knownCheck(name string) bool {
	for _, known := range checks.AllCheckNames() {
		if known == name {
			return true
		}
	}
	for _, f := range s.store.LatestFindings() {
		if f.Check == name {
			return true
		}
	}
	return false
}

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
		if !suppressionCheckName.MatchString(req.Check) {
			writeJSONError(w, "check must be a check name such as webshell; patterns and spaces are not allowed", http.StatusBadRequest)
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
		resp := map[string]interface{}{"id": id}
		if !s.knownCheck(req.Check) {
			resp["warning"] = "No known check is named " + req.Check + "; the rule matches nothing until a finding with that check appears."
		}
		writeOK(w, resp)

	case http.MethodDelete:
		var req struct {
			ID string `json:"id"`
		}
		if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.ID == "" {
			writeJSONError(w, "id is required", http.StatusBadRequest)
			return
		}

		found := false
		err := s.store.UpdateSuppressions(func(rules []state.SuppressionRule) ([]state.SuppressionRule, error) {
			var filtered []state.SuppressionRule
			for _, rule := range rules {
				if rule.ID != req.ID {
					filtered = append(filtered, rule)
				} else {
					found = true
				}
			}
			return filtered, nil
		})
		if err != nil {
			writeJSONError(w, "failed to save suppressions: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			writeJSONError(w, "Suppression rule not found", http.StatusNotFound)
			return
		}
		s.auditLog(r, "unsuppress", req.ID, "removed suppression rule")
		writeOK(w, map[string]interface{}{"id": req.ID})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
