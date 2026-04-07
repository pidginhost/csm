package webui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
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
			Reason      string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Check == "" {
			writeJSONError(w, "check field is required", http.StatusBadRequest)
			return
		}

		// Generate unique ID
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)

		rules := s.store.LoadSuppressions()
		rules = append(rules, state.SuppressionRule{
			ID:          id,
			Check:       req.Check,
			PathPattern: req.PathPattern,
			Reason:      req.Reason,
			CreatedAt:   time.Now(),
		})
		if err := s.store.SaveSuppressions(rules); err != nil {
			writeJSONError(w, "failed to save suppression: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "suppress", req.Check, "pattern: "+req.PathPattern)
		writeJSON(w, map[string]string{"status": "created", "id": id})

	case http.MethodDelete:
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			writeJSONError(w, "id is required", http.StatusBadRequest)
			return
		}

		rules := s.store.LoadSuppressions()
		var filtered []state.SuppressionRule
		for _, rule := range rules {
			if rule.ID != req.ID {
				filtered = append(filtered, rule)
			}
		}
		if err := s.store.SaveSuppressions(filtered); err != nil {
			writeJSONError(w, "failed to save suppressions: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "unsuppress", req.ID, "removed suppression rule")
		writeJSON(w, map[string]string{"status": "deleted"})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
