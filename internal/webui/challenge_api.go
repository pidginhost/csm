package webui

import (
	"net/http"

	"github.com/pidginhost/csm/internal/checks"
)

// apiChallengeStats returns challenge-routing activity for the web UI: the live
// pending count, how many challenge timeouts escalated to a hard block, the
// cumulative routes per source check since daemon start, and the most recent
// routes. Read-only; safe for read-scope tokens.
func (s *Server) apiChallengeStats(w http.ResponseWriter, _ *http.Request) {
	stats := checks.ChallengeUIStats()
	resp := map[string]interface{}{
		"routed_by_check": stats.RoutedByCheck,
		"recent":          stats.Recent,
		"pending":         0,
		"escalated":       0,
	}
	if s.provider != nil {
		automation := s.provider.AutomationStatus()
		resp["pending"] = automation.ChallengePending
		resp["escalated"] = automation.ChallengeEscalated
	}
	writeJSON(w, resp)
}
