package webui

import (
	"net/http"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/health"
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
		snap := health.Build(s.provider, s.version, health.Capabilities())
		resp["pending"] = snap.Automation.ChallengePending
		resp["escalated"] = snap.Automation.ChallengeEscalated
	}
	writeJSON(w, resp)
}
