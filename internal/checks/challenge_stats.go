package checks

import (
	"sync"
	"time"
)

// challengeRecentMax bounds the recent-routes ring buffer surfaced to the web
// UI. Small: the panel shows the latest handful, history holds the rest.
const challengeRecentMax = 20

// ChallengeRouteRecord is one IP routed to the challenge, for the web UI's
// recent-activity list.
type ChallengeRouteRecord struct {
	IP    string    `json:"ip"`
	Check string    `json:"check"`
	At    time.Time `json:"at"`
}

// ChallengeUIStatsSnapshot is the web-UI view of challenge routing: cumulative
// per-check counts since daemon start plus the most recent routes. It is a
// copy, safe for the caller to read without locking.
type ChallengeUIStatsSnapshot struct {
	RoutedByCheck map[string]int         `json:"routed_by_check"`
	Recent        []ChallengeRouteRecord `json:"recent"`
}

var (
	challengeStatsMu       sync.Mutex
	challengeRoutedByCheck = map[string]int{}
	challengeRecentRoutes  []ChallengeRouteRecord
)

// recordChallengeRouteStat records one route for the web-UI stats. Kept
// separate from the Prometheus counter (observeChallengeRouted) so the UI does
// not depend on scraping /metrics.
func recordChallengeRouteStat(ip, check string, at time.Time) {
	challengeStatsMu.Lock()
	defer challengeStatsMu.Unlock()
	challengeRoutedByCheck[check]++
	challengeRecentRoutes = append(challengeRecentRoutes, ChallengeRouteRecord{IP: ip, Check: check, At: at})
	if len(challengeRecentRoutes) > challengeRecentMax {
		challengeRecentRoutes = challengeRecentRoutes[len(challengeRecentRoutes)-challengeRecentMax:]
	}
}

// ChallengeUIStats returns a copy of the current challenge routing stats for
// the web UI. Most recent route is last in Recent.
func ChallengeUIStats() ChallengeUIStatsSnapshot {
	challengeStatsMu.Lock()
	defer challengeStatsMu.Unlock()
	byCheck := make(map[string]int, len(challengeRoutedByCheck))
	for k, v := range challengeRoutedByCheck {
		byCheck[k] = v
	}
	recent := make([]ChallengeRouteRecord, len(challengeRecentRoutes))
	copy(recent, challengeRecentRoutes)
	return ChallengeUIStatsSnapshot{RoutedByCheck: byCheck, Recent: recent}
}
