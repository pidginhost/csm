package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Challenge routing must feed a UI-readable stats snapshot: per-check routed
// counts and a recent-routes buffer, so the web UI can show challenge activity
// without scraping Prometheus.
func TestChallengeUIStatsTracksRoutesByCheckAndRecent(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true

	oldList := GetChallengeIPList()
	SetChallengeIPList(&staticChallengeIPList{ips: make(map[string]bool)})
	t.Cleanup(func() { SetChallengeIPList(oldList) })

	before := ChallengeUIStats().RoutedByCheck["http_scanner_profile"]

	ChallengeRouteIPs(cfg, []alert.Finding{{
		Check:    "http_scanner_profile",
		Severity: alert.High,
		SourceIP: "203.0.113.70",
		Message:  "URL scanner profile from 203.0.113.70",
	}})

	got := ChallengeUIStats()
	if got.RoutedByCheck["http_scanner_profile"] != before+1 {
		t.Errorf("routed_by_check delta = %d, want 1", got.RoutedByCheck["http_scanner_profile"]-before)
	}
	if n := len(got.Recent); n == 0 || got.Recent[n-1].IP != "203.0.113.70" || got.Recent[n-1].Check != "http_scanner_profile" {
		t.Errorf("recent last entry = %+v, want IP 203.0.113.70 check http_scanner_profile", got.Recent)
	}
}
