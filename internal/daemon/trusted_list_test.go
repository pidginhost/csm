package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A proxy named only in challenge.trusted_proxies stands for its visitors
// in the realtime access-log reader too: one list governs both.
func TestAccessLogBruteForceTrustsTheChallengeList(t *testing.T) {
	resetAccessLogTrackerState()
	t.Cleanup(resetAccessLogTrackerState)
	cfg := &config.Config{}
	cfg.Challenge.TrustedProxies = []string{"203.0.113.0/28"}
	line := `203.0.113.5 - - [09/Nov/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
	for i := 0; i <= accessLogWPLoginThreshold; i++ {
		if got := parseAccessLogBruteForceForLog(line, cfg, false); len(got) != 0 {
			t.Fatalf("request %d: %+v, want no finding against the proxy", i+1, got)
		}
	}
	if got := accessLogTrackerCount.Load(); got != 0 {
		t.Fatalf("tracker count = %d, want 0", got)
	}
}

// The realtime reader acts only on a peer it can read as an address, in its
// canonical form; anything else in the first field is not counted.
func TestAccessLogBruteForceIgnoresAnUnreadablePeer(t *testing.T) {
	for _, peer := range []string{"client.example", "203.0.113.5:443", "[2001:db8::5]", "2001:db8::1%eth0"} {
		resetAccessLogTrackerState()
		line := peer + ` - - [09/Nov/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
		for i := 0; i <= accessLogWPLoginThreshold; i++ {
			if got := parseAccessLogBruteForceForLog(line, &config.Config{}, false); len(got) != 0 {
				t.Fatalf("peer %q: %+v, want no finding", peer, got)
			}
		}
		if got := accessLogTrackerCount.Load(); got != 0 {
			t.Fatalf("peer %q: tracker count = %d, want 0", peer, got)
		}
	}
	resetAccessLogTrackerState()
}
