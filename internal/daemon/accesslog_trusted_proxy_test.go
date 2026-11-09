package daemon

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A request a trusted proxy forwarded carries the proxy's address in the
// first field. Counting it would aim a brute-force finding, and its block,
// at the proxy that serves every visitor behind it.
func TestAccessLogBruteForceSkipsTrustedProxyPeer(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28", "2001:db8::10"}
	cfg.Thresholds.XMLRPCThreshold = config.DefaultXMLRPCThreshold

	paths := []string{"/wp-login.php", "/xmlrpc.php", "/phpmyadmin/index.php"}
	count := accessLogWPLoginThreshold
	if cfg.Thresholds.XMLRPCThreshold > count {
		count = cfg.Thresholds.XMLRPCThreshold
	}
	send := func(peer string) int {
		resetAccessLogTrackerState()
		t.Cleanup(resetAccessLogTrackerState)
		n := 0
		for _, path := range paths {
			for i := 0; i < count; i++ {
				line := fmt.Sprintf(`%s - - [09/Nov/2026:12:00:00 +0000] "POST %s HTTP/1.1" 200 123 "-" "Mozilla/5.0"`, peer, path)
				n += len(parseAccessLogBruteForceForLog(line, cfg, false))
			}
		}
		return n
	}

	if got := send("198.51.100.7"); got != len(paths) {
		t.Fatalf("untrusted peer: %d findings, want %d", got, len(paths))
	}
	for _, peer := range []string{"203.0.113.5", "2001:db8::10"} {
		if got := send(peer); got != 0 {
			t.Fatalf("trusted proxy peer %s: %d findings, want 0", peer, got)
		}
	}
}
