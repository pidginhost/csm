package checks

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Trust follows the address used by the finding, including accepted log
// spellings with brackets or ports: a trusted proxy's requests without a
// usable header are never counted against it. Client-controlled headers on
// unrelated peers must neither name the proxy nor take attribution from the
// peer.
func TestDomlogProxyTrustFollowsNormalizedAddress(t *testing.T) {
	for name, tc := range map[string]struct {
		logged, address, trusted string
	}{
		"ipv4":         {"192.0.2.10", "192.0.2.10", "192.0.2.10"},
		"ipv4 port":    {"192.0.2.10:443", "192.0.2.10", "192.0.2.10"},
		"ipv4 range":   {"192.0.2.10:443", "192.0.2.10", "192.0.2.0/24"},
		"mapped ipv4":  {"[::ffff:192.0.2.10]:443", "192.0.2.10", "192.0.2.0/24"},
		"ipv6":         {"2001:0db8:0:0:0:0:0:10", "2001:db8::10", "2001:db8::10"},
		"ipv6 bracket": {"[2001:db8::10]", "2001:db8::10", "2001:db8::10"},
		"ipv6 port":    {"[2001:db8::10]:443", "2001:db8::10", "2001:db8::10"},
		"ipv6 range":   {"[2001:db8::10]:443", "2001:db8::10", "2001:db8::/64"},
	} {
		t.Run(name, func(t *testing.T) {
			for route, profile := range map[string]struct {
				ua, method string
				checks     []string
				bot        botClassifier
			}{
				"login":   {"Mozilla/5.0", "POST", []string{"wp_login_bruteforce"}, nopBotClassifier{}},
				"scanner": {"sqlmap/1.7", "GET", []string{"http_request_flood", "http_scanner_profile", "http_ua_spoof"}, nopBotClassifier{}},
				"pending": {"Googlebot/2.1 fake", "GET", []string{"http_claimed_bot_unverified"}, pendingVerifyClassifier{}},
			} {
				t.Run(route, func(t *testing.T) {
					cfg := &config.Config{}
					cfg.WebServer.TrustedProxies = []string{tc.trusted}
					if route != "login" {
						cfg.Thresholds.HTTPFloodThreshold = 20
						cfg.Thresholds.HTTPScannerMinRequests = 10
						cfg.Thresholds.HTTPScannerErrorPct = 80
						cfg.Thresholds.HTTPScannerMinDistinctPaths = 5
					}
					const peer = "203.0.113.80"
					var lines []string
					for i := 0; i < 20; i++ {
						uri := "/wp-login.php"
						if route != "login" {
							uri = fmt.Sprintf("/probe-%d", i)
						}
						lines = append(lines,
							domlogTestLine(tc.logged, i, profile.method, uri, 404, profile.ua)+` "not-an-address"`,
							domlogTestLine(peer, i, profile.method, uri, 404, profile.ua)+` "`+tc.address+`"`)
					}
					path, findings := scanDomlogFile(t, cfg, profile.bot, lines)
					if len(findings) != len(profile.checks) {
						t.Fatalf("findings %+v, want one per check for the direct peer", findings)
					}
					for _, check := range profile.checks {
						seen := map[string]bool{}
						for _, f := range findings {
							if f.Check != check {
								continue
							}
							if seen[f.SourceIP] {
								t.Fatalf("duplicate %s finding for %s", check, f.SourceIP)
							}
							seen[f.SourceIP] = true
							switch f.SourceIP {
							case peer:
								wantScanObservation(t, f, ProducerDomlogScan, lineRef(t, path, lines, 39), domlogTestTime(19))
								wantPeerMints(t, f)
							default:
								t.Fatalf("unexpected source %s", f.SourceIP)
							}
						}
						if len(seen) != 1 {
							t.Fatalf("%s addresses %v, want the direct peer only", check, seen)
						}
					}
				})
			}
		})
	}
}
