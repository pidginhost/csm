package daemon

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A request a trusted proxy forwarded carries the proxy's address in the
// first field. Counting it would aim a brute-force finding, and its block,
// at the proxy that serves every visitor behind it.
func TestAccessLogBruteForceSkipsTrustedProxyPeer(t *testing.T) {
	paths := []struct {
		path  string
		check string
	}{
		{"/wp-login.php", "wp_login_bruteforce"},
		{"/xmlrpc.php", "xmlrpc_abuse"},
		{"/phpmyadmin/index.php", "admin_panel_bruteforce"},
	}
	cases := []struct {
		name    string
		peer    string
		proxy   string
		xff     string
		wantIP  string
		trusted bool
	}{
		{"IPv4 CIDR", "203.0.113.5", "203.0.113.0/28", "", "203.0.113.5", true},
		{"IPv4 exact", "203.0.113.5", "203.0.113.5", "", "203.0.113.5", true},
		{"IPv6 exact", "2001:db8::10", "2001:db8::10", "", "2001:db8::10", true},
		{"IPv6 CIDR", "2001:db8::10", "2001:db8::/64", "", "2001:db8::10", true},
		{"mapped peer", "::ffff:203.0.113.5", "203.0.113.0/28", "", "::ffff:203.0.113.5", true},
		{"mapped proxy", "203.0.113.5", "::ffff:203.0.113.5", "", "203.0.113.5", true},
		{"mapped CIDR", "203.0.113.5", "::ffff:203.0.113.0/124", "", "203.0.113.5", true},
		{"whitespace", " \t203.0.113.5\t", " \t203.0.113.0/28\n", "", "203.0.113.5", true},
		{"forwarded client", "203.0.113.5", "203.0.113.0/28", ` "198.51.100.7"`, "203.0.113.5", true},
		{"forwarded chain", "203.0.113.5", "203.0.113.0/28", ` "192.0.2.8, 198.51.100.7"`, "203.0.113.5", true},
		{"malformed forwarded client", "203.0.113.5", "203.0.113.0/28", ` "not-an-address"`, "203.0.113.5", true},
		{"direct IPv4", "198.51.100.7", "203.0.113.0/28", "", "198.51.100.7", false},
		{"direct IPv6", "2001:db8:1::10", "2001:db8::/64", "", "2001:db8:1::10", false},
		{"direct mapped IPv4", "::ffff:198.51.100.7", "203.0.113.0/28", "", "::ffff:198.51.100.7", false},
		{"outside CIDR", "203.0.113.16", "203.0.113.0/28", "", "203.0.113.16", false},
		{"no proxy configured", "203.0.113.5", "", "", "203.0.113.5", false},
		{"invalid proxy configured", "203.0.113.5", "203.0.113.0/invalid", "", "203.0.113.5", false},
		{"spoofed forwarded proxy", "198.51.100.7", "203.0.113.0/28", ` "203.0.113.5"`, "198.51.100.7", false},
		{"direct whitespace", " \t198.51.100.7\t", "203.0.113.0/28", ` "203.0.113.5"`, "198.51.100.7", false},
	}
	for _, tc := range cases {
		for _, central := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/central=%v", tc.name, central), func(t *testing.T) {
				resetAccessLogTrackerState()
				t.Cleanup(resetAccessLogTrackerState)
				cfg := &config.Config{}
				if tc.proxy != "" {
					cfg.WebServer.TrustedProxies = []string{tc.proxy}
				}
				cfg.Thresholds.XMLRPCThreshold = config.DefaultXMLRPCThreshold

				for _, endpoint := range paths {
					count := accessLogWPLoginThreshold
					if endpoint.check == "xmlrpc_abuse" {
						count = cfg.Thresholds.XMLRPCThreshold
					}
					for i := 0; i <= count; i++ {
						line := fmt.Sprintf(`%s - - [09/Nov/2026:12:00:00 +0000] "POST %s HTTP/1.1" 200 123 "-" "Mozilla/5.0"%s`, tc.peer, endpoint.path, tc.xff)
						got := parseAccessLogBruteForceForLog(line, cfg, central)
						want := 0
						if !tc.trusted && i == count-1 {
							want = 1
						}
						if len(got) != want {
							t.Fatalf("%s request %d: got %d findings, want %d", endpoint.path, i+1, len(got), want)
						}
						if want == 1 && (got[0].Check != endpoint.check || got[0].SourceIP != tc.wantIP || got[0].Severity != alert.Critical || got[0].Attribution != admission.AttributionHTTPPeer) {
							t.Fatalf("unexpected direct-peer finding: %+v", got[0])
						}
					}
				}

				wantTrackers := int64(1)
				if tc.trusted {
					wantTrackers = 0
				}
				if got := accessLogTrackerCount.Load(); got != wantTrackers {
					t.Errorf("tracker count = %d, want %d", got, wantTrackers)
				}
				var trackers int64
				accessLogTrackers.Range(func(key, _ any) bool {
					trackers++
					if key != tc.wantIP {
						t.Errorf("tracker for %v, want only direct peer %s", key, tc.wantIP)
					}
					return true
				})
				if trackers != wantTrackers {
					t.Errorf("tracker entries = %d, want %d", trackers, wantTrackers)
				}
			})
		}
	}
}

// ModSecurity names the proxy as the client of every request it forwards.
// Its denies stay visible, but they must not escalate to a block of it.
func TestModSecEscalationSkipsTrustedProxyPeer(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28"}
	const format = `[Wed Apr 01 17:13:54.047783 2026] [error] [client %s] ModSecurity: Access denied with code 403, [Rule: 'REQUEST_URI' '/\.env'] [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/.env_sample"]`

	escalations := func(peer string) (n, events int) {
		for i := 0; i < 10; i++ {
			for _, f := range parseModSecLogLineDeduped(fmt.Sprintf(format, peer), cfg) {
				switch f.Check {
				case "modsec_block_escalation", "modsec_csm_block_escalation":
					n++
				case "modsec_block_realtime":
					events++
				}
			}
		}
		return n, events
	}
	if n, _ := escalations("198.51.100.61"); n == 0 {
		t.Fatal("untrusted peer did not escalate; the fixture no longer reaches the threshold")
	}
	n, events := escalations("203.0.113.5")
	if n != 0 {
		t.Fatalf("trusted proxy peer escalated %d times, want 0", n)
	}
	if events == 0 {
		t.Fatal("trusted proxy peer lost its per-request ModSecurity finding")
	}
}

// A cPanel API auth failure counts as brute force against its source and
// can block it. From a trusted proxy that source is every visitor behind it.
func TestCpanelAPIFailureSkipsTrustedProxyPeer(t *testing.T) {
	resetPurgeTrackerState()
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28"}
	const format = `%s - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/execute/Email/list_pops HTTP/1.1" 401 0 "-" "Mozilla/5.0" "example.com:2083"`

	if got := parseAccessLogLineEnhanced(fmt.Sprintf(format, "198.51.100.11"), cfg); len(got) != 1 || got[0].Check != "api_auth_failure_realtime" {
		t.Fatalf("untrusted peer: %+v, want one api_auth_failure_realtime", got)
	}
	if got := parseAccessLogLineEnhanced(fmt.Sprintf(format, "203.0.113.5"), cfg); len(got) != 0 {
		t.Fatalf("trusted proxy peer: %+v, want none", got)
	}
}
