package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
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
		{"mapped peer", "::ffff:203.0.113.5", "203.0.113.0/28", "", "203.0.113.5", true},
		{"mapped proxy", "203.0.113.5", "::ffff:203.0.113.5", "", "203.0.113.5", true},
		{"mapped CIDR", "203.0.113.5", "::ffff:203.0.113.0/124", "", "203.0.113.5", true},
		{"whitespace", " \t203.0.113.5\t", " \t203.0.113.0/28\n", "", "203.0.113.5", true},
		{"forwarded client", "203.0.113.5", "203.0.113.0/28", ` "198.51.100.7"`, "203.0.113.5", true},
		{"forwarded chain", "203.0.113.5", "203.0.113.0/28", ` "192.0.2.8, 198.51.100.7"`, "203.0.113.5", true},
		{"malformed forwarded client", "203.0.113.5", "203.0.113.0/28", ` "not-an-address"`, "203.0.113.5", true},
		{"direct IPv4", "198.51.100.7", "203.0.113.0/28", "", "198.51.100.7", false},
		{"direct IPv6", "2001:db8:1::10", "2001:db8::/64", "", "2001:db8:1::10", false},
		{"direct mapped IPv4", "::ffff:198.51.100.7", "203.0.113.0/28", "", "198.51.100.7", false},
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
	if n, events := escalations("198.51.100.61"); n != 1 || events != 1 {
		t.Fatalf("untrusted peer: %d escalations, %d events, want one each", n, events)
	}
	n, events := escalations("203.0.113.5")
	if n != 0 {
		t.Fatalf("trusted proxy peer escalated %d times, want 0", n)
	}
	if events != 1 {
		t.Fatalf("trusted proxy peer: %d events, want one deduplicated event", events)
	}
}

// A cPanel API auth failure counts as brute force against its source and
// can block it. From a trusted proxy that source is every visitor behind it.
func TestCpanelAPIFailureSkipsTrustedProxyPeer(t *testing.T) {
	resetPurgeTrackerState()
	t.Cleanup(resetPurgeTrackerState)
	for _, tc := range []struct {
		name    string
		peer    string
		proxy   string
		trusted bool
	}{
		{"IPv4", "203.0.113.5", "203.0.113.0/28", true},
		{"IPv6", "2001:db8::5", "2001:db8::/64", true},
		{"mapped IPv4", "::ffff:203.0.113.5", "203.0.113.0/28", true},
		{"outside CIDR", "203.0.113.16", "203.0.113.0/28", false},
		{"unconfigured", "203.0.113.5", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{tc.proxy}
			for _, path := range []string{"/cpsess1234567/execute/Email/list_pops", "/json-api/listaccts"} {
				for _, status := range []int{401, 403} {
					line := fmt.Sprintf(`%s - - [11/Apr/2026:12:00:00 +0000] "GET %s HTTP/1.1" %d 0 "-" "Mozilla/5.0" "203.0.113.80:2083"`, tc.peer, path, status)
					got := parseAccessLogLineEnhanced(line, cfg)
					if tc.trusted {
						if len(got) != 0 {
							t.Fatalf("%s %d: trusted proxy produced %+v", path, status, got)
						}
					} else if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" || got[0].SourceIP != tc.peer || got[0].Attribution != admission.AttributionPeer {
						t.Fatalf("%s %d: got %+v, want one API auth failure from %s", path, status, got, tc.peer)
					}
				}
			}
		})
	}
}

// Every retained observation must stay visible without authorizing an IP
// response or increasing the proxy's attack score.
func assertTrustedProxyObservation(t *testing.T, got []alert.Finding, check, peer string, severity alert.Severity) {
	t.Helper()
	if len(got) != 1 || got[0].Check != check || got[0].SourceIP != peer || got[0].Severity != severity {
		t.Fatalf("got %+v, want one %s observation from %s at %v", got, check, peer, severity)
	}
	f := got[0]
	policy := checks.ResponsePolicyFor(f.Check)
	if policy.Block != checks.BlockNever || policy.ChallengeFirst || checks.AddressEvidence(f.Check, f.Severity) {
		t.Fatalf("trusted proxy observation authorizes an IP response: %+v", policy)
	}
	db := attackdb.NewForTest(nil)
	for i := 0; i < 100; i++ {
		db.RecordFinding(f)
	}
	if rec := db.LookupIP(peer); rec != nil && rec.ThreatScore != 0 {
		t.Fatalf("trusted proxy observation raised attack score to %d", rec.ThreatScore)
	}
}

func TestCpanelTrustedProxyPreservesObservations(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28"}
	const peer = "203.0.113.5"
	for _, tc := range []struct {
		name     string
		request  string
		port     int
		check    string
		severity alert.Severity
	}{
		{"file manager", "POST /execute/Fileman/upload_files", 2083, "cpanel_file_upload_realtime", alert.Warning},
		{"webmail", "POST /login/", 2096, "webmail_login_realtime", alert.Warning},
		{"WHM login", "POST /login/?login_only=1", 2087, "whm_login_realtime", alert.Warning},
		{"WHM tokenless request", "GET /scripts2/listaccts", 2087, "whm_unauth_scripts_realtime", alert.Critical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := fmt.Sprintf(`%s - - [11/Apr/2026:12:00:00 +0000] "%s HTTP/1.1" 200 0 "-" "Mozilla/5.0" "203.0.113.80:%d"`, peer, tc.request, tc.port)
			assertTrustedProxyObservation(t, parseAccessLogLineEnhanced(line, cfg), tc.check, peer, tc.severity)
		})
	}
}

func TestModSecTrustedProxyStateAndObservations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rule       int
		action     string
		check      string
		severity   alert.Severity
		escalation string
	}{
		{"CSM deny", 900115, "Access denied", "modsec_block_realtime", alert.High, "modsec_csm_block_escalation"},
		{"single-hit deny", 900122, "Access denied", "modsec_block_realtime", alert.High, "modsec_csm_block_escalation"},
		{"unknown deny", 123456, "Access denied", "modsec_block_realtime", alert.Warning, "modsec_block_escalation"},
		{"policy deny", 920420, "Access denied", "modsec_block_realtime", alert.Warning, "modsec_block_escalation"},
		{"high-confidence warning", 900115, "Warning", "modsec_warning_realtime", alert.High, ""},
		{"unknown warning", 123456, "Warning", "modsec_warning_realtime", alert.Warning, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			cfg := &config.Config{}
			cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28"}
			const peer = "203.0.113.5"
			line := func(ip string) string {
				return fmt.Sprintf(`[Wed Apr 01 17:13:54.047783 2026] [error] [client %s] ModSecurity: %s [id "%d"] [uri "/"]`, ip, tc.action, tc.rule)
			}
			count := modsecLowConfEscalationHits(cfg) + 1
			for i := 0; i < count; i++ {
				got := parseModSecLogLineDeduped(line(peer), cfg)
				if i == 0 {
					assertTrustedProxyObservation(t, got, tc.check, peer, tc.severity)
				} else if len(got) != 0 {
					t.Fatalf("duplicate %d: got %+v, want no findings", i, got)
				}
			}
			modsecBlockCount.Range(func(key, _ any) bool {
				t.Errorf("trusted proxy allocated escalation state for %v", key)
				return true
			})
			modsecGapMu.Lock()
			gaps := len(modsecGapReported)
			modsecGapMu.Unlock()
			if gaps != 0 {
				t.Fatal("trusted proxy consumed classifier-gap reporting state")
			}
			key := fmt.Sprintf("%s:%d", peer, tc.rule)
			dedupEntries := 0
			modsecDedup.Range(func(k, _ any) bool {
				dedupEntries++
				if k != key {
					t.Errorf("unexpected dedup key %v, want %s", k, key)
				}
				return true
			})
			if dedupEntries != 1 {
				t.Fatalf("dedup entries = %d, want 1", dedupEntries)
			}
			hits, window := modsecEscalationParams(cfg)
			evictModSecState(time.Now().Add(modsecDedupTTL), hits, window)
			if _, ok := modsecDedup.Load(key); ok {
				t.Fatal("trusted proxy dedup entry survived expiry without an escalation counter")
			}
			assertTrustedProxyObservation(t, parseModSecLogLineDeduped(line(peer), cfg), tc.check, peer, tc.severity)

			// Proxy observations must not consume the direct peer's dedup or
			// classifier-gap state, or disable its normal escalation policy.
			const directPeer = "198.51.100.61"
			counts := make(map[string]int)
			for i := 0; i < count; i++ {
				for _, f := range parseModSecLogLineDeduped(line(directPeer), cfg) {
					if f.SourceIP != directPeer {
						t.Fatalf("direct finding attributed to %s", f.SourceIP)
					}
					counts[f.Check]++
				}
			}
			if counts[tc.check] != 1 {
				t.Errorf("direct observations = %d, want 1", counts[tc.check])
			}
			if tc.escalation != "" && counts[tc.escalation] != 1 {
				t.Errorf("direct escalations = %d, want 1", counts[tc.escalation])
			}
			if tc.escalation == "" && (counts["modsec_block_escalation"] != 0 || counts["modsec_csm_block_escalation"] != 0) {
				t.Errorf("direct warnings escalated: %v", counts)
			}
			if tc.rule == 123456 && counts["modsec_classifier_gap"] != 1 {
				t.Errorf("direct classifier gaps = %d, want 1", counts["modsec_classifier_gap"])
			}
		})
	}
}
