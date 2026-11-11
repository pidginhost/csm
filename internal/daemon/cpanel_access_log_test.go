package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func TestCpanelProxyRecordsRetainAlertsWithoutPeerEvidence(t *testing.T) {
	for _, tc := range []struct {
		request, port, check string
	}{
		{"GET /scripts2/listaccts", "2087", "whm_unauth_scripts_realtime"},
		{"POST /login/?login_only=1", "2087", "whm_login_realtime"},
		{"POST /login/", "2096", "webmail_login_realtime"},
		{"GET /execute/Themes/list", "2083", "api_auth_failure_realtime"},
	} {
		t.Run(tc.check, func(t *testing.T) {
			line := `192.0.2.66 proxy - [11/09/2026:12:00:00 -0000] "` + tc.request + ` HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" ` + tc.port
			got := parseAccessLogLineEnhanced(line, &config.Config{})
			if len(got) != 1 || got[0].Check != tc.check || got[0].Attribution != admission.AttributionUnknown {
				t.Fatalf("proxy alert lost or attributed as peer: %+v", got)
			}
			if got[0].SourceIP != "" || strings.Contains(got[0].Message, "192.0.2.66") || !strings.Contains(got[0].Details, "192.0.2.66") {
				t.Fatalf("unverified address escaped the finding details: %+v", got[0])
			}
			db := attackdb.NewForTest(nil)
			db.RecordFinding(got[0])
			if rec := db.LookupIP("192.0.2.66"); rec != nil {
				t.Fatalf("proxy alert created an address history: %+v", rec)
			}
			f := got[0]
			f.Observation = alert.Observation{Producer: string(checks.ProducerCpanelAccessLog), Stream: "test", Cursor: "1", ObservedAt: time.Now()}
			if _, _, err := checks.AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseKindNotAllowed {
				t.Fatalf("proxy alert attribution: %v, want unknown address refused", err)
			}
		})
	}
}

func TestCpanelWHMScriptsAlertWithLongMethod(t *testing.T) {
	for _, method := range []string{strings.Repeat("M", 64), strings.Repeat(`\x4d`, 64)} {
		line := `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "` + method + ` /scripts2/listaccts HTTP/1.1" 401 0 "-" "agent" "-" "-" 2087`
		got := parseAccessLogLineEnhanced(line, &config.Config{})
		if len(got) != 1 || got[0].Check != "whm_unauth_scripts_realtime" || got[0].SourceIP != "192.0.2.66" {
			t.Fatalf("valid long method hid tokenless WHM request: %+v", got)
		}
	}
}

func TestCpanelProxyAlertsDoNotTrustAddressExemptions(t *testing.T) {
	oldTracker := purgeTracker
	resetPurgeTrackerState()
	t.Cleanup(func() { purgeTracker = oldTracker })
	purgeTracker.recordLogin("192.0.2.66", "alice")
	purgeTracker.recordPurge("alice")
	trustedProxy := &config.Config{}
	trustedProxy.WebServer.TrustedProxies = []string{"192.0.2.66"}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"session purge", &config.Config{}},
		{"infrastructure", &config.Config{InfraIPs: []string{"192.0.2.66"}}},
		{"trusted proxy", trustedProxy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, request := range []struct {
				target, port, check string
			}{
				{"POST /login/?login_only=1", "2087", "whm_login_realtime"},
				{"GET /scripts2/listaccts", "2087", "whm_unauth_scripts_realtime"},
				{"GET /execute/Themes/list", "2083", "api_auth_failure_realtime"},
			} {
				line := `192.0.2.66 proxy - [11/09/2026:12:00:00 -0000] "` + request.target + ` HTTP/1.1" 401 0 "-" "agent" "-" "198.51.100.7" ` + request.port
				got := parseAccessLogLineEnhanced(line, tc.cfg)
				if len(got) != 1 || got[0].Check != request.check || got[0].SourceIP != "" || got[0].Attribution != admission.AttributionUnknown {
					t.Errorf("%s: unverified proxy address hid an alert or supplied evidence: %+v", request.check, got)
				}
			}
		})
	}
}

func TestCpanelProxyHandlerCannotUseStaleSessionEvidence(t *testing.T) {
	oldTracker := purgeTracker
	resetPurgeTrackerState()
	t.Cleanup(func() { purgeTracker = oldTracker })
	for _, denialFirst := range []bool{false, true} {
		d := &Daemon{staleSession401: newStaleSession401s()}
		now := time.Now()
		obs := alert.Observation{Producer: string(checks.ProducerCpanelAccessLog), Stream: "test", Cursor: "1", ObservedAt: now}
		if denialFirst {
			d.staleSession401.observeSessionLine(staleTabDenialLine, now)
		}
		line := strings.Replace(staleTabSessionLine, " - alice ", " proxy alice ", 1)
		got := d.cpanelAccessLogObservedHandler(line, obs, &config.Config{})
		if len(got) != 1 || got[0].Check != "api_auth_failure_realtime" || got[0].SourceIP != "" ||
			got[0].Attribution != admission.AttributionUnknown || got[0].Observation != obs {
			t.Fatalf("proxy alert was held, suppressed or attributed (denial first %v): %+v", denialFirst, got)
		}
		if !denialFirst {
			d.staleSession401.observeSessionLine(staleTabDenialLine, now)
		}
		got = d.cpanelAccessLogObservedHandler(staleTabDeadLine, obs, &config.Config{})
		if len(got) != 0 {
			t.Fatalf("direct session request was not held: %+v", got)
		}
		got = d.staleSession401.due(time.Now().Add(staleSession401Hold))
		if len(got) != 1 || got[0].SourceIP != "198.51.100.7" || got[0].Attribution != admission.AttributionPeer || got[0].Observation != obs {
			t.Fatalf("proxy request explained a direct failure (denial first %v): %+v", denialFirst, got)
		}
		got = d.cpanelAccessLogObservedHandler(staleTabSessionLine, obs, &config.Config{})
		if len(got) != 0 {
			t.Fatalf("direct named request lost its stale-session explanation: %+v", got)
		}
		got = d.staleSession401.due(time.Now().Add(staleSession401Hold))
		if len(got) != 0 {
			t.Fatalf("explained direct request was emitted: %+v", got)
		}
	}
}

func TestCpanelWHMAlertsIgnoreForgedUserRecords(t *testing.T) {
	for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000", "09/Nov/2026:12:00:00 +0000"} {
		for _, user := range []string{
			`x"`,
			`x [bad] "y`,
			`x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
		} {
			for _, suffix := range []string{`"-" "agent" "-" "-" 2087`, `"-" "agent" "example.com:2086"`} {
				for request, check := range map[string]string{
					"GET /scripts2/listaccts":   "whm_unauth_scripts_realtime",
					"POST /login/?login_only=1": "whm_login_realtime",
				} {
					line := `192.0.2.66 - ` + user + ` [` + stamp + `] "` + request + ` HTTP/1.1" 401 0 ` + suffix
					got := parseAccessLogLineEnhanced(line, &config.Config{})
					if len(got) != 1 || got[0].Check != check || got[0].SourceIP != "192.0.2.66" {
						t.Errorf("%q: got %+v, want one %s", line, got, check)
					}
				}
			}
		}
	}
}
