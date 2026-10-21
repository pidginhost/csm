package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestPAMNormalizedAddressesRespectInfra(t *testing.T) {
	for _, tt := range []struct{ remote, infra string }{
		{"::ffff:203.0.113.10", "203.0.113.10"},
		{"203.0.113.10", "::ffff:203.0.113.10/128"},
		{"::ffff:203.0.113.10", "203.0.113.0/24"},
		{"2001:0db8:0:0:0:0:0:10", "2001:db8::10"},
		{"2001:db8::10", "2001:db8::/32"},
	} {
		t.Run(tt.remote+"/"+tt.infra, func(t *testing.T) {
			ch := make(chan alert.Finding, 8)
			cfg := &config.Config{InfraIPs: []string{tt.infra}}
			cfg.Thresholds.PAMBruteforceThreshold = 2
			p := &PAMListener{cfg: cfg, alertCh: ch, failures: make(map[string]*pamFailureTracker)}
			p.processEvent("FAIL ip=" + tt.remote + " user=alice service=sshd")
			p.processEvent("FAIL ip=" + tt.remote + " user=alice service=sshd")
			p.processEvent("OK ip=" + tt.remote + " user=alice service=sshd")
			if len(ch) != 0 || len(p.failures) != 0 || p.stuffing != nil {
				t.Fatal("normalized infrastructure address reached alerts or failure trackers")
			}
		})
	}
}

func TestPAMNormalizedAddressesShareStuffingAndSuccess(t *testing.T) {
	for _, tt := range []struct{ first, second, canonical string }{
		{"::ffff:203.0.113.10", "203.0.113.10", "203.0.113.10"},
		{"2001:0db8:0:0:0:0:0:10", "2001:db8::10", "2001:db8::10"},
	} {
		t.Run(tt.canonical, func(t *testing.T) {
			p, ch := observingPAMListener(t)
			p.cfg.Thresholds.PAMBruteforceThreshold = 100
			p.cfg.Thresholds.CredStuffingDistinctAccounts = 2
			p.processEvent("FAIL ip=" + tt.first + " user=alice service=sshd pid=10 ts=1700000000.100000000")
			p.processEvent("FAIL ip=" + tt.second + " user=bob service=sshd pid=11 ts=1700000001.200000000")
			if len(ch) != 1 {
				t.Fatalf("got %d findings, want one credential stuffing finding", len(ch))
			}
			f := <-ch
			if f.Check != "credential_stuffing" || f.SourceIP != tt.canonical || f.Observation.Cursor != "11:1700000001.200000000" {
				t.Fatalf("normalized stuffing finding lost address or observation: %+v", f)
			}
			p.processEvent("OK ip=" + tt.first + " user=bob service=sshd")
			p.processEvent("OK ip=" + tt.second + " user=alice service=sshd")
			if len(p.failures) != 0 || len(ch) != 2 {
				t.Fatalf("success did not clear the shared tracker: trackers=%d, alerts=%d", len(p.failures), len(ch))
			}
			for range 2 {
				if f := <-ch; f.Check != "pam_login" || f.SourceIP != tt.canonical {
					t.Fatalf("incorrect normalized success alert: %+v", f)
				}
			}
		})
	}
}
