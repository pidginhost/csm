package checks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
)

// A host address can identify forwarded attacks or a compromised local
// process. Interface membership cannot establish that the events are benign.
func TestCheckLocalThreatScoreReportsHostOwnAddress(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	ips := map[string]bool{"198.51.100.7": true}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			t.Fatal(err)
		}
		ips[ip.String()] = true
	}
	for ip := range ips {
		t.Run(ip, func(t *testing.T) {
			db := attackdb.NewForTest(nil)
			attackdb.SetGlobal(db)
			t.Cleanup(func() { attackdb.SetGlobal(nil) })
			for i := 0; i < 20; i++ {
				for _, check := range []string{"webshell", "user_outbound_connection", "email_auth_failure_realtime"} {
					db.RecordFinding(alert.Finding{Check: check, SourceIP: ip, Timestamp: time.Now()})
				}
			}
			findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want one for attack evidence regardless of interface membership", len(findings))
			}
			if findings[0].SourceIP != ip || findings[0].Check != "local_threat_score" || findings[0].Severity != alert.Critical {
				t.Errorf("unexpected finding: %+v", findings[0])
			}
			if !strings.Contains(findings[0].Message, ip) {
				t.Error("finding must identify the attributed address")
			}
		})
	}
}

// Repeated low-signal HTTP observations alone must not produce a critical
// score, whether the logged client is the host or a remote address.
func TestCheckLocalThreatScoreDoesNotEscalateRoutineHTTP(t *testing.T) {
	db := attackdb.NewForTest(nil)
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })
	for i := 0; i < 300; i++ {
		db.RecordFinding(alert.Finding{Check: "http_request_flood", SourceIP: "203.0.113.10", Timestamp: time.Now()})
	}
	if findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil); len(findings) != 0 {
		t.Fatalf("routine HTTP observations produced a critical score: %+v", findings)
	}
}
