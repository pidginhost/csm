package checks

import (
	"context"
	"fmt"
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
			// A sustained mail-auth brute force from the address.
			for i := 0; i < 60; i++ {
				db.RecordFinding(alert.Finding{Check: "email_auth_failure_realtime", SourceIP: ip, Timestamp: time.Now()})
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

// An outbound connection names where a local process connected to, not who
// attacked the host. Its destination must never build a local threat score:
// the score hard-blocks the address, and the blocked set also cuts the
// host's own traffic to it.
func TestCheckLocalThreatScoreIgnoresOutboundDestinations(t *testing.T) {
	db := attackdb.NewForTest(nil)
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })
	// Two accounts reaching the same service is ordinary; the live
	// connection path attributes each finding to its process's account.
	for i, account := range []string{"alice", "bob"} {
		for n := 0; n < 20; n++ {
			db.RecordFinding(alert.Finding{
				Severity:  alert.High,
				Check:     "user_outbound_connection",
				Message:   "Non-root user connecting to unusual destination: 203.0.113.20:8443",
				Details:   fmt.Sprintf("UID: %d (%s), Local port: 40000, Proto: tcp", 1001+i, account),
				TenantID:  account,
				Timestamp: time.Now(),
			})
		}
	}
	if findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil); len(findings) != 0 {
		t.Fatalf("an outbound destination produced a critical score: %+v", findings)
	}
	if rec := db.LookupIP("203.0.113.20"); rec != nil {
		t.Fatalf("an outbound destination was recorded as an attacker: %+v", rec)
	}
}
