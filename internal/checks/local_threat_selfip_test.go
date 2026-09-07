package checks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// A cPanel host proxies nginx to Apache over its own public address rather
// than loopback, so the host's address accumulates inbound "attack" events
// against itself. Alerting on that is noise: the firewall already refuses to
// block a local address, so the finding names a threat no operator can act on
// and no responder can resolve.
func TestCheckLocalThreatScoreSkipsHostOwnAddress(t *testing.T) {
	now := time.Now()

	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.10"),
			net.ParseIP("2001:db8::1"),
		}, nil
	}))

	highScore := func(ip string) *attackdb.IPRecord {
		return &attackdb.IPRecord{
			IP:                    ip,
			ThreatScore:           95,
			EventCount:            300,
			FirstSeen:             now.Add(-2 * time.Hour),
			LastSeen:              now,
			BruteForceWindowStart: now.Add(-2 * time.Hour),
			BruteForceWindowCount: 300,
			BruteForceSustainedAt: now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackBruteForce: 300,
			},
			Accounts: map[string]int{"alice": 5},
		}
	}

	db := attackdb.NewForTest(map[string]*attackdb.IPRecord{
		// The host's own v4 and v6 addresses: must never be reported.
		"203.0.113.10": highScore("203.0.113.10"),
		"2001:db8::1":  highScore("2001:db8::1"),
		// A genuine external attacker at the same score: must be reported.
		"198.51.100.7": highScore("198.51.100.7"),
	})
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })

	findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)

	if len(findings) != 1 {
		t.Fatalf("findings: got %d, want 1 (only the external attacker). findings=%+v", len(findings), findings)
	}
	if findings[0].SourceIP != "198.51.100.7" {
		t.Errorf("SourceIP = %q, want 198.51.100.7", findings[0].SourceIP)
	}
	for _, f := range findings {
		for _, own := range []string{"203.0.113.10", "2001:db8::1"} {
			if strings.Contains(f.Message, own) {
				t.Errorf("finding reports the host's own address %s: %q", own, f.Message)
			}
		}
	}
}

// A failed interface enumeration must not silently discard real attackers.
func TestCheckLocalThreatScoreReportsWhenHostLookupFails(t *testing.T) {
	now := time.Now()

	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, net.UnknownNetworkError("boom")
	}))

	db := attackdb.NewForTest(map[string]*attackdb.IPRecord{
		"198.51.100.7": {
			IP:                    "198.51.100.7",
			ThreatScore:           95,
			EventCount:            300,
			FirstSeen:             now.Add(-2 * time.Hour),
			LastSeen:              now,
			BruteForceWindowStart: now.Add(-2 * time.Hour),
			BruteForceWindowCount: 300,
			BruteForceSustainedAt: now,
			AttackCounts: map[attackdb.AttackType]int{
				attackdb.AttackBruteForce: 300,
			},
			Accounts: map[string]int{"alice": 5},
		},
	})
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })

	findings := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings: got %d, want 1 (lookup failure must fail open)", len(findings))
	}
}
