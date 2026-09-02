package reporting

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The gate demanded Critical for every class, but the only producer of the
// bad_asn_egress class emits High, so enabling that class reported nothing
// and nobody could tell. Each class carries its own minimum severity.
func TestGateConsiderUsesPerClassMinimumSeverity(t *testing.T) {
	g := Gate{Enabled: map[Class]bool{ClassBadASNEgress: true, ClassBruteforce: true}}
	now := time.Now()
	if _, ok := g.Consider(alert.Finding{Severity: alert.High, Check: "bad_asn_outbound", SourceIP: "198.51.100.30", Timestamp: now}); !ok {
		t.Fatal("High bad_asn_outbound was not reported although the class is enabled and its producer never emits Critical")
	}
	if _, ok := g.Consider(alert.Finding{Severity: alert.High, Check: "wp_login_bruteforce", SourceIP: "198.51.100.31", Timestamp: now}); ok {
		t.Fatal("High brute-force finding reported; that class still requires Critical")
	}
}
