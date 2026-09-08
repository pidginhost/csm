package checks

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// Direct SMTP egress carries the process owner as tenant: the verified
// process account when the enricher supplied one, else the socket's user.
func TestDirectSMTPEgressCarriesTenant(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	base := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	byUser, ok := EvaluateDirectSMTPEgress(cfg, base)
	if !ok {
		t.Fatal("expected finding")
	}
	enriched := base
	enriched.User = "php-fpm"
	enriched.Process = &processctx.ProcessContext{Account: "bob"}
	byProcess, ok := EvaluateDirectSMTPEgress(cfg, enriched)
	if !ok {
		t.Fatal("expected finding")
	}
	for _, tc := range []struct {
		f    alert.Finding
		want string
	}{{byUser, "alice"}, {byProcess, "bob"}} {
		if tc.f.TenantID != tc.want || extractAccountFromFinding(tc.f) != tc.want {
			t.Errorf("TenantID %q (resolved %q), want %q", tc.f.TenantID, extractAccountFromFinding(tc.f), tc.want)
		}
	}
	res := CorrelateFindings([]alert.Finding{byUser, byProcess, critical("db_rogue_admin", "carol")})
	if len(res.Unattributed) != 0 {
		t.Fatalf("attributed SMTP egress counted as unattributed: %v", res.Unattributed)
	}
}
