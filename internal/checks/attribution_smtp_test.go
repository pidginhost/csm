package checks

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// Direct SMTP egress carries the process owner as tenant: the verified
// process account when the enricher supplied one, else a verified hosting
// account for the socket's user.
func TestDirectSMTPEgressCarriesTenant(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
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

func TestDirectSMTPEgressDoesNotAttributeServiceUser(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	for _, user := range []string{"nobody", "uid:4242", "unknown"} {
		for _, enriched := range []bool{false, true} {
			input := DirectSMTPEgressInput{
				UID: 65534, User: user, PID: 4242, Comm: "fixture",
				DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
			}
			if enriched {
				input.Process = &processctx.ProcessContext{Account: user}
				// A failed process owner lookup must not fall back to another user.
				input.User = "alice"
			}
			finding, ok := EvaluateDirectSMTPEgress(sampleDirectSMTPCfg(), input)
			if !ok || finding.Check != "direct_smtp_egress" {
				t.Fatalf("missing SMTP finding: %+v", finding)
			}
			if finding.TenantID != "" {
				t.Errorf("service user %q (enriched=%t) attributed as %q", user, enriched, finding.TenantID)
			}
		}
	}
}
