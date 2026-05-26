package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// TestMaybeReclassifyKind_UpgradesToStrongerKind asserts that an
// incident opened as a low-severity Web account compromise is
// promoted when a later finding reveals a stronger pattern (host
// integrity, post-exploit process, etc.). Without re-classification,
// the incident stays misnamed forever and operators routing on Kind
// miss the escalation.
func TestMaybeReclassifyKind_UpgradesToStrongerKind(t *testing.T) {
	cases := []struct {
		name     string
		start    Kind
		finding  alert.Finding
		wantKind Kind
	}{
		{
			name:     "web compromise upgrades to host integrity",
			start:    KindWebAccountCompromise,
			finding:  alert.Finding{Check: "fake_kernel_thread"},
			wantKind: KindHostIntegrityRisk,
		},
		{
			name:     "mailbox takeover upgrades to post-exploit when exe runs from /tmp",
			start:    KindMailboxTakeover,
			finding:  alert.Finding{Process: &processctx.ProcessContext{Exe: "/tmp/x"}},
			wantKind: KindPostExploitProcess,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inc := &Incident{Kind: tc.start, Timeline: nil}
			maybeReclassifyKind(inc, tc.finding)
			if inc.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", inc.Kind, tc.wantKind)
			}
		})
	}
}

// TestMaybeReclassifyKind_DoesNotDowngrade: a host integrity
// incident must not be silently downgraded by a later web-compromise
// finding.
func TestMaybeReclassifyKind_DoesNotDowngrade(t *testing.T) {
	inc := &Incident{Kind: KindHostIntegrityRisk}
	maybeReclassifyKind(inc, alert.Finding{TenantID: "alice"})
	if inc.Kind != KindHostIntegrityRisk {
		t.Errorf("Kind downgraded to %q, want unchanged", inc.Kind)
	}
}

// TestMaybeReclassifyKind_CompoundWebshellPlusC2: a chain of
// webshell + outbound C2 connection upgrades the incident to a
// post-exploit kind so operators see it as an active attack,
// not just a file detection.
func TestMaybeReclassifyKind_CompoundWebshellPlusC2(t *testing.T) {
	inc := &Incident{
		Kind: KindWebAccountCompromise,
		Timeline: []IncidentEvent{
			{Check: "webshell"},
		},
	}
	maybeReclassifyKind(inc, alert.Finding{Check: "c2_connection", SourceIP: "203.0.113.5"})
	if inc.Kind != KindPostExploitProcess {
		t.Errorf("Kind = %q, want %q (compound webshell + c2 should promote)", inc.Kind, KindPostExploitProcess)
	}
}

// TestMaybeReclassifyKind_KeepsKindWhenNoChange: re-classification
// is idempotent for the no-upgrade case.
func TestMaybeReclassifyKind_KeepsKindWhenNoChange(t *testing.T) {
	inc := &Incident{Kind: KindMailboxTakeover}
	maybeReclassifyKind(inc, alert.Finding{Check: "smtp_brute_failure_then_success", Mailbox: "alice@example.com"})
	if inc.Kind != KindMailboxTakeover {
		t.Errorf("Kind drifted to %q, want unchanged", inc.Kind)
	}
}
