package incident

import (
	"testing"
	"time"

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

func TestMaybeReclassifyKind_DoesNotDowngradeHostTakeover(t *testing.T) {
	inc := &Incident{Kind: KindHostTakeover}
	maybeReclassifyKind(inc, alert.Finding{TenantID: "alice"})
	if inc.Kind != KindHostTakeover {
		t.Errorf("Kind downgraded to %q, want unchanged", inc.Kind)
	}
}

func TestMaybeReclassifyKind_CompoundDoesNotDowngradeHostIntegrity(t *testing.T) {
	inc := &Incident{
		Kind: KindHostIntegrityRisk,
		Timeline: []IncidentEvent{
			{Check: "webshell"},
		},
	}
	maybeReclassifyKind(inc, alert.Finding{Check: "c2_connection", SourceIP: "203.0.113.5"})
	if inc.Kind != KindHostIntegrityRisk {
		t.Errorf("Kind downgraded to %q, want %q", inc.Kind, KindHostIntegrityRisk)
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

func TestMaybeReclassifyKind_CompoundRecognizesOfflineObfuscatedPHP(t *testing.T) {
	inc := &Incident{
		Kind: KindWebAccountCompromise,
		Timeline: []IncidentEvent{
			{Check: "obfuscated_php"},
		},
	}
	maybeReclassifyKind(inc, alert.Finding{Check: "backdoor_port_outbound", SourceIP: "203.0.113.5"})
	if inc.Kind != KindPostExploitProcess {
		t.Errorf("Kind = %q, want %q (offline obfuscated_php + outbound backdoor should promote)", inc.Kind, KindPostExploitProcess)
	}
}

// TestMaybeReclassifyKind_CompoundSurvivesTimelineEviction: the
// compound webshell+C2 detection must not depend on the webshell
// IncidentEvent still being in the timeline. Long-running incidents
// trim the middle of the timeline (head+tail retention) so an early
// webshell can be evicted before the C2 finding arrives. Sticky
// compound markers on the Incident itself ensure reclassify still
// promotes the Kind.
func TestMaybeReclassifyKind_CompoundSurvivesTimelineEviction(t *testing.T) {
	inc := &Incident{
		Kind:          KindWebAccountCompromise,
		CompoundFlags: CompoundFlags{Webshell: true},
		Timeline:      nil,
	}
	maybeReclassifyKind(inc, alert.Finding{Check: "c2_connection", SourceIP: "203.0.113.5"})
	if inc.Kind != KindPostExploitProcess {
		t.Errorf("Kind = %q, want %q (sticky webshell marker + new C2 should promote even with empty timeline)", inc.Kind, KindPostExploitProcess)
	}
}

func TestMaybeReclassifyKind_HostTakeoverRequiresUID0AndSUID(t *testing.T) {
	tests := []struct {
		name    string
		flags   CompoundFlags
		finding alert.Finding
		want    Kind
	}{
		{
			name:    "uid0 only",
			finding: alert.Finding{Check: "uid0_account"},
			want:    KindHostIntegrityRisk,
		},
		{
			name:    "suid only",
			finding: alert.Finding{Check: "suid_binary"},
			want:    KindHostIntegrityRisk,
		},
		{
			name:    "sticky uid0 plus suid",
			flags:   CompoundFlags{UID0: true},
			finding: alert.Finding{Check: "suid_binary"},
			want:    KindHostTakeover,
		},
		{
			name:    "sticky suid plus uid0",
			flags:   CompoundFlags{SUID: true},
			finding: alert.Finding{Check: "uid0_account"},
			want:    KindHostTakeover,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inc := &Incident{Kind: KindHostIntegrityRisk, CompoundFlags: tt.flags}
			maybeReclassifyKind(inc, tt.finding)
			if inc.Kind != tt.want {
				t.Fatalf("Kind = %q, want %q", inc.Kind, tt.want)
			}
		})
	}
}

func TestMaybeReclassifyKind_HostTakeoverTwoOfThreeWithBadASN(t *testing.T) {
	tests := []struct {
		name    string
		flags   CompoundFlags
		finding alert.Finding
		want    Kind
	}{
		{
			name:    "bad_asn alone is one leg",
			finding: alert.Finding{Check: "bad_asn_outbound"},
			want:    KindHostIntegrityRisk,
		},
		{
			name:    "sticky uid0 plus bad_asn",
			flags:   CompoundFlags{UID0: true},
			finding: alert.Finding{Check: "bad_asn_outbound"},
			want:    KindHostTakeover,
		},
		{
			name:    "sticky suid plus bad_asn",
			flags:   CompoundFlags{SUID: true},
			finding: alert.Finding{Check: "bad_asn_outbound"},
			want:    KindHostTakeover,
		},
		{
			name:    "sticky bad_asn plus uid0",
			flags:   CompoundFlags{BadASNOutbound: true},
			finding: alert.Finding{Check: "uid0_account"},
			want:    KindHostTakeover,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inc := &Incident{Kind: KindHostIntegrityRisk, CompoundFlags: tt.flags}
			maybeReclassifyKind(inc, tt.finding)
			if inc.Kind != tt.want {
				t.Fatalf("Kind = %q, want %q", inc.Kind, tt.want)
			}
		})
	}
}

func TestHydrateCompoundFlagsReadsPastCompletedWebCompound(t *testing.T) {
	flags := CompoundFlags{Webshell: true, C2: true}
	hydrateCompoundFlagsFromTimeline(&flags, []IncidentEvent{
		{Check: "uid0_account"},
		{Check: "suid_binary"},
	})
	if !flags.UID0 || !flags.SUID {
		t.Fatalf("host flags not hydrated after web flags already set: %+v", flags)
	}
}

// TestCorrelator_CompoundSurvivesTimelineCap drives the correlator end
// to end: an early webshell finding is evicted by timeline trimming
// after enough subsequent noise, then a C2 finding arrives. Without
// sticky compound markers the incident kind would stay weak.
func TestCorrelator_CompoundSurvivesTimelineCap(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{OpenThreshold: 1})
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	mkFinding := func(check string, i int) alert.Finding {
		return alert.Finding{
			Check:     check,
			Severity:  alert.Warning,
			TenantID:  "alice",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		}
	}

	id, _, err := c.OnFinding(mkFinding("wp_login_bruteforce", 0))
	if err != nil {
		t.Fatalf("OnFinding opener: %v", err)
	}

	// Push 250 wp_login_bruteforce events so the webshell lands at
	// timeline slot 251 (beyond the head-retain half once trimmed).
	for i := 1; i <= 250; i++ {
		if _, _, err := c.OnFinding(mkFinding("wp_login_bruteforce", i)); err != nil {
			t.Fatalf("OnFinding noise %d: %v", i, err)
		}
	}
	if _, _, err := c.OnFinding(mkFinding("webshell", 251)); err != nil {
		t.Fatalf("OnFinding webshell: %v", err)
	}

	// Push enough more noise to drive trimming so the webshell slot
	// falls into the elided middle.
	for i := 252; i <= maxIncidentTimeline+50; i++ {
		if _, _, err := c.OnFinding(mkFinding("wp_login_bruteforce", i)); err != nil {
			t.Fatalf("OnFinding noise %d: %v", i, err)
		}
	}

	// Confirm webshell event is no longer present in timeline.
	snap, ok := c.Get(id)
	if !ok {
		t.Fatal("incident missing")
	}
	for _, ev := range snap.Timeline {
		if ev.Check == "webshell" {
			t.Fatalf("test precondition broken: webshell event still in timeline (len=%d); pick larger noise count", len(snap.Timeline))
		}
	}

	// Now push the C2 finding -- reclassify must still promote.
	if _, _, err := c.OnFinding(mkFinding("c2_connection", maxIncidentTimeline+100)); err != nil {
		t.Fatalf("OnFinding c2: %v", err)
	}
	snap, ok = c.Get(id)
	if !ok {
		t.Fatal("incident missing after c2")
	}
	if snap.Kind != KindPostExploitProcess {
		t.Errorf("Kind = %q after evicted-webshell + C2, want %q", snap.Kind, KindPostExploitProcess)
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
