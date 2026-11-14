package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// A block admission applied is recorded where a legacy block is: a tracker
// row (which netblock escalation counts), a permanent-block strike and the
// Critical auto_block finding naming its cause. A repeated delivery changes
// nothing.
func TestRecordAdmissionBlocks(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	b := AdmissionBlock{IP: "203.0.113.61", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", FindingID: "0123456789abcdef", BlockedAt: at, ExpiresAt: at.Add(24 * time.Hour)}
	findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{b})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.Check != "auto_block" || f.Severity != alert.Critical || f.SourceIP != b.IP || f.Message != "AUTO-BLOCK: 203.0.113.61 blocked (expires in 24h0m0s)" ||
		!strings.Contains(f.Details, b.Reason) || f.Cause == nil || *f.Cause != (alert.Cause{FindingID: b.FindingID, Check: b.Check}) {
		t.Fatalf("finding = %+v", f)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 {
		t.Fatalf("tracker = %+v, want one row", state.IPs)
	}
	row := state.IPs[0]
	if row.IP != b.IP || row.FindingID != b.FindingID || row.Reason != b.Reason || !row.BlockedAt.Equal(at) || !row.ExpiresAt.Equal(b.ExpiresAt) || !countsTowardNetblock(row) {
		t.Fatalf("tracker row = %+v", row)
	}
	if strikes := loadPermBlockTracker(cfg.StatePath).IPs[b.IP]; len(strikes) != 1 {
		t.Fatalf("strikes = %v, want one", strikes)
	}
	if again := RecordAdmissionBlocks(cfg, []AdmissionBlock{b}); len(again) != 0 {
		t.Fatalf("repeated delivery emitted %+v", again)
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 1 || len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]) != 1 {
		t.Fatalf("repeated delivery changed the tracker or strikes: %+v", state.IPs)
	}
	if len(blocker.calls) != 0 {
		t.Fatalf("recording called the engine: %+v", blocker.calls)
	}
}

// A strike that reaches the permanent-block count promotes nothing: the
// block is admission's, and a permanent block is not an admission
// response. The strike still counts toward a later legacy block.
func TestRecordAdmissionBlocksPromotesNothing(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	cfg.AutoResponse.PermBlockInterval = "24h"
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	at := time.Now().Add(-time.Minute).UTC()
	first := AdmissionBlock{IP: "203.0.113.62", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
	second := first
	second.ExpiresAt = at.Add(2 * time.Hour)
	findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{first, second})
	if len(findings) != 2 || len(blocker.calls) != 0 || len(blocker.promoted) != 0 {
		t.Fatalf("findings %+v, engine calls %+v, promoted %v; want two notices and no promotion", findings, blocker.calls, blocker.promoted)
	}
	for _, f := range findings {
		if strings.Contains(f.Message, "PERMBLOCK") {
			t.Fatalf("promotion notice %q", f.Message)
		}
	}
	if strikes := loadPermBlockTracker(cfg.StatePath).IPs[first.IP]; len(strikes) != 2 {
		t.Fatalf("strikes = %v, want two", strikes)
	}
}

// The notice carries the Cloudflare coverage warning a legacy block gets,
// and no strike is counted with permanent blocking off or for a listed C2
// server, as for a legacy block.
func TestRecordAdmissionBlocksWarnsAndSkipsStrikesAsLegacy(t *testing.T) {
	at := time.Now().Add(-time.Minute).UTC()
	for _, tc := range []struct {
		name      string
		permBlock bool
		c2        bool
		cf        bool
		strikes   int
	}{
		{"cloudflare", true, false, true, 1},
		{"permblock off", false, false, false, 0},
		{"listed c2", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.PermBlock = tc.permBlock
			b := AdmissionBlock{IP: "203.0.113.63", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
			if tc.c2 {
				cfg.C2Blocklist = []string{b.IP}
			}
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive, cfCovers: tc.cf}
			applyBlockTestSetup(t, blocker)
			findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{b})
			if len(findings) != 1 {
				t.Fatalf("findings = %+v", findings)
			}
			if warned := strings.Contains(findings[0].Details, firewall.CloudflareCoverageWarning); warned != tc.cf {
				t.Fatalf("details %q, Cloudflare warning %v, want %v", findings[0].Details, warned, tc.cf)
			}
			if got := len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]); got != tc.strikes {
				t.Fatalf("strikes = %d, want %d", got, tc.strikes)
			}
		})
	}
}
