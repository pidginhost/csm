package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// A derived block that asks to last longer than block_expiry keeps its
// legacy block while admission executes: admission would cut it to
// block_expiry. A previewing admission still sees it, and a block that
// fits is taken.
func TestApplyBlockKeepsLongerDerivedBlocksLegacy(t *testing.T) {
	const week = 7 * 24 * time.Hour
	for _, tc := range []struct {
		name     string
		executes bool
		ttl      time.Duration
		handed   int
		legacy   bool
	}{
		{"executing, longer", true, week, 0, true},
		{"previewing, longer", false, week, 1, true},
		{"executing, at block expiry", true, time.Hour, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = tc.executes
			_, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.91", EngineReason: "CSM incident block", Reason: "incident rung 2",
				TTL: tc.ttl, Source: BlockSourceIncident, Entry: admission.EntryIncident,
				Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"},
			})
			if got := len(a.responses()); got != tc.handed {
				t.Fatalf("admission handed %d blocks, want %d", got, tc.handed)
			}
			if !tc.legacy {
				if !errors.Is(err, ErrBlockTakenByAdmission) || len(blocker.calls) != 0 {
					t.Fatalf("ApplyBlock = %v, engine calls %+v; want the block left to admission", err, blocker.calls)
				}
				return
			}
			if err != nil || len(blocker.calls) != 1 || blocker.calls[0].timeout != tc.ttl {
				t.Fatalf("ApplyBlock = %v, engine calls %+v; want the legacy block for %s", err, blocker.calls, tc.ttl)
			}
		})
	}
}

// A policy publication during the hand-off cannot take a longer block
// legacy kept for the previewing owner: the hand-off reads execution once.
func TestApplyBlockLongerBlockUsesOneAdmissionSnapshot(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	preview := withAdmission(t)
	SetResponseAdmission(scanSwitchAdmission{preview, func() {
		preview.mu.Lock()
		preview.executes = true
		preview.mu.Unlock()
	}})
	const week = 7 * 24 * time.Hour
	_, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.92", EngineReason: "CSM incident block", Reason: "incident rung 2",
		TTL: week, Source: BlockSourceIncident, Entry: admission.EntryIncident,
		Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"},
	})
	if err != nil || len(blocker.calls) != 1 || blocker.calls[0].timeout != week {
		t.Fatalf("ApplyBlock = %v, engine calls %+v; want the legacy block", err, blocker.calls)
	}
}

// A longer derived block whose root admission refused as a CDN edge or a
// proxied client is blocked by neither path, as one that fits is, and the
// refusal is counted once.
func TestApplyBlockLongerBlockOfAnUncontainedRootIsNotBlocked(t *testing.T) {
	for _, cause := range []admission.Cause{admission.CauseProxyPeer, admission.CauseUnreachable} {
		t.Run(cause.String(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = true
			_, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.93", EngineReason: "CSM incident block", Reason: "incident rung 2",
				TTL: 7 * 24 * time.Hour, Source: BlockSourceIncident, Entry: admission.EntryIncident,
				Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: attributionRefusal(cause),
			})
			if !errors.Is(err, ErrBlockTakenByAdmission) || len(blocker.calls) != 0 {
				t.Fatalf("ApplyBlock = %v, engine calls %+v; want no block", err, blocker.calls)
			}
			if len(a.refused) != 1 {
				t.Fatalf("refusals counted = %v, want one", a.refused)
			}
		})
	}
}

// The lifetime rule reads block_expiry as the scan loop does: an empty,
// unparsable or nonpositive value falls back to 24 hours. Only a block asked
// to outlast that lease stays legacy while admission executes, and the
// legacy block keeps the asked lifetime.
func TestApplyBlockLeaseParsingBoundary(t *testing.T) {
	for _, tc := range []struct {
		setting string
		lease   time.Duration
	}{{"", 24 * time.Hour}, {"invalid", 24 * time.Hour}, {"1h", time.Hour}, {"0s", 24 * time.Hour}, {"-1h", 24 * time.Hour}} {
		if got := parseExpiry(tc.setting); got != tc.lease {
			t.Fatalf("lease of %q = %s, want %s", tc.setting, got, tc.lease)
		}
	}
	for _, tc := range []struct {
		setting string
		lease   time.Duration
	}{{"", 24 * time.Hour}, {"invalid", 24 * time.Hour}, {"1h", time.Hour}} {
		type run struct {
			name     string
			ttl      time.Duration
			executes bool
			rootErr  error
			legacy   bool
		}
		runs := []run{
			{"below", tc.lease / 2, true, nil, false},
			{"equal", tc.lease, true, nil, false},
			{"above", 2 * tc.lease, true, nil, true},
			{"above, previewing", 2 * tc.lease, false, nil, true},
			{"above, proxy edge root", 2 * tc.lease, true, attributionRefusal(admission.CauseProxyPeer), false},
			{"above, proxied client root", 2 * tc.lease, true, attributionRefusal(admission.CauseUnreachable), false},
		}
		for _, r := range runs {
			t.Run(tc.setting+"/"+r.name, func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.BlockExpiry = tc.setting
				blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
				applyBlockTestSetup(t, blocker)
				a := withAdmission(t)
				a.executes = r.executes
				_, err := ApplyBlock(cfg, ApplyBlockRequest{
					IP: "203.0.113.89", EngineReason: "CSM incident block", Reason: "incident block",
					TTL: r.ttl, Source: BlockSourceIncident, Entry: admission.EntryIncident,
					Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: r.rootErr,
				})
				if r.legacy {
					if err != nil || len(blocker.calls) != 1 || blocker.calls[0].timeout != r.ttl {
						t.Fatalf("ApplyBlock = %v, engine calls %+v; want the legacy block for %s", err, blocker.calls, r.ttl)
					}
					return
				}
				if !errors.Is(err, ErrBlockTakenByAdmission) || len(blocker.calls) != 0 {
					t.Fatalf("ApplyBlock = %v, engine calls %+v; want the block left to admission", err, blocker.calls)
				}
			})
		}
	}
}
