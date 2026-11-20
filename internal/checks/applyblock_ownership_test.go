package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// A derived block admission takes or refuses ends in ApplyBlock before the
// engine: no kernel call, no tracker row, and a sentinel the callers treat
// as an expected outcome. A root the web server may have rewritten still
// gets the legacy block.
func TestApplyBlockLeavesTakenBlocksToAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		executes bool
		rootErr  error
		legacy   bool
	}{
		{"taken", true, nil, false},
		{"previewing", false, nil, true},
		{"unobserved root", true, attributionRefusal(admission.CauseNoObservation), false},
		{"rewritten root", true, attributionRefusal(admission.CauseRewrittenLog), true},
		{"proxied client", true, attributionRefusal(admission.CauseUnreachable), false},
		{"proxy edge", true, attributionRefusal(admission.CauseProxyPeer), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = tc.executes
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.97", EngineReason: "CSM challenge-timeout: wp brute", Reason: "challenge timeout after wp brute",
				TTL: time.Hour, Source: BlockSourceChallenge, Entry: admission.EntryChallengeTimeout,
				Check: "wp_login_bruteforce", RootFinding: alert.Finding{Check: "wp_login_bruteforce"}, RootErr: tc.rootErr,
			})
			if tc.legacy {
				if err != nil || len(blocker.calls) != 1 {
					t.Fatalf("ApplyBlock = %v, engine calls %+v; want the legacy block", err, blocker.calls)
				}
				return
			}
			if !errors.Is(err, ErrBlockTakenByAdmission) || res.Outcome != firewall.BlockOutcomeNoop || len(blocker.calls) != 0 || len(loadBlockState(cfg.StatePath).IPs) != 0 {
				t.Fatalf("ApplyBlock = %+v, %v, engine calls %+v; want the block left to admission", res, err, blocker.calls)
			}
		})
	}
}
