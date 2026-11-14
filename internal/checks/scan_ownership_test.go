package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// While admission applies block picks, a scan block it takes leaves no
// legacy work: no engine call, no queued retry, no tracker row and no
// hourly charge. A refusal legacy does not share keeps the legacy block;
// a CDN edge or a proxied client is blocked by neither; a previewing
// admission changes nothing.
func TestScanLeavesTakenBlocksToAdmission(t *testing.T) {
	const ip = "203.0.113.95"
	for _, tc := range []struct {
		name     string
		executes bool
		mintErr  error
		legacy   bool
	}{
		{"taken", true, nil, false},
		{"rewritten log", true, attributionRefusal(admission.CauseRewrittenLog), true},
		{"no observation", true, attributionRefusal(admission.CauseNoObservation), true},
		{"proxy edge", true, attributionRefusal(admission.CauseProxyPeer), false},
		{"proxied client", true, attributionRefusal(admission.CauseUnreachable), false},
		{"previewing", false, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes, a.mintErr = tc.executes, tc.mintErr
			AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "WordPress brute force from " + ip, Timestamp: time.Now()}})
			state := loadBlockState(cfg.StatePath)
			blocked := len(blocker.calls) == 1 && blocker.calls[0].ip == ip
			if tc.legacy {
				if !blocked || len(state.IPs) != 1 || state.BlocksThisHour != 1 {
					t.Fatalf("legacy block missing: engine %+v, tracker %+v, hour %d", blocker.calls, state.IPs, state.BlocksThisHour)
				}
				return
			}
			if len(blocker.calls) != 0 || len(state.IPs) != 0 || len(state.Pending) != 0 || state.BlocksThisHour != 0 {
				t.Fatalf("legacy work for a block admission takes: engine %+v, tracker %+v, pending %+v, hour %d", blocker.calls, state.IPs, state.Pending, state.BlocksThisHour)
			}
		})
	}
}

// Mail spray keeps its legacy block while admission executes: admission does
// not model its lifetime or its budget, so it is not handed the block. A
// previewing admission still sees it.
func TestScanKeepsMailSprayLegacyWhileAdmissionExecutes(t *testing.T) {
	const ip = "203.0.113.96"
	for _, tc := range []struct {
		name     string
		executes bool
		handed   int
	}{
		{"previewing", false, 1},
		{"executing", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			a := withAdmission(t)
			a.executes = tc.executes
			AutoBlockIPs(cfg, []alert.Finding{{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "SMTP password spray from " + ip, BlockTTL: 720 * time.Hour, Timestamp: time.Now()}})
			if got := len(a.responses()); got != tc.handed {
				t.Fatalf("admission handed %d spray blocks, want %d: %+v", got, tc.handed, a.responses())
			}
			if len(blocker.calls) != 1 || blocker.calls[0].ip != ip || blocker.calls[0].timeout != 720*time.Hour {
				t.Fatalf("engine calls = %+v, want the legacy spray block", blocker.calls)
			}
		})
	}
}

type scanSwitchAdmission struct {
	*fakeAdmission
	afterRead func()
}

func (a scanSwitchAdmission) ExecutesBlocks() bool {
	executes := a.fakeAdmission.ExecutesBlocks()
	a.afterRead()
	return executes
}

// A concurrent owner replacement or policy publication cannot turn a spray
// preview into a taken block and lose its legacy lifetime and budget.
func TestScanSprayUsesOneAdmissionSnapshot(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy publication", true: "owner replacement"}[replace], func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			preview := withAdmission(t)
			executing := &fakeAdmission{executes: true}
			SetResponseAdmission(scanSwitchAdmission{preview, func() {
				if replace {
					SetResponseAdmission(executing)
				} else {
					preview.mu.Lock()
					preview.executes = true
					preview.mu.Unlock()
				}
			}})
			const ip = "203.0.113.97"
			const ttl = 720 * time.Hour
			before := time.Now()
			AutoBlockIPs(cfg, []alert.Finding{{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "SMTP password spray from " + ip, BlockTTL: ttl, Timestamp: time.Now()}})
			after := time.Now()
			if got := len(executing.responses()); got != 0 {
				t.Errorf("replacement owner received %d spray blocks", got)
			}
			if got := len(preview.responses()); got != 1 {
				t.Errorf("preview owner received %d spray blocks, want 1", got)
			}
			if len(blocker.calls) != 1 || blocker.calls[0].ip != ip || blocker.calls[0].timeout != ttl {
				t.Fatalf("engine calls = %+v, want the legacy spray block", blocker.calls)
			}
			state := loadBlockState(cfg.StatePath)
			if len(state.IPs) != 1 || state.IPs[0].IP != ip || !state.IPs[0].LoginSpray || len(state.Pending) != 0 || state.BlocksThisHour != 0 || state.LoginSprayBlocksThisHour != 1 {
				t.Fatalf("legacy spray state = %+v", state)
			}
			if expires := state.IPs[0].ExpiresAt; expires.Before(before.Add(ttl)) || expires.After(after.Add(ttl)) {
				t.Fatalf("spray expiry = %v, want between %v and %v", expires, before.Add(ttl), after.Add(ttl))
			}
		})
	}
}

// Exhausting legacy's budget must not queue a taken finding for a later
// duplicate block. A refused finding must still enter that queue.
func TestScanOwnershipWithExhaustedLegacyBudget(t *testing.T) {
	for _, accepted := range []bool{true, false} {
		t.Run(map[bool]string{true: "taken", false: "refused"}[accepted], func(t *testing.T) {
			cfg := pendingTestConfig(t)
			setAutoBlockNow(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
			cfg.AutoResponse.MaxBlocksPerHour = 1
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, blocker)
			saveBlockState(cfg.StatePath, &blockState{BlocksThisHour: 1, HourKey: autoBlockNow().Format("2006-01-02T15")})
			a := withAdmission(t)
			a.executes = true
			if !accepted {
				a.respondErr = &admission.Error{Reason: admission.ReasonQueueOverflow}
			}
			const ip = "203.0.113.95"
			AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "WordPress brute force from " + ip, Timestamp: autoBlockNow()}})
			if len(a.responses()) != 1 {
				t.Fatal("scan did not hand the block to admission")
			}
			state := loadBlockState(cfg.StatePath)
			if len(blocker.calls) != 0 || len(state.IPs) != 0 || state.BlocksThisHour != 1 {
				t.Fatalf("exhausted budget changed: engine %+v, tracker %+v, hour %d", blocker.calls, state.IPs, state.BlocksThisHour)
			}
			if accepted {
				if len(state.Pending) != 0 {
					t.Fatalf("taken block queued by legacy: %+v", state.Pending)
				}
			} else if len(state.Pending) != 1 || state.Pending[0].IP != ip {
				t.Fatalf("refused block missing from legacy queue: %+v", state.Pending)
			}
		})
	}
}
