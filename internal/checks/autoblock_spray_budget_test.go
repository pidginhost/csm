package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

type sprayBudgetBlocker struct {
	outcomeStubBlocker
	requests []firewall.ActionRequest
	apply    func(firewall.ActionRequest) (firewall.BlockOutcome, error)
}

func (*sprayBudgetBlocker) DurableActionsEnabled() bool { return true }

func (b *sprayBudgetBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	b.requests = append(b.requests, req)
	return b.apply(req)
}

// An uncertain result can already have changed the firewall. It must spend
// spray credit even if recovery later reports the request as a no-op.
func TestAutoBlockSprayUncertainOutcomeUsesBudget(t *testing.T) {
	for _, failure := range []error{firewall.ErrActionUnknown, firewall.ErrStateCommitUncertain} {
		t.Run(failure.Error(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.MaxBlocksPerHour = 1
			now := time.Now()
			setAutoBlockNow(t, now)
			b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
				return firewall.BlockOutcomeNoop, failure
			}}
			applyBlockTestSetup(t, b)
			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.100")})
			first := loadBlockState(cfg.StatePath)
			if first.LoginSprayBlocksThisHour != 1 || first.BlocksThisHour != 0 || len(first.Pending) != 1 {
				t.Fatalf("uncertain spray block was not charged separately: %+v", first)
			}
			b.apply = func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
				return firewall.BlockOutcomeLive, nil
			}
			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.101"), wafFinding("198.51.100.100")})
			if len(b.requests) != 2 || b.requests[1].Target != "198.51.100.100" {
				t.Fatalf("spray retry or fresh spray bypassed cap, or scan was starved: %+v", b.requests)
			}
			state := loadBlockState(cfg.StatePath)
			if state.LoginSprayBlocksThisHour != 1 || state.BlocksThisHour != 1 || len(state.Pending) != 2 {
				t.Fatalf("separate budgets or pending candidates changed: %+v", state)
			}
			// With no fresh competitor, the original request retries next hour.
			state.Pending = first.Pending
			saveBlockState(cfg.StatePath, state)
			autoBlockNow = func() time.Time { return now.Add(time.Hour) }
			b.apply = func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
				return firewall.BlockOutcomeNoop, nil
			}
			AutoBlockIPs(cfg, nil)
			if len(b.requests) != 3 || b.requests[2] != b.requests[0] {
				t.Fatalf("recovery changed the original request: %+v", b.requests)
			}
			if state := loadBlockState(cfg.StatePath); len(state.Pending) != 0 || state.LoginSprayBlocksThisHour != 0 {
				t.Fatalf("completed no-op retained queue or spent new credit: %+v", state)
			}
		})
	}
}

// Saving the tracker after a live mutation can fail or never happen. The
// previous persisted counter must already cover the block in that case.
func TestAutoBlockSprayReservesBudgetBeforeMutation(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now()
	setAutoBlockNow(t, now)
	queued := pendingIP{IP: "198.51.100.101", Check: "waf_attack_blocked", Severity: alert.Critical, QueuedAt: now}
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: 1, Pending: []pendingIP{queued}})
	originalPersist := persistAutoBlockState
	t.Cleanup(func() { persistAutoBlockState = originalPersist })
	b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
		state := loadBlockState(cfg.StatePath)
		if state.LoginSprayBlocksThisHour != 1 || state.BlocksThisHour != 1 || len(state.Pending) != 1 || state.Pending[0].IP != queued.IP {
			t.Errorf("mutation ran without a saved reservation or erased pending work: %+v", state)
		}
		persistAutoBlockState = func(string, *blockState) error { return errors.New("tracker write unavailable") }
		return firewall.BlockOutcomeLive, nil
	}}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.102")})
	persistAutoBlockState = originalPersist
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.103")})
	if len(b.requests) != 1 {
		t.Fatalf("failed final save reset the spray budget: %+v", b.requests)
	}
}

func TestAutoBlockSprayBudgetStorageFailureDefersMutation(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	setAutoBlockNow(t, time.Now())
	saveBlockState(cfg.StatePath, &blockState{HourKey: autoBlockNow().Format("2006-01-02T15"), BlocksThisHour: 1})
	b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
		return firewall.BlockOutcomeLive, nil
	}}
	applyBlockTestSetup(t, b)
	originalPersist := persistAutoBlockState
	t.Cleanup(func() { persistAutoBlockState = originalPersist })
	persistAutoBlockState = func(string, *blockState) error { return errors.New("tracker write unavailable") }
	actions := AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.104")})
	if len(b.requests) != 0 {
		t.Fatalf("spray mutation ran without writable accounting: %+v", b.requests)
	}
	if len(actions) != 1 || actions[0].Severity != alert.Warning || actions[0].Check != "auto_block" {
		t.Fatalf("accounting failure was not reported: %+v", actions)
	}
	persistAutoBlockState = originalPersist
	if state := loadBlockState(cfg.StatePath); state.BlocksThisHour != 1 {
		t.Fatalf("accounting failure erased existing credit usage: %+v", state)
	}
}

func TestAutoBlockSprayReservationSettlesByOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome firewall.BlockOutcome
		err     error
		charged bool
	}{
		{name: "live", outcome: firewall.BlockOutcomeLive, charged: true},
		{name: "audit pending", outcome: firewall.BlockOutcomeLive, err: firewall.ErrActionAuditPending, charged: true},
		{name: "unknown", outcome: firewall.BlockOutcomeNoop, err: firewall.ErrActionUnknown, charged: true},
		{name: "dry run", outcome: firewall.BlockOutcomeDryRun},
		{name: "allowed", outcome: firewall.BlockOutcomeAllowed},
		{name: "allowlisted", outcome: firewall.BlockOutcomeAllowlisted},
		{name: "no-op", outcome: firewall.BlockOutcomeNoop},
		{name: "protected", outcome: firewall.BlockOutcomeNoop, err: firewall.ErrIPProtected},
		{name: "rejected", outcome: firewall.BlockOutcomeNoop, err: firewall.ErrActionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.MaxBlocksPerHour = 1
			setAutoBlockNow(t, time.Now())
			b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
				return tc.outcome, tc.err
			}}
			applyBlockTestSetup(t, b)
			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.105"), loginSprayFinding("192.0.2.106")})
			wantCalls, wantUsed := 2, 0
			if tc.charged {
				wantCalls, wantUsed = 1, 1
			}
			state := loadBlockState(cfg.StatePath)
			if len(b.requests) != wantCalls || state.LoginSprayBlocksThisHour != wantUsed || state.BlocksThisHour != 0 {
				t.Fatalf("calls=%d, spray=%d, scan=%d; want %d, %d, 0", len(b.requests), state.LoginSprayBlocksThisHour, state.BlocksThisHour, wantCalls, wantUsed)
			}
		})
	}
}

func TestAutoBlockSprayReservationFailureKeepsScanBudget(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	setAutoBlockNow(t, time.Now())
	originalPersist := persistAutoBlockState
	t.Cleanup(func() { persistAutoBlockState = originalPersist })
	persistAutoBlockState = func(path string, state *blockState) error {
		if state.LoginSprayBlocksThisHour > 0 {
			return errors.New("spray reservation unavailable")
		}
		return writeBlockState(path, state)
	}
	b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
		return firewall.BlockOutcomeLive, nil
	}}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.107"), loginSprayFinding("192.0.2.108"), wafFinding("198.51.100.107")})
	if len(b.requests) != 1 || b.requests[0].Target != "198.51.100.107" || b.requests[0].TTL != time.Hour {
		t.Fatalf("reservation failure blocked scan work or admitted spray: %+v", b.requests)
	}
	state := loadBlockState(cfg.StatePath)
	if state.BlocksThisHour != 1 || state.LoginSprayBlocksThisHour != 0 || len(state.Pending) != 2 {
		t.Fatalf("reservation failure lost independent accounting or retries: %+v", state)
	}
	for _, p := range state.Pending {
		if !p.LoginSpray || p.TTL != loginSprayTTL || p.QueuedAt.IsZero() {
			t.Fatalf("reservation failure lost retry policy: %+v", p)
		}
	}
}

// An unreadable block-state file is warned about and replaced: blocking goes
// on from an empty state with fresh counters, spray blocks included.
func TestAutoBlockUnreadableStateKeepsBlocking(t *testing.T) {
	cfg := pendingTestConfig(t)
	setAutoBlockNow(t, time.Now())
	if err := os.WriteFile(filepath.Join(cfg.StatePath, blockStateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &sprayBudgetBlocker{apply: func(firewall.ActionRequest) (firewall.BlockOutcome, error) {
		return firewall.BlockOutcomeLive, nil
	}}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.109"), wafFinding("198.51.100.109")})
	ttls := map[string]time.Duration{}
	for _, r := range b.requests {
		ttls[r.Target] = r.TTL
	}
	if len(b.requests) != 2 || ttls["192.0.2.109"] != loginSprayTTL || ttls["198.51.100.109"] != time.Hour {
		t.Fatalf("requests = %+v, want the spray and the WAF block", b.requests)
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LoginSprayBlocksThisHour != 1 || state.BlocksThisHour != 1 || len(state.IPs) != 2 {
		t.Fatalf("state = %+v, want fresh counters and both blocks", state)
	}
}

// A spray backlog over its budget holds at most half the retry queue, so it
// cannot push other retries out of it.
func TestAutoBlockSprayBacklogKeepsOtherRetries(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now()
	setAutoBlockNow(t, now)
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: 1, LoginSprayBlocksThisHour: 1})
	b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, b)
	var findings []alert.Finding
	for i := range maxPendingBlocks {
		findings = append(findings, loginSprayFinding(fmt.Sprintf("2001:db8:5::%x", i)))
	}
	const others = maxPendingBlocks / 2
	for i := range others {
		findings = append(findings, wafFinding(fmt.Sprintf("2001:db8:6::%x", i)))
	}

	AutoBlockIPs(cfg, findings)
	if len(b.calls) != 0 {
		t.Fatalf("block calls = %d, want none with both budgets spent", len(b.calls))
	}
	spray, other := 0, 0
	for _, p := range loadBlockState(cfg.StatePath).Pending {
		if p.LoginSpray {
			spray++
		} else {
			other++
		}
	}
	if spray != maxPendingBlocks/2 || other != others {
		t.Fatalf("queued spray=%d other=%d, want spray capped at %d and all %d other retries", spray, other, maxPendingBlocks/2, others)
	}
}

// The hourly warning names the budget that is full, so a full spray budget
// does not read as a limit on WAF or SSH blocks.
func TestAutoBlockRateWarningNamesBudget(t *testing.T) {
	for _, tc := range []struct {
		name            string
		scanUsed, spray int
		want            string
	}{
		{"spray budget full", 0, 1, "Auto-block mail login spray budget reached (1/hour), 1 IPs queued for next cycle"},
		{"scan budget full", 1, 0, "Auto-block rate limit reached (1/hour), 1 IPs queued for next cycle"},
		{"both full", 1, 1, "Auto-block rate limit and mail login spray budget reached (1/hour each), 2 IPs queued for next cycle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.MaxBlocksPerHour = 1
			now := time.Now()
			setAutoBlockNow(t, now)
			saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: tc.scanUsed, LoginSprayBlocksThisHour: tc.spray})
			applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive})

			var warnings []string
			for _, f := range AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.88"), wafFinding("198.51.100.88")}) {
				if f.Severity == alert.Warning {
					warnings = append(warnings, f.Message)
				}
			}
			if len(warnings) != 1 || warnings[0] != tc.want {
				t.Fatalf("warnings = %q, want %q", warnings, tc.want)
			}
		})
	}
}
