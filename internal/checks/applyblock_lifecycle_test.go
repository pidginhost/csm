package checks

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

type durableAdmissionBlocker struct {
	outcomeStubBlocker
	enabled      bool
	request      firewall.ActionRequest
	budget       *firewall.ScanAdmission
	durableCalls int
}

func (b *durableAdmissionBlocker) DurableActionsEnabled() bool { return b.enabled }
func (b *durableAdmissionBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	b.durableCalls++
	b.request = req
	if budget != nil {
		copied := *budget
		b.budget = &copied
	}
	return b.outcome, b.err
}

func TestApplyBlockDurableAdmissionPreservesSourcePolicy(t *testing.T) {
	priorNow := autoBlockNow
	autoBlockNow = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	t.Cleanup(func() { autoBlockNow = priorNow })
	for _, source := range []string{BlockSourceScan, BlockSourceChallenge, BlockSourceIncident, BlockSourceCentral} {
		for _, configuredLimit := range []int{0, 7} {
			t.Run(source+map[int]string{0: "-default", 7: "-configured"}[configuredLimit], func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.MaxBlocksPerHour = configuredLimit
				blocker := &durableAdmissionBlocker{enabled: true, outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}}
				applyBlockTestSetup(t, blocker)
				req := ApplyBlockRequest{ActionID: "causal-request", FindingID: "finding-origin", IP: "203.0.113.70", EngineReason: "CSM auto-block: observed abuse", Reason: "observed abuse", TTL: time.Hour, Source: source}
				res, err := ApplyBlock(cfg, req)
				if err != nil || res.Outcome != firewall.BlockOutcomeLive || len(res.Findings) != 1 {
					t.Fatalf("result=%+v err=%v", res, err)
				}
				want := firewall.ActionRequest{ID: "causal-request", Operation: "block", Target: "203.0.113.70", Reason: "CSM auto-block: observed abuse", Source: source, FindingID: "finding-origin", TTL: time.Hour, Actor: "daemon", Automatic: true}
				if blocker.durableCalls != 1 || len(blocker.calls) != 0 || blocker.request != want {
					t.Fatalf("durable request lost attribution: %+v; legacy=%d durable=%d", blocker.request, len(blocker.calls), blocker.durableCalls)
				}
				var wantBudget *firewall.ScanAdmission
				if source == BlockSourceScan {
					limit := configuredLimit
					if limit == 0 {
						limit = config.DefaultMaxBlocksPerHour
					}
					wantBudget = &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: limit}
				}
				if !reflect.DeepEqual(blocker.budget, wantBudget) {
					t.Fatalf("wrong source policy: budget=%+v want=%+v", blocker.budget, wantBudget)
				}
				tracked := loadBlockState(cfg.StatePath)
				if len(tracked.IPs) != 1 || tracked.IPs[0].FindingID != "finding-origin" {
					t.Fatalf("durable live block omitted causal tracker evidence: %+v", tracked.IPs)
				}
			})
		}
	}
}

func TestApplyBlockDurableFailuresDoNotRecordSuccess(t *testing.T) {
	for _, failure := range []error{firewall.ErrStateCommitUncertain, firewall.ErrActionUnknown, firewall.ErrScanBudget} {
		t.Run(failure.Error(), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &durableAdmissionBlocker{enabled: true, outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive, err: failure}}
			applyBlockTestSetup(t, blocker)
			res, err := ApplyBlock(cfg, ApplyBlockRequest{ActionID: "request-uncertain", IP: "203.0.113.71", Source: BlockSourceScan, TTL: time.Hour})
			if !errors.Is(err, failure) || len(res.Findings) != 0 {
				t.Fatalf("failed admission reported success: %+v %v", res, err)
			}
			if blocker.durableCalls != 1 || len(blocker.calls) != 0 {
				t.Fatalf("wrong dispatch: durable=%d legacy=%d", blocker.durableCalls, len(blocker.calls))
			}
			if _, found := GetThreatDB().Lookup("203.0.113.71"); found {
				t.Fatal("uncertain action wrote a successful threat row")
			}
			if state := loadBlockState(cfg.StatePath); len(state.IPs) != 0 {
				t.Fatalf("uncertain action wrote tracker success: %+v", state.IPs)
			}
		})
	}
}

func TestApplyBlockVerifiedAuditFailureKeepsBookkeeping(t *testing.T) {
	for _, tc := range []struct {
		name     string
		durable  bool
		outcome  firewall.BlockOutcome
		wantLive bool
	}{
		{name: "verified", durable: true, outcome: firewall.BlockOutcomeLive, wantLive: true},
		{name: "replayed", durable: true, outcome: firewall.BlockOutcomeNoop},
		{name: "legacy", outcome: firewall.BlockOutcomeLive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.PermBlock = true
			deliveryErr := errors.New("audit sink unavailable")
			blocker := &durableAdmissionBlocker{enabled: tc.durable, outcomeStubBlocker: outcomeStubBlocker{outcome: tc.outcome, err: errors.Join(firewall.ErrActionAuditPending, deliveryErr)}}
			applyBlockTestSetup(t, blocker)
			res, err := ApplyBlock(cfg, ApplyBlockRequest{ActionID: "verified-request", FindingID: "finding-linked", IP: "203.0.113.73", EngineReason: "CSM auto-block: observed abuse", Reason: "observed abuse", Source: BlockSourceScan, TTL: time.Hour})
			if !errors.Is(err, firewall.ErrActionAuditPending) || !errors.Is(err, deliveryErr) {
				t.Fatalf("audit delivery failure was hidden: %v", err)
			}
			_, threatFound := GetThreatDB().Lookup("203.0.113.73")
			state := loadBlockState(cfg.StatePath)
			escalation := loadPermBlockTracker(cfg.StatePath)
			wantRows := 0
			if tc.wantLive {
				wantRows = 1
			}
			if threatFound != tc.wantLive || len(state.IPs) != wantRows || len(res.Findings) != wantRows || len(escalation.IPs["203.0.113.73"]) != wantRows {
				t.Fatalf("wrong verified bookkeeping: threat=%t tracker=%+v findings=%+v escalation=%+v", threatFound, state.IPs, res.Findings, escalation)
			}
			if tc.wantLive && (state.IPs[0].FindingID != "finding-linked" || state.IPs[0].ExpiresAt.Sub(state.IPs[0].BlockedAt) < 59*time.Minute) {
				t.Fatalf("verified block lost cause or expiry: %+v", state.IPs[0])
			}
		})
	}
}

func TestApplyBlockDisabledDurableAdmissionUsesLegacyDispatch(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &durableAdmissionBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeDryRun}}
	applyBlockTestSetup(t, blocker)
	res, err := ApplyBlock(cfg, ApplyBlockRequest{ActionID: "unused-request", IP: "203.0.113.72", EngineReason: "legacy reason", Source: BlockSourceScan, TTL: time.Hour})
	if err != nil || res.Outcome != firewall.BlockOutcomeDryRun || len(res.Findings) != 1 {
		t.Fatalf("legacy outcome changed: %+v %v", res, err)
	}
	if blocker.durableCalls != 0 || len(blocker.calls) != 1 || blocker.calls[0].reason != "legacy reason" {
		t.Fatalf("disabled durable path dispatched: durable=%d legacy=%+v", blocker.durableCalls, blocker.calls)
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 0 {
		t.Fatalf("legacy dry run wrote tracker: %+v", state.IPs)
	}
}
