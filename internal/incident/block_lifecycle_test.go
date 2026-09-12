package incident

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func blockLifecycleCorrelator(t *testing.T, spray bool, callback func(string, string, time.Duration) bool) (*Correlator, alert.Finding) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	kind, check := KindWebAttack, "modsec_csm_block_escalation"
	if spray {
		kind, check = KindCredentialSpray, "email_auth_failure_realtime"
	}
	cfg := CorrelatorConfig{
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "high"},
		OnIncidentBlock: callback,
	}
	if spray {
		cfg.SpraySuppression = sprayTestConfig(true, false)
		cfg.SpraySuppression.BlockAtSeverity = "high"
		cfg.OnSprayBlock = callback
		cfg.OnIncidentBlock = func(string, string, time.Duration) bool { t.Error("spray reached generic block path"); return false }
	}
	c := NewCorrelator(cfg)
	c.now = func() time.Time { return now }
	c.Restore([]Incident{{
		ID: "inc_ladder", Status: StatusOpen, Kind: kind, Severity: alert.Critical,
		CorrelationKey: &Key{RemoteIP: "192.0.2.10"}, CreatedAt: now, UpdatedAt: now,
		Timeline:  []IncidentEvent{{Kind: "finding", Check: check, RemoteIP: "192.0.2.10"}},
		AutoBlock: AutoBlockState{Count: 1, LastAt: now.Add(-25 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}})
	return c, alert.Finding{Check: check, SourceIP: "192.0.2.10", Mailbox: "alice@example.com", Severity: alert.Critical, Timestamp: now}
}

func TestLapsedBlockCoalescesAndDeclinedCallbackKeepsRung(t *testing.T) {
	for _, spray := range []bool{false, true} {
		t.Run(map[bool]string{false: "generic", true: "spray"}[spray], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var mu sync.Mutex
			var calls []time.Duration
			live := false
			c, f := blockLifecycleCorrelator(t, spray, func(_, _ string, ttl time.Duration) bool {
				mu.Lock()
				calls = append(calls, ttl)
				first := len(calls) == 1
				mu.Unlock()
				if first {
					close(entered)
					<-release
				}
				return live
			})
			done := make(chan struct{})
			go func() { defer close(done); _, _, _ = c.OnFinding(f) }()
			<-entered
			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				wg.Go(func() { _, _, _ = c.OnFinding(f) })
			}
			wg.Wait()
			close(release)
			<-done
			inc, _ := c.Get("inc_ladder")
			if len(calls) != 1 || calls[0] != 7*24*time.Hour || inc.AutoBlock.Count != 1 {
				t.Fatalf("declined/coalesced block: calls=%v state=%+v", calls, inc.AutoBlock)
			}
			live = true
			_, _, _ = c.OnFinding(f)
			_, _, _ = c.OnFinding(f)
			inc, _ = c.Get("inc_ladder")
			if len(calls) != 2 || calls[1] != 7*24*time.Hour || inc.AutoBlock.Count != 2 {
				t.Fatalf("retry skipped rung or duplicated block: calls=%v state=%+v", calls, inc.AutoBlock)
			}
		})
	}
}

func TestPendingBlockCannotOverwriteOperatorOrClosedState(t *testing.T) {
	for _, spray := range []bool{false, true} {
		for _, change := range []string{"operator", "close", "reopen", "reopen-first", "restore"} {
			t.Run(map[bool]string{false: "generic", true: "spray"}[spray]+"/"+change, func(t *testing.T) {
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				c, f := blockLifecycleCorrelator(t, spray, func(string, string, time.Duration) bool { close(entered); <-release; return true })
				if change == "reopen-first" {
					inc, _ := c.Get("inc_ladder")
					inc.AutoBlock = AutoBlockState{}
					c.Restore([]Incident{inc})
				}
				go func() { defer close(done); _, _, _ = c.OnFinding(f) }()
				<-entered
				switch change {
				case "operator":
					if err := c.RecordOperatorBlock("inc_ladder", f.SourceIP, 0); err != nil {
						t.Error(err)
					}
				case "restore":
					inc, _ := c.Get("inc_ladder")
					c.Restore([]Incident{inc})
				default:
					if err := c.SetStatus("inc_ladder", StatusResolved, "closed"); err != nil {
						t.Error(err)
					}
					if change == "reopen" || change == "reopen-first" {
						if err := c.SetStatus("inc_ladder", StatusOpen, "reopened"); err != nil {
							t.Error(err)
						}
					}
				}
				before, _ := c.Get("inc_ladder")
				close(release)
				<-done
				after, _ := c.Get("inc_ladder")
				if after.AutoBlock != before.AutoBlock {
					t.Fatalf("pending callback overwrote state: before=%+v after=%+v", before.AutoBlock, after.AutoBlock)
				}
				if len(c.pendingSprayBlocks)+len(c.pendingIncidentBlocks) != 0 {
					t.Fatal("pending slot leaked")
				}
				if change == "reopen" || change == "reopen-first" {
					var cap blockCapture
					c.cfg.OnIncidentBlock, c.cfg.OnSprayBlock = cap.record, cap.record
					for i := 0; i < 3; i++ {
						f.Mailbox = string(rune('a'+i)) + "@example.com"
						_, _, _ = c.OnFinding(f)
					}
					if cap.len() != 1 || cap.calls[0].TTL != 24*time.Hour {
						t.Fatalf("reopened episode did not restart at first rung: %+v", cap.calls)
					}
				}
			})
		}
	}
}

func TestAutomaticCloseResetsBlockLadder(t *testing.T) {
	for _, closeBy := range []string{"idle", "age", "cap"} {
		t.Run(closeBy, func(t *testing.T) {
			c, _ := blockLifecycleCorrelator(t, false, nil)
			now := c.now().Add(48 * time.Hour)
			switch closeBy {
			case "idle":
				c.CloseStale(now, map[Kind]time.Duration{KindWebAttack: time.Hour}, false)
			case "age":
				c.CloseStaleByAge(now, time.Hour, 0)
			case "cap":
				c.Restore([]Incident{{ID: "inc_new", Status: StatusOpen, UpdatedAt: now}})
				c.EnforceActiveCap(now, 1, 0)
			}
			inc, _ := c.Get("inc_ladder")
			if inc.Status != StatusResolved || inc.AutoBlock != (AutoBlockState{}) {
				t.Fatalf("automatic close kept ladder: %+v", inc)
			}
		})
	}
}

func TestSprayPromotionSharesPendingBlockGuard(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var sprayCalls blockCapture
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "high"
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		AutoBlock:        IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "high"},
		OnIncidentBlock:  func(string, string, time.Duration) bool { close(entered); <-release; return true },
		OnSprayBlock:     sprayCalls.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	go func() {
		defer close(done)
		_, _, _ = c.OnFinding(alert.Finding{Check: "modsec_csm_block_escalation", SourceIP: "192.0.2.10", Severity: alert.Critical, Timestamp: now})
	}()
	<-entered
	sprayBurst(c, now, 0)
	if sprayCalls.len() != 0 {
		t.Error("promotion made a second firewall call while the generic block was pending")
	}
	close(release)
	<-done
	sprayBurst(c, now, 10)
	if sprayCalls.len() != 0 {
		t.Error("promotion lost the completed generic block")
	}
	incs := c.Snapshot()
	if len(incs) != 1 || incs[0].Kind != KindCredentialSpray || incs[0].AutoBlock.Count != 1 {
		t.Fatalf("promoted ladder state = %+v", incs)
	}
}
