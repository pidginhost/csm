//go:build linux

package firewall

import (
	"errors"
	"testing"
	"time"
)

// While an apply-confirmed window can roll the firewall back, admission's
// member checks, batches, probes and retirements are refused before they
// read or write anything (design C9). The refusal is not a state fault, so
// the owner holds and probes rather than repairing state. The read-only
// admission snapshot a forecast takes still answers. A hold that ends lets
// them run again.
func TestHeldBlockBatchesRefuseEveryCall(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	writes := f.countWrites(t)
	f.e.HoldBlockBatches(true)
	m := f.member("act_00112233445566778899aabbccddeeff", "203.0.113.10")
	calls := map[string]error{}
	_, calls["check"] = f.e.CheckBlockBatchEffects([]BlockMember{m})
	_, calls["apply"] = f.e.ApplyBlockBatch([]BlockMember{m})
	_, calls["retire"] = f.e.RetireBlockActions([]BlockAction{{Action: m.Action, IP: m.IP}})
	calls["probe"] = f.e.ProbeBlockState()
	for name, err := range calls {
		if !errors.Is(err, ErrConfirmPending) || errors.Is(err, ErrBlockBatchState) {
			t.Errorf("%s during a confirmation window = %v", name, err)
		}
	}
	if _, err := f.e.BlockAdmissionSnapshot([]BlockMember{m}, nil); err != nil {
		t.Errorf("a forecast snapshot during a confirmation window = %v", err)
	}
	if f.sends != 0 || *writes != 0 {
		t.Fatalf("a held engine sent %d batches and wrote state %d times", f.sends, *writes)
	}
	f.e.HoldBlockBatches(false)
	if err := f.e.ProbeBlockState(); err != nil {
		t.Fatalf("probe after the window = %v", err)
	}
}

// The hold takes the engine mutex, so a window opened while a batch is in
// flight waits for it, and the batch's rows land in the window's snapshot.
func TestHoldBlockBatchesWaitsForACallInFlight(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.mu.Lock()
	done := make(chan struct{})
	go func() {
		f.e.HoldBlockBatches(true)
		close(done)
	}()
	select {
	case <-done:
		f.e.mu.Unlock()
		t.Fatal("the hold did not wait for the call holding the engine")
	case <-time.After(50 * time.Millisecond):
	}
	f.e.mu.Unlock()
	<-done
	if err := f.e.ProbeBlockState(); !errors.Is(err, ErrConfirmPending) {
		t.Fatalf("probe after the hold = %v", err)
	}
}
