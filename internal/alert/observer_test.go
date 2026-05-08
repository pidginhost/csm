package alert

import (
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestRegisterFindingObserverCalledOnDispatch(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var calls atomic.Int64
	cancel := RegisterFindingObserver(func(f Finding) {
		calls.Add(1)
	})
	defer cancel()

	cfg := &config.Config{Hostname: "test"}
	emitAudit(cfg, []Finding{{Check: "x", Message: "y"}, {Check: "z", Message: "w"}})

	if got := calls.Load(); got != 2 {
		t.Errorf("observer calls: want 2, got %d", got)
	}
}

func TestRegisterFindingObserverCancelStops(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var calls atomic.Int64
	cancel := RegisterFindingObserver(func(f Finding) { calls.Add(1) })
	cancel()

	cfg := &config.Config{Hostname: "test"}
	emitAudit(cfg, []Finding{{Check: "x"}})

	if calls.Load() != 0 {
		t.Errorf("observer must not fire after cancel; got %d", calls.Load())
	}
}

func TestObserverPanicIsolated(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	var goodCalls atomic.Int64
	cancelBad := RegisterFindingObserver(func(f Finding) { panic("boom") })
	defer cancelBad()
	cancelGood := RegisterFindingObserver(func(f Finding) { goodCalls.Add(1) })
	defer cancelGood()

	cfg := &config.Config{Hostname: "test"}
	emitAudit(cfg, []Finding{{Check: "x"}})

	if goodCalls.Load() != 1 {
		t.Errorf("panicking observer must not stop fan-out; goodCalls=%d", goodCalls.Load())
	}
}
