package yaraworker

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// A worker that started with a failed rule compile (scanner == nil,
// compileErr set) must be able to recover: a later OpReload, once the rules
// on disk are fixed, has to build a fresh scanner instead of no-op'ing
// forever. Before the fix, handler.Reload returned early on a nil scanner, so
// YARA stayed silently dead until the worker happened to crash.
func TestHandlerReloadRecoversFromNilScanner(t *testing.T) {
	rebuilt := &fakeScanner{ruleCount: 12}
	built := 0
	h := newRecoverableHandler(nil, func() (Scanner, error) {
		built++
		return rebuilt, nil
	}, "bad rule at line 3")

	// Before recovery: Ping is alive but reports the compile error + 0 rules.
	ping, _ := h.Ping()
	if !ping.Alive || ping.RuleCount != 0 || ping.CompileError == "" {
		t.Fatalf("pre-recovery ping = %+v, want alive + 0 rules + compile error", ping)
	}

	res, err := h.Reload(yaraipc.ReloadArgs{})
	if err != nil {
		t.Fatalf("Reload after fixed rules: %v", err)
	}
	if res.RuleCount != 12 {
		t.Errorf("Reload RuleCount = %d, want 12", res.RuleCount)
	}
	if built != 1 {
		t.Errorf("rebuild factory called %d times, want 1", built)
	}

	// After recovery: Ping reports the new rules and clears the compile error.
	ping, _ = h.Ping()
	if ping.RuleCount != 12 || ping.CompileError != "" {
		t.Errorf("post-recovery ping = %+v, want 12 rules + no compile error", ping)
	}

	// Scans now route to the rebuilt scanner.
	if _, err := h.ScanBytes(yaraipc.ScanBytesArgs{Data: []byte("x")}); err != nil {
		t.Fatalf("ScanBytes after recovery: %v", err)
	}
	if len(rebuilt.bytesCalls) != 1 {
		t.Errorf("scan did not reach the rebuilt scanner: %d calls", len(rebuilt.bytesCalls))
	}
}

// While the rules on disk are still broken, Reload must surface the compile
// error (so doForgeUpdate does not record a bogus success) and keep the error
// visible via Ping for the daemon to alert on.
func TestHandlerReloadStillFailingSurfacesError(t *testing.T) {
	h := newRecoverableHandler(nil, func() (Scanner, error) {
		return nil, errors.New("still bad at line 3")
	}, "bad rule at line 3")

	if _, err := h.Reload(yaraipc.ReloadArgs{}); err == nil {
		t.Fatal("Reload must return the compile error while rules stay broken")
	}
	ping, _ := h.Ping()
	if ping.CompileError == "" {
		t.Errorf("ping should still report a compile error, got %+v", ping)
	}
}

// The no-engine path (plain build / no rules dir): NewHandler(nil) has no
// rebuild factory, so Reload is a no-op with no error and Ping is alive with
// no compile error -- exactly the previous behaviour for that case.
func TestHandlerNilScannerNoRebuildIsNoop(t *testing.T) {
	h := NewHandler(nil)
	res, err := h.Reload(yaraipc.ReloadArgs{})
	if err != nil || res.RuleCount != 0 {
		t.Fatalf("no-engine Reload = (%+v, %v), want (0, nil)", res, err)
	}
	ping, _ := h.Ping()
	if !ping.Alive || ping.CompileError != "" {
		t.Errorf("no-engine ping = %+v, want alive + no compile error", ping)
	}
}
