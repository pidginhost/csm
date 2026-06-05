package alert

import (
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDispatch_OffersEachFindingToReportHook(t *testing.T) {
	prev := ReportHook
	t.Cleanup(func() { SetReportHook(prev) })

	var mu sync.Mutex
	var seen []string
	SetReportHook(func(f Finding) {
		mu.Lock()
		seen = append(seen, f.Check)
		mu.Unlock()
	})

	findings := []Finding{
		{Check: "pam_bruteforce", Severity: Critical},
		{Check: "file_warning", Severity: Warning},
	}
	// Zero-value Config: no delivery channels enabled; Dispatch still offers
	// every finding to the report hook (gating happens inside the hook).
	cfg := &config.Config{}
	_ = Dispatch(cfg, findings)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(findings) {
		t.Fatalf("report hook saw %d findings, want %d (%v)", len(seen), len(findings), seen)
	}
}

func TestDispatch_NilReportHookIsSafe(t *testing.T) {
	prev := ReportHook
	SetReportHook(nil)
	t.Cleanup(func() { SetReportHook(prev) })
	if err := Dispatch(&config.Config{}, []Finding{{Check: "x", Severity: Critical}}); err != nil {
		t.Fatalf("dispatch with nil hook: %v", err)
	}
}

func TestDispatch_ReportHookPanicDoesNotAbortDispatch(t *testing.T) {
	prev := ReportHook
	SetReportHook(func(Finding) { panic("broken reporter") })
	t.Cleanup(func() { SetReportHook(prev) })

	if err := Dispatch(&config.Config{}, []Finding{{Check: "x", Severity: Critical}}); err != nil {
		t.Fatalf("dispatch with panicking hook: %v", err)
	}
}
