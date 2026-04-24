package daemon

import (
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

func TestHandleBaselineNeedsConfirmWhenHistoryExists(t *testing.T) {
	d := newDaemonForListener(t)
	// Seed history so the confirm gate triggers. Short-circuit
	// happens before checks.RunAll, so this test stays safe.
	seedHistoryForBaselineTest(t, d, 3)

	listener := &ControlListener{d: d}
	argsJSON, _ := json.Marshal(control.BaselineArgs{Confirm: false})
	raw, err := listener.handleBaseline(argsJSON)
	if err != nil {
		t.Fatalf("handleBaseline: %v", err)
	}
	r := raw.(control.BaselineResult)
	if !r.NeedsConfirm {
		t.Fatalf("NeedsConfirm=false; expected true when history count > 0 and Confirm=false")
	}
	if r.HistoryCleared != 3 {
		t.Errorf("HistoryCleared=%d; want 3 (count that WOULD be cleared)", r.HistoryCleared)
	}
}

// TestHandleBaselineRunsWhenConfirmed would need to drive checks.RunAll
// to completion, which fans out real host scans (processes, /proc, etc.)
// and hangs a unit test for several minutes. See the similar rationale
// for tier.run tests in control_handlers_test.go (around the
// newListenerForFuzz comment). Behaviour verified by code inspection
// and by the end-of-phase e2e smoke run.

// seedHistoryForBaselineTest plumbs a bbolt store.Global() for the test
// and appends n findings so HistoryCount() returns n. newDaemonForListener
// only wires up the in-memory state.Store; the confirm gate reads from
// store.Global(), so we open a dedicated bbolt DB under t.TempDir and
// register it for the duration of the test.
func seedHistoryForBaselineTest(t *testing.T, d *Daemon, n int) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})

	findings := make([]alert.Finding, n)
	for i := range findings {
		findings[i] = alert.Finding{
			Severity: alert.Warning,
			Check:    "test",
			Message:  "seeded",
		}
	}
	d.store.AppendHistory(findings)
}
