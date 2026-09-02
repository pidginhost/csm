package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A finding still queued at shutdown used to be written to history only.
// For realtime-only checks nothing re-detects it after a restart, so the
// auto-response it should have triggered was lost for good. The batch is now
// parked and replayed through the full dispatch pipeline at the next start.
func TestPendingFindingsAtShutdownAreDispatchedAtNextStart(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	stopping := New(&config.Config{StatePath: dir}, st, nil, "")
	stopping.persistPendingFindingsOnShutdown([]alert.Finding{{
		Severity:  alert.Critical,
		Check:     "webshell_realtime",
		FilePath:  "/home/acct/public_html/shell.php",
		Message:   "webshell written at shutdown",
		Timestamp: time.Now(),
	}})

	previousHook := alert.CentralHook
	var dispatched atomic.Int64
	alert.SetCentralHook(func(alert.Finding) { dispatched.Add(1) })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })

	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	starting := New(&config.Config{StatePath: dir}, reopened, nil, "")
	starting.replayPendingFindings()

	if n := dispatched.Load(); n != 1 {
		t.Fatalf("dispatched %d findings from the parked shutdown batch, want 1", n)
	}
	if left := reopened.TakePendingFindings(); len(left) != 0 {
		t.Fatalf("%d findings still parked after replay", len(left))
	}
}
