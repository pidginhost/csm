package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func stubQueueCompanionSweeps(t *testing.T) *[][]alert.Finding {
	t.Helper()
	var calls [][]alert.Finding
	prev := queueCompanionSweeps
	queueCompanionSweeps = func(findings []alert.Finding) {
		calls = append(calls, append([]alert.Finding(nil), findings...))
	}
	t.Cleanup(func() { queueCompanionSweeps = prev })
	return &calls
}

func companionTrigger(path string) alert.Finding {
	return alert.Finding{
		Severity: alert.Critical,
		Check:    "yara_match_realtime",
		Message:  "YARA rule match [kit_loader]: " + path,
		FilePath: path,
	}
}

func queuedPaths(calls [][]alert.Finding) map[string]int {
	out := map[string]int{}
	for _, call := range calls {
		for _, f := range call {
			out[f.FilePath]++
		}
	}
	return out
}

// Every finding the dispatcher treats as new and unsuppressed reaches the
// companion sweep, whichever detector produced it. An alert already sent and
// a suppressed finding do not.
func TestDispatchBatchQueuesCompanionSweeps(t *testing.T) {
	d := newTestDaemon(t)
	calls := stubQueueCompanionSweeps(t)
	if err := d.store.SaveSuppressions([]state.SuppressionRule{{Check: "yara_match_scheduled"}}); err != nil {
		t.Fatal(err)
	}

	first := companionTrigger("/home/alice/public_html/wp-content/themes/t/assets/loader-1.php")
	muted := alert.Finding{
		Severity: alert.Critical,
		Check:    "yara_match_scheduled",
		Message:  "YARA rule match [kit_loader]: /home/bob/public_html/x.php",
		FilePath: "/home/bob/public_html/x.php",
	}
	d.dispatchBatch([]alert.Finding{first, muted})
	d.dispatchBatch([]alert.Finding{first})

	got := queuedPaths(*calls)
	if got[first.FilePath] != 1 {
		t.Fatalf("queued = %v, want %s exactly once", got, first.FilePath)
	}
	if got[muted.FilePath] != 0 {
		t.Fatalf("queued = %v, a suppressed finding must not start a sweep", got)
	}
}

func TestInitialScanQueuesCompanionSweeps(t *testing.T) {
	d := newTestDaemon(t)
	calls := stubQueueCompanionSweeps(t)
	f := companionTrigger("/home/alice/public_html/loader.php")
	d.respondToInitialScan(d.currentCfg(), []alert.Finding{f})
	if got := queuedPaths(*calls)[f.FilePath]; got != 1 {
		t.Fatalf("initial scan queued %d sweeps, want 1", got)
	}
}
