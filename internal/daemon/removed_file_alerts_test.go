package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

const removedTestPath = "/home/alice/public_html/wp-includes/Text/index.php"

type fakeRemovedFiles struct {
	seq     uint64
	removed map[string]checks.RemovedFile
}

func stubRemovedFiles(t *testing.T) *fakeRemovedFiles {
	t.Helper()
	fake := &fakeRemovedFiles{removed: map[string]checks.RemovedFile{}}
	prevSince, prevAt := removedFilesSince, removedFileAt
	removedFilesSince = func(after uint64) ([]checks.RemovedFile, uint64) {
		var out []checks.RemovedFile
		for _, r := range fake.removed {
			if r.Seq > after {
				out = append(out, r)
			}
		}
		return out, fake.seq
	}
	removedFileAt = func(path string) (checks.RemovedFile, bool) {
		r, ok := fake.removed[path]
		return r, ok
	}
	t.Cleanup(func() { removedFilesSince, removedFileAt = prevSince, prevAt })
	return fake
}

func (f *fakeRemovedFiles) remove(path string, at time.Time) {
	f.seq++
	f.removed[path] = checks.RemovedFile{Path: path, SHA256: "digest", Size: 1, At: at, Action: "quarantine", Seq: f.seq}
}

func removedFileFinding(check string, observed time.Time) alert.Finding {
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     check,
		Message:   "Obfuscated PHP detected: " + removedTestPath,
		FilePath:  removedTestPath,
		Timestamp: observed,
	}
}

// A loop that writes a removed file back produces the finding CSM already
// reported. Without clearing the alert state at removal, the repeat window
// hides every return for a day.
func TestDispatchBatchReportsAFileAgainAfterCSMRemovedIt(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	removed := stubRemovedFiles(t)
	first := removedFileFinding("obfuscated_php_realtime", time.Now())
	d.dispatchBatch([]alert.Finding{first})
	before, ok := d.store.EntryForKey(first.Key())
	if !ok {
		t.Fatal("setup: first report left no alert state")
	}
	if got := hook.count(first.Message); got != 1 {
		t.Fatalf("initial notifications = %d, want 1", got)
	}

	removed.remove(removedTestPath, time.Now())
	d.dispatchBatch([]alert.Finding{removedFileFinding("obfuscated_php_realtime", time.Now())})

	after, ok := d.store.EntryForKey(first.Key())
	if !ok {
		t.Fatal("the file's return left no alert state")
	}
	if !after.FirstSeen.After(before.FirstSeen) {
		t.Fatalf("return treated as a repeat: first seen %v, before removal %v", after.FirstSeen, before.FirstSeen)
	}
	if got := hook.count(first.Message); got != 2 {
		t.Fatalf("notifications after return = %d, want 2", got)
	}
}

// A scan responds before alert delivery sees its findings, and another batch
// can consume the removal first. State written for a finding observed before
// its file was removed must still be cleared, while a later observation of
// the file coming back keeps its state.
func TestDispatchBatchClearsFindingsObservedBeforeTheirFileWasRemoved(t *testing.T) {
	d := newTestDaemon(t)
	removed := stubRemovedFiles(t)
	observed := time.Now().Add(-time.Minute)
	removed.remove(removedTestPath, observed.Add(time.Second))
	d.dispatchBatch([]alert.Finding{{Severity: alert.Warning, Check: "unrelated", Message: "takes the removal first", Timestamp: time.Now()}})

	scan := removedFileFinding("obfuscated_php", observed)
	d.dispatchBatch([]alert.Finding{scan})
	if entry, ok := d.store.EntryForKey(scan.Key()); ok {
		t.Fatalf("alert state from before the removal survived: %+v", entry)
	}

	d.dispatchBatch([]alert.Finding{removedFileFinding("obfuscated_php", time.Now())})
	if _, ok := d.store.EntryForKey(scan.Key()); !ok {
		t.Fatal("the return's own alert state was cleared")
	}
}

// The initial scan runs outside dispatchBatch. Its removals must clear state
// without waiting for another batch, which may not arrive before shutdown.
func TestInitialScanClearsRemovedFileAlerts(t *testing.T) {
	for _, when := range []string{"before delivery", "during delivery"} {
		t.Run(when, func(t *testing.T) {
			cfg, hook := emailRepeatSetup(t)
			d := openRepeatDaemon(t, cfg)
			removed := stubRemovedFiles(t)
			f := removedFileFinding("obfuscated_php", time.Now())
			wantNotifications := 1
			if when == "before delivery" {
				d.dispatchBatch([]alert.Finding{f})
				removed.remove(f.FilePath, time.Now())
				wantNotifications++
			} else {
				hook.onSend = func() { removed.remove(f.FilePath, time.Now()) }
			}

			d.respondToInitialScan(cfg, []alert.Finding{f})
			hook.onSend = nil

			if got := hook.count(f.Message); got != wantNotifications {
				t.Errorf("initial scan notifications = %d, want %d", got, wantNotifications)
			}
			if entry, ok := d.store.EntryForKey(f.Key()); ok {
				t.Fatalf("initial scan left removed file muted: %+v", entry)
			}
			returned := removedFileFinding(f.Check, time.Now())
			d.dispatchBatch([]alert.Finding{returned})
			if got := hook.count(f.Message); got != wantNotifications+1 {
				t.Fatalf("notifications after return = %d, want %d", got, wantNotifications+1)
			}
			if _, ok := d.store.EntryForKey(f.Key()); !ok {
				t.Fatal("return's own alert state was cleared")
			}
		})
	}
}

// Startup replay can overlap live dispatch. An older snapshot finishing last
// may repeat a clear, but must never advance past an unconsumed removal.
func TestConcurrentRemovalSnapshotsDoNotSkipAlerts(t *testing.T) {
	d := newTestDaemon(t)
	first := removedFileFinding("obfuscated_php", time.Now())
	second := first
	second.Message = "another file"
	second.FilePath = removedTestPath + ".second"
	batch := []alert.Finding{first, second}
	d.store.Update(batch)
	removals := []checks.RemovedFile{
		{Path: first.FilePath, Seq: 1},
		{Path: second.FilePath, Seq: 2},
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	prev := removedFilesSince
	t.Cleanup(func() { removedFilesSince = prev })
	var calls atomic.Uint64
	removedFilesSince = func(after uint64) ([]checks.RemovedFile, uint64) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return removals[:1], 1
		}
		var newer []checks.RemovedFile
		for _, r := range removals {
			if r.Seq > after {
				newer = append(newer, r)
			}
		}
		return newer, removals[len(removals)-1].Seq
	}
	go func() {
		defer close(done)
		d.forgetRemovedFileAlerts(nil)
	}()
	<-started
	d.forgetRemovedFileAlerts(nil)
	close(release)
	<-done
	if got := d.store.FilterNew(batch); len(got) != 2 {
		t.Fatalf("concurrent snapshots left alerts muted: %+v", got)
	}

	third := first
	third.Message = "later file"
	third.FilePath = removedTestPath + ".third"
	d.store.Update([]alert.Finding{third})
	removals = append(removals, checks.RemovedFile{Path: third.FilePath, Seq: 3})
	d.forgetRemovedFileAlerts(nil)
	if got := d.store.FilterNew([]alert.Finding{third}); len(got) != 1 {
		t.Fatal("overlapping snapshots skipped the later removal")
	}
}
