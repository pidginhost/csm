package daemon

import (
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
	d := newTestDaemon(t)
	removed := stubRemovedFiles(t)
	first := removedFileFinding("obfuscated_php_realtime", time.Now())
	d.dispatchBatch([]alert.Finding{first})
	before, ok := d.store.EntryForKey(first.Key())
	if !ok {
		t.Fatal("setup: first report left no alert state")
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
