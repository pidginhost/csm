//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// The writer can exit right after the write, so the processes behind it are
// named when the write is seen, not when the response runs.
func TestRestoredFileFindingCarriesTheWriterChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})
	var gotPID int
	var gotAt time.Time
	prev := restoreWriterChain
	restoreWriterChain = func(pid int, at time.Time) []int {
		gotPID, gotAt = pid, at
		return []int{writerPID, 700}
	}
	t.Cleanup(func() { restoreWriterChain = prev })
	seen := time.Now()

	if err := os.WriteFile(path, []byte(restoredPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, analyzerCh: make(chan fileEvent, 1)}
	fm.handleEvent(openRawFd(t, path), writerPID, FAN_CLOSE_WRITE)
	event := <-fm.analyzerCh
	if gotPID != writerPID || gotAt.Before(seen) || !gotAt.Equal(event.at) {
		t.Fatalf("chain not captured at event admission: pid=%d at=%v event=%v", gotPID, gotAt, event.at)
	}
	// The short-lived writer has exited while waiting in the analyzer queue.
	restoreWriterChain = func(int, time.Time) []int {
		t.Error("looked up the writer after event admission")
		return nil
	}
	fm.analyzeFile(event)
	close(ch)
	var found []alert.Finding
	for f := range ch {
		found = append(found, f)
	}

	got := restoredFindings(found)
	if len(got) != 1 || !reflect.DeepEqual(got[0].WriterChain, []int{writerPID, 700}) {
		t.Fatalf("restore findings = %+v, want the captured chain", got)
	}
	if !got[0].WriterObservedAt.Equal(event.at) {
		t.Fatalf("writer observation time = %v, want %v", got[0].WriterObservedAt, event.at)
	}
	if gotPID != writerPID || !gotAt.Equal(event.at) {
		t.Fatalf("chain captured for pid %d at %v, want pid %d at the event time %v", gotPID, gotAt, writerPID, event.at)
	}
}
