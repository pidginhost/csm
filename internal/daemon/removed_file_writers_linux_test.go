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
	seen := time.Now().Add(-time.Second)

	if err := os.WriteFile(path, []byte(restoredPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, path), pid: writerPID, at: seen})
	close(ch)
	var found []alert.Finding
	for f := range ch {
		found = append(found, f)
	}

	got := restoredFindings(found)
	if len(got) != 1 || !reflect.DeepEqual(got[0].WriterChain, []int{writerPID, 700}) {
		t.Fatalf("restore findings = %+v, want the captured chain", got)
	}
	if gotPID != writerPID || !gotAt.Equal(seen) {
		t.Fatalf("chain captured for pid %d at %v, want pid %d at the event time %v", gotPID, gotAt, writerPID, seen)
	}
}
