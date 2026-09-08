package attackdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A DB with no configured path has nowhere to persist to. The flat-file
// fallback joined that empty path with the file name, producing a relative
// path, so a flush wrote records.json and events.jsonl into whatever the
// working directory happened to be. Under `go test` that is the package
// source directory, so flushing littered the repository.
//
// Writing state into an unrelated directory is worse than not persisting:
// on a daemon it would scatter attack records wherever the process was
// started from, and leave the operator with no way to find them.
func TestFlushWithoutPathWritesNothingToWorkingDir(t *testing.T) {
	// Run in a scratch directory so a regression is contained and visible
	// here rather than as stray files in the source tree.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	if err := os.Chdir(scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Now()})
	if err := db.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("Flush created %s in the working directory", filepath.Join(scratch, e.Name()))
	}
}

// The guard must not break the case it exists to serve: a DB with a real
// path still persists.
func TestFlushWithPathStillPersists(t *testing.T) {
	dir := t.TempDir()
	db := NewForTest(nil)
	db.dbPath = dir
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Now()})
	if err := db.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("Flush with a configured path wrote nothing")
	}
}
