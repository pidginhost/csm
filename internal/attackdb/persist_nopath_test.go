package attackdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
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
	scratch := t.TempDir()
	t.Chdir(scratch)
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })

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
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })
	dir := t.TempDir()
	db := NewForTest(nil)
	db.dbPath = dir
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Now()})
	if err := db.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	reloaded := NewForTest(nil)
	reloaded.dbPath = dir
	reloaded.load()
	if rec := reloaded.LookupIP("198.51.100.23"); rec == nil || rec.EventCount != 1 {
		t.Fatalf("persisted record = %+v, want one event", rec)
	}
	if events := reloaded.QueryEvents("198.51.100.23", 10); len(events) != 1 || events[0].CheckName != "webshell" {
		t.Fatalf("persisted events = %+v, want one webshell finding", events)
	}
	db.RemoveIP("198.51.100.23")
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded.load()
	if reloaded.LookupIP("198.51.100.23") != nil {
		t.Fatal("removed record survived reload")
	}
	if events := reloaded.QueryEvents("198.51.100.23", 10); len(events) != 1 {
		t.Fatalf("forget erased event history: %+v", events)
	}
}

func TestWithoutPathIgnoresWorkingDirectoryState(t *testing.T) {
	t.Chdir(t.TempDir())
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })
	files := map[string]string{
		recordsFile: `{"198.51.100.23":{"ip":"198.51.100.23","event_count":7}}`,
		eventsFile:  "{\"ip\":\"198.51.100.23\",\"check\":\"webshell\"}\n",
	}
	for path, data := range files {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	db := NewForTest(nil)
	db.load()
	if db.LookupIP("198.51.100.23") != nil {
		t.Fatal("loaded unrelated working-directory record")
	}
	if events := db.QueryEvents("198.51.100.23", 10); len(events) != 0 {
		t.Fatalf("read unrelated working-directory events: %+v", events)
	}
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Now()})
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if rec := db.LookupIP("198.51.100.23"); rec == nil || rec.EventCount != 1 {
		t.Fatalf("in-memory record lost during flush: %+v", rec)
	}
	for path, want := range files {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("working-directory file %s changed: %q, %v", path, got, err)
		}
	}
}

func TestWithoutPathStillUsesBbolt(t *testing.T) {
	_, cleanup := setupBboltStore(t)
	defer cleanup()
	t.Chdir(t.TempDir())
	db := NewForTest(nil)
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Now()})
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded := NewForTest(nil)
	reloaded.load()
	if rec := reloaded.LookupIP("198.51.100.23"); rec == nil || rec.EventCount != 1 {
		t.Fatalf("bbolt record lost with no flat-file path: %+v", rec)
	}
	if events := reloaded.QueryEvents("198.51.100.23", 10); len(events) != 1 || events[0].CheckName != "webshell" {
		t.Fatalf("bbolt events lost with no flat-file path: %+v", events)
	}
	entries, err := os.ReadDir(".")
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected working-directory state: %v, %v", entries, err)
	}
}
