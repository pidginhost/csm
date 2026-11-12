package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// useRemovedFilesState points the ledger at a fresh state directory and
// returns a function that simulates a daemon restart: memory is lost and the
// ledger is loaded again from that directory.
func useRemovedFilesState(t *testing.T) (dir string, restart func()) {
	t.Helper()
	dir = t.TempDir()
	removedFiles.Lock()
	prevPath, prevByPath := removedFiles.path, removedFiles.byPath
	removedFiles.byPath = nil
	removedFiles.Unlock()
	t.Cleanup(func() {
		removedFiles.Lock()
		removedFiles.path, removedFiles.byPath = prevPath, prevByPath
		removedFiles.Unlock()
	})
	LoadRemovedFiles(dir)
	return dir, func() {
		removedFiles.Lock()
		removedFiles.byPath = nil
		removedFiles.path = ""
		removedFiles.Unlock()
		LoadRemovedFiles(dir)
	}
}

// A restart used to forget every removal, so a loop that wrote a file back
// after it was no longer recognised as restoring removed content.
func TestRemovedFilesSurviveARestart(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 42, "clean")
	before, _ := RemovedFileAt(path)

	restart()

	got, ok := RemovedFileAt(path)
	if !ok {
		t.Fatal("removal forgotten across a restart")
	}
	if got.Path != before.Path || got.SHA256 != "digest" || got.Size != 42 || got.Action != "clean" || !got.At.Equal(before.At) {
		t.Fatalf("restored removal = %+v, want %+v", got, before)
	}
	if got.RestoreKey() != before.RestoreKey() {
		t.Fatalf("restore key changed across a restart: %q -> %q", before.RestoreKey(), got.RestoreKey())
	}
}

// Alert state was cleared when the removal happened. A restart must not clear
// it again: by then it may belong to the file's return.
func TestLoadedRemovalsAreNotReportedAsNew(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 1, "quarantine")
	_, seq := RemovedFilesSince(0)

	restart()

	if newer, _ := RemovedFilesSince(0); len(newer) != 0 {
		t.Fatalf("loaded removals reported as new: %+v", newer)
	}
	later := filepath.Join(t.TempDir(), "later.php")
	rememberRemovedFile(later, "digest", 1, "quarantine")
	newer, next := RemovedFilesSince(seq)
	if len(newer) != 1 || newer[0].Path != later || next <= seq {
		t.Fatalf("a removal after the restart = %+v (next %d after %d), want only %s", newer, next, seq, later)
	}
}

func TestForgottenRemovalStaysForgottenAfterRestart(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 1, "quarantine")
	ForgetRemovedFile(path)

	restart()

	if got, ok := RemovedFileAt(path); ok {
		t.Fatalf("an operator restore came back after a restart: %+v", got)
	}
}

func TestExpiredRemovalsAreNotLoaded(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	useRemovedFilesClock(t, &now)
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 1, "quarantine")

	now = now.Add(removedFileMemory)
	restart()

	removedFiles.RLock()
	_, kept := removedFiles.byPath[filepath.Clean(path)]
	removedFiles.RUnlock()
	if kept {
		t.Fatal("an expired removal was loaded")
	}
}

// The state file is root's, but a damaged one must not stop the daemon or
// plant entries that misdirect a response.
func TestDamagedRemovedFilesStateIsIgnored(t *testing.T) {
	dir, restart := useRemovedFilesState(t)
	state := filepath.Join(dir, removedFilesStateName)
	good := filepath.Join(t.TempDir(), "good.php")
	at := removedFilesNow().UTC().Format(time.RFC3339Nano)
	for name, content := range map[string]string{
		"not json": "{",
		"bad entries": `[
			{"path": "relative.php", "sha256": "d", "size": 1, "at": "` + at + `", "action": "quarantine"},
			{"path": "/x/unknown.php", "sha256": "d", "size": 1, "at": "` + at + `", "action": "delete"},
			{"path": "/x/negative.php", "sha256": "d", "size": -1, "at": "` + at + `", "action": "clean"},
			{"path": "/x/no-time.php", "sha256": "d", "size": 1, "action": "clean"},
			{"path": "` + good + `", "sha256": "d", "size": 1, "at": "` + at + `", "action": "clean"}
		]`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(state, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			restart()
			removedFiles.RLock()
			loaded := len(removedFiles.byPath)
			removedFiles.RUnlock()
			want := 0
			if name == "bad entries" {
				want = 1
				if _, ok := RemovedFileAt(good); !ok {
					t.Fatal("the valid entry was not loaded")
				}
			}
			if loaded != want {
				t.Fatalf("loaded %d entries, want %d", loaded, want)
			}
		})
	}
}

func TestRemovedFilesStateIsPrivate(t *testing.T) {
	dir, _ := useRemovedFilesState(t)
	rememberRemovedFile(filepath.Join(t.TempDir(), "index.php"), "digest", 1, "quarantine")
	info, err := os.Stat(filepath.Join(dir, removedFilesStateName))
	if err != nil {
		t.Fatalf("removal not saved: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode %o, want 600", perm)
	}
}
