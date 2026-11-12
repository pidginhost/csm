package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// useRemovedFilesState points the ledger at a fresh state directory and
// returns a function that simulates a daemon restart: memory is lost and the
// ledger is loaded again from that directory.
func useRemovedFilesState(t *testing.T) (dir string, restart func()) {
	t.Helper()
	dir = t.TempDir()
	removedFiles.Lock()
	prevPath, prevByPath, prevSeq := removedFiles.path, removedFiles.byPath, removedFiles.seq
	removedFiles.byPath = nil
	removedFiles.seq = 0
	removedFiles.Unlock()
	t.Cleanup(func() {
		removedFiles.Lock()
		removedFiles.path, removedFiles.byPath, removedFiles.seq = prevPath, prevByPath, prevSeq
		removedFiles.Unlock()
	})
	LoadRemovedFiles(dir)
	return dir, func() {
		removedFiles.Lock()
		removedFiles.byPath = nil
		removedFiles.seq = 0
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
	rememberRemovedFile(path, strings.Repeat("a", 64), 42, "clean")
	before, _ := RemovedFileAt(path)

	restart()

	got, ok := RemovedFileAt(path)
	if !ok {
		t.Fatal("removal forgotten across a restart")
	}
	if got.Path != before.Path || got.SHA256 != strings.Repeat("a", 64) || got.Size != 42 || got.Action != "clean" || !got.At.Equal(before.At) {
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
	rememberRemovedFile(path, strings.Repeat("a", 64), 1, "quarantine")
	_, seq := RemovedFilesSince(0)
	if seq != 1 {
		t.Fatalf("first sequence = %d", seq)
	}

	restart()

	if newer, _ := RemovedFilesSince(0); len(newer) != 0 {
		t.Fatalf("loaded removals reported as new: %+v", newer)
	}
	later := filepath.Join(t.TempDir(), "later.php")
	rememberRemovedFile(later, strings.Repeat("a", 64), 1, "quarantine")
	newer, next := RemovedFilesSince(0)
	if len(newer) != 1 || newer[0].Path != later || next != 1 {
		t.Fatalf("a removal after the restart = %+v (next %d after %d), want only %s", newer, next, seq, later)
	}
}

func TestForgottenRemovalStaysForgottenAfterRestart(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, strings.Repeat("a", 64), 1, "quarantine")
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
	rememberRemovedFile(path, strings.Repeat("a", 64), 1, "quarantine")

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
		"not json":     "{",
		"invalid utf8": `[{"path":"/example/` + string([]byte{0xff}) + `.php","size":1,"at":"` + at + `","action":"clean"}]`,
		"bad entries": `[
			{"path": "relative.php", "sha256": "` + strings.Repeat("a", 64) + `", "size": 1, "at": "` + at + `", "action": "quarantine"},
			{"path": "/x/unknown.php", "sha256": "` + strings.Repeat("a", 64) + `", "size": 1, "at": "` + at + `", "action": "delete"},
			{"path": "/x/negative.php", "sha256": "` + strings.Repeat("a", 64) + `", "size": -1, "at": "` + at + `", "action": "clean"},
			{"path": "/x/no-time.php", "sha256": "` + strings.Repeat("a", 64) + `", "size": 1, "action": "clean"},
			{"path": "` + good + `", "sha256": "` + strings.Repeat("a", 64) + `", "size": 1, "at": "` + at + `", "action": "clean"}
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
	rememberRemovedFile(filepath.Join(t.TempDir(), "index.php"), strings.Repeat("a", 64), 1, "quarantine")
	info, err := os.Stat(filepath.Join(dir, removedFilesStateName))
	if err != nil {
		t.Fatalf("removal not saved: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode %o, want 600", perm)
	}
}

func TestRemovedFilesRejectUnsafeState(t *testing.T) {
	for _, kind := range []string{"symlink", "permissions", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir, restart := useRemovedFilesState(t)
			path := filepath.Join(t.TempDir(), "target.php")
			state := filepath.Join(dir, removedFilesStateName)
			entry := RemovedFile{Path: path, SHA256: strings.Repeat("a", 64), Size: 1, At: time.Now(), Action: "quarantine"}
			data, err := json.Marshal([]RemovedFile{entry})
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "other.json")
				if err := os.WriteFile(target, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, state); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(state, 0600); err != nil {
					t.Fatal(err)
				}
				fd, err := unix.Open(state, unix.O_RDWR|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := unix.Write(fd, data); err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() { time.Sleep(100 * time.Millisecond); _ = unix.Close(fd); close(done) }()
				defer func() { <-done }()
			default:
				if kind == "oversize" {
					data = append(data, []byte(strings.Repeat(" ", 64<<20))...)
				}
				if err := os.WriteFile(state, data, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "permissions" {
					if err := os.Chmod(state, 0666); err != nil {
						t.Fatal(err)
					}
				}
			}
			restart()
			if got, ok := RemovedFileAt(path); ok {
				t.Fatalf("unsafe state authorized a response: %+v", got)
			}
		})
	}
}

func TestRemovedFilesRejectInvalidEvidence(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	useRemovedFilesClock(t, &now)
	for _, kind := range []string{"future", "unclean path", "nul path", "invalid digest"} {
		t.Run(kind, func(t *testing.T) {
			dir, restart := useRemovedFilesState(t)
			entry := RemovedFile{Path: "/example/target.php", SHA256: strings.Repeat("a", 64), Size: 1, At: now, Action: "clean"}
			switch kind {
			case "future":
				entry.At = now.Add(time.Hour)
			case "unclean path":
				entry.Path = "/example/link/../target.php"
			case "nul path":
				entry.Path += "\x00"
			case "invalid digest":
				entry.SHA256 = "not-a-digest"
			}
			data, err := json.Marshal([]RemovedFile{entry})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, removedFilesStateName), data, 0600); err != nil {
				t.Fatal(err)
			}
			restart()
			removedFiles.RLock()
			count := len(removedFiles.byPath)
			removedFiles.RUnlock()
			if count != 0 {
				t.Fatalf("loaded %d invalid removals", count)
			}
		})
	}
}

func TestConcurrentRemovedFilesPersistLatestState(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		path := filepath.Join(t.TempDir(), "target.php")
		wg.Go(func() {
			rememberRemovedFile(path, strings.Repeat("a", 64), 1, "quarantine")
			ForgetRemovedFile(path)
		})
	}
	wg.Wait()
	restart()
	removedFiles.RLock()
	count := len(removedFiles.byPath)
	removedFiles.RUnlock()
	if count != 0 {
		t.Fatalf("restart resurrected %d forgotten removals", count)
	}
}

// Stat metadata is copied so this ownership check also runs without root.
type removedStateInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i removedStateInfo) Sys() any { return &i.stat }

func TestRemovedFilesStateRejectsForeignOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !privateRemovedFilesState(info) {
		t.Fatal("rejected private daemon-owned state")
	}
	foreign := removedStateInfo{FileInfo: info, stat: *info.Sys().(*syscall.Stat_t)}
	foreign.stat.Uid ^= 1
	if privateRemovedFilesState(foreign) {
		t.Fatal("accepted foreign-owned state")
	}
}

func TestRemovedFilesPreserveNonUTF8Paths(t *testing.T) {
	_, restart := useRemovedFilesState(t)
	path := filepath.Join(t.TempDir(), "target-\xff.php")
	rememberRemovedFile(path, strings.Repeat("a", 64), 1, "quarantine")
	before, _ := RemovedFileAt(path)
	restart()
	got, ok := RemovedFileAt(path)
	if !ok || got.Path != path || got.RestoreKey() != before.RestoreKey() {
		t.Fatal("restart changed the removed path or its response key")
	}
	alias := strings.ToValidUTF8(path, "\ufffd")
	if _, ok := RemovedFileAt(alias); ok {
		t.Fatal("restart redirected removal evidence to a different filename")
	}
}

func TestRemovedFilesRejectConflictingPaths(t *testing.T) {
	dir, restart := useRemovedFilesState(t)
	entry := savedRemoval(RemovedFile{Path: "/example/one.php", SHA256: strings.Repeat("a", 64), Size: 1, At: time.Now(), Action: "quarantine"})
	entry.PathBytes = []byte("/example/two.php")
	data, err := json.Marshal([]savedRemovedFile{entry})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, removedFilesStateName), data, 0600); err != nil {
		t.Fatal(err)
	}
	restart()
	removedFiles.RLock()
	count := len(removedFiles.byPath)
	removedFiles.RUnlock()
	if count != 0 {
		t.Fatal("ambiguous paths authorized a response")
	}
}

func TestLoadedRemovalStillBindsTheContentResponse(t *testing.T) {
	for _, action := range []string{"clean", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			_, restart := useRemovedFilesState(t)
			path := filepath.Join(realTempDir(t), "target.php")
			content := []byte("removed content")
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(content)
			rememberRemovedFile(path, hex.EncodeToString(digest[:]), int64(len(content)), action)
			before, _ := RemovedFileAt(path)
			restart()
			got, matched := restoredFileResponseInfo(path, before.RestoreKey(), info)
			if matched == nil || got.Action != action || got.Seq != 0 {
				t.Fatalf("loaded removal failed to bind the response: %+v", got)
			}
			// Keep the length so digest validation, not the size gate, refuses it.
			if writeErr := os.WriteFile(path, []byte("changed content"), 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			changed, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, matched := restoredFileResponseInfo(path, before.RestoreKey(), changed); matched != nil {
				t.Fatal("loaded removal authorized different bytes")
			}
		})
	}
}
