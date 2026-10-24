//go:build linux

package workerproc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The kernel removes a unit's cgroup about 10 ms after an OOM kill, before
// the daemon sees the worker die. The watch must read the kill at the
// kernel's notification and keep the verdict after the cgroup is gone.
func TestOOMWatchV2KeepsKillAfterCgroupRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "csm-parse-worker-mail0-1.service")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "memory.events")
	writeValue(t, events, "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	w, err := memoryCgroup{dir: dir, v2: true}.watchOOM()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.stop)
	rewriteInPlace(t, events, "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n")
	deadline := time.Now().Add(5 * time.Second)
	for !w.seen.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if !w.wait(5 * time.Second) {
		t.Fatal("OOM kill lost when the cgroup went away")
	}
}

func TestOOMWatchV2NoKillEndsAtRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "csm-parse-worker-mail0-2.service")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "memory.events")
	writeValue(t, events, "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	w, err := memoryCgroup{dir: dir, v2: true}.watchOOM()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.stop)
	rewriteInPlace(t, events, "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not end when the cgroup went away")
	}
	if w.seen.Load() {
		t.Fatal("a memory.events change without a kill read as an OOM kill")
	}
}

// rewriteInPlace changes a counter file the way the kernel does: in place, so
// an inotify watch on it stays. writeValue's rename would drop the watch.
func rewriteInPlace(t *testing.T, path, value string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt([]byte(value), 0); err != nil {
		t.Fatal(err)
	}
}

// On cgroup v1 the eventfd fires at an OOM and again at cgroup removal, which
// happens after rmdir. One count with the directory gone is the removal alone.
func TestOOMEventV1Verdict(t *testing.T) {
	for _, tc := range []struct {
		count uint64
		alive bool
		want  bool
	}{
		{1, true, true},
		{3, true, true},
		{1, false, false},
		{2, false, true},
	} {
		if got := oomFromV1Event(tc.count, tc.alive); got != tc.want {
			t.Errorf("count %d alive %v: %v, want %v", tc.count, tc.alive, got, tc.want)
		}
	}
}

func TestUnitOOMKilledUsesWatchVerdict(t *testing.T) {
	w := &oomWatch{done: make(chan struct{}), stop: func() {}}
	w.seen.Store(true)
	close(w.done)
	p := &unitProcess{cg: memoryCgroup{dir: filepath.Join(t.TempDir(), "gone"), v2: true}, oom: w}
	if !p.OOMKilled() {
		t.Fatal("watch saw the kill, but OOMKilled read the gone cgroup")
	}
}
