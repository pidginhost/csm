//go:build linux

package workerproc

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type oomEventReader func([]byte) (int, error)

func (f oomEventReader) Read(p []byte) (int, error) { return f(p) }

// Removal can happen after the OOM read resets eventfd but before stat.
// Its notification then arrives in a separate read, not in the first count.
func TestOOMWatchV1RemovalBetweenReadAndStat(t *testing.T) {
	for _, tc := range []struct {
		counts []uint64
		want   bool
	}{
		{[]uint64{1, 1}, true},
		{[]uint64{2}, true},
		{[]uint64{1}, false},
	} {
		w := &oomWatch{}
		read := 0
		ev := oomEventReader(func(p []byte) (int, error) {
			if read == len(tc.counts) {
				return 0, io.EOF
			}
			binary.NativeEndian.PutUint64(p, tc.counts[read])
			read++
			return 8, nil
		})
		w.readOOMv1(ev, func() bool { return false })
		if got := w.seen.Load(); got != tc.want {
			t.Errorf("event counts %v after removal: OOM = %v, want %v", tc.counts, got, tc.want)
		}
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

// A quiet cgroup may never notify the watcher. Closing its descriptor must
// still unblock the reader and release every watch on repeated launches.
// Only cgroup v1 has a watch; v2 reads the slice counter.
func TestOOMWatchStopReleasesResources(t *testing.T) {
	dir := t.TempDir()
	writeValue(t, filepath.Join(dir, "memory.oom_control"), "oom_kill 0\n")
	writeValue(t, filepath.Join(dir, "cgroup.event_control"), "")
	before := openFDs(t)
	for range 10 {
		w, err := (memoryCgroup{dir: dir}).watchOOM()
		if err != nil {
			t.Fatal(err)
		}
		w.stop()
		select {
		case <-w.done:
		case <-time.After(time.Second):
			t.Fatal("stopped watch left a blocked reader")
		}
		if w.seen.Load() {
			t.Fatal("stopping the watch reported an OOM")
		}
	}
	assertNoFDLeak(t, before)
}

// Each prefix gets its own slice under system.slice: one level down, so it
// shares system.slice's CPU and memory, and holding one live unit at a time.
func TestUnitSliceName(t *testing.T) {
	if got := unitSlice("csm-parse-worker-zip0"); got != `system-csm\x2dparse\x2dworker\x2dzip0.slice` {
		t.Fatalf("slice = %q", got)
	}
}

// On cgroup v2 a slice's memory.events counts its children's OOM kills and
// outlives them: the verdict holds after the unit's cgroup is gone, however
// fast systemd removed it.
func TestUnitOOMKilledReadsSliceCounter(t *testing.T) {
	slice := filepath.Join(t.TempDir(), `system-csm\x2dparse\x2dworker\x2dmail0.slice`)
	if err := os.Mkdir(slice, 0o755); err != nil {
		t.Fatal(err)
	}
	writeValue(t, filepath.Join(slice, "memory.events"), "low 0\nhigh 0\nmax 0\noom 2\noom_kill 2\n")
	gone := memoryCgroup{dir: filepath.Join(slice, "csm-parse-worker-mail0-1.service"), v2: true}
	p := &unitProcess{cg: gone, slice: &memoryCgroup{dir: slice, v2: true}, sliceOOMKills: 2}
	if p.OOMKilled() {
		t.Fatal("kills from before this worker started read as its own")
	}
	writeValue(t, filepath.Join(slice, "memory.events"), "low 0\nhigh 0\nmax 1\noom 3\noom_kill 3\n")
	if !p.OOMKilled() {
		t.Fatal("an OOM kill in the slice after this worker started was not seen")
	}
}
