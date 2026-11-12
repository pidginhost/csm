//go:build linux && bpf && kernelintegration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	bpfprog "github.com/pidginhost/csm/internal/daemon/placement_bpfprog"
)

// mountScratchTmpfs mounts a private tmpfs so the watched device holds only
// this test's entries, and returns its path and stat(2) device.
func mountScratchTmpfs(t *testing.T) (string, uint64) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Mount("tmpfs", dir, "tmpfs", 0, "size=8m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if unmountErr := unix.Unmount(dir, unix.MNT_DETACH); unmountErr != nil {
			t.Error(unmountErr)
		}
	})
	var st unix.Stat_t
	if err = unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return dir, uint64(st.Dev) // #nosec G115 -- device ids are non-negative on Linux
}

func writeScratch(t *testing.T, path string) uint64 {
	t.Helper()
	if err := os.WriteFile(path, []byte("<?php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return inodeOf(t, path)
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

type placementSeen struct {
	path  string
	ino   uint64
	kind  placementKind
	isDir bool
}

func TestKernelPlacementReportsRenameLinkExchange(t *testing.T) {
	root, dev := mountScratchTmpfs(t)
	other, _ := mountScratchTmpfs(t)
	for _, dir := range []string{filepath.Join(root, "staging"), filepath.Join(root, "site"), filepath.Join(other, "a")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fm := &FileMonitor{watchRoots: []watchRootMark{{path: root, scope: markScopeFilesystem, device: dev}}}
	p, err := startPlacementBPF(context.Background(), fm)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopReader := p.source.Start(ctx)
	defer func() {
		cancel()
		for _, l := range p.links {
			_ = l.Close()
		}
		stopReader()
		_ = p.objs.Close()
	}()

	// A device outside watched_devs must never reach the ring. It runs first
	// so a leaked event would arrive before the watched ones below.
	unwatched := filepath.Join(other, "a", "x.txt")
	writeScratch(t, unwatched)
	if err = os.Rename(unwatched, filepath.Join(other, "a", "x.php")); err != nil {
		t.Fatal(err)
	}

	var want []placementSeen
	staged := filepath.Join(root, "staging", "shell.txt")
	ino := writeScratch(t, staged)
	if err = os.Rename(staged, filepath.Join(root, "site", "shell.php")); err != nil {
		t.Fatal(err)
	}
	want = append(want, placementSeen{filepath.Join(root, "site", "shell.php"), ino, placementRename, false})

	linked := filepath.Join(root, "staging", "linked.txt")
	ino = writeScratch(t, linked)
	if err = os.Link(linked, filepath.Join(root, "site", "linked.php")); err != nil {
		t.Fatal(err)
	}
	want = append(want, placementSeen{filepath.Join(root, "site", "linked.php"), ino, placementLink, false})

	fd, err := unix.Open(filepath.Join(root, "site"), unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if err = unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(root, "site", "tmpfile.php"), unix.AT_EMPTY_PATH); err != nil {
		t.Fatal(err)
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	want = append(want, placementSeen{filepath.Join(root, "site", "tmpfile.php"), st.Ino, placementLink, false})

	plugin := filepath.Join(root, "staging", "plugin")
	if err = os.Mkdir(plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	ino = inodeOf(t, plugin)
	if err = os.Rename(plugin, filepath.Join(root, "site", "plugin")); err != nil {
		t.Fatal(err)
	}
	want = append(want, placementSeen{filepath.Join(root, "site", "plugin"), ino, placementRename, true})

	// An exchange moves both inodes; each must be reported at its new name.
	inSite, inStaging := filepath.Join(root, "site", "index.php"), filepath.Join(root, "staging", "payload.txt")
	siteIno, stagingIno := writeScratch(t, inSite), writeScratch(t, inStaging)
	if err = unix.Renameat2(unix.AT_FDCWD, inStaging, unix.AT_FDCWD, inSite, unix.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	want = append(want,
		placementSeen{inSite, stagingIno, placementRename, false},
		placementSeen{inStaging, siteIno, placementRename, false})

	// The walk follows 64 names: a file 64 names below the root resolves, and
	// one level deeper arrives truncated with the 64 names nearest the file.
	deep := root
	for range 63 {
		deep = filepath.Join(deep, "d")
	}
	if err = os.MkdirAll(filepath.Join(deep, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{deep, filepath.Join(deep, "d")} {
		from := filepath.Join(root, "staging", "deep.txt")
		ino = writeScratch(t, from)
		if err = os.Rename(from, filepath.Join(dir, "x.php")); err != nil {
			t.Fatal(err)
		}
		if dir == deep {
			want = append(want, placementSeen{filepath.Join(dir, "x.php"), ino, placementRename, false})
		}
	}
	truncated := 0

	got := make(map[placementSeen]int)
	deadline := time.After(10 * time.Second)
	for received := 0; received < len(want)+1; received++ {
		select {
		case work, ok := <-p.source.Events():
			if !ok {
				t.Fatal("reader stopped early")
			}
			work.Process(func(raw PlacementRawEvent) {
				if raw.Truncated {
					truncated++
					if len(raw.Components) != 64 || raw.Components[0] != "x.php" || raw.Ino != ino {
						t.Errorf("truncated walk kept %d names leaf-first %q, ino %d want %d", len(raw.Components), raw.Components[:min(2, len(raw.Components))], raw.Ino, ino)
					}
					if _, resolved := p.fm.placementFromRaw(raw, p.mounts, time.Now()); resolved {
						t.Error("truncated placement resolved")
					}
					return
				}
				ev, ok := p.fm.placementFromRaw(raw, p.mounts, time.Now())
				if !ok {
					t.Errorf("unresolved event %+v", raw)
					return
				}
				if ev.Dev != dev {
					t.Errorf("event on device %#x, want only %#x: %+v", ev.Dev, dev, ev)
				}
				// The kernel reports the initial-namespace pid, which differs
				// from os.Getpid inside the CI container.
				if ev.PID <= 0 {
					t.Errorf("event pid %d", ev.PID)
				}
				got[placementSeen{ev.Path, ev.Ino, ev.Kind, ev.IsDir}]++
			})
		case <-deadline:
			t.Fatalf("received %d of %d placements: %v", received, len(want), got)
		}
	}
	if truncated != 1 {
		t.Errorf("truncated placements = %d, want 1", truncated)
	}
	for _, w := range want {
		if got[w] != 1 {
			t.Errorf("placement %+v seen %d times; all: %v", w, got[w], got)
		}
	}
	select {
	case work := <-p.source.Events():
		t.Errorf("unexpected extra placement %+v", work.Value)
	case <-time.After(200 * time.Millisecond):
	}
	// Every hook call above reached the ring at its used length; none failed.
	var counts struct{ Lost, Submitted uint64 }
	if err = p.objs.QueueStats.Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Lost != 0 || counts.Submitted != uint64(len(want)+1) {
		t.Errorf("kernel counters %+v, want submitted=%d lost=0", counts, len(want)+1)
	}

	// A hook that finds its CPU's slot mid-build counts a loss and leaves the
	// slot to its owner. Marking every slot busy stands in for that overlap.
	setPlacementSlotsBusy(t, p, 1)
	overlapped := filepath.Join(root, "staging", "overlap.txt")
	writeScratch(t, overlapped)
	if err = os.Rename(overlapped, filepath.Join(root, "site", "overlap.php")); err != nil {
		t.Fatal(err)
	}
	select {
	case work := <-p.source.Events():
		t.Errorf("overlapping hook emitted %+v", work.Value)
	case <-time.After(200 * time.Millisecond):
	}
	if err = p.objs.QueueStats.Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Lost != 1 || counts.Submitted != uint64(len(want)+1) {
		t.Errorf("overlap counters %+v, want submitted=%d lost=1", counts, len(want)+1)
	}
	slots := placementSlots(t, p)
	for cpu, slot := range slots {
		if slot.Busy != 1 {
			t.Errorf("cpu %d: overlapping hook released the owner's slot (busy=%d)", cpu, slot.Busy)
		}
	}
}

func placementSlots(t *testing.T, p *placementBPF) []bpfprog.PlacementPlacementSlot {
	t.Helper()
	var slots []bpfprog.PlacementPlacementSlot
	if err := p.objs.Scratch.Lookup(uint32(0), &slots); err != nil {
		t.Fatal(err)
	}
	return slots
}

func setPlacementSlotsBusy(t *testing.T, p *placementBPF, busy uint32) {
	t.Helper()
	slots := placementSlots(t, p)
	for i := range slots {
		slots[i].Busy = busy
	}
	if err := p.objs.Scratch.Update(uint32(0), slots, ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}
}
