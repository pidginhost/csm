//go:build linux && kernelintegration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fidScratchDir returns a directory on a filesystem fanotify can report
// directory handles for, and its device. tmpfs reports an fsid only on newer
// kernels; on older ones the checkout's filesystem stands in.
func fidScratchDir(t *testing.T) (string, uint64) {
	t.Helper()
	dir, dev := mountScratchTmpfs(t)
	var sfs unix.Statfs_t
	if err := unix.Statfs(dir, &sfs); err != nil {
		t.Fatal(err)
	}
	if sfs.Fsid != (unix.Fsid{}) {
		return dir, dev
	}
	dir, err := os.MkdirTemp(".", ".fid-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.Abs(dir); err != nil {
		t.Fatal(err)
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return dir, uint64(st.Dev) // #nosec G115 -- device ids are non-negative on Linux
}

func TestKernelPlacementFIDReportsRenameAndLink(t *testing.T) {
	root, dev := fidScratchDir(t)
	site, staging := filepath.Join(root, "site"), filepath.Join(root, "staging")
	for _, dir := range []string{site, staging} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fm := &FileMonitor{watchRoots: []watchRootMark{{path: site, scope: markScopeFilesystem, device: dev}}}
	p, err := startPlacementFID(context.Background(), fm)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan placementEvent, 32)
	p.handle = func(ev placementEvent) { seen <- ev }
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { p.Run(ctx); close(stopped) }()
	defer func() {
		cancel()
		<-stopped
	}()

	// Outside the watch root, and an empty new directory: neither is reported.
	writeScratch(t, filepath.Join(staging, "ignored.txt"))
	if err = os.Rename(filepath.Join(staging, "ignored.txt"), filepath.Join(staging, "ignored.php")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(site, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}

	want := map[string]placementEvent{}
	expect := func(path string, ino uint64, kind placementKind, isDir bool) {
		want[path] = placementEvent{Path: path, Dev: dev, Ino: ino, IsDir: isDir, PID: int32(os.Getpid()), Kind: kind} // #nosec G115 -- pids fit in pid_t
	}

	ino := writeScratch(t, filepath.Join(staging, "shell.txt"))
	if err = os.Rename(filepath.Join(staging, "shell.txt"), filepath.Join(site, "shell.php")); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(site, "shell.php"), ino, placementRename, false)

	ino = writeScratch(t, filepath.Join(staging, "linked.txt"))
	if err = os.Link(filepath.Join(staging, "linked.txt"), filepath.Join(site, "linked.php")); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(site, "linked.php"), ino, placementLink, false)

	// The kernel marks a removed directory's path with this suffix; a live
	// one may carry it in its name.
	decoy := filepath.Join(site, "x (deleted)")
	if err = os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	ino = writeScratch(t, filepath.Join(staging, "decoy.txt"))
	if err = os.Rename(filepath.Join(staging, "decoy.txt"), filepath.Join(decoy, "decoy.php")); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(decoy, "decoy.php"), ino, placementRename, false)

	if err = os.Mkdir(filepath.Join(staging, "plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	ino = inodeOf(t, filepath.Join(staging, "plugin"))
	if err = os.Rename(filepath.Join(staging, "plugin"), filepath.Join(site, "plugin")); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(site, "plugin"), ino, placementRename, true)

	// A linked O_TMPFILE has one name and no close-write at it: it is
	// analysed once its settle window ends.
	fd, err := unix.Open(site, unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if err = unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(site, "tmpfile.php"), unix.AT_EMPTY_PATH); err != nil {
		t.Fatal(err)
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(site, "tmpfile.php"), st.Ino, placementCreate, false)

	deadline := time.After(fidCreateSettle + 5*time.Second)
	for len(want) > 0 {
		select {
		case ev := <-seen:
			w, ok := want[ev.Path]
			ev.At = time.Time{}
			if !ok || ev != w {
				t.Fatalf("reported %+v, want one of %+v", ev, want)
			}
			delete(want, ev.Path)
		case <-deadline:
			t.Fatalf("never reported %+v; statuses %+v", want, p.QueueStatuses(time.Now()))
		}
	}
	select {
	case ev := <-seen:
		t.Fatalf("unexpected report %+v", ev)
	case <-time.After(fidPollMillis * 2 * time.Millisecond):
	}
}
