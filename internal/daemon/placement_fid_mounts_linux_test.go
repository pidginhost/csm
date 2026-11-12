//go:build linux

package daemon

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

func TestFIDKeepsEachWatchedMountOfOneFilesystem(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	first, second := t.TempDir(), t.TempDir()
	dev, err := statDevice(first)
	if err != nil {
		t.Fatal(err)
	}
	fm.watchRoots = []watchRootMark{{path: first, device: dev}, {path: second, device: dev}}
	// The first view is the whole filesystem, the other a subtree bind.
	all := []mountEntry{
		{Dev: dev, Root: "/", MountPoint: first},
		{Dev: dev, Root: "/site", MountPoint: second},
	}
	p := newPlacementFID(fm, -1, make(map[unix.Fsid][]fidMount))
	t.Cleanup(p.close)
	marks := 0
	mark := func(_ int, flags uint, mask uint64, _ int, _ string) error {
		marks++
		if flags != FAN_MARK_ADD|FAN_MARK_FILESYSTEM || mask != unix.FAN_MOVED_TO|unix.FAN_CREATE|unix.FAN_ONDIR {
			t.Fatalf("unexpected mark flags %x mask %x", flags, mask)
		}
		return nil
	}
	if err = p.markFilesystemsWith(all, mark); err != nil {
		t.Fatal(err)
	}
	if marks != 1 {
		t.Fatalf("marked one filesystem %d times", marks)
	}
	// Substitute handle lookup only. Real descriptors, path resolution,
	// admission boundaries and inode checks still run for both mount views.
	p.openDir = func(fd int, _ unix.FileHandle, _ int) (int, error) { return unix.Dup(fd) }
	name := "placed.php"
	if err = os.WriteFile(filepath.Join(first, name), []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(filepath.Join(first, name), filepath.Join(second, name)); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(first, &fs); err != nil {
		t.Fatal(err)
	}
	body := dfidNameBody(8, make([]byte, 8), name)
	binary.NativeEndian.PutUint32(body[:4], uint32(fs.Fsid.Val[0]))  // #nosec G115 -- preserve the fsid bit pattern
	binary.NativeEndian.PutUint32(body[4:8], uint32(fs.Fsid.Val[1])) // #nosec G115 -- preserve the fsid bit pattern
	p.dispatch(fidEventRecord(unix.FAN_MOVED_TO, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, body)), time.Now())
	got := routedPlacements(p)
	if len(got) != 2 {
		t.Fatalf("placements %+v, want both watched mount paths", got)
	}
	if got[0].Path != filepath.Join(first, name) || got[1].Path != filepath.Join(second, name) ||
		got[0].Dev != dev || got[1].Dev != dev || got[0].Ino != got[1].Ino {
		t.Fatalf("wrong placement identities or paths: %+v", got)
	}
}

func TestFIDResolvesDirectoryPlacedAtWatchRoot(t *testing.T) {
	parent := t.TempDir()
	site := filepath.Join(parent, "site")
	if err := os.Mkdir(site, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	fm.watchRoots = []watchRootMark{{path: site}}
	p := newTestPlacementFID(t, fm)
	p.openDir = func(fd int, _ unix.FileHandle, _ int) (int, error) { return unix.Dup(fd) }
	want := placementOf(t, site, 77)
	want.IsDir = true
	now := time.Now()
	want.At = now
	ev, ok, err := p.resolve(fidRecord{Mask: unix.FAN_MOVED_TO | unix.FAN_ONDIR, PID: 77, Name: "site"}, fidMount{fd: fd, path: parent}, now)
	if err != nil || !ok || ev != want {
		t.Fatalf("watch root placement = %+v, %v, %v; want %+v", ev, ok, err, want)
	}
	if err = os.Mkdir(filepath.Join(parent, "outside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if ev, ok, err = p.resolve(fidRecord{Mask: unix.FAN_MOVED_TO | unix.FAN_ONDIR, Name: "outside"}, fidMount{fd: fd, path: parent}, now); err != nil || ok {
		t.Fatalf("outside directory was not filtered: %+v, %v, %v", ev, ok, err)
	}
}
