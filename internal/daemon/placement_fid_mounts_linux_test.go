//go:build linux

package daemon

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if _, err = p.markFilesystemsWith(all, mark); err != nil {
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

// twoRootsOneFilesystem returns a monitor watching two directories of one
// filesystem, the first seen as a subtree bind and the second whole.
func twoRootsOneFilesystem(t *testing.T) (*FileMonitor, []mountEntry, chan alert.Finding) {
	t.Helper()
	alerts := make(chan alert.Finding, 16)
	fm := placementTestMonitor(alerts)
	first, second := t.TempDir(), t.TempDir()
	dev, err := statDevice(first)
	if err != nil {
		t.Fatal(err)
	}
	fm.watchRoots = []watchRootMark{{path: first, device: dev}, {path: second, device: dev}}
	return fm, []mountEntry{
		{Dev: dev, Root: "/shm", MountPoint: first},
		{Dev: dev, Root: "/", MountPoint: second},
	}, alerts
}

// A kernel that cannot mark one filesystem (tmpfs before file handles) loses
// only the roots on it, and says so once.
func TestFIDSkipsRootsOnFilesystemsWithoutHandles(t *testing.T) {
	fm, all, alerts := twoRootsOneFilesystem(t)
	p := newPlacementFID(fm, -1, make(map[unix.Fsid][]fidMount))
	t.Cleanup(p.close)
	calls := 0
	mark := func(int, uint, uint64, int, string) error {
		calls++
		if calls == 1 {
			return unix.ENODEV
		}
		return nil
	}
	skipped, err := p.markFilesystemsWith(all, mark)
	if err != nil {
		t.Fatalf("one unmarkable root failed the group: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != all[0] {
		t.Fatalf("skipped %+v, want the first mount", skipped)
	}
	var kept []fidMount
	for _, mounts := range p.mounts {
		kept = append(kept, mounts...)
	}
	if len(kept) != 1 || kept[0].path != all[1].MountPoint {
		t.Fatalf("resolving through %+v, want only the marked root", kept)
	}

	p.reportCoverage(all, skipped)
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 || found[0].Severity != alert.Warning ||
		!strings.Contains(found[0].Details, all[0].MountPoint) || strings.Contains(found[0].Details, all[1].MountPoint) ||
		!strings.Contains(found[0].Details, "deep scan") {
		t.Fatalf("findings %+v, want one Warning naming only the skipped root", found)
	}
}

func TestFIDWithNoMarkableRootLacksSupport(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENODEV, unix.EOPNOTSUPP, unix.EXDEV} {
		fm, all, _ := twoRootsOneFilesystem(t)
		p := newPlacementFID(fm, -1, make(map[unix.Fsid][]fidMount))
		_, err := p.markFilesystemsWith(all, func(int, uint, uint64, int, string) error { return errno })
		if !errors.Is(err, errPlacementFIDUnsupported) || !errors.Is(err, errno) {
			t.Errorf("%v on every root: %v, want missing kernel support", errno, err)
		}
		if len(p.mounts) != 0 {
			t.Errorf("%v: kept %+v after skipping every root", errno, p.mounts)
		}
		p.close()
	}
	// Anything else still fails the whole group.
	fm, all, _ := twoRootsOneFilesystem(t)
	p := newPlacementFID(fm, -1, make(map[unix.Fsid][]fidMount))
	t.Cleanup(p.close)
	_, err := p.markFilesystemsWith(all, func(int, uint, uint64, int, string) error { return unix.EPERM })
	if err == nil || errors.Is(err, errPlacementFIDUnsupported) {
		t.Fatalf("EPERM mark: %v, want a plain failure", err)
	}
}
