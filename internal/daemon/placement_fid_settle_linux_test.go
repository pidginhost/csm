//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

func TestFIDCloseWriteAtAnotherNameDoesNotSettle(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	dir := t.TempDir()
	target, alias := filepath.Join(dir, "target.php"), filepath.Join(dir, "alias.txt")
	if err := os.WriteFile(target, []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := placementOf(t, target, 0)
	created.Kind = placementCreate
	now := time.Now()
	p.route(created, now)
	// The inode had one name when CREATE was resolved. A later hard link
	// must not let a close at an ignored name cancel the pending PHP scan.
	if err := os.Link(target, alias); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(alias, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeWriteVia(t, fm, fd)
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 1 || got[0] != created {
		t.Fatalf("close at another name canceled the placed file: %+v", got)
	}
}

func TestFIDRepeatedCreateCannotPostponeAnalysis(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	now := time.Now()
	ev := placementEvent{Path: "/home/user/site/shell.php", Dev: 1, Ino: 2, Kind: placementCreate}
	p.route(ev, now)
	// A writer can repeatedly unlink and recreate a hard link to one inode.
	ev.PID = 77
	ev.At = now.Add(fidCreateSettle / 2)
	p.route(ev, now.Add(fidCreateSettle/2))
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 1 || got[0] != ev {
		t.Fatalf("repeated create postponed the original deadline: %+v", got)
	}
	if st := p.QueueStatuses(now.Add(fidCreateSettle))["create_settle"]; st.Depth != 0 || st.DroppedTotal != 0 {
		t.Fatalf("expired create left queue state %+v", st)
	}
}

func TestFIDDroppedCloseWriteDoesNotSettle(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	path := filepath.Join(t.TempDir(), "placed.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A hard link retains its old mtime. Ordinary close-write overflow
	// recovery does not scan it if opening and closing did not write bytes.
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	ev := placementOf(t, path, 0)
	ev.Kind = placementCreate
	now := time.Now()
	p.route(ev, now)
	fillAnalyzerQueue(fm)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeWriteVia(t, fm, fd)
	if got := fm.EventStats(); got.Dropped != 1 {
		t.Fatalf("close-write was not dropped: %+v", got)
	}
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 1 || got[0] != ev {
		t.Fatalf("dropped close-write canceled the placed file: %+v", got)
	}
}

func TestFIDPendingCreatesKeepDistinctNames(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 16))
	p := newTestPlacementFID(t, fm)
	now := time.Now()
	first := placementEvent{Path: "/home/user/site/first.php", Dev: 1, Ino: 2, Kind: placementCreate}
	second := first
	second.Path = "/home/user/site/second.php"
	p.route(first, now)
	p.route(second, now)
	p.expire(now.Add(fidCreateSettle))
	if got := routedPlacements(p); len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("creates at different names replaced each other: %+v", got)
	}
}
