//go:build linux

package daemon

import (
	"strings"
	"testing"
)

// A filesystem-scoped mark covers the whole superblock, not the path it names.
// Where /home, /tmp and /var/tmp live on the root filesystem -- the default on
// a single-partition VPS -- the four watch roots resolved to one superblock and
// CSM marked it four times, then reported the four paths as if each were its
// own scope. The operator-visible effect was a daemon that received every
// close-write on the machine while its startup log claimed it watched /home.

func fakeDevStat(devices map[string]uint64) func(string) (uint64, bool) {
	return func(path string) (uint64, bool) {
		dev, ok := devices[path]
		return dev, ok
	}
}

func TestWatchRootsMarkOneSuperblockOnce(t *testing.T) {
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		marked = append(marked, path)
		return nil
	}
	roots := []string{"/home", "/tmp", "/dev/shm", "/var/tmp"}
	devices := map[string]uint64{"/home": 2049, "/tmp": 2049, "/dev/shm": 21, "/var/tmp": 2049}

	marks, err := markWatchRoots(3, roots, mark, fakeDevStat(devices))
	if err != nil {
		t.Fatalf("markWatchRoots: %v", err)
	}

	if len(marked) != 2 {
		t.Fatalf("issued %d marks for 2 superblocks: %v", len(marked), marked)
	}
	if len(marks) != len(roots) {
		t.Fatalf("reported %d roots, want all %d", len(marks), len(roots))
	}
	byPath := map[string]watchRootMark{}
	for _, m := range marks {
		byPath[m.path] = m
	}
	if got := byPath["/tmp"].coveredBy; got != "/home" {
		t.Errorf("/tmp reports coveredBy %q, want /home", got)
	}
	if got := byPath["/dev/shm"].coveredBy; got != "" {
		t.Errorf("/dev/shm on its own superblock reports coveredBy %q", got)
	}
	if byPath["/home"].scope != markScopeFilesystem {
		t.Errorf("/home scope = %v, want filesystem", byPath["/home"].scope)
	}
}

// A mount-scoped mark only covers the vfsmount it names, so two roots on one
// superblock still need one mark each.
func TestWatchRootsOnOneSuperblockStillMarkEachMount(t *testing.T) {
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		if flags&FAN_MARK_FILESYSTEM != 0 {
			return errFilesystemScopeUnsupported
		}
		marked = append(marked, path)
		return nil
	}
	roots := []string{"/home", "/tmp"}
	devices := map[string]uint64{"/home": 2049, "/tmp": 2049}

	marks, err := markWatchRoots(3, roots, mark, fakeDevStat(devices))
	if err != nil {
		t.Fatalf("markWatchRoots: %v", err)
	}

	if len(marked) != 2 {
		t.Fatalf("issued %d mount marks, want one per root: %v", len(marked), marked)
	}
	for _, m := range marks {
		if m.coveredBy != "" {
			t.Errorf("%s was skipped as covered by %s, but a mount mark does not reach it", m.path, m.coveredBy)
		}
	}
}

func TestWatchRootsSkipRootsThatCannotBeStatted(t *testing.T) {
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		marked = append(marked, path)
		return nil
	}

	marks, err := markWatchRoots(3, []string{"/home", "/absent"}, mark, fakeDevStat(map[string]uint64{"/home": 2049}))
	if err != nil {
		t.Fatalf("markWatchRoots: %v", err)
	}

	if len(marked) != 1 || marked[0] != "/home" {
		t.Fatalf("marked %v, want only the root that exists", marked)
	}
	if len(marks) != 1 {
		t.Fatalf("reported %d roots, want only the one that was marked", len(marks))
	}
}

func TestWatchRootsReportErrorWhenNothingCouldBeMarked(t *testing.T) {
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		return errFilesystemScopeUnsupported
	}

	marks, err := markWatchRoots(3, []string{"/home"}, mark, fakeDevStat(map[string]uint64{"/home": 2049}))
	if err == nil {
		t.Fatal("a watch root that could not be marked was reported as watched")
	}
	if len(marks) != 0 {
		t.Fatalf("reported %d marks after every attempt failed", len(marks))
	}
}

// The startup line used to name the paths CSM asked for. An operator reading it
// on a single-partition host had no way to see that the mark covers every write
// on the machine.
func TestWatchScopeSummaryNamesTheRealScope(t *testing.T) {
	marks := []watchRootMark{
		{path: "/home", scope: markScopeFilesystem, device: 2049, ownMount: false},
		{path: "/tmp", scope: markScopeFilesystem, device: 2049, coveredBy: "/home"},
		{path: "/dev/shm", scope: markScopeMount, device: 21, ownMount: true},
	}

	summary := watchScopeSummary(marks)

	for _, want := range []string{"/home", "filesystem", "/tmp", "covered by /home", "/dev/shm", "mount"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q does not mention %q", summary, want)
		}
	}
}

func TestWatchScopeSummaryFlagsARootThatIsNotItsOwnMount(t *testing.T) {
	wider := watchScopeSummary([]watchRootMark{
		{path: "/home", scope: markScopeFilesystem, device: 2049, ownMount: false},
	})
	if !strings.Contains(wider, "wider") {
		t.Errorf("summary %q does not say the mark reaches past the watch root", wider)
	}

	contained := watchScopeSummary([]watchRootMark{
		{path: "/home", scope: markScopeFilesystem, device: 2049, ownMount: true},
	})
	if strings.Contains(contained, "wider") {
		t.Errorf("summary %q warns about a root that is its own mount point", contained)
	}
}
