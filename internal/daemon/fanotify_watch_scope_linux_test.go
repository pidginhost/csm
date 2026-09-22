//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A filesystem-scoped mark covers the whole superblock, not the path it names.
// Where /home, /tmp and /var/tmp live on the root filesystem -- the default on
// a single-partition VPS -- the four watch roots resolved to one superblock and
// CSM marked it four times, then reported the four paths as if each were its
// own scope. The operator-visible effect was a daemon that received every
// close-write on the machine while its startup log claimed it watched /home.

func fakeDevStat(devices map[string]uint64) devStatFunc {
	return func(path string) (uint64, error) {
		dev, ok := devices[path]
		if !ok {
			return 0, unix.ENOENT
		}
		return dev, nil
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
			return unix.EINVAL
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
		return unix.EINVAL
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
		{path: "/home", scope: markScopeFilesystem, device: 2049},
		{path: "/tmp", scope: markScopeFilesystem, device: 2049, coveredBy: "/home"},
		{path: "/dev/shm", scope: markScopeMount, device: 21},
	}

	summary := watchScopeSummary(marks)

	for _, want := range []string{"/home", "filesystem", "/tmp", "covered by /home", "/dev/shm", "mount"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q does not mention %q", summary, want)
		}
	}
}

func TestWatchScopeSummaryDescribesScopeBeyondRequestedRoot(t *testing.T) {
	summary := watchScopeSummary([]watchRootMark{
		{path: "/home", scope: markScopeFilesystem, device: 2049},
	})
	if !strings.Contains(summary, "whole filesystem") {
		t.Errorf("summary %q does not describe scope beyond the requested root", summary)
	}
}

func TestWatchRootsReportPartialMarkFailure(t *testing.T) {
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		if path == "/unwatched" {
			return unix.EACCES
		}
		return nil
	}
	marks, err := markWatchRoots(3, []string{"/home", "/unwatched"}, mark,
		fakeDevStat(map[string]uint64{"/home": 1, "/unwatched": 2}))
	if !errors.Is(err, unix.EACCES) || !strings.Contains(err.Error(), "/unwatched") {
		t.Fatalf("partial watch failure lost its path or cause: %v", err)
	}
	if len(marks) != 1 || marks[0].path != "/home" {
		t.Fatalf("reported unwatched root as covered: %+v", marks)
	}
}

func TestWatchScopeSummaryDoesNotInferContainmentFromMountPoint(t *testing.T) {
	// A filesystem mark includes every mount of its superblock, even when
	// the root is /, a symlink target, or a bind mount within the same device.
	for _, path := range []string{"/", "/home", "/symlink", "/bind"} {
		t.Run(path, func(t *testing.T) {
			for _, scope := range []markScope{markScopeFilesystem, markScopeMount} {
				want := "whole filesystem, including all bind mounts"
				if scope == markScopeMount {
					want = "whole containing mount"
				}
				summary := watchScopeSummary([]watchRootMark{{path: path, scope: scope, device: 1}})
				if !strings.Contains(summary, want) {
					t.Errorf("%v scope summary %q does not describe %q", scope, summary, want)
				}
			}
		})
	}
}

func TestWatchRootsReportStatFailuresWithoutClaimingCoverage(t *testing.T) {
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		marked = append(marked, path)
		return nil
	}
	stat := func(path string) (uint64, error) {
		if path == "/denied" {
			return 1, unix.EACCES
		}
		return 1, nil
	}
	marks, err := markWatchRoots(3, []string{"/home", "/denied"}, mark, stat)
	if !errors.Is(err, unix.EACCES) || !strings.Contains(err.Error(), "/denied") {
		t.Fatalf("stat failure lost its path or cause: %v", err)
	}
	if len(marked) != 1 || marked[0] != "/home" || len(marks) != 1 || marks[0].path != "/home" {
		t.Fatalf("root with failed stat reported as watched: marked=%v records=%+v", marked, marks)
	}
}

func TestWatchRootsFilesystemFallbackOrdering(t *testing.T) {
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		if path == "/first" && flags&FAN_MARK_FILESYSTEM != 0 {
			return unix.EINVAL
		}
		marked = append(marked, path)
		return nil
	}
	roots := []string{"/first", "/second", "/third"}
	marks, err := markWatchRoots(3, roots, mark,
		fakeDevStat(map[string]uint64{"/first": 1, "/second": 1, "/third": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 2 || marked[0] != "/first" || marked[1] != "/second" {
		t.Fatalf("mount-only mark must not deduplicate later roots: %v", marked)
	}
	if len(marks) != 3 {
		t.Fatalf("want all three roots in summary, got %+v", marks)
	}
	for _, i := range []int{0, 2} {
		if marks[i].scope != markScopeFilesystem || marks[i].coveredBy != "/second" {
			t.Errorf("filesystem mark did not cover root %d: %+v", i, marks[i])
		}
	}
}

func TestWatchRootsFollowSymlinkDevice(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "alias")
	if err := os.Symlink("/dev/shm", link); err != nil {
		t.Fatal(err)
	}
	var marked []string
	mark := func(fd int, flags uint, mask uint64, dirFd int, path string) error {
		marked = append(marked, path)
		return nil
	}
	marks, err := markWatchRoots(3, []string{link, "/dev/shm"}, mark, statDevice)
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 1 || marked[0] != link || len(marks) != 2 || marks[1].coveredBy != link {
		t.Fatalf("symlink target was not deduplicated: marked=%v records=%+v", marked, marks)
	}
}
