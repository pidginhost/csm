package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func changedPassForTest(t *testing.T, fx changedFixture, ctx context.Context, budget int, accounts ...string) []alert.Finding {
	t.Helper()
	var findings []alert.Finding
	var ordered []rollingAccount
	for _, name := range accounts {
		ordered = append(ordered, rollingAccount{name: name, home: "/home/" + name})
	}
	scan := newPHPContentScan(fx.cfg, nil, false)
	used := rollingChangedPass(ctx, fx.cfg, scan, store.Global(), ordered, budget, &findings)
	if used > budget {
		t.Fatalf("used %d reads with budget %d", used, budget)
	}
	return findings
}

func changedCursorForTest(t *testing.T, account string) store.ScanCursorRecord {
	t.Helper()
	cur, err := rollingContentCursors.load(store.Global(), account)
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

func TestChangedBacklogFinishesWithoutRepeatingPrefix(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	var paths []string
	for i := range 5 {
		path := fmt.Sprintf("/home/alice/public_html/assets/lib/new%d.php", i)
		fx.write(t, path, rollingBenignPHP)
		paths = append(paths, path)
	}
	for range 3 {
		changedPassForTest(t, fx, context.Background(), 2, "alice")
	}
	cur := changedCursorForTest(t, "alice")
	if cur.ChangedFrom != "" || !cur.ChangedLapStart.IsZero() {
		t.Errorf("completed backlog retained an unfinished lap: %+v", cur)
	}
	// Empty clean caches model the periodic forced scan expiring rolling stamps.
	changedPassForTest(t, fx, context.Background(), 2, "alice")
	for _, path := range paths {
		if got := fx.os.count(path); got != 1 {
			t.Errorf("%s opened %d times, want 1", path, got)
		}
	}
}

func TestChangedEmptyPassAdvancesWatermark(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	before := changedCursorForTest(t, "alice").ChangedThrough
	changedPassForTest(t, fx, context.Background(), 1, "alice")
	if after := changedCursorForTest(t, "alice").ChangedThrough; !after.After(before) {
		t.Fatalf("empty pass left watermark at %v", after)
	}
}

func TestChangedIncludesWatermarkBoundary(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	path := "/home/alice/public_html/assets/lib/boundary.php"
	fx.write(t, path, rollingDormantPHP)
	info, err := fx.os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cur := changedCursorForTest(t, "alice")
	cur.ChangedThrough = time.Unix(0, phpFileStampOf(info).Ctime)
	saveRollingCursor(store.Global(), cur)
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, path) {
		t.Fatal("file with ctime equal to watermark was missed")
	}
}

type changedFaultOS struct {
	openCountOS
	statHook func(string) error
	openHook func(string) error
	dirHook  func(string) error
}

func (o changedFaultOS) Stat(path string) (os.FileInfo, error) {
	if o.statHook != nil {
		if err := o.statHook(path); err != nil {
			return nil, err
		}
	}
	return o.openCountOS.Stat(path)
}
func (o changedFaultOS) Lstat(path string) (os.FileInfo, error) {
	if o.statHook != nil {
		if err := o.statHook(path); err != nil {
			return nil, err
		}
	}
	return o.openCountOS.Lstat(path)
}
func (o changedFaultOS) Open(path string) (*os.File, error) {
	if o.openHook != nil {
		if err := o.openHook(path); err != nil {
			return nil, err
		}
	}
	return o.openCountOS.Open(path)
}
func (o changedFaultOS) ReadDir(path string) ([]os.DirEntry, error) {
	if o.dirHook != nil {
		if err := o.dirHook(path); err != nil {
			return nil, err
		}
	}
	return o.openCountOS.ReadDir(path)
}

func TestChangedFailureDoesNotLoseUnscannedFiles(t *testing.T) {
	for _, operation := range []string{"stat", "open", "directory", "roots"} {
		t.Run(operation, func(t *testing.T) {
			fx := newChangedFixture(t, 1, "alice")
			blocked := "/home/alice/public_html/assets/blocked/shell.php"
			if operation == "roots" {
				blocked = "/home/alice/addon/assets/shell.php"
			}
			good := "/home/alice/public_html/assets/lib/new.php"
			fx.write(t, blocked, rollingDormantPHP)
			fx.write(t, good, rollingBenignPHP)
			before := changedCursorForTest(t, "alice").ChangedThrough
			fault := changedFaultOS{openCountOS: fx.os}
			deny := func(path string) error {
				if path == blocked {
					return os.ErrPermission
				}
				return nil
			}
			switch operation {
			case "stat":
				fault.statHook = deny
			case "open":
				fault.openHook = deny
			case "directory":
				fault.dirHook = func(path string) error {
					if path == filepath.Dir(blocked) {
						return os.ErrPermission
					}
					return nil
				}
			case "roots":
				fault.dirHook = func(path string) error {
					if path == "/home/alice" {
						return os.ErrPermission
					}
					return nil
				}
			}
			withMockOS(t, fault)
			changedPassForTest(t, fx, context.Background(), 10, "alice")
			if after := changedCursorForTest(t, "alice").ChangedThrough; !after.Equal(before) {
				t.Errorf("%s failure advanced watermark from %v to %v", operation, before, after)
			}
			withMockOS(t, fx.os)
			if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, blocked) {
				t.Fatal("recovered file was lost behind watermark")
			}
		})
	}
}

func TestChangedMetadataSweepStopsOnCancellation(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats := 0
	withMockOS(t, changedFaultOS{openCountOS: fx.os, statHook: func(string) error { stats++; cancel(); return nil }})
	before := changedCursorForTest(t, "alice").ChangedThrough
	changedPassForTest(t, fx, ctx, 10, "alice")
	if stats != 1 {
		t.Errorf("canceled sweep statted %d files, want 1", stats)
	}
	if after := changedCursorForTest(t, "alice").ChangedThrough; !after.Equal(before) {
		t.Fatal("canceled sweep advanced watermark")
	}
}

func TestChangedClockRollbackDoesNotHideFiles(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	path := "/home/alice/public_html/assets/lib/new.php"
	fx.write(t, path, rollingDormantPHP)
	cur := changedCursorForTest(t, "alice")
	cur.ChangedThrough = time.Now().Add(time.Hour)
	saveRollingCursor(store.Global(), cur)
	// Use the real production margin to cover a write immediately before this pass.
	rollingChangedMargin = 2 * time.Minute
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, path) {
		t.Fatal("clock rollback hid a new payload")
	}
}

func TestChangedClockRollbackKeepsAccountsFair(t *testing.T) {
	fx := newChangedFixture(t, 1, "aaa", "bbb")
	for _, account := range []string{"aaa", "bbb"} {
		cur := changedCursorForTest(t, account)
		cur.ChangedServedAt = time.Now().Add(time.Hour)
		saveRollingCursor(store.Global(), cur)
	}
	victim := "/home/bbb/public_html/assets/lib/new.php"
	fx.write(t, victim, rollingDormantPHP)
	found := false
	for i := range 2 {
		fx.write(t, fmt.Sprintf("/home/aaa/public_html/assets/lib/new%d.php", i), rollingBenignPHP)
		found = findsPath(changedPassForTest(t, fx, context.Background(), 1, "aaa", "bbb"), victim) || found
	}
	if !found {
		t.Fatal("clock rollback let the flooding account starve its neighbour")
	}
}

type changedClockOS struct {
	openCountOS
	uptime float64
}

func (o changedClockOS) ReadFile(path string) ([]byte, error) {
	if path == "/proc/uptime" {
		return []byte(fmt.Sprintf("%f 0", o.uptime)), nil
	}
	if path == "/proc/sys/kernel/random/boot_id" {
		return []byte("test-boot"), nil
	}
	return o.openCountOS.ReadFile(path)
}

func TestChangedClockStepBetweenCycles(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	wall := time.Now().Add(time.Hour)
	previous := phpContentNow
	phpContentNow = func() time.Time { return wall }
	t.Cleanup(func() { phpContentNow = previous })
	rollingChangedMargin = 2 * time.Minute
	withMockOS(t, changedClockOS{openCountOS: fx.os, uptime: 10000})
	changedPassForTest(t, fx, context.Background(), 10, "alice")
	if through := changedCursorForTest(t, "alice").ChangedThrough; !through.Equal(wall.Add(-rollingChangedMargin)) {
		t.Fatalf("first pass did not establish the new wall clock: %v", through)
	}
	// Seventy minutes elapsed, but the clock was set back an hour. Wall time
	// still increased, so comparing wall timestamps alone cannot see the step.
	wall = wall.Add(10 * time.Minute)
	withMockOS(t, changedClockOS{openCountOS: fx.os, uptime: 14200})
	path := "/home/alice/public_html/assets/lib/new.php"
	fx.write(t, path, rollingDormantPHP)
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, path) {
		t.Fatal("clock step between cycles hid a new payload")
	}
}

func TestChangedLapDefersNewWritesWithoutLosingThem(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	first := "/home/alice/public_html/assets/lib/p1.php"
	last := "/home/alice/public_html/assets/lib/p9.php"
	fx.write(t, first, rollingBenignPHP)
	fx.write(t, last, rollingBenignPHP)
	changedPassForTest(t, fx, context.Background(), 1, "alice")
	if fx.os.count(first) != 1 {
		t.Fatal("first lap did not read its first file")
	}
	// Insert both behind and ahead of the saved position, plus beyond the
	// original end. They must not extend this lap or disappear behind it.
	paths := []string{
		"/home/alice/public_html/assets/lib/p0.php",
		"/home/alice/public_html/assets/lib/p5.php",
		"/home/alice/public_html/assets/lib/z.php",
	}
	time.Sleep(20 * time.Millisecond)
	for _, path := range paths {
		fx.write(t, path, rollingDormantPHP)
	}
	changedPassForTest(t, fx, context.Background(), 1, "alice")
	if fx.os.count(last) != 1 {
		t.Fatal("new files prevented the first lap from finishing")
	}
	if cur := changedCursorForTest(t, "alice"); !cur.ChangedLapStart.IsZero() {
		t.Fatal("completed lap remained pending")
	}
	got := changedPassForTest(t, fx, context.Background(), 10, "alice")
	for _, path := range paths {
		if !findsPath(got, path) {
			t.Errorf("next lap missed %s", path)
		}
	}
	if fx.os.count(first) != 1 || fx.os.count(last) != 1 {
		t.Fatal("next lap reread the previous lap's files")
	}
}

func TestChangedPartialFailureSurvivesRestart(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	bad := "/home/alice/public_html/assets/lib/p0.php"
	good := "/home/alice/public_html/assets/lib/p1.php"
	fx.write(t, bad, rollingDormantPHP)
	fx.write(t, good, rollingDormantPHP)
	before := changedCursorForTest(t, "alice").ChangedThrough
	withMockOS(t, changedFaultOS{openCountOS: fx.os, openHook: func(path string) error {
		if path == bad {
			return os.ErrPermission
		}
		return nil
	}})
	changedPassForTest(t, fx, context.Background(), 1, "alice")
	// Discard the in-memory fallback: resume only from the persisted record.
	rollingContentCursors = phpContentCursors{}
	withMockOS(t, fx.os)
	if got := changedPassForTest(t, fx, context.Background(), 1, "alice"); !findsPath(got, good) {
		t.Fatal("partial lap did not resume")
	}
	if after := changedCursorForTest(t, "alice").ChangedThrough; !after.Equal(before) {
		t.Fatal("partial read failure was forgotten after restart")
	}
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, bad) {
		t.Fatal("failed file was not retried")
	}
}

func TestChangedCanceledAccountYieldsItsTurn(t *testing.T) {
	fx := newChangedFixture(t, 1, "aaa", "bbb")
	victim := "/home/bbb/public_html/assets/lib/new.php"
	fx.write(t, victim, rollingDormantPHP)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withMockOS(t, changedFaultOS{openCountOS: fx.os, statHook: func(path string) error {
		if strings.HasPrefix(path, "/home/aaa/") {
			cancel()
		}
		return nil
	}})
	changedPassForTest(t, fx, ctx, 1, "aaa", "bbb")
	withMockOS(t, fx.os)
	fx.write(t, "/home/aaa/public_html/assets/lib/new.php", rollingBenignPHP)
	if got := changedPassForTest(t, fx, context.Background(), 1, "aaa", "bbb"); !findsPath(got, victim) {
		t.Fatal("timed-out account kept the next cycle's budget")
	}
}

func TestChangedBacklogStaysDrainedAcrossForcedCycles(t *testing.T) {
	fx := newChangedFixture(t, 2, "alice")
	for i := range 5 {
		fx.write(t, fmt.Sprintf("/home/alice/public_html/assets/lib/new%d.php", i), rollingBenignPHP)
	}
	wall := time.Now().Add(5 * time.Minute)
	previous := phpContentNow
	phpContentNow = func() time.Time { return wall }
	t.Cleanup(func() { phpContentNow = previous })
	rollingChangedMargin = 2 * time.Minute
	// Include two periodic forced runs, both of which expire rolling stamps.
	for cycle := 2; cycle <= 13; cycle++ {
		fx.cycle(t)
		if cycle >= 4 {
			cur := changedCursorForTest(t, "alice")
			if !cur.ChangedLapStart.IsZero() {
				t.Fatalf("cycle %d recreated or retained the changed backlog", cycle)
			}
		}
		wall = wall.Add(time.Hour)
	}
}

func TestChangedClockReadFailureRetainsReference(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	wall := time.Now().Add(time.Hour)
	previous := phpContentNow
	phpContentNow = func() time.Time { return wall }
	t.Cleanup(func() { phpContentNow = previous })
	rollingChangedMargin = 2 * time.Minute
	withMockOS(t, changedClockOS{openCountOS: fx.os, uptime: 10000})
	changedPassForTest(t, fx, context.Background(), 10, "alice")
	before := changedCursorForTest(t, "alice").ChangedThrough
	wall = wall.Add(5 * time.Minute)
	withMockOS(t, changedClockOS{openCountOS: fx.os, uptime: -1})
	changedPassForTest(t, fx, context.Background(), 10, "alice")
	if after := changedCursorForTest(t, "alice").ChangedThrough; !after.Equal(before) {
		t.Fatal("unverifiable clock advanced the watermark")
	}
	wall = wall.Add(5 * time.Minute)
	withMockOS(t, changedClockOS{openCountOS: fx.os, uptime: 14200})
	path := "/home/alice/public_html/assets/lib/new.php"
	fx.write(t, path, rollingDormantPHP)
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, path) {
		t.Fatal("clock read failure lost the reference needed to detect a rollback")
	}
}

func TestChangedFailedReadDoesNotRetireFindings(t *testing.T) {
	fx := newChangedFixture(t, 100, "alice")
	path := "/home/alice/public_html/assets/lib/new.php"
	fx.write(t, path, rollingDormantPHP)
	withMockOS(t, changedFaultOS{openCountOS: fx.os, openHook: func(name string) error {
		if name == path {
			return os.ErrPermission
		}
		return nil
	}})
	ctx, _ := withIncompleteCheckCollector(context.Background())
	CheckPHPContent(ctx, fx.cfg, nil)
	if !checkMarkedIncomplete(ctx, "php_content") {
		t.Fatal("failed changed read authorized retirement of earlier findings")
	}
}

type changedNonregularInfo struct{ os.FileInfo }

func (info changedNonregularInfo) Mode() os.FileMode { return os.ModeNamedPipe | 0o600 }

type changedNonregularOS struct {
	openCountOS
	path string
}

func (o changedNonregularOS) Stat(path string) (os.FileInfo, error) {
	info, err := o.openCountOS.Stat(path)
	if err == nil && path == o.path {
		return changedNonregularInfo{info}, nil
	}
	return info, err
}
func (o changedNonregularOS) Lstat(path string) (os.FileInfo, error) { return o.Stat(path) }

func TestChangedNonregularFileInvalidatesStamp(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	path := "/home/alice/public_html/assets/lib/new.php"
	fx.write(t, path, rollingBenignPHP)
	withMockOS(t, changedNonregularOS{openCountOS: fx.os, path: path})
	scan := newPHPContentScan(fx.cfg, phpContentCache{path: {Inode: 1, Ctime: 1}}, false)
	var findings []alert.Finding
	rollingChangedPass(context.Background(), fx.cfg, scan, store.Global(), []rollingAccount{{name: "alice", home: "/home/alice"}}, 1, &findings)
	if _, kept := scan.merged()[path]; kept {
		t.Fatal("nonregular candidate retained a clean-file stamp")
	}
	if fx.os.count(path) != 0 {
		t.Fatal("nonregular candidate was opened")
	}
}

func TestRollingPreservesFailedFixedRead(t *testing.T) {
	fx := newChangedFixture(t, 100, "alice")
	path := "/home/alice/public_html/wp-content/plugins/example/shell.php"
	fx.write(t, path, rollingDormantPHP)
	// This file predates the changed-file watermark. Its failed fixed walk
	// must still prevent rolling coverage from declaring the account complete.
	cur := changedCursorForTest(t, "alice")
	cur.ChangedThrough = time.Now()
	saveRollingCursor(store.Global(), cur)
	withMockOS(t, changedFaultOS{openCountOS: fx.os, openHook: func(name string) error {
		if name == path {
			return os.ErrPermission
		}
		return nil
	}})
	ctx, _ := withIncompleteCheckCollector(context.Background())
	CheckPHPContent(ctx, fx.cfg, nil)
	if !checkMarkedIncomplete(ctx, "php_content") {
		t.Fatal("rolling skip of a failed fixed read retired its finding")
	}
}

func TestChangedNewSymlinkCannotBorrowOldTargetTime(t *testing.T) {
	target := filepath.Join(t.TempDir(), "old.php")
	writeFile(t, target, rollingDormantPHP)
	fx := newChangedFixture(t, 1, "alice")
	path := "/home/alice/public_html/assets/lib/new.php"
	if err := os.Symlink(target, filepath.Join(fx.root, path)); err != nil {
		t.Fatal(err)
	}
	if got := changedPassForTest(t, fx, context.Background(), 1, "alice"); !findsPath(got, path) {
		t.Fatal("new PHP symlink evaded priority scanning using its old target's ctime")
	}
}

type rebootClockOS struct {
	openCountOS
	uptime float64
	boot   string
}

func (o rebootClockOS) ReadFile(path string) ([]byte, error) {
	switch path {
	case "/proc/uptime":
		return []byte(fmt.Sprintf("%f 0", o.uptime)), nil
	case "/proc/sys/kernel/random/boot_id":
		return []byte(o.boot), nil
	}
	return o.openCountOS.ReadFile(path)
}

// A reboot loses the uptime reference, not the files' history. Rereading every
// file after each reboot would leave new files waiting behind that backlog for
// days; only a wall clock now behind the last pass rewinds the bound.
func TestChangedPassAfterARebootReadsOnlyNewChanges(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	wall := time.Now()
	previous := phpContentNow
	phpContentNow = func() time.Time { return wall }
	t.Cleanup(func() { phpContentNow = previous })
	withMockOS(t, rebootClockOS{openCountOS: fx.os, uptime: 10000, boot: "boot-a"})
	changedPassForTest(t, fx, context.Background(), 10, "alice")
	// Change times are coarse: keep the next write past the zero-margin bound.
	time.Sleep(20 * time.Millisecond)

	wall = wall.Add(10 * time.Minute)
	withMockOS(t, rebootClockOS{openCountOS: fx.os, uptime: 60, boot: "boot-b"})
	planted := "/home/alice/public_html/assets/lib/after-reboot.php"
	fx.write(t, planted, rollingDormantPHP)
	before := map[string]int{}
	for _, name := range []string{"a00.php", "a01.php", "a02.php", "a03.php"} {
		before[name] = fx.os.count("/home/alice/public_html/assets/lib/" + name)
	}

	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, planted) {
		t.Fatal("a file planted after the reboot was not read")
	}
	for name, n := range before {
		if after := fx.os.count("/home/alice/public_html/assets/lib/" + name); after != n {
			t.Errorf("unchanged %s reread after a reboot: opens %d -> %d", name, n, after)
		}
	}
}

// A clock that comes back behind the watermark resets it to the new time, so
// files written after the reboot are read.
func TestChangedPassAfterARebootWithTheClockBehindTheWatermark(t *testing.T) {
	fx := newChangedFixture(t, 1, "alice")
	rollingChangedMargin = 2 * time.Minute
	wall := time.Now().Add(time.Hour)
	previous := phpContentNow
	phpContentNow = func() time.Time { return wall }
	t.Cleanup(func() { phpContentNow = previous })
	withMockOS(t, rebootClockOS{openCountOS: fx.os, uptime: 10000, boot: "boot-a"})
	changedPassForTest(t, fx, context.Background(), 10, "alice")

	// The machine came back with its clock an hour behind the last pass.
	wall = time.Now()
	withMockOS(t, rebootClockOS{openCountOS: fx.os, uptime: 60, boot: "boot-b"})
	planted := "/home/alice/public_html/assets/lib/after-reboot.php"
	fx.write(t, planted, rollingDormantPHP)
	if got := changedPassForTest(t, fx, context.Background(), 10, "alice"); !findsPath(got, planted) {
		t.Fatal("a clock set back across a reboot hid a new file")
	}
}
