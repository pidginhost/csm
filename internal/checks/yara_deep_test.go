package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

type deepYARATestBackend struct {
	err error
}

func (b *deepYARATestBackend) ScanFile(string, int) []yara.Match { return nil }
func (b *deepYARATestBackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *deepYARATestBackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	if b.err != nil {
		return nil, b.err
	}
	if string(data) == "dormant malware" {
		return []yara.Match{{RuleName: "dormant_webshell", Meta: map[string]string{"severity": "critical"}}}, nil
	}
	return nil, nil
}
func (b *deepYARATestBackend) RuleCount() int { return 1 }
func (b *deepYARATestBackend) Reload() error  { return nil }

func TestCheckYARADeepFindsDormantFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "uploads", "image.dat")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("dormant malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	yara.SetActive(&deepYARATestBackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Check != "yara_match_scheduled" || findings[0].FilePath != path {
		t.Fatalf("finding = %+v, want YARA match for %s", findings[0], path)
	}
	if findings[0].ContentSHA256 == "" || findings[0].DetectLogic == "" {
		t.Fatalf("YARA finding lacks content fingerprint: %+v", findings[0])
	}
}

func TestCheckYARADeepReportsIncompleteScan(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}
	yara.SetActive(&deepYARATestBackend{err: errors.New("worker unavailable")})
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want one yara_scan_incomplete finding", findings)
	}
}

// oversizeInlineBackend rejects inline byte scans the way the real IPC client
// does for a payload past the frame ceiling, and matches only when the file is
// scanned by path. It proves the deep scan falls back to a path scan instead of
// dropping a large file into the coverage gap.
type oversizeInlineBackend struct{ scanFileCalls int32 }

func (b *oversizeInlineBackend) ScanFile(string, int) []yara.Match {
	atomic.AddInt32(&b.scanFileCalls, 1)
	return []yara.Match{{RuleName: "webshell_php_exec_ladder", Meta: map[string]string{"severity": "critical"}}}
}
func (b *oversizeInlineBackend) ScanBytes(data []byte) []yara.Match {
	m, _ := b.ScanBytesChecked(data)
	return m
}
func (b *oversizeInlineBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, fmt.Errorf("%w (%d > %d bytes)", yaraipc.ErrPayloadTooLarge, 15000000, yaraipc.MaxScanBytes)
}
func (b *oversizeInlineBackend) RuleCount() int { return 1 }
func (b *oversizeInlineBackend) Reload() error  { return nil }

func TestCheckYARADeepScansOversizeInlineFileByPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "wp-content", "big.js")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("padded bundle content"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &oversizeInlineBackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	if atomic.LoadInt32(&backend.scanFileCalls) == 0 {
		t.Fatal("oversize-inline file was not scanned by path")
	}
	var got *alert.Finding
	for i := range findings {
		if findings[i].Check == "yara_scan_incomplete" {
			t.Fatalf("oversize file recorded as coverage gap instead of scanned: %+v", findings[i])
		}
		if findings[i].Check == "yara_match_scheduled" {
			got = &findings[i]
		}
	}
	if got == nil || got.FilePath != path {
		t.Fatalf("findings = %+v, want yara_match_scheduled for %s", findings, path)
	}
}

func TestYARADeepRunsWithAndWithoutFanotify(t *testing.T) {
	for _, checks := range [][]namedCheck{deepChecks(), reducedDeepChecks()} {
		found := false
		for _, check := range checks {
			if check.name == "yara_deep" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("yara_deep missing from a scheduled deep-check set")
		}
	}
}

func TestIncompleteCheckDoesNotPurgeLastCompletedFindings(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		markCheckIncomplete(ctx, "yara_deep")
		return []alert.Finding{{Check: "yara_scan_incomplete", Severity: alert.High}}
	}}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want incomplete finding", findings)
	}
	for _, name := range purge {
		if name == "yara_match_scheduled" || name == "yara_scan_incomplete" || name == "yara_deep" {
			t.Fatalf("incomplete scan included %q in purge list: %v", name, purge)
		}
	}
}

func TestCompletedYARADeepDoesNotOwnRealtimeFindings(t *testing.T) {
	check := namedCheck{name: "yara_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return nil
	}}

	_, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if !containsYARAPurgeName(purge, "yara_match_scheduled") {
		t.Fatalf("completed scheduled scan purge list = %v, want yara_match_scheduled", purge)
	}
	if containsYARAPurgeName(purge, "yara_match_realtime") {
		t.Fatalf("scheduled scan owns real-time findings: %v", purge)
	}
}

func TestUnavailableYARADeepPreservesLastScheduledFindings(t *testing.T) {
	originalBackend := activeYARABackend
	originalAvailable := yaraAvailable
	activeYARABackend = func() yara.Backend { return nil }
	yaraAvailable = func() bool { return true }
	t.Cleanup(func() {
		activeYARABackend = originalBackend
		yaraAvailable = originalAvailable
	})
	check := namedCheck{name: "yara_deep", fn: CheckYARADeep}

	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, nil, []namedCheck{check}, "deep", true)
	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("unavailable YARA findings = %+v, want yara_scan_incomplete", findings)
	}
	if containsYARAPurgeName(purge, "yara_match_scheduled") {
		t.Fatalf("unavailable YARA backend purged prior findings: %v", purge)
	}
}

func containsYARAPurgeName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// recordingYARABackend identifies scanned files by their content and lets a
// test advance a fake clock from inside the scan loop.
type recordingYARABackend struct {
	scanned []string
	onScan  func()
}

func (b *recordingYARABackend) ScanFile(string, int) []yara.Match { return nil }
func (b *recordingYARABackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *recordingYARABackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	b.scanned = append(b.scanned, string(data))
	if b.onScan != nil {
		b.onScan()
	}
	if strings.HasPrefix(string(data), "mal") {
		return []yara.Match{{RuleName: "test_rule", Meta: map[string]string{"severity": "critical"}}}, nil
	}
	return nil, nil
}
func (b *recordingYARABackend) RuleCount() int { return 1 }
func (b *recordingYARABackend) Reload() error  { return nil }

type concurrentYARABackend struct {
	firstStarted chan struct{}
	releaseFirst chan struct{}
	slowCalls    atomic.Int32
}

func (b *concurrentYARABackend) ScanFile(string, int) []yara.Match { return nil }
func (b *concurrentYARABackend) ScanBytes(data []byte) []yara.Match {
	matches, _ := b.ScanBytesChecked(data)
	return matches
}
func (b *concurrentYARABackend) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	if string(data) == "slow first" && b.slowCalls.Add(1) == 1 {
		close(b.firstStarted)
		<-b.releaseFirst
	}
	return nil, nil
}
func (b *concurrentYARABackend) RuleCount() int { return 1 }
func (b *concurrentYARABackend) Reload() error  { return nil }

type faultingYARADeepOS struct {
	OS
	lstat   func(string) (os.FileInfo, error)
	readDir func(string) ([]os.DirEntry, error)
}

func (f *faultingYARADeepOS) Lstat(path string) (os.FileInfo, error) {
	if f.lstat != nil {
		return f.lstat(path)
	}
	return f.OS.Lstat(path)
}

func (f *faultingYARADeepOS) ReadDir(path string) ([]os.DirEntry, error) {
	if f.readDir != nil {
		return f.readDir(path)
	}
	return f.OS.ReadDir(path)
}

func writeYARADeepFile(t *testing.T, root string, rel, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func useYARADeepClock(t *testing.T, clock *time.Time) {
	t.Helper()
	prev := yaraDeepNow
	yaraDeepNow = func() time.Time { return *clock }
	t.Cleanup(func() { yaraDeepNow = prev })
}

func putYARADeepCursor(t *testing.T, db *store.DB, lastPath string, wrappedAt time.Time) {
	t.Helper()
	var record store.ScanCursorRecord
	record.Check = yaraDeepCursorCheck
	record.LastPath = lastPath
	record.WrappedAt = wrappedAt
	if err := db.PutScanCursor(record); err != nil {
		t.Fatal(err)
	}
}

func TestCheckYARADeepReturnsPartialFindingsAtSoftDeadline(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	writeYARADeepFile(t, root, "b/two.dat", "mal two")

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{onScan: func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	var matches []alert.Finding
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" {
			matches = append(matches, f)
		}
	}
	if len(matches) != 1 || matches[0].FilePath != first {
		t.Fatalf("matches = %+v, want the pre-deadline match for %s", matches, first)
	}
	if !collector.contains("yara_deep") {
		t.Fatal("partial run must mark yara_deep incomplete so prior findings survive the purge")
	}
	cur, ok, err := db.GetScanCursor("", "yara_deep")
	if err != nil || !ok {
		t.Fatalf("cursor after partial run: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != first {
		t.Fatalf("cursor.LastPath = %q, want %q", cur.LastPath, first)
	}
}

func TestCheckYARADeepResumesFromCursorAndCompletesCycle(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	second := writeYARADeepFile(t, root, "z/two.dat", "mal two")
	putYARADeepCursor(t, db, first, time.Now().UTC())

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	var paths []string
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" {
			paths = append(paths, f.FilePath)
		}
	}
	if len(paths) != 1 || paths[0] != second {
		t.Fatalf("resumed run scanned %v, want only %s", paths, second)
	}
	for _, content := range backend.scanned {
		if content == "mal one" {
			t.Fatal("resumed run re-scanned the file the cursor already covered")
		}
	}
	if !collector.contains("yara_deep") {
		t.Fatal("a resumed run saw only part of the space and must not purge prior findings")
	}
	cur, ok, err := db.GetScanCursor("", "yara_deep")
	if err != nil || !ok {
		t.Fatalf("cursor after cycle completion: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" {
		t.Fatalf("cursor.LastPath = %q, want cleared after full cycle", cur.LastPath)
	}
	if cur.LastFullCycleTS.IsZero() {
		t.Fatal("full cycle completion must stamp LastFullCycleTS")
	}
}

func TestCheckYARADeepCursorSkipKeepsSiblingDirAfterDotFile(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	scannedAlready := writeYARADeepFile(t, root, "ab.zz", "clean already covered")
	inSibling := writeYARADeepFile(t, root, "ab/x.dat", "mal sibling")
	putYARADeepCursor(t, db, scannedAlready, time.Now().UTC())

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)

	found := false
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" && f.FilePath == inSibling {
			found = true
		}
	}
	if !found {
		t.Fatalf("dir sorting after the cursor's dot-file sibling was skipped; findings = %+v", findings)
	}
	for _, content := range backend.scanned {
		if content == "clean already covered" {
			t.Fatal("file at the cursor position was re-scanned")
		}
	}
}

func TestCheckYARADeepCursorFollowsFullPathOrder(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "ab.zz", "mal dot file")
	writeYARADeepFile(t, root, "ab/x.dat", "mal directory file")

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{onScan: func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	var paths []string
	for _, finding := range findings {
		if finding.Check == "yara_match_scheduled" {
			paths = append(paths, finding.FilePath)
		}
	}
	if len(paths) != 1 || paths[0] != first {
		t.Fatalf("first cursor window scanned %v, want lexicographically first path %s", paths, first)
	}
	if !collector.contains("yara_deep") {
		t.Fatal("partial path-order window must preserve findings from other windows")
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after first window: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != first {
		t.Fatalf("cursor.LastPath = %q, want %q", cur.LastPath, first)
	}
}

func TestCheckYARADeepOrdersRootSubtreesByFullPath(t *testing.T) {
	db := useRollingStore(t)
	parent := t.TempDir()
	laterRoot := filepath.Join(parent, "ab")
	firstRoot := filepath.Join(parent, "ab.zz")
	first := writeYARADeepFile(t, firstRoot, "one.dat", "mal dot root")
	writeYARADeepFile(t, laterRoot, "two.dat", "mal plain root")

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{onScan: func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{laterRoot, firstRoot}}, nil)

	var paths []string
	for _, finding := range findings {
		if finding.Check == "yara_match_scheduled" {
			paths = append(paths, finding.FilePath)
		}
	}
	if len(paths) != 1 || paths[0] != first {
		t.Fatalf("first root window scanned %v, want lexicographically first path %s", paths, first)
	}
	if !collector.contains("yara_deep") {
		t.Fatal("partial root-order window must preserve findings from other windows")
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after first root window: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != first {
		t.Fatalf("cursor.LastPath = %q, want %q", cur.LastPath, first)
	}
}

func TestCheckYARADeepResumesRootWithTrailingSeparator(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a-first.dat", "mal first")
	second := writeYARADeepFile(t, root, "z-second.dat", "mal second")
	cfg := &config.Config{AccountRoots: []string{root + string(filepath.Separator)}}

	base := time.Now().Add(time.Hour)
	clock := base
	firstBackend := &recordingYARABackend{onScan: func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }}
	yara.SetActive(firstBackend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	firstFindings := CheckYARADeep(ctx, cfg, nil)
	cancel()
	if !findsPath(firstFindings, first) {
		t.Fatalf("first window did not scan %s: %+v", first, firstFindings)
	}

	secondBackend := &recordingYARABackend{}
	yara.SetActive(secondBackend)
	secondCtx, collector := withIncompleteCheckCollector(context.Background())
	secondFindings := CheckYARADeep(secondCtx, cfg, nil)

	if !findsPath(secondFindings, second) {
		t.Fatalf("resumed trailing-separator root did not scan %s: %+v", second, secondFindings)
	}
	if findsPath(secondFindings, first) {
		t.Fatalf("resumed trailing-separator root rescanned %s: %+v", first, secondFindings)
	}
	if !collector.contains("yara_deep") {
		t.Fatal("resumed trailing-separator root must preserve earlier-window findings")
	}
}

func TestCheckYARADeepSerializesCursorUpdates(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a-first.dat", "slow first")
	writeYARADeepFile(t, root, "z-last.dat", "clean last")

	backend := &concurrentYARABackend{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	base := time.Now().Add(time.Hour)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	previousNow := yaraDeepNow
	yaraDeepNow = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(func() { yaraDeepNow = previousNow })

	firstCtx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	firstDone := make(chan struct{})
	go func() {
		CheckYARADeep(firstCtx, &config.Config{AccountRoots: []string{root}}, nil)
		close(firstDone)
	}()
	<-backend.firstStarted

	secondDone := make(chan struct{})
	go func() {
		CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
		close(secondDone)
	}()

	select {
	case <-secondDone:
		clock.Store(base.Add(2 * time.Minute).UnixNano())
		close(backend.releaseFirst)
		<-firstDone
		t.Fatal("second scan completed while the first scan still owned the shared cursor")
	case <-time.After(100 * time.Millisecond):
	}
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	close(backend.releaseFirst)
	<-firstDone
	<-secondDone

	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after concurrent scans: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" {
		t.Fatalf("older partial window overwrote the completed cursor with %q, first path %q", cur.LastPath, first)
	}
}

func TestCheckYARADeepAdvancesCursorPastLstatError(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	bad := writeYARADeepFile(t, root, "a-bad.dat", "unreadable")
	writeYARADeepFile(t, root, "z-good.dat", "mal later")

	base := time.Now().Add(time.Hour)
	clock := base
	fs := &faultingYARADeepOS{OS: realOS{}}
	fs.lstat = func(path string) (os.FileInfo, error) {
		if path == bad {
			clock = clock.Add(2 * yaraDeepDeadlineMargin)
			return nil, errors.New("metadata unavailable")
		}
		return fs.OS.Lstat(path)
	}
	withMockOS(t, fs)
	useYARADeepClock(t, &clock)

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if !collector.contains("yara_deep") || !containsFindingCheck(findings, "yara_scan_incomplete") {
		t.Fatalf("metadata error did not mark the partial scan incomplete: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after metadata error: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != bad {
		t.Fatalf("cursor.LastPath = %q, want metadata error path %q", cur.LastPath, bad)
	}
}

func TestCheckYARADeepAdvancesCursorPastOversizeFile(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	oversize := writeYARADeepFile(t, root, "a-large.dat", strings.Repeat("x", 2*1024*1024))
	writeYARADeepFile(t, root, "z-good.dat", "mal later")

	base := time.Now().Add(time.Hour)
	clock := base
	fs := &faultingYARADeepOS{OS: realOS{}}
	fs.lstat = func(path string) (os.FileInfo, error) {
		info, err := fs.OS.Lstat(path)
		if path == oversize {
			clock = clock.Add(2 * yaraDeepDeadlineMargin)
		}
		return info, err
	}
	withMockOS(t, fs)
	useYARADeepClock(t, &clock)

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)
	cfg := &config.Config{AccountRoots: []string{root}}
	cfg.Thresholds.FullScanMaxFileMB = 1

	findings := CheckYARADeep(ctx, cfg, nil)

	if !collector.contains("yara_deep") || !containsFindingCheck(findings, "yara_scan_incomplete") {
		t.Fatalf("oversize file did not mark the partial scan incomplete: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after oversize file: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != oversize {
		t.Fatalf("cursor.LastPath = %q, want oversize path %q", cur.LastPath, oversize)
	}
}

func TestCheckYARADeepAdvancesCursorPastUnreadableDirectory(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	badDir := filepath.Join(root, "a-bad")
	if err := os.Mkdir(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeYARADeepFile(t, root, "z-good.dat", "mal later")

	base := time.Now().Add(time.Hour)
	clock := base
	fs := &faultingYARADeepOS{OS: realOS{}}
	fs.readDir = func(path string) ([]os.DirEntry, error) {
		if path == badDir {
			clock = clock.Add(2 * yaraDeepDeadlineMargin)
			return nil, errors.New("directory unavailable")
		}
		return fs.OS.ReadDir(path)
	}
	withMockOS(t, fs)
	useYARADeepClock(t, &clock)

	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if !collector.contains("yara_deep") || !containsFindingCheck(findings, "yara_scan_incomplete") {
		t.Fatalf("directory error did not mark the partial scan incomplete: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after directory error: ok=%v err=%v", ok, err)
	}
	want := badDir + string(filepath.Separator)
	if cur.LastPath != want {
		t.Fatalf("cursor.LastPath = %q, want unreadable subtree marker %q", cur.LastPath, want)
	}
}

func TestCheckYARADeepFullRunStaysComplete(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "a/one.dat", "mal one")
	writeYARADeepFile(t, root, "b/two.dat", "mal two")

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	count := 0
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("full run found %d matches, want 2: %+v", count, findings)
	}
	if collector.contains("yara_deep") {
		t.Fatal("an uninterrupted full run must stay complete so stale findings purge normally")
	}
	cur, ok, err := db.GetScanCursor("", "yara_deep")
	if err != nil || !ok {
		t.Fatalf("cursor after full run: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != "" || cur.LastFullCycleTS.IsZero() {
		t.Fatalf("cursor = %+v, want empty LastPath with LastFullCycleTS stamped", cur)
	}
}

func TestCheckYARADeepWarnsWhenFullCycleStale(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	writeYARADeepFile(t, root, "b/two.dat", "mal two")
	putYARADeepCursor(t, db, first, time.Now().UTC().Add(-yaraDeepFullCycleStale-24*time.Hour))

	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	// Soft deadline already passed at entry: no progress is possible this run.
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
	defer cancel()

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	warned := false
	for _, f := range findings {
		if f.Check == "yara_scan_incomplete" && f.Severity == alert.Warning && strings.Contains(f.Message, "full pass") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("stale rolling cycle produced no full-pass warning: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", "yara_deep")
	if err != nil || !ok {
		t.Fatalf("cursor: ok=%v err=%v", ok, err)
	}
	if cur.LastPath != first {
		t.Fatalf("no-progress run moved the cursor: %q, want %q", cur.LastPath, first)
	}
}

func TestCheckYARADeepKeepsStaleCycleWhenNoPathWasScanned(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "a/one.dat", "mal one")
	wrappedAt := time.Now().UTC().Add(-yaraDeepFullCycleStale - 24*time.Hour)
	var seed store.ScanCursorRecord
	seed.Check = yaraDeepCursorCheck
	seed.WrappedAt = wrappedAt
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

	base := time.Now().Add(time.Hour)
	clock := base
	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin-time.Second))
	defer cancel()
	ctx, collector := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if !collector.contains("yara_deep") {
		t.Fatal("no-progress partial run must preserve findings from earlier windows")
	}
	warned := false
	for _, finding := range findings {
		if finding.Check == "yara_scan_incomplete" && finding.Severity == alert.Warning {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("stale cycle with no cursor path produced no warning: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("cursor after no-progress run: ok=%v err=%v", ok, err)
	}
	if !cur.WrappedAt.Equal(wrappedAt) {
		t.Fatalf("cursor.WrappedAt = %s, want original cycle start %s", cur.WrappedAt, wrappedAt)
	}
}

func TestCheckYARADeepHardCancelKeepsCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	putYARADeepCursor(t, db, first, time.Now().UTC())

	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, nil)

	if findings != nil {
		t.Fatalf("hard-canceled run returned findings the runner would drop: %+v", findings)
	}
	cur, ok, err := db.GetScanCursor("", "yara_deep")
	if err != nil || !ok || cur.LastPath != first {
		t.Fatalf("hard cancel disturbed the cursor: %+v ok=%v err=%v", cur, ok, err)
	}
}
