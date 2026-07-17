package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
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
	seed := store.ScanCursorRecord{Account: "", Check: "yara_deep", LastPath: first, WrappedAt: time.Now().UTC()}
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

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
	seed := store.ScanCursorRecord{Account: "", Check: "yara_deep", LastPath: scannedAlready, WrappedAt: time.Now().UTC()}
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

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
	seed := store.ScanCursorRecord{
		Account:   "",
		Check:     "yara_deep",
		LastPath:  first,
		WrappedAt: time.Now().UTC().Add(-yaraDeepFullCycleStale - 24*time.Hour),
	}
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

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

func TestCheckYARADeepHardCancelKeepsCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	seed := store.ScanCursorRecord{Account: "", Check: "yara_deep", LastPath: first, WrappedAt: time.Now().UTC()}
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

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
