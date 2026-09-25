package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const testMiB = int64(1024 * 1024)

// errorLogFixture is a /home tree plus the cPanel domain map the check reads.
// Warn is 1 MiB and critical 4 MiB so sparse files keep the tests cheap.
type errorLogFixture struct {
	home    string
	main    string
	cfg     *config.Config
	mapData string
	mapErr  error
}

func newErrorLogFixture(t *testing.T) *errorLogFixture {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	fx := &errorLogFixture{home: home, main: filepath.Join(home, "alice", "public_html")}
	if err := os.MkdirAll(fx.main, 0o755); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				if fx.mapErr != nil {
					return nil, fx.mapErr
				}
				return []byte(fx.mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		lstat:   os.Lstat,
		glob:    filepath.Glob,
	})
	enabled := true
	fx.cfg = &config.Config{AccountRoots: []string{filepath.Join(home, "*", "public_html")}}
	fx.cfg.Performance.Enabled = &enabled
	fx.cfg.Performance.ErrorLogWarnSizeMB = 1
	fx.cfg.Performance.ErrorLogCriticalSizeMB = 4
	return fx
}

// mapDocroot adds a cPanel domain map row serving domain from docroot.
func (fx *errorLogFixture) mapDocroot(t *testing.T, user, domain, docroot string) {
	t.Helper()
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatal(err)
	}
	row := fmt.Sprintf("%s: %s==root==addon==example.com==%s==192.0.2.10:80==192.0.2.10:443====0==ea-php82", domain, user, docroot)
	if fx.mapData != "" {
		fx.mapData += "\n"
	}
	fx.mapData += row
}

// writeSizedFile creates a sparse file of exactly size bytes.
func writeSizedFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// errorLogFindingPaths maps each reported path to how often it was reported.
// The Web UI's truncate button reads the path from the Message, so that is the
// contract asserted here.
func errorLogFindingPaths(t *testing.T, findings []alert.Finding) map[string]int {
	t.Helper()
	out := make(map[string]int)
	for _, f := range findings {
		if f.Check != "perf_error_logs" {
			t.Errorf("unexpected check %q", f.Check)
			continue
		}
		path, ok := strings.CutPrefix(f.Message, "Bloated error_log: ")
		if !ok {
			t.Errorf("message %q lacks the path prefix", f.Message)
			continue
		}
		out[path]++
	}
	return out
}

func errorLogFindingFor(t *testing.T, findings []alert.Finding, path string) alert.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Message == "Bloated error_log: "+path {
			return f
		}
	}
	t.Fatalf("no finding for %s in %+v", path, findings)
	return alert.Finding{}
}

func withErrorLogClock(t *testing.T, now *time.Time) {
	t.Helper()
	prev := errorLogNow
	errorLogNow = func() time.Time { return *now }
	t.Cleanup(func() { errorLogNow = prev })
}

// Addon domains are served from /home/<user>/<domain>/, never below
// public_html, so a check that only walked public_html never saw their logs.
func TestErrorLogBloatCoversAddonDomainDocroots(t *testing.T) {
	fx := newErrorLogFixture(t)
	addon := filepath.Join(fx.home, "alice", "shop.example.com")
	fx.mapDocroot(t, "alice", "example.com", fx.main)
	fx.mapDocroot(t, "alice", "shop.example.com", addon)
	writeSizedFile(t, filepath.Join(fx.main, "error_log"), 2*testMiB)
	writeSizedFile(t, filepath.Join(addon, "error_log"), 2*testMiB)

	got := errorLogFindingPaths(t, CheckErrorLogBloat(context.Background(), fx.cfg, nil))

	want := map[string]int{
		filepath.Join(fx.main, "error_log"): 1,
		filepath.Join(addon, "error_log"):   1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reported paths = %v, want %v", got, want)
	}
}

// A docroot nested inside another is scanned as its own root; the broader
// root must leave that subtree alone or the same log is reported twice.
func TestErrorLogBloatNestedDocrootReportedOnce(t *testing.T) {
	fx := newErrorLogFixture(t)
	nested := filepath.Join(fx.main, "blog")
	fx.mapDocroot(t, "alice", "example.com", fx.main)
	fx.mapDocroot(t, "alice", "blog.example.com", nested)
	writeSizedFile(t, filepath.Join(nested, "error_log"), 2*testMiB)

	got := errorLogFindingPaths(t, CheckErrorLogBloat(context.Background(), fx.cfg, nil))

	if want := map[string]int{filepath.Join(nested, "error_log"): 1}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reported paths = %v, want %v", got, want)
	}
}

// PHP writes error_log next to the executing script, so admin-ajax.php errors
// land in wp-admin/error_log. The walk still does not descend into these
// trees, but a log sitting directly inside one is reported.
func TestErrorLogBloatChecksLogsDirectlyInsideSkippedDirs(t *testing.T) {
	fx := newErrorLogFixture(t)
	adminLog := filepath.Join(fx.main, "wp-admin", "error_log")
	contentLog := filepath.Join(fx.main, "wp-content", "error_log")
	pluginLog := filepath.Join(fx.main, "wp-content", "plugins", "shop", "error_log")
	for _, p := range []string{adminLog, contentLog, pluginLog} {
		writeSizedFile(t, p, 2*testMiB)
	}

	got := errorLogFindingPaths(t, CheckErrorLogBloat(context.Background(), fx.cfg, nil))

	want := map[string]int{adminLog: 1, contentLog: 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reported paths = %v, want %v", got, want)
	}
}

// A log directly inside a skipped directory is only reported when it is a
// regular file; a symlink named error_log must not redirect the size probe.
func TestErrorLogBloatIgnoresSymlinkInsideSkippedDir(t *testing.T) {
	fx := newErrorLogFixture(t)
	target := filepath.Join(fx.home, "alice", "big.bin")
	writeSizedFile(t, target, 8*testMiB)
	if err := os.MkdirAll(filepath.Join(fx.main, "wp-admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(fx.main, "wp-admin", "error_log")); err != nil {
		t.Fatal(err)
	}

	if got := CheckErrorLogBloat(context.Background(), fx.cfg, nil); len(got) != 0 {
		t.Fatalf("symlinked error_log reported: %+v", got)
	}
}

// Size decides severity: over the warning size is a Warning (Performance page
// only), over the critical size is High so the operator is told.
func TestErrorLogBloatSeverityFollowsSizeTiers(t *testing.T) {
	fx := newErrorLogFixture(t)
	small := filepath.Join(fx.main, "a", "error_log")
	warn := filepath.Join(fx.main, "b", "error_log")
	crit := filepath.Join(fx.main, "c", "error_log")
	writeSizedFile(t, small, testMiB/2)
	writeSizedFile(t, warn, 2*testMiB)
	writeSizedFile(t, crit, 5*testMiB)

	findings := CheckErrorLogBloat(context.Background(), fx.cfg, nil)

	if got := errorLogFindingPaths(t, findings); got[small] != 0 || got[warn] != 1 || got[crit] != 1 {
		t.Fatalf("reported paths = %v", got)
	}
	if sev := errorLogFindingFor(t, findings, warn).Severity; sev != alert.Warning {
		t.Errorf("2 MiB log severity = %v, want Warning", sev)
	}
	if sev := errorLogFindingFor(t, findings, crit).Severity; sev != alert.High {
		t.Errorf("5 MiB log severity = %v, want High", sev)
	}
}

// The finding identity must survive the log growing, or every hourly run is a
// "new" finding: a High one re-alerts each hour and a dismissal never sticks.
// Crossing into the critical tier is a new event and gets a new identity.
func TestErrorLogBloatKeyIsStableAsLogGrows(t *testing.T) {
	fx := newErrorLogFixture(t)
	path := filepath.Join(fx.main, "error_log")
	keyAt := func(size int64) string {
		t.Helper()
		writeSizedFile(t, path, size)
		findings := CheckErrorLogBloat(context.Background(), fx.cfg, nil)
		return errorLogFindingFor(t, findings, path).Key()
	}

	warnSmall, warnLarge := keyAt(2*testMiB), keyAt(3*testMiB)
	critSmall, critLarge := keyAt(5*testMiB), keyAt(9*testMiB)

	if warnSmall != warnLarge {
		t.Errorf("warning key changed with size: %q -> %q", warnSmall, warnLarge)
	}
	if critSmall != critLarge {
		t.Errorf("critical key changed with size: %q -> %q", critSmall, critLarge)
	}
	if warnSmall == critSmall {
		t.Errorf("escalation to critical kept the warning key %q", warnSmall)
	}
}

// Growth separates a live problem from an old, static log. The rate is only
// claimed across at least an hour, and a shrink (truncation, rotation) has no
// rate at all.
func TestErrorLogBloatReportsGrowthRate(t *testing.T) {
	fx := newErrorLogFixture(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	path := filepath.Join(fx.main, "error_log")
	details := func(size int64) string {
		t.Helper()
		writeSizedFile(t, path, size)
		return errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, store), path).Details
	}

	if got := details(2 * testMiB); got != "Size: 2M" {
		t.Fatalf("first observation details = %q, want %q", got, "Size: 2M")
	}
	now = now.Add(10 * time.Minute)
	if got := details(3 * testMiB); got != "Size: 3M" {
		t.Fatalf("details after 10 minutes = %q, want no rate yet", got)
	}
	// 12 hours after the first observation the log is 10 MiB larger: 20 MiB/day.
	now = now.Add(12*time.Hour - 10*time.Minute)
	if got := details(12 * testMiB); got != "Size: 12M, growing 20M/day" {
		t.Fatalf("details after 12 hours = %q", got)
	}
	now = now.Add(12 * time.Hour)
	if got := details(2 * testMiB); got != "Size: 2M" {
		t.Fatalf("details after a shrink = %q, want no rate", got)
	}
}

// A truncation minutes after the last run restarts the baseline at once;
// keeping the older, larger size would hide the regrowth that follows.
func TestErrorLogBloatShrinkRestartsBaselineImmediately(t *testing.T) {
	fx := newErrorLogFixture(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	path := filepath.Join(fx.main, "error_log")
	details := func(size int64) string {
		t.Helper()
		writeSizedFile(t, path, size)
		return errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, store), path).Details
	}

	_ = details(12 * testMiB)
	now = now.Add(10 * time.Minute)
	_ = details(2 * testMiB)
	now = now.Add(12 * time.Hour)
	if got := details(12 * testMiB); got != "Size: 12M, growing 20M/day" {
		t.Fatalf("details after regrowth = %q", got)
	}
}

// A log that disappears loses its baseline, so its return is not compared
// against a stale size from before it was deleted.
func TestErrorLogBloatDropsBaselineForVanishedLogs(t *testing.T) {
	fx := newErrorLogFixture(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	path := filepath.Join(fx.main, "error_log")

	writeSizedFile(t, path, 2*testMiB)
	_ = CheckErrorLogBloat(context.Background(), fx.cfg, store)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if got := CheckErrorLogBloat(context.Background(), fx.cfg, store); len(got) != 0 {
		t.Fatalf("removed log still reported: %+v", got)
	}
	now = now.Add(2 * time.Hour)
	writeSizedFile(t, path, 6*testMiB)
	got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, store), path).Details
	if got != "Size: 6M" {
		t.Fatalf("details = %q, want no rate against the pre-deletion size", got)
	}
}

// A run that could not read the domain map never looked at addon docroots.
// Their baselines must survive it, or one bad read resets every growth rate.
func TestErrorLogBloatIncompleteScanKeepsUnscannedBaselines(t *testing.T) {
	fx := newErrorLogFixture(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	addon := filepath.Join(fx.home, "alice", "shop.example.com")
	fx.mapDocroot(t, "alice", "shop.example.com", addon)
	path := filepath.Join(addon, "error_log")

	writeSizedFile(t, path, 2*testMiB)
	_ = CheckErrorLogBloat(context.Background(), fx.cfg, store)
	now = now.Add(2 * time.Hour)
	fx.mapErr = fs.ErrPermission
	_ = CheckErrorLogBloat(context.Background(), fx.cfg, store)
	now = now.Add(10 * time.Hour)
	fx.mapErr = nil
	writeSizedFile(t, path, 12*testMiB)

	got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, store), path).Details
	if got != "Size: 12M, growing 20M/day" {
		t.Fatalf("details = %q, want the rate from the first observation", got)
	}
}

// The finding cap keeps the page readable, but it must keep the worst logs,
// not whichever 20 the walk happened to visit first.
func TestErrorLogBloatKeepsLargestWhenCapped(t *testing.T) {
	fx := newErrorLogFixture(t)
	for i := 0; i < 25; i++ {
		// d00 is the smallest (2 MiB), d24 the largest (26 MiB).
		writeSizedFile(t, filepath.Join(fx.main, fmt.Sprintf("d%02d", i), "error_log"), int64(i+2)*testMiB)
	}

	findings := CheckErrorLogBloat(context.Background(), fx.cfg, nil)

	got := errorLogFindingPaths(t, findings)
	var reported []string
	for p := range got {
		reported = append(reported, filepath.Base(filepath.Dir(p)))
	}
	sort.Strings(reported)
	var want []string
	for i := 5; i < 25; i++ {
		want = append(want, fmt.Sprintf("d%02d", i))
	}
	if strings.Join(reported, ",") != strings.Join(want, ",") {
		t.Fatalf("reported dirs = %v, want %v", reported, want)
	}
}

// An unreadable domain map means addon docroots went unscanned; the runner
// must keep the previous findings instead of clearing them as resolved.
func TestErrorLogBloatMarksIncompleteWhenDomainMapUnreadable(t *testing.T) {
	fx := newErrorLogFixture(t)
	fx.mapErr = fs.ErrPermission
	path := filepath.Join(fx.main, "error_log")
	writeSizedFile(t, path, 2*testMiB)

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	got := errorLogFindingPaths(t, CheckErrorLogBloat(ctx, fx.cfg, nil))

	if got[path] != 1 {
		t.Errorf("public_html log not reported: %v", got)
	}
	if !incomplete.contains("perf_error_logs") {
		t.Fatal("unreadable domain map must mark perf_error_logs incomplete")
	}
}
