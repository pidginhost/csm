package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/state"
)

// The JS consumer records one gap per file it could not analyze. When the
// analyzer cannot run, that is every candidate script on the host, and
// retaining one path string per file for the length of a scan grows without
// limit. Past the bound the run keeps counting but reports its exact path set
// as incomplete, so the purge is suppressed instead of carrying forward an
// arbitrary prefix.
func TestJSTaintGapPathsAreBounded(t *testing.T) {
	for _, withAliases := range []bool{false, true} {
		t.Run(fmt.Sprintf("aliases=%t", withAliases), func(t *testing.T) {
			status := jstaint.StatusResourceLimit.String()
			gaps := newJSTaintGapCollector()
			ctx, coverage := withCoveragePathCollector(context.Background())
			resolved := 0
			wantResolved, wantAliases := 0, maxJSTaintGapPaths
			if withAliases {
				wantResolved, wantAliases = maxJSTaintGapPaths, 2*maxJSTaintGapPaths
				gaps.resolveAliases = func(path string) ([]string, bool) {
					resolved++
					return []string{path, "/resolved" + path}, true
				}
			}
			gaps.recordCoverage = func(paths []string) {
				recordCoverageGapPaths(ctx, logicalOwnerJSTaintDeep, paths)
			}
			for i := 0; i < maxJSTaintGapPaths; i++ {
				gaps.record(fmt.Sprintf("/home/u/public_html/f%d.js", i), status)
			}
			// Seeing a retained path again still leaves the exact set authoritative.
			gaps.record("/home/u/public_html/f0.js", status)
			if gaps.pathsIncomplete() {
				t.Fatal("duplicate retained path falsely reported the exact set as incomplete")
			}
			gaps.record("/home/u/public_html/overflow.js", status)
			// Duplicates after overflow must reuse the aliases captured before it.
			gaps.record("/home/u/public_html/f0.js", status)
			if !gaps.pathsIncomplete() {
				t.Fatal("hit the bound without reporting the path set as incomplete")
			}
			if len(gaps.paths) != maxJSTaintGapPaths {
				t.Fatalf("retained %d paths, want exactly %d", len(gaps.paths), maxJSTaintGapPaths)
			}
			if gaps.hasPath("/home/u/public_html/overflow.js") {
				t.Fatal("a path past the bound was retained")
			}
			if resolved != wantResolved || len(gaps.aliasesByPath) != maxJSTaintGapPaths {
				t.Fatalf("resolved=%d cached=%d, want %d and %d", resolved, len(gaps.aliasesByPath), wantResolved, maxJSTaintGapPaths)
			}
			if len(gaps.pathAliases) != wantAliases {
				t.Fatalf("retained %d aliases, want %d", len(gaps.pathAliases), wantAliases)
			}
			if withAliases && !gaps.hasPath("/resolved/home/u/public_html/f0.js") {
				t.Fatal("retained alias no longer matches its gap")
			}
			published := coverage.gapPaths(logicalOwnerJSTaintDeep)
			if len(published) != wantAliases || published["/home/u/public_html/overflow.js"] || published["/resolved/home/u/public_html/overflow.js"] {
				t.Fatalf("published %d aliases, want only the %d retained aliases", len(published), wantAliases)
			}
			finding := gaps.finding()
			if want := fmt.Sprintf("JavaScript taint deep scan could not analyze %d file(s)", maxJSTaintGapPaths+3); finding.Message != want {
				t.Fatalf("message = %q, want the full count", finding.Message)
			}
			if !strings.Contains(finding.Details, "retained for only the first") {
				t.Fatalf("details = %q, want the truncation stated", finding.Details)
			}
		})
	}
}

// Virtual names share a real snapshot so the full walk can exceed the cap
// without creating thousands of files. Real metadata still exercises the
// stable-identity checks used when a gap is recorded.
type jsGapBoundOS struct {
	OS
	root     string
	snapshot string
	info     os.FileInfo
	count    int
}

func (o *jsGapBoundOS) ReadDir(path string) ([]os.DirEntry, error) {
	if path != o.root {
		return o.OS.ReadDir(path)
	}
	entries := make([]os.DirEntry, o.count)
	for i := range entries {
		entries[i] = dirEntry(fmt.Sprintf("f%06d.js", i), false)
	}
	return entries, nil
}

func (o *jsGapBoundOS) Lstat(path string) (os.FileInfo, error) {
	if filepath.Dir(path) == o.root {
		return o.info, nil
	}
	return o.OS.Lstat(path)
}

func (o *jsGapBoundOS) Open(path string) (*os.File, error) {
	if filepath.Dir(path) == o.root {
		return o.OS.Open(o.snapshot)
	}
	return o.OS.Open(path)
}

func TestCheckYARADeepJSGapOverflowPreservesFindings(t *testing.T) {
	useRollingStore(t)
	useNilYARABackend(t)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	root := t.TempDir()
	snapshot := writeYARADeepFile(t, t.TempDir(), "snapshot.js", jsKeyloggerFixture)
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	fs := &jsGapBoundOS{OS: osFS, root: root, snapshot: snapshot, info: info, count: maxJSTaintGapPaths + 2}
	withMockOS(t, fs)
	prior := []alert.Finding{
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "retained gap", FilePath: filepath.Join(root, "f000000.js")},
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "overflow gap", FilePath: filepath.Join(root, fmt.Sprintf("f%06d.js", maxJSTaintGapPaths))},
		{Check: "js_keylogger_dataflow", Severity: alert.Critical, Message: "missing path", FilePath: filepath.Join(root, "missing.js")},
	}
	st.SetLatestFindings(prior)
	prev := jsTaintAnalyze
	t.Cleanup(func() { jsTaintAnalyze = prev })
	calls := 0
	jsTaintAnalyze = func(ctx context.Context, data []byte) jstaint.Report {
		calls++
		if calls == fs.count {
			return jstaint.Analyze(ctx, data)
		}
		return jstaint.Report{Status: jstaint.StatusResourceLimit}
	}
	cfg := &config.Config{AccountRoots: []string{root}, DisabledChecks: []string{"yara_deep", logicalOwnerPHPTaintDeep}}
	ctx, gaps := WithCoverageGaps(context.Background())
	checks := []namedCheck{{name: "yara_deep", fn: CheckYARADeep}}
	findings, purge := runParallelWithContext(ctx, cfg, st, checks, "deep", true)
	if calls != fs.count {
		t.Fatalf("analyzed %d files, want %d", calls, fs.count)
	}
	if slices.Contains(purge, "js_keylogger_dataflow") || !gaps.Snapshot().IncompleteChecks["js_keylogger_dataflow"] {
		t.Error("overflow allowed the JS owner to retire prior findings")
	}
	if !slices.Contains(purge, "js_taint_scan_incomplete") {
		t.Error("overflow must still replace the previous coverage diagnostic")
	}
	if len(gaps.Paths()["js_keylogger_dataflow"]) != 0 {
		t.Error("overflow published a truncated path set as authoritative")
	}
	incomplete := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(incomplete) != 1 {
		t.Fatalf("got %d coverage diagnostics, want one", len(incomplete))
	}
	if want := fmt.Sprintf("JavaScript taint deep scan could not analyze %d file(s)", fs.count-1); incomplete[0].Message != want || !strings.Contains(incomplete[0].Details, "retained for only the first") {
		t.Fatalf("diagnostic = %+v, want full count and truncation", incomplete[0])
	}
	fresh := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(fresh) != 1 || fresh[0].ScanCarryForward || fresh[0].FilePath != filepath.Join(root, fmt.Sprintf("f%06d.js", fs.count-1)) {
		t.Fatalf("JS findings = %+v, want the new detection after overflow", fresh)
	}
	StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
	stored := jsFindingsByCheck(st.LatestFindings(), "js_keylogger_dataflow")
	if len(stored) != len(prior)+1 {
		t.Fatalf("stored %d findings, want all %d prior findings and the new detection", len(stored), len(prior))
	}
	for _, f := range prior {
		if !slices.ContainsFunc(stored, func(got alert.Finding) bool { return got.Key() == f.Key() }) {
			t.Errorf("lost prior finding at %s", f.FilePath)
		}
	}

	// Truncation is per run: a later complete scan may retire old state.
	fs.count = 1
	jsTaintAnalyze = func(context.Context, []byte) jstaint.Report {
		return jstaint.Report{Status: jstaint.StatusAnalyzed}
	}
	findings, purge = runParallelWithContext(ctx, cfg, st, checks, "deep", true)
	if !slices.Contains(purge, "js_keylogger_dataflow") || gaps.Snapshot().IncompleteChecks["js_keylogger_dataflow"] {
		t.Fatal("a complete scan remained incomplete after the overflowing run")
	}
	StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
	for _, check := range jsOwnerPurgeNames() {
		if got := jsFindingsByCheck(st.LatestFindings(), check); len(got) != 0 {
			t.Errorf("complete clean scan retained %s: %+v", check, got)
		}
	}
}
