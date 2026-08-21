package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
)

// Panics and timeouts mean a file crashed or stalled the analyzer. They are not
// the same thing as a file being too large to read. Reporting all three in one
// finding buried the hard failures on a real host.
func TestPHPTaintGapsReportAnalyzerDefeatsSeparately(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/error_log", phptaint.StatusOversize.String())
	gaps.record("/home/u/public_html/panic-in-path.php", phptaint.StatusPanic.String())
	gaps.record("/home/u/public_html/stalled.php", phptaint.StatusTimeout.String())

	found := gaps.findings()
	if len(found) != 2 {
		t.Fatalf("findings = %d, want 2 (routine gaps and analyzer defeats separately): %+v", len(found), found)
	}

	var routine, defeat alert.Finding
	for _, f := range found {
		if f.Check != "php_taint_scan_incomplete" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if strings.Contains(f.Message, "crashed or stalled") {
			defeat = f
		} else {
			routine = f
		}
	}
	if defeat.Message == "" {
		t.Fatal("no finding reported the analyzer-defeating content")
	}
	if routine.Message == "" {
		t.Fatal("no finding reported the routine gaps")
	}
	if strings.Contains(strings.ToLower(defeat.Message), "parser") {
		t.Errorf("generic panic status was falsely attributed to the parser: %q", defeat.Message)
	}
	if strings.Contains(routine.Details, phptaint.StatusPanic.String()) || strings.Contains(routine.Details, phptaint.StatusTimeout.String()) {
		t.Errorf("routine-gap finding carries analyzer-defeat counts: %q", routine.Details)
	}
	if strings.Contains(defeat.Details, phptaint.StatusOversize.String()) {
		t.Errorf("analyzer-defeat finding was diluted with oversize counts: %q", defeat.Details)
	}
	if !strings.Contains(defeat.Details, "panic=1") || !strings.Contains(defeat.Details, "timeout=1") {
		t.Errorf("analyzer-defeat details lost a hard-failure status: %q", defeat.Details)
	}
	if routine.Key() == defeat.Key() {
		t.Fatalf("split findings share dedup key %q", routine.Key())
	}
}

// A run with no analyzer defeat must still produce exactly one finding, so the
// split does not double-report the ordinary case.
func TestPHPTaintGapsStayOneFindingWithoutAnalyzerDefeat(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/error_log", phptaint.StatusOversize.String())
	gaps.record("/home/u/public_html/big.json", phptaint.StatusOversize.String())

	found := gaps.findings()
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Details, phptaint.StatusOversize.String()) {
		t.Errorf("details lost the oversize count: %q", found[0].Details)
	}
}

// And a run whose only gap is an analyzer defeat reports just that.
func TestPHPTaintGapsReportAnalyzerDefeatAlone(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/shell.php", phptaint.StatusPanic.String())
	gaps.pathsTruncated = true

	found := gaps.findings()
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Details, phptaint.StatusPanic.String()) {
		t.Errorf("details lost the panic count: %q", found[0].Details)
	}
	if !strings.Contains(found[0].Details, "exact paths retained") {
		t.Errorf("defeat-only finding lost the path-retention gap: %q", found[0].Details)
	}
}

// Range-loss diagnostics describe the collector as a whole. Splitting status
// groups must not duplicate them, and the retained single finding must carry
// the same status counts and range-loss facts as the split form.
func TestPHPTaintGapSplitPreservesCoverageFactsExactlyOnce(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/big.php", phptaint.StatusOversize.String())
	gaps.record("/home/u/public_html/shell.php", phptaint.StatusPanic.String())
	gaps.recordUnknownRange("reading /home/u/hidden: permission denied")
	gaps.pathsTruncated = true

	unsplit := gaps.finding()
	found := gaps.findings()
	if len(found) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(found), found)
	}
	joined := found[0].Details + "; " + found[1].Details
	for _, fact := range []string{"oversize=1", "panic=1", "unreadable-range=1", "exact paths retained"} {
		if strings.Count(unsplit.Details, fact) != 1 {
			t.Errorf("single finding has %d copies of %q: %q", strings.Count(unsplit.Details, fact), fact, unsplit.Details)
		}
		if strings.Count(joined, fact) != 1 {
			t.Errorf("split findings have %d copies of %q: %q", strings.Count(joined, fact), fact, joined)
		}
	}
}

// The split must reach the deep scan's output, not just the collector. A test
// that only exercises the helper passes with the call site reverted.
func TestCheckYARADeepEmitsAnalyzerDefeatFinding(t *testing.T) {
	for _, status := range []phptaint.Status{phptaint.StatusPanic, phptaint.StatusTimeout} {
		t.Run(status.String(), func(t *testing.T) {
			useRollingStore(t)
			enablePHPTaintConsumer(t)
			root := t.TempDir()
			writeYARADeepFile(t, root, "a/one.php", "<?php $x = curl_exec($c); eval($x); }")
			withPHPTaintAnalyzer(t, func(ctx context.Context, src []byte) phptaint.Report {
				return phptaint.Report{Status: status, Reason: "analysis failed"}
			})

			findings := CheckYARADeep(context.Background(), &config.Config{
				AccountRoots:   []string{root},
				DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
			}, nil)

			var defeat bool
			for _, f := range findings {
				if f.Check == "php_taint_scan_incomplete" && strings.Contains(f.Message, "crashed or stalled") {
					defeat = true
				}
			}
			if !defeat {
				t.Fatalf("deep scan did not surface the analyzer-defeat finding for %s: %+v", status, findings)
			}
		})
	}
}
