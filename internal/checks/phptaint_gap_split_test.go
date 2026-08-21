package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"

	"github.com/pidginhost/csm/internal/phptaint"
)

// A panic means content that looked like PHP defeated the parser. That is
// either an upstream parser defect or a deliberate evasion attempt, and it is
// not the same thing as a log file being too big to read. Reporting both in one
// finding buried the panics: a real scan carried oversize=617 alongside panic=3.
func TestPHPTaintGapsReportParserDefeatSeparately(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/error_log", phptaint.StatusOversize.String())
	gaps.record("/home/u/public_html/shell.php", phptaint.StatusPanic.String())

	found := gaps.findings()
	if len(found) != 2 {
		t.Fatalf("findings = %d, want 2 (benign gaps and parser defeat separately): %+v", len(found), found)
	}

	var benign, defeat string
	for _, f := range found {
		if f.Check != "php_taint_scan_incomplete" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if strings.Contains(f.Details, phptaint.StatusPanic.String()) {
			defeat = f.Details
		} else {
			benign = f.Details
		}
	}
	if defeat == "" {
		t.Fatal("no finding reported the parser-defeating content")
	}
	if benign == "" {
		t.Fatal("no finding reported the benign gaps")
	}
	if strings.Contains(benign, phptaint.StatusPanic.String()) {
		t.Error("the benign-gap finding must not carry the panic count")
	}
	if strings.Contains(defeat, phptaint.StatusOversize.String()) {
		t.Error("the parser-defeat finding must not be diluted with oversize counts")
	}
}

// A run with no parser defeat must still produce exactly one finding, so the
// split does not double-report the ordinary case.
func TestPHPTaintGapsStayOneFindingWithoutParserDefeat(t *testing.T) {
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

// And a run whose only gap is a parser defeat reports just that.
func TestPHPTaintGapsReportParserDefeatAlone(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/shell.php", phptaint.StatusPanic.String())

	found := gaps.findings()
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Details, phptaint.StatusPanic.String()) {
		t.Errorf("details lost the panic count: %q", found[0].Details)
	}
}

// The split must reach the deep scan's output, not just the collector. A test
// that only exercises the helper passes with the call site reverted.
func TestCheckYARADeepEmitsParserDefeatFinding(t *testing.T) {
	useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "a/one.php", "<?php $x = curl_exec($c); eval($x); }")
	withPHPTaintAnalyzer(t, func(ctx context.Context, src []byte) phptaint.Report {
		return phptaint.Report{Status: phptaint.StatusPanic, Reason: "recovered panic during analysis"}
	})

	findings := CheckYARADeep(context.Background(), &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)

	var defeat bool
	for _, f := range findings {
		if f.Check == "php_taint_scan_incomplete" && strings.Contains(f.Message, "crash the parser") {
			defeat = true
		}
	}
	if !defeat {
		t.Fatalf("deep scan did not surface the parser-defeat finding: %+v", findings)
	}
}
