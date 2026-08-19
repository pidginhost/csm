package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/phptaint"
)

func withPHPTaintAnalyzer(t *testing.T, fn func(context.Context, []byte) phptaint.Report) {
	t.Helper()
	prev := phpTaintAnalyze
	phpTaintAnalyze = fn
	t.Cleanup(func() { phpTaintAnalyze = prev })
}

// TestPHPTaintDefaultsToACoverageGapWithoutAWorker is the safety property of
// this whole adapter. The analyzer must never run in the daemon's own process:
// its parser can loop forever on attacker input and no in-process deadline can
// stop it. So when no worker is wired, the honest answer is a recorded gap --
// NOT a fallback to analyzing here, and NOT silence, which would read as clean.
func TestPHPTaintDefaultsToACoverageGapWithoutAWorker(t *testing.T) {
	report := defaultPHPTaintAnalyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if report.Status == phptaint.StatusAnalyzed || report.Status == phptaint.StatusNotCandidate {
		t.Fatalf("status = %v, want a coverage gap when no worker is configured", report.Status)
	}
	if report.Reason == "" {
		t.Fatal("gap has no reason")
	}
}

func TestPHPTaintSnapshotReportsAFlow(t *testing.T) {
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results: []phptaint.Result{{
				Source: "curl_exec", Sink: "eval",
				Confidence: phptaint.ConfidenceHigh, Identifiers: []string{"$p"},
			}},
		}
	})
	gaps := newPHPTaintGapCollector()
	got := analyzePHPTaintSnapshot(context.Background(), "/home/u/public_html/x.php", "sha", nil, gaps)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].Check != "php_remote_taint" || got[0].Severity != alert.Critical {
		t.Fatalf("finding = %+v", got[0])
	}
	if !gaps.empty() {
		t.Fatal("an analyzed file was recorded as a gap")
	}
}

func TestPHPTaintSnapshotStaysSilentWhenClean(t *testing.T) {
	for _, status := range []phptaint.Status{phptaint.StatusAnalyzed, phptaint.StatusNotCandidate} {
		withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
			return phptaint.Report{Status: status}
		})
		gaps := newPHPTaintGapCollector()
		if got := analyzePHPTaintSnapshot(context.Background(), "/x.php", "sha", nil, gaps); len(got) != 0 {
			t.Fatalf("status %v produced findings %+v", status, got)
		}
		if !gaps.empty() {
			t.Fatalf("status %v recorded a gap", status)
		}
	}
}

// TestPHPTaintRecordsEveryNonCompletedStatusAsAGap walks the full status set so
// a status added later cannot quietly fall through as clean.
func TestPHPTaintRecordsEveryNonCompletedStatusAsAGap(t *testing.T) {
	gapStatuses := []phptaint.Status{
		phptaint.StatusOversize, phptaint.StatusParseError, phptaint.StatusPartialParse,
		phptaint.StatusResourceLimit, phptaint.StatusCanceled, phptaint.StatusPanic,
		phptaint.StatusTimeout, phptaint.StatusWorkerFailure,
	}
	for _, status := range gapStatuses {
		withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
			return phptaint.Report{Status: status, Reason: "r"}
		})
		gaps := newPHPTaintGapCollector()
		if got := analyzePHPTaintSnapshot(context.Background(), "/x.php", "sha", nil, gaps); len(got) != 0 {
			t.Fatalf("status %v produced findings", status)
		}
		if gaps.empty() || !gaps.hasPath("/x.php") {
			t.Fatalf("status %v was not recorded as a gap", status)
		}
		if name := status.String(); name == "unknown" {
			t.Fatalf("status %v renders as unknown in the gap report", status)
		}
	}
}

// TestPHPTaintAdapterContainsAPanic keeps a defect in adapter-side code from
// escaping through the owning check.
func TestPHPTaintAdapterContainsAPanic(t *testing.T) {
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		panic("boom")
	})
	report := runPHPTaintAnalysis(context.Background(), nil)
	if report.Status != phptaint.StatusPanic {
		t.Fatalf("status = %v, want StatusPanic", report.Status)
	}
}

func TestPHPTaintCarriesForwardPriorFindingOnAGap(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/x.php", phptaint.StatusTimeout.String())
	prior := []alert.Finding{
		{Check: "php_remote_taint", FilePath: "/home/u/public_html/x.php", Message: "old"},
		{Check: "php_remote_taint", FilePath: "/home/u/other.php", Message: "not gapped"},
		{Check: "something_else", FilePath: "/home/u/public_html/x.php", Message: "wrong check"},
	}
	carried := carryForwardPHPTaintFindings(prior, gaps)
	if len(carried) != 1 || carried[0].FilePath != "/home/u/public_html/x.php" {
		t.Fatalf("carried = %+v, want only the gapped path's finding", carried)
	}
}

func TestPHPTaintGapFindingNamesStatusesAndCounts(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/a.php", phptaint.StatusTimeout.String())
	gaps.record("/b.php", phptaint.StatusTimeout.String())
	gaps.record("/c.php", phptaint.StatusWorkerFailure.String())
	f := gaps.finding()
	if f.Check != "php_taint_scan_incomplete" {
		t.Fatalf("check = %s", f.Check)
	}
	if !strings.Contains(f.Details, "timeout=2") || !strings.Contains(f.Details, "worker_failure=1") {
		t.Fatalf("details = %q, want per-status counts", f.Details)
	}
	if !strings.Contains(f.Message, "3") {
		t.Fatalf("message = %q, want the total", f.Message)
	}
}

// TestPHPTaintConsumerSilentWithoutAnAnalyzer pins the readiness gate. Without
// an isolated analyzer the feature is inactive, and an inactive feature must
// report nothing at all -- not a coverage gap per candidate file, which would
// put a warning on every scan of every host that has not enabled it.
func TestPHPTaintConsumerSilentWithoutAnAnalyzer(t *testing.T) {
	SetPHPTaintAnalyzer(nil)
	if phpTaintAnalyzerReady() {
		t.Fatal("reported ready with no analyzer installed")
	}
}

// TestPHPTaintConsumerReadyWithAnAnalyzer is the other half: once the daemon
// supervises a worker, the consumer dispatches.
func TestPHPTaintConsumerReadyWithAnAnalyzer(t *testing.T) {
	SetPHPTaintAnalyzer(stubPHPAnalyzer{})
	t.Cleanup(func() { SetPHPTaintAnalyzer(nil) })
	if !phpTaintAnalyzerReady() {
		t.Fatal("analyzer installed but not reported ready")
	}
	if got := defaultPHPTaintAnalyze(context.Background(), []byte("<?php")); got.Status != phptaint.StatusAnalyzed {
		t.Fatalf("status = %v, want the installed analyzer to be used", got.Status)
	}
}

type stubPHPAnalyzer struct{}

func (stubPHPAnalyzer) Analyze(context.Context, []byte) phptaint.Report {
	return phptaint.Report{Status: phptaint.StatusAnalyzed}
}
