package checks

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Production behaviour this pins down: a YARA deep scan that met one
// unreadable file reported only "could not inspect 18 file or directory
// entries" and froze every yara_match_scheduled finding on the host. The gap
// kinds were indistinguishable, so a permanently oversized log looked the same
// as a lost subtree.

func TestYARAGapFindingNamesEachGapKind(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/a/big.zip", "oversize")
	g.record("/home/a/other.zip", "oversize")
	g.record("/home/b/locked.php", "open_error")

	f := g.finding()
	if f.Check != "yara_scan_incomplete" {
		t.Fatalf("check = %q", f.Check)
	}
	if !strings.Contains(f.Message, "3 file(s)") {
		t.Fatalf("message should count every gap, got %q", f.Message)
	}
	for _, want := range []string{"oversize=2", "open_error=1", "/home/a/big.zip"} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details missing %q, got %q", want, f.Details)
		}
	}
}

// A gap that names a file must not make the run partial: the scan covered
// everything else and is entitled to retire those findings.
func TestYARAKnownPathGapsDoNotMakeTheRunPartial(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/a/big.zip", "oversize")
	if g.pathsIncomplete() {
		t.Fatal("a gap that names a file leaves the path set authoritative")
	}
}

// An unknown range does, because the unscanned span cannot be enumerated.
func TestYARAUnknownRangeMakesTheRunPartial(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/a/big.zip", "oversize")
	g.recordUnknownRange("/home/c/unreadable-dir")
	if !g.pathsIncomplete() {
		t.Fatal("a lost range must suppress the purge for the whole owner")
	}
	if !strings.Contains(g.finding().Details, "unreadable-range=1") {
		t.Errorf("details should report the lost range, got %q", g.finding().Details)
	}
}

// Past the retention bound the path set can no longer be trusted, so the run
// goes partial rather than letting a purge clear a path it cannot name.
func TestYARAGapPathTruncationMakesTheRunPartial(t *testing.T) {
	g := newYARAGapCollector()
	for i := 0; i < maxYARAGapPaths+5; i++ {
		g.record("/home/a/f"+strconv.Itoa(i), "oversize")
	}
	if !g.pathsIncomplete() {
		t.Fatal("a truncated path set must suppress the purge")
	}
	if !strings.Contains(g.finding().Details, "exact paths retained") {
		t.Errorf("details should admit truncation, got %q", g.finding().Details)
	}
}

// The carry-forward is what lets the purge run at all: a file the scan could
// not read has its existing finding re-emitted, so the purge clears everything
// else without discarding a finding nothing disproved.
func TestYARACarryForwardReEmitsOnlyGappedPaths(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/b/error_log", "oversize")

	prior := []alert.Finding{
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "gapped", Severity: alert.Critical, Timestamp: time.Unix(100, 0)},
		{Check: "yara_match_scheduled", FilePath: "/home/a/scanned.php", Message: "covered", Severity: alert.Critical, Timestamp: time.Unix(100, 0)},
		{Check: "php_remote_taint", FilePath: "/home/b/error_log", Message: "other owner", Severity: alert.Critical, Timestamp: time.Unix(100, 0)},
	}

	carried := carryForwardYARAFindings(prior, g)
	if len(carried) != 1 {
		t.Fatalf("want only the gapped YARA finding carried, got %d: %+v", len(carried), carried)
	}
	if carried[0].FilePath != "/home/b/error_log" || carried[0].Check != "yara_match_scheduled" {
		t.Fatalf("carried the wrong finding: %+v", carried[0])
	}
}

// One finding per gapped path, newest wins, so a carry-forward cannot multiply
// findings across cycles.
func TestYARACarryForwardKeepsOneFindingPerPath(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/b/error_log", "oversize")

	prior := []alert.Finding{
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "old", Severity: alert.Critical, Timestamp: time.Unix(100, 0)},
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "new", Severity: alert.Critical, Timestamp: time.Unix(200, 0)},
	}
	carried := carryForwardYARAFindings(prior, g)
	if len(carried) != 1 || carried[0].Message != "new" {
		t.Fatalf("want the newest finding only, got %+v", carried)
	}
}

// findingByCheck returns the first finding with the given check name, or a
// zero finding so a caller's assertion fails on empty details rather than
// panicking.
func findingByCheck(findings []alert.Finding, check string) alert.Finding {
	for _, f := range findings {
		if f.Check == check {
			return f
		}
	}
	return alert.Finding{}
}
