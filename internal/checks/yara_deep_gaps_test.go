package checks

import (
	"os"
	"path/filepath"
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

// Every distinct rule match at a gapped path survives. Duplicate snapshots of
// one identity collapse to the newest, so repeated carry-forward cannot grow
// the set or refresh its timestamps.
func TestYARACarryForwardKeepsEveryRuleAndStableIdentity(t *testing.T) {
	g := newYARAGapCollector()
	g.record("/home/b/error_log", "oversize")

	prior := []alert.Finding{
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "rule-a", Severity: alert.Critical, Timestamp: time.Unix(100, 0)},
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "rule-a", Severity: alert.Critical, Timestamp: time.Unix(200, 0)},
		{Check: "yara_match_scheduled", FilePath: "/home/b/error_log", Message: "rule-b", Severity: alert.High, Timestamp: time.Unix(150, 0)},
	}
	carried := carryForwardYARAFindings(prior, g)
	if len(carried) != 2 {
		t.Fatalf("want both distinct YARA rules, got %+v", carried)
	}
	byMessage := map[string]alert.Finding{}
	for _, finding := range carried {
		byMessage[finding.Message] = finding
	}
	if !byMessage["rule-a"].Timestamp.Equal(time.Unix(200, 0)) ||
		!byMessage["rule-b"].Timestamp.Equal(time.Unix(150, 0)) {
		t.Fatalf("carry-forward did not keep the newest stable snapshots: %+v", carried)
	}

	again := carryForwardYARAFindings(carried, g)
	if len(again) != len(carried) {
		t.Fatalf("second carry-forward changed finding count: first=%+v second=%+v", carried, again)
	}
	for i := range carried {
		if again[i].Key() != carried[i].Key() || !again[i].Timestamp.Equal(carried[i].Timestamp) {
			t.Fatalf("second carry-forward changed identity or timestamp: first=%+v second=%+v", carried, again)
		}
	}
}

func TestYARACarryForwardMatchesEquivalentPathSpellings(t *testing.T) {
	realRoot := t.TempDir()
	path := filepath.Join(realRoot, "error_log")
	if err := os.WriteFile(path, []byte("oversize"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(t.TempDir(), "docroot")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	g := newYARAGapCollector()
	g.record(path, "oversize")
	prior := alert.Finding{
		Check: "yara_match_scheduled", FilePath: linkRoot + string(filepath.Separator) + "." + string(filepath.Separator) + "error_log",
		Message: "rule through former symlink root", Severity: alert.Critical, Timestamp: time.Unix(100, 0),
	}
	carried := carryForwardYARAFindings([]alert.Finding{prior}, g)
	if len(carried) != 1 || carried[0].Key() != prior.Key() {
		t.Fatalf("equivalent symlink/clean path spelling lost prior finding: %+v", carried)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{relative, path + string(filepath.Separator)} {
		candidate := prior
		candidate.FilePath = spelling
		candidate.Message = "rule at " + spelling
		if got := carryForwardYARAFindings([]alert.Finding{candidate}, g); len(got) != 1 {
			t.Errorf("equivalent spelling %q lost prior finding: %+v", spelling, got)
		}
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
