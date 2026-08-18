package phptaint

import (
	"context"
	"strings"
	"testing"
)

func TestParseCleanSourceSucceeds(t *testing.T) {
	_, status, reason := parseSource([]byte("<?php $a = 1;"))
	if status != StatusAnalyzed {
		t.Fatalf("status = %v (%s), want StatusAnalyzed", status, reason)
	}
}

func TestParseRecoveredSyntaxIsPartialNotClean(t *testing.T) {
	// PHP 8.3 typed class constants are beyond the parser's 8.1 ceiling; it
	// recovers and returns a partial tree, which must not count as analyzed.
	_, status, _ := parseSource([]byte("<?php class C { const string FOO = 'a'; }"))
	if status != StatusPartialParse {
		t.Fatalf("status = %v, want StatusPartialParse", status)
	}
}

func TestParseUnusableSourceIsParseError(t *testing.T) {
	_, status, _ := parseSource([]byte("<?php function f( {"))
	if status != StatusParseError {
		t.Fatalf("status = %v, want StatusParseError", status)
	}
}

func TestReasonIsBoundedAndHasNoSourceExcerpt(t *testing.T) {
	src := []byte("<?php class C { const string " + strings.Repeat("Z", 4096) + " = 'a'; }")
	_, _, reason := parseSource(src)
	if len(reason) > MaxReasonBytes {
		t.Errorf("reason is %d bytes, want <= %d", len(reason), MaxReasonBytes)
	}
	if strings.Contains(reason, strings.Repeat("Z", 64)) {
		t.Error("reason leaked a source excerpt")
	}
}

func TestPartialParseReasonDoesNotExposeUnexpectedInput(t *testing.T) {
	const attackerText = "ATTACKER_SOURCE_EXCERPT"
	src := []byte("<?php $x = " + attackerText + " @@@; curl_exec($c); eval($x);")
	_, status, reason := parseSource(src)
	if status == StatusAnalyzed {
		t.Fatal("malformed source unexpectedly parsed cleanly")
	}
	if strings.Contains(reason, attackerText) {
		t.Errorf("reason leaked source text: %q", reason)
	}
}

func TestAnalyzePropagatesPartialParse(t *testing.T) {
	src := []byte("<?php $d = curl_exec($c); eval($d); class C { const string F = 'a'; }")
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusPartialParse {
		t.Fatalf("Status = %v, want StatusPartialParse", rep.Status)
	}
	if len(rep.Results) != 0 {
		t.Error("a coverage gap must never carry results")
	}
}

// TestPreFilterGatesParsing pins down that isCandidate genuinely gates the
// parse step in Analyze. Before this task, both branches of the isCandidate
// check returned StatusNotCandidate, so a regression making isCandidate
// always report true would pass every existing test unnoticed. Now a
// candidate reaches the parser and yields a parse-derived status instead.
func TestPreFilterGatesParsing(t *testing.T) {
	nonCandidate := []byte("<?php function f( {")
	rep := Analyze(context.Background(), nonCandidate)
	if rep.Status != StatusNotCandidate {
		t.Fatalf("non-candidate source: Status = %v, want StatusNotCandidate", rep.Status)
	}

	// Same broken syntax, but now with a source/sink keyword pair present so
	// isCandidate admits it to the parser.
	candidateBroken := []byte("<?php curl_exec($c); eval($d); function f( {")
	rep = Analyze(context.Background(), candidateBroken)
	if rep.Status != StatusParseError && rep.Status != StatusPartialParse {
		t.Fatalf("candidate with broken syntax: Status = %v, want StatusParseError or StatusPartialParse", rep.Status)
	}
}
