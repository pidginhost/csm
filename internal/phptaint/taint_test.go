package phptaint

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func analyzeScope(t *testing.T, src string) (taintState, *scopeFacts) {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	return taintedLocals(f, summaryTables{}), f
}

func TestFindFlowsDiscardsPartialResultsOnCancellation(t *testing.T) {
	facts := mustParse(t, "<?php $d = curl_exec($h); eval($d); include $d;")
	ctx := newCancelOnErrCheck(4)
	t.Cleanup(ctx.cancel)

	results, err := findFlows(ctx, facts, summaryTables{}, nil)
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %+v, want no partial results", results)
	}
}

func TestTaintFlowsThroughDirectAssignment(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c);")
	if _, ok := st["a"]; !ok {
		t.Errorf("state = %v, want $a tainted", st)
	}
}

func TestTaintFlowsThroughChainedAssignment(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = $a; $d = $b;")
	for _, name := range []string{"a", "b", "d"} {
		if _, ok := st[name]; !ok {
			t.Errorf("state = %v, want $%s tainted", st, name)
		}
	}
}

// reverseChainHops exceeds the fixed round cap (16) a reverse-ordered chain
// could once walk past undetected, before the fixpoint's round limit was
// derived from input size instead. See
// TestTaintedLocalsFallbackHandlesLongReverseChain below for the same margin
// applied to the fallback solver directly.
const reverseChainHops = 21

func TestTaintFixpointHandlesLongReverseChain(t *testing.T) {
	src := "<?php "
	for i := 0; i < reverseChainHops; i++ {
		src += fmt.Sprintf("$v%d = $v%d;", i, i+1)
	}
	src += fmt.Sprintf("$v%d = curl_exec($c);", reverseChainHops)
	st, _ := analyzeScope(t, src)
	if _, ok := st["v0"]; !ok {
		t.Errorf("state omitted the head of a %d-hop reverse chain", reverseChainHops+1)
	}
}

func TestTaintHandlesDeeplyNestedAssignments(t *testing.T) {
	const depth = 5000
	var src strings.Builder
	src.WriteString("<?php ")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&src, "$v%d = (", i)
	}
	src.WriteString("curl_exec($c)")
	src.WriteString(strings.Repeat(")", depth))
	src.WriteByte(';')
	st, _ := analyzeScope(t, src.String())
	if len(st) != depth {
		t.Errorf("state has %d variables, want %d", len(st), depth)
	}
}

func TestTaintFlowsThroughConcatenation(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = 'x' . $a . 'y';")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted through concat", st)
	}
}

func TestTaintFlowsThroughReferenceAssignment(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b =& $a;")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted through reference assignment", st)
	}
}

func TestTaintFlowsBackThroughReferenceAlias(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $b =& $a; $b = curl_exec($c);")
	if _, ok := st["a"]; !ok {
		t.Errorf("state = %v, want $a tainted by a later write through $b", st)
	}
}

// TestArrayElementWriteTaintsContainingValue locks in the still-accepted
// half of the version-1 container over-approximation: an array element
// write taints its whole containing variable, because the spec permits
// over-approximating containers and array keys are not tracked.
func TestArrayElementWriteTaintsContainingValue(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a['payload'] = curl_exec($c);")
	if _, ok := st["a"]; !ok {
		t.Errorf("state = %v, want $a tainted as a whole", st)
	}
}

// TestPropertyWriteDoesNotTaintBaseVariable: $obj->payload = curl_exec($c)
// must taint the specific "obj->payload" key, never the bare $obj it hangs
// off of. A property write that flattened onto the base variable would let
// one tainted property poison every later use of the object -- including
// an entirely different property. This is deliberately not special-cased
// to $this: $obj here is the general case that must also be covered.
func TestPropertyWriteDoesNotTaintBaseVariable(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $obj->payload = curl_exec($c); $obj->other = 'clean';")
	if _, ok := st["obj"]; ok {
		t.Errorf("state = %v, want bare $obj NOT tainted by a property write", st)
	}
	if _, ok := st["obj->other"]; ok {
		t.Errorf("state = %v, want obj->other clean: a different property was written", st)
	}
	if _, ok := st["obj->payload"]; !ok {
		t.Errorf("state = %v, want obj->payload tainted", st)
	}
}

// TestPropertyReadPicksUpItsOwnWrite is the detection-preserving half of
// property-scoped taint: scoping taint to the specific property must not
// stop a read of THAT SAME property from seeing its own taint.
func TestPropertyReadPicksUpItsOwnWrite(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $obj->payload = curl_exec($c); $b = $obj->payload;")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted by reading the property that was written", st)
	}
}

// TestPropertyReadInheritsWholeObjectTaint proves the fix does not go too
// far: reassigning the WHOLE object ($obj = ...) must still taint every
// property read off it, because the object itself -- not one property of
// it -- is what carries the taint in that case.
func TestPropertyReadInheritsWholeObjectTaint(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $obj = curl_exec($c); $b = $obj->anything;")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted via the whole tainted object", st)
	}
}

// TestArrayOverPropertyKeysToTheProperty is a regression guard: an
// array-dim fetch OUTERMOST over a property fetch ($obj->log[] = ...) must
// still key to the property ("obj->log"), not fall through to the bare
// base variable. assignedTargetKey originally only unwrapped
// ExprPropertyFetch/ExprNullsafePropertyFetch, so an ExprArrayDimFetch
// sitting on top broke the chain walk immediately and fell back to
// assignedVarName, which flattens straight to "obj" -- reintroducing the
// exact false-positive class property-scoped taint was meant to close.
// $obj->prop[] = ... is one of the most common idioms in OO PHP (logs,
// queues, error collections, caches).
func TestArrayOverPropertyKeysToTheProperty(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $obj->log[] = curl_exec($c); $obj->other = 'clean';")
	if _, ok := st["obj"]; ok {
		t.Errorf("state = %v, want bare $obj NOT tainted", st)
	}
	if _, ok := st["obj->other"]; ok {
		t.Errorf("state = %v, want obj->other clean: a different property was written", st)
	}
	if _, ok := st["obj->log"]; !ok {
		t.Errorf("state = %v, want obj->log tainted", st)
	}
}

// TestArrayOverPropertyReadStillDetects is the false-negative guard:
// reading the same property back through [] must still pick up the taint
// the write recorded under the compound key.
func TestArrayOverPropertyReadStillDetects(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $obj->log[] = curl_exec($c); $b = $obj->log[0];")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted by reading the property that was written through []", st)
	}
}

// TestDeepMixedAccessChainKeysThePath proves the fix is general, not a
// one-off "array directly over property" special case: property and
// array-dim fetches interleaved at any depth ($a->b[0]->c) must key to the
// full static path, so a different path off the same base stays clean
// while the same path still detects.
func TestDeepMixedAccessChainKeysThePath(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a->b[0]->c = curl_exec($h); $a->b[0]->d = 'clean';")
	if _, ok := st["a"]; ok {
		t.Errorf("state = %v, want bare $a NOT tainted", st)
	}
	if _, ok := st["a->b->d"]; ok {
		t.Errorf("state = %v, want a->b->d clean: a different path was written", st)
	}
	if _, ok := st["a->b->c"]; !ok {
		t.Errorf("state = %v, want a->b->c tainted", st)
	}
}

// hasDroppedTaint parses src, collects one flat scope from it, and reports
// whether hasUnresolvableTaintedTarget finds a real (tainted) drop --
// exercising the dropped-taint marker directly, the same way analyzeScope
// exercises taintedLocals.
func hasDroppedTaint(t *testing.T, src string) bool {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	dropped, err := hasUnresolvableTaintedTarget(context.Background(), f, summaryTables{})
	if err != nil {
		t.Fatalf("dropped-taint check: %v", err)
	}
	return dropped
}

// TestUnresolvableTargetUntaintedValueNoMarker: an earlier version of the
// marker fired on the SHAPE of an unkeyable assignment target alone,
// regardless of whether anything was actually tainted, which made it fire
// on 38.75% of analyzed corpus files -- dominated by list() destructuring
// and static properties, both completely ordinary and benign. An
// unresolvable target assigned a value that carries no remote content
// drops nothing worth flagging.
func TestUnresolvableTargetUntaintedValueNoMarker(t *testing.T) {
	tests := []string{
		`<?php list($a, $b) = array('x', 'y');`, // list() destructuring
		`<?php Foo::$cache = 'literal';`,        // static property
		`<?php $obj->b()->c = 'literal';`,       // method call mid-chain
	}
	for _, src := range tests {
		if hasDroppedTaint(t, src) {
			t.Errorf("%s: want no dropped-taint marker for an untainted value", src)
		}
	}
}

// TestUnresolvableTargetTaintedValueMarksLoss is the other half: the same
// three shapes, now assigned genuinely remote content, must be flagged --
// this IS a real, silent loss of tracking.
func TestUnresolvableTargetTaintedValueMarksLoss(t *testing.T) {
	tests := []string{
		`<?php list($a, $b) = curl_exec($u);`, // list() destructuring
		`<?php Foo::$cache = curl_exec($u);`,  // static property
		`<?php $obj->b()->c = curl_exec($u);`, // method call mid-chain
	}
	for _, src := range tests {
		if !hasDroppedTaint(t, src) {
			t.Errorf("%s: want the dropped-taint marker for a tainted value", src)
		}
	}
}

func TestUnresolvableTargetRecognizesAliasedSource(t *testing.T) {
	src := `<?php
use function curl_exec as fetch_remote;
Foo::$cache = fetch_remote($u);`
	if !hasDroppedTaint(t, src) {
		t.Fatal("want the dropped-taint marker for an aliased source")
	}
}

func TestUnresolvableTargetCheckHonorsCancellation(t *testing.T) {
	f := mustParse(t, `<?php Foo::$cache = curl_exec($u);`)
	ctx := newCancelOnErrCheck(2)
	t.Cleanup(ctx.cancel)

	dropped, err := hasUnresolvableTaintedTarget(ctx, f, summaryTables{})
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if dropped {
		t.Fatal("dropped = true for canceled check")
	}
}

// TestResolvableTaintedTargetNeverMarksLoss guards the other direction:
// hasUnresolvableTaintedTarget must never fire for a target it CAN key,
// no matter how tainted the value is -- that is simply not what this
// marker means.
func TestResolvableTaintedTargetNeverMarksLoss(t *testing.T) {
	tests := []string{
		`<?php $a = curl_exec($u);`,
		`<?php $obj->prop = curl_exec($u);`,
		`<?php $arr[0] = curl_exec($u);`,
		`<?php $obj->log[] = curl_exec($u);`,
	}
	for _, src := range tests {
		if hasDroppedTaint(t, src) {
			t.Errorf("%s: want no dropped-taint marker; the target is keyable", src)
		}
	}
}

func TestNestedAssignmentTargetDoesNotTaintItsValue(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = ($a = 'clean');")
	if _, ok := st["b"]; ok {
		t.Errorf("state = %v, nested assignment target was mistaken for a read", st)
	}
}

func TestNestedAssignmentValueKeepsDecoderCorrelation(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $b = base64_decode($a = curl_exec($c));")
	if got := st["b"]; got != ConfidenceCertain {
		t.Errorf("confidence = %v, want Certain", got)
	}
}

func TestMethodAndStaticSummariesPropagateTaint(t *testing.T) {
	root, status, reason := parseSource([]byte("<?php $a = $obj->fetch(); $b = Client::load();"))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	st := taintedLocals(f, summaryTables{methods: map[string]Confidence{"fetch": ConfidenceHigh, "load": ConfidenceLow}})
	if st["a"] != ConfidenceHigh || st["b"] != ConfidenceLow {
		t.Errorf("state = %v, want method/static summary confidence", st)
	}
}

func TestCompiledTaintMatchesReferenceEvaluation(t *testing.T) {
	tests := []struct {
		src       string
		summaries summaryTables
	}{
		{"<?php $a = curl_exec($c); $b = $a;", summaryTables{}},
		{"<?php $a = curl_exec($c); $b = ($a = 'clean');", summaryTables{}},
		{"<?php $x = (($a = curl_exec($c)) . ($b = $a));", summaryTables{}},
		{"<?php $obj->body = curl_exec($c); $obj->other = 'clean'; $b = $obj->body . $obj->other;", summaryTables{}},
		{"<?php $a['x'] = fopen('https://host/x', 'r'); $b = fread($a, 10);", summaryTables{}},
		{"<?php $b =& $a; $b = curl_exec($c);", summaryTables{}},
		{"<?php $a = curl_exec($c); $b = base64_decode($clean, $a);", summaryTables{}},
		{"<?php $a = $obj->fetch(); $b = Client::load();", summaryTables{methods: map[string]Confidence{
			"fetch": ConfidenceHigh,
			"load":  ConfidenceLow,
		}}},
	}
	for _, test := range tests {
		root, status, reason := parseSource([]byte(test.src))
		if status != StatusAnalyzed {
			t.Fatalf("parse status %v: %s", status, reason)
		}
		facts := collectScope(root)
		got := taintedLocals(facts, test.summaries)
		want := taintedLocalsFallback(facts, test.summaries)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: compiled=%v fallback=%v", test.src, got, want)
		}
	}
}

// TestTaintedLocalsFallbackHandlesLongReverseChain proves the fallback's
// round cap (len(assignments)+1, not a fixed constant) neither evades
// detection nor fails to terminate on a chain far longer than the fixed cap
// of 16 that a reverse-ordered chain could previously walk past undetected:
// such a chain needs exactly one fixpoint round per hop.
//
// taintedLocals never reaches taintedLocalsFallback through real parser
// output: every real ExprAssign/ExprVariable/ExprFunctionCall node this
// package's test corpus and a short fuzz run against compileAssignments
// could produce carries a valid position, so compileAssignments always
// succeeds and taintedLocals always takes the compiled-solver branch. The
// fallback is exercised here directly, as this file already does elsewhere
// to use it as a reference oracle, and its result is checked against the
// compiled solver on the same input.
func TestTaintedLocalsFallbackHandlesLongReverseChain(t *testing.T) {
	const hops = 30
	src := "<?php "
	for i := 0; i < hops; i++ {
		src += fmt.Sprintf("$v%d = $v%d;", i, i+1)
	}
	src += fmt.Sprintf("$v%d = curl_exec($c);", hops)
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	facts := collectScope(root)
	compiled := taintedLocals(facts, summaryTables{})
	fallback := taintedLocalsFallback(facts, summaryTables{})
	if !reflect.DeepEqual(compiled, fallback) {
		t.Fatalf("compiled=%v fallback=%v, want equal", compiled, fallback)
	}
	if _, ok := fallback["v0"]; !ok {
		t.Errorf("fallback state = %v, want $v0 tainted through a %d-hop reverse chain", fallback, hops)
	}
}

func TestDecoderRaisesConfidenceToCertain(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = base64_decode($a);")
	got, ok := st["b"]
	if !ok {
		t.Fatalf("state = %v, want $b tainted", st)
	}
	if got != ConfidenceCertain {
		t.Errorf("confidence = %v, want Certain after a decoder", got)
	}
}

func TestUntaintedVariablesStayClean(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = 'literal'; $b = $a . 'more'; $c = file_get_contents(__DIR__ . '/x');")
	if len(st) != 0 {
		t.Errorf("state = %v, want empty", st)
	}
}

// TestStreamReaderInheritsHandleTaint: fread/fgets/stream_get_contents are
// not sources themselves -- they take a stream resource, not a path, so
// their argument carries no locality signal. The acquiring call (fopen on a
// remote URL) is the source, and the handle variable it taints carries that
// taint into any expression that references it, including a call to a
// function that is not itself a recognised source.
func TestStreamReaderInheritsHandleTaint(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $fh = fopen('http://host/x'); $c = fread($fh, 999);")
	if _, ok := st["c"]; !ok {
		t.Errorf("state = %v, want $c tainted via handle $fh", st)
	}
}

func TestWordPressResponseBodyInheritsRequestTaint(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $response = wp_remote_get($url); $body = $response['body'];")
	if _, ok := st["body"]; !ok {
		t.Errorf("state = %v, want response body tainted from wp_remote_get", st)
	}
}

// TestTaintPropagationIsStructuralNotNamed locks in that any expression
// referencing a tainted variable is tainted, regardless of what function
// wraps it. There is deliberately no allowlist of "passthrough" function
// names: trim($a) is covered by the same structural rule as an entirely
// unlisted some_helper($a), so a name list would add nothing and could only
// ever be narrower. The unlisted-helper case is the load-bearing half of
// this test; it is what proves the rule is structural rather than name-based.
func TestTaintPropagationIsStructuralNotNamed(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = trim($a); $d = some_helper($a);")
	for _, name := range []string{"b", "d"} {
		if _, ok := st[name]; !ok {
			t.Errorf("state = %v, want $%s tainted", st, name)
		}
	}
}

// TestCompoundConcatTaintsPreviouslyCleanTarget exercises the concats loop
// in taintedLocals specifically: $a starts clean and is only ever tainted
// by the .= step, so this cannot pass by accident through the assigns loop.
func TestCompoundConcatTaintsPreviouslyCleanTarget(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = 'x'; $a .= curl_exec($c);")
	if _, ok := st["a"]; !ok {
		t.Errorf("state = %v, want $a tainted via .=", st)
	}
}

// TestDecoderOnTaintedArgumentRaisesConfidence is the correlated case: the
// decoder is applied directly to the tainted value, so confidence must
// still reach Certain.
func TestDecoderOnTaintedArgumentRaisesConfidence(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = base64_decode($a);")
	got, ok := st["b"]
	if !ok {
		t.Fatalf("state = %v, want $b tainted", st)
	}
	if got != ConfidenceCertain {
		t.Errorf("confidence = %v, want Certain: the decoder's own argument is tainted", got)
	}
}

// TestDecoderOnUnrelatedArgumentDoesNotRaiseConfidence is the load-bearing
// case: a decoder call appears in the same expression as the tainted
// value, but decodes something else ($clean) entirely. The decoder signal
// means "the remote payload itself was decoded before execution"; a
// decoder applied to an unrelated argument must not borrow that meaning,
// so confidence stays at the grade the source itself earned.
func TestDecoderOnUnrelatedArgumentDoesNotRaiseConfidence(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = some_call(base64_decode($clean), $a);")
	got, ok := st["b"]
	if !ok {
		t.Fatalf("state = %v, want $b tainted via $a", st)
	}
	if got != ConfidenceHigh {
		t.Errorf("confidence = %v, want High: base64_decode never touched $a, only $clean", got)
	}
}

func TestDecoderOptionDoesNotRaiseConfidence(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = base64_decode($clean, $a);")
	if got := st["b"]; got != ConfidenceHigh {
		t.Errorf("confidence = %v, want High: the tainted value is only the strict option", got)
	}
}

func TestPackRaisesConfidenceForValueNotFormat(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $value = pack('H*', $a); $format = pack($a, 1);")
	if got := st["value"]; got != ConfidenceCertain {
		t.Errorf("value confidence = %v, want Certain", got)
	}
	if got := st["format"]; got != ConfidenceHigh {
		t.Errorf("format confidence = %v, want High", got)
	}
}

func TestExprTaintHandlesDeepDecoderChain(t *testing.T) {
	const depth = 5000
	src := "<?php $a = curl_exec($c); $b = " + strings.Repeat("base64_decode(", depth) + "$a" + strings.Repeat(")", depth) + ";"
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	if len(f.assigns) != 2 {
		t.Fatalf("assignments = %d, want 2", len(f.assigns))
	}
	confidence, tainted := exprTaint(f.assigns[1].Expr, taintState{"a": ConfidenceHigh}, summaryTables{})
	if !tainted || confidence != ConfidenceCertain {
		t.Errorf("tainted=%t confidence=%v, want true/Certain", tainted, confidence)
	}
}
