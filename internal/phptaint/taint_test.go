package phptaint

import (
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
	return taintedLocals(f, map[string]Confidence{}), f
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

func TestTaintFixpointHandlesLongReverseChain(t *testing.T) {
	src := "<?php "
	for i := 0; i < maxFixpointRounds+5; i++ {
		src += fmt.Sprintf("$v%d = $v%d;", i, i+1)
	}
	src += fmt.Sprintf("$v%d = curl_exec($c);", maxFixpointRounds+5)
	st, _ := analyzeScope(t, src)
	if _, ok := st["v0"]; !ok {
		t.Errorf("state omitted the head of a %d-hop reverse chain", maxFixpointRounds+6)
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

func TestElementAndPropertyWritesTaintContainingValue(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a['payload'] = curl_exec($c); $obj->payload = curl_exec($c);")
	for _, name := range []string{"a", "obj"} {
		if _, ok := st[name]; !ok {
			t.Errorf("state = %v, want $%s tainted as a whole", st, name)
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
	st := taintedLocals(f, map[string]Confidence{"fetch": ConfidenceHigh, "load": ConfidenceLow})
	if st["a"] != ConfidenceHigh || st["b"] != ConfidenceLow {
		t.Errorf("state = %v, want method/static summary confidence", st)
	}
}

func TestCompiledTaintMatchesReferenceEvaluation(t *testing.T) {
	tests := []struct {
		src       string
		summaries map[string]Confidence
	}{
		{"<?php $a = curl_exec($c); $b = $a;", nil},
		{"<?php $a = curl_exec($c); $b = ($a = 'clean');", nil},
		{"<?php $x = (($a = curl_exec($c)) . ($b = $a));", nil},
		{"<?php $a['x'] = fopen('https://host/x', 'r'); $b = fread($a, 10);", nil},
		{"<?php $b =& $a; $b = curl_exec($c);", nil},
		{"<?php $a = curl_exec($c); $b = base64_decode($clean, $a);", nil},
		{"<?php $a = $obj->fetch(); $b = Client::load();", map[string]Confidence{
			"fetch": ConfidenceHigh,
			"load":  ConfidenceLow,
		}},
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

// TestStreamReaderInheritsHandleTaint proves the Task 7 ruling that dropped
// fread/fgets/stream_get_contents from the source set is safe: the acquiring
// call (fopen on a remote URL) is the source, and the handle variable it
// taints carries that taint into any expression that references it,
// including a call to a function that is not itself a recognised source.
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
	confidence, tainted := exprTaint(f.assigns[1].Expr, taintState{"a": ConfidenceHigh}, nil)
	if !tainted || confidence != ConfidenceCertain {
		t.Errorf("tainted=%t confidence=%v, want true/Certain", tainted, confidence)
	}
}
