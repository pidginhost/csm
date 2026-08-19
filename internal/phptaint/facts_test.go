package phptaint

import (
	"context"
	"strings"
	"testing"

	"github.com/VKCOM/php-parser/pkg/ast"
)

func mustParse(t *testing.T, src string) *scopeFacts {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	return collectScope(root)
}

func TestCollectFindsAssignmentsAndCalls(t *testing.T) {
	f := mustParse(t, "<?php $a = curl_exec($c); $b = $a;")
	if len(f.assigns) != 2 {
		t.Errorf("assigns = %d, want 2", len(f.assigns))
	}
	if !f.calls["curl_exec"] {
		t.Errorf("calls = %v, want curl_exec present", f.calls)
	}
}

func TestCollectFindsMethodAndStaticCalls(t *testing.T) {
	f := mustParse(t, "<?php $a = $obj->fetch(); $b = Client::load(); $c = $obj?->read();")
	for _, name := range []string{"fetch", "load", "read"} {
		if !f.calls[name] {
			t.Errorf("calls = %v, want %q present", f.calls, name)
		}
	}
}

func TestCollectRecordsDynamicCallPrecisionLoss(t *testing.T) {
	f := mustParse(t, "<?php $fn(); $obj->$method();")
	if !f.precisionLoss["dynamic-call"] {
		t.Errorf("precisionLoss = %v, want dynamic-call", f.precisionLoss)
	}
}

func TestCollectSeparatesAssignmentWritesFromReads(t *testing.T) {
	f := mustParse(t, "<?php $result = ($target = $input);")
	reads := map[string]bool{}
	for _, variable := range f.readVarNodes() {
		reads[variable.name] = true
	}
	if reads["target"] {
		t.Errorf("reads = %v, assignment target is not a value read", reads)
	}
	if !reads["input"] {
		t.Errorf("reads = %v, want input present", reads)
	}
}

func TestNestedDeclarationFilterReusesFactsWithoutExclusions(t *testing.T) {
	f := mustParse(t, "<?php $result = $input;")
	exclude := spanIndex{}

	if got := f.withoutNestedDeclarationVars(&exclude); got != f {
		t.Fatal("empty exclusion index copied facts, want the original collection")
	}
}

func TestCollectFindsEverySinkKind(t *testing.T) {
	f := mustParse(t, `<?php eval($a); include $b; include_once $c; require $d; require_once $e;`)
	got := map[string]bool{}
	for _, s := range f.sinks {
		got[s.kind] = true
	}
	for _, want := range []string{"eval", "include", "include_once", "require", "require_once"} {
		if !got[want] {
			t.Errorf("sink %q not collected; got %v", want, got)
		}
	}
}

func TestCollectFindsCallBasedSinks(t *testing.T) {
	f := mustParse(t, `<?php assert($a); create_function('', $b);`)
	got := map[string]bool{}
	for _, s := range f.sinks {
		got[s.kind] = true
	}
	for _, want := range []string{"assert", "create_function"} {
		if !got[want] {
			t.Errorf("sink %q not collected; got %v", want, got)
		}
	}
}

func TestCollectFindsFunctionsAndReturns(t *testing.T) {
	f := mustParse(t, "<?php function g($u) { return file_get_contents($u); }")
	if len(f.funcs) != 1 {
		t.Fatalf("funcs = %d, want 1", len(f.funcs))
	}
	body := collectOwnStmts(f.funcs[0].Stmts, nil)
	if len(body.returns) != 1 {
		t.Errorf("returns = %d, want 1", len(body.returns))
	}
}

func TestCollectRecordsVariableNames(t *testing.T) {
	f := mustParse(t, "<?php $alpha = 1; $beta = $alpha;")
	if !f.vars["alpha"] || !f.vars["beta"] {
		t.Errorf("vars = %v, want alpha and beta", f.vars)
	}
}

func TestCollectRecordsVariableVariablePrecisionLoss(t *testing.T) {
	f := mustParse(t, "<?php $$name = 1;")
	if !f.precisionLoss["variable-variable"] {
		t.Errorf("precisionLoss = %v, want variable-variable", f.precisionLoss)
	}
}

func TestCalleeNameResolvesLeadingBackslash(t *testing.T) {
	f := mustParse(t, `<?php \curl_exec($c); \assert($x);`)
	if !f.calls["curl_exec"] {
		t.Errorf("calls = %v, want curl_exec present for \\curl_exec", f.calls)
	}
	got := map[string]bool{}
	for _, s := range f.sinks {
		got[s.kind] = true
	}
	if !got["assert"] {
		t.Errorf("sinks = %v, want assert present for \\assert", f.sinks)
	}
}

func TestCalleeNameKeepsNamespaceQualifiedDistinct(t *testing.T) {
	f := mustParse(t, `<?php \Foo\curl_exec($d);`)
	if f.calls["curl_exec"] {
		t.Errorf("calls = %v, want \\Foo\\curl_exec NOT collapsed to curl_exec", f.calls)
	}
	if !f.calls["foo\\curl_exec"] {
		t.Errorf("calls = %v, want foo\\curl_exec present", f.calls)
	}
}

func TestFunctionAliasResolvesToCanonicalCall(t *testing.T) {
	f := mustParse(t, `<?php use function curl_exec as fetch_remote; fetch_remote($c);`)
	if !f.calls["curl_exec"] {
		t.Errorf("calls = %v, want canonical curl_exec", f.calls)
	}
	if _, ok := sourceConfidence(f.callNodes[0]); !ok {
		t.Error("aliased curl_exec call was not recognized as a source")
	}
}

func TestFunctionAliasResolvesCallSink(t *testing.T) {
	f := mustParse(t, `<?php use function assert as check; check($code);`)
	if _, ok := sinkOfKind(f, "assert"); !ok {
		t.Errorf("sinks = %v, want aliased assert sink", f.sinks)
	}
}

func TestFunctionAliasDoesNotCollapseNamespacedTarget(t *testing.T) {
	f := mustParse(t, `<?php use function Vendor\curl_exec; curl_exec($c);`)
	if f.calls["curl_exec"] {
		t.Errorf("calls = %v, imported Vendor\\curl_exec was treated as the builtin", f.calls)
	}
	if !f.calls["vendor\\curl_exec"] {
		t.Errorf("calls = %v, want vendor\\curl_exec", f.calls)
	}
	if _, ok := sourceConfidence(f.callNodes[0]); ok {
		t.Error("namespaced function alias was treated as a remote source")
	}
}

func TestGroupFunctionAliasResolvesCanonicalTarget(t *testing.T) {
	f := mustParse(t, `<?php use function Vendor\{fetch as load}; load($arg);`)
	if !f.calls["vendor\\fetch"] {
		t.Errorf("calls = %v, want vendor\\fetch", f.calls)
	}
}

func sinkOfKind(f *scopeFacts, kind string) (sinkSite, bool) {
	for _, s := range f.sinks {
		if s.kind == kind {
			return s, true
		}
	}
	return sinkSite{}, false
}

func TestAssertSinkCapturesFirstArgument(t *testing.T) {
	f := mustParse(t, `<?php assert($tainted, "some description");`)
	s, ok := sinkOfKind(f, "assert")
	if !ok {
		t.Fatal("assert sink not collected")
	}
	captured := collectScope(s.expr)
	if !captured.vars["tainted"] {
		t.Errorf("assert sink captured vars %v, want tainted (first argument)", captured.vars)
	}
}

// TestAssertBooleanExpressionIsNotASink: PHP 8 removed assert()'s
// string-eval form outright, and PHP 7 only ever evaluated a *string*
// argument as code, so a logical/comparison/identity/instanceof
// expression -- which can only ever produce a bool -- is not a
// code-execution sink on any version. This reproduces the exact shape from
// SimplePie/src/File.php: assert(is_array($info) && $info['x'] >= 0).
func TestAssertBooleanExpressionIsNotASink(t *testing.T) {
	tests := []string{
		`<?php assert(is_array($info) && $info['redirect_count'] >= 0);`,
		`<?php assert($this->body !== null);`,
		`<?php assert($a == $b);`,
		`<?php assert($a || $b);`,
		`<?php assert($a and $b);`,
		`<?php assert($a or $b);`,
		`<?php assert($a xor $b);`,
		`<?php assert(!$a);`,
		`<?php assert($a instanceof Foo);`,
		`<?php assert($a < $b);`,
		`<?php assert($a <= $b);`,
		`<?php assert($a > $b);`,
		`<?php assert($a >= $b);`,
		`<?php assert($a <=> $b);`,
		`<?php assert($a === $b);`,
		`<?php assert($a !== $b);`,
	}
	for _, src := range tests {
		f := mustParse(t, src)
		if _, ok := sinkOfKind(f, "assert"); ok {
			t.Errorf("%s: assert recorded as a sink, want excluded (boolean argument)", src)
		}
	}
}

// TestAssertStringCapableArgumentIsStillASink guards against
// over-correcting the boolean-argument exclusion into never treating
// assert as a sink: a plain variable, a string literal, or a concatenation
// can all still carry executable PHP 7 code, so they must remain sinks.
func TestAssertStringCapableArgumentIsStillASink(t *testing.T) {
	tests := []string{
		`<?php assert($code);`,
		`<?php assert('return 1;');`,
		`<?php assert('return ' . $code);`,
	}
	for _, src := range tests {
		f := mustParse(t, src)
		if _, ok := sinkOfKind(f, "assert"); !ok {
			t.Errorf("%s: assert not recorded as a sink, want included", src)
		}
	}
}

func TestCreateFunctionSinkCapturesSecondArgument(t *testing.T) {
	f := mustParse(t, `<?php create_function('$a', $code);`)
	s, ok := sinkOfKind(f, "create_function")
	if !ok {
		t.Fatal("create_function sink not collected")
	}
	captured := collectScope(s.expr)
	if !captured.vars["code"] {
		t.Errorf("create_function sink captured vars %v, want code (second argument)", captured.vars)
	}
}

func TestCollectFindsClassMethod(t *testing.T) {
	f := mustParse(t, "<?php class C { function m($u) { return curl_exec($u); } }")
	if len(f.methods) != 1 {
		t.Fatalf("methods = %d, want 1", len(f.methods))
	}
	// StmtClassMethod.Stmt (unlike StmtFunction.Stmts) is a single Vertex
	// holding the block; a concrete method body is *ast.StmtStmtList.
	block, ok := f.methods[0].Stmt.(*ast.StmtStmtList)
	if !ok {
		t.Fatalf("method body = %T, want *ast.StmtStmtList", f.methods[0].Stmt)
	}
	body := collectOwnStmts(block.Stmts, nil)
	if len(body.returns) != 1 {
		t.Errorf("returns = %d, want 1", len(body.returns))
	}
	if !body.calls["curl_exec"] {
		t.Errorf("calls = %v, want curl_exec present", body.calls)
	}
}

// TestCollectionBudgetReachableThroughAnalyze proves the node budget is a
// real production guard, not just a property of collectScope in isolation.
// A source bigger than MaxSourceBytes could never reach this guard through
// the public API -- Analyze rejects it on the size check first, before any
// collection begins -- so the fixture here stays under MaxSourceBytes and
// still trips the budget on variable-read volume alone.
func TestCollectionBudgetReachableThroughAnalyze(t *testing.T) {
	src := manyInterpolatedVarsSource(1_000_000)
	if len(src) >= MaxSourceBytes {
		t.Fatalf("fixture is %d bytes, want under MaxSourceBytes (%d)", len(src), MaxSourceBytes)
	}
	rep := Analyze(context.Background(), src)
	if rep.Status != StatusResourceLimit {
		t.Fatalf("status = %v, want StatusResourceLimit", rep.Status)
	}
	if rep.Reason != "resource_limit: collection budget exceeded" {
		t.Errorf("reason = %q, want the collection-budget detail", rep.Reason)
	}
	if len(rep.Results) != 0 {
		t.Errorf("results = %+v, want none for a coverage-gap status", rep.Results)
	}
}

// manyInterpolatedVarsSource builds a source that stays under MaxSourceBytes
// while still packing far more than maxCollectedNodes variable reads into one
// interpolated string -- the shape a hostile upload could actually submit,
// unlike a source larger than MaxSourceBytes ever could.
func manyInterpolatedVarsSource(n int) []byte {
	var b strings.Builder
	b.WriteString(`<?php eval($x); file_get_contents($u); $s = "`)
	for i := 0; i < n; i++ {
		b.WriteString("$a")
	}
	b.WriteString(`";`)
	return []byte(b.String())
}

func TestCollectWalksDeepTreesWithoutRecursion(t *testing.T) {
	const depth = 100_000
	src := "<?php $a = " + strings.Repeat("!", depth) + "curl_exec($c);"
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	f := collectScope(root)
	if !f.calls["curl_exec"] {
		t.Errorf("deep tree lost curl_exec call: calls=%v", f.calls)
	}
	if f.budgetExceeded {
		t.Errorf("deep tree unexpectedly exceeded %d-node budget", maxCollectedNodes)
	}
}
