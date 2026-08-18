package phptaint

import (
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
	reads := f.readVars()
	if reads["target"] {
		t.Errorf("reads = %v, assignment target is not a value read", reads)
	}
	if !reads["input"] {
		t.Errorf("reads = %v, want input present", reads)
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
	body := collectAll(f.funcs[0].Stmts)
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

// TestAssertBooleanExpressionIsNotASink is Task 11 Fix 2: PHP 8 removed
// assert()'s string-eval form outright, and PHP 7 only ever evaluated a
// *string* argument as code, so a logical/comparison/identity/instanceof
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
// over-correcting Fix 2 into never treating assert as a sink: a plain
// variable, a string literal, or a concatenation can all still carry
// executable PHP 7 code, so they must remain sinks.
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
	body := collectAll(block.Stmts)
	if len(body.returns) != 1 {
		t.Errorf("returns = %d, want 1", len(body.returns))
	}
	if !body.calls["curl_exec"] {
		t.Errorf("calls = %v, want curl_exec present", body.calls)
	}
}

func TestCollectStopsAtNodeBudget(t *testing.T) {
	src := "<?php " + repeatStmt(maxCollectedNodes/2+10)
	root, status, _ := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Skip("generator produced unparseable source")
	}
	f := collectScope(root)
	if !f.budgetExceeded {
		t.Error("budgetExceeded = false, want true past the node budget")
	}
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

func repeatStmt(n int) string {
	out := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		out = append(out, "$a = 1;"...)
	}
	return string(out)
}
