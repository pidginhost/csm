package phptaint

import "testing"

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

func repeatStmt(n int) string {
	out := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		out = append(out, "$a = 1;"...)
	}
	return string(out)
}
