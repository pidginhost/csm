package phptaint

import "testing"

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

func TestTaintFlowsThroughConcatenation(t *testing.T) {
	st, _ := analyzeScope(t, "<?php $a = curl_exec($c); $b = 'x' . $a . 'y';")
	if _, ok := st["b"]; !ok {
		t.Errorf("state = %v, want $b tainted through concat", st)
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
