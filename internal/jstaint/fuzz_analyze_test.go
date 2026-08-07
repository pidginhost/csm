package jstaint

import (
	"context"
	"strings"
	"testing"
)

// FuzzAnalyze asserts the invariants every caller depends on: the analyzer
// never panics, never returns an undefined status, never reports results
// without having completed an analysis, keeps Reason bounded, and is
// deterministic. A fuzz input may legitimately produce any defined status.
func FuzzAnalyze(f *testing.F) {
	seeds := []string{
		"",
		"var a=1;",
		candidateSrc,
		`document.addEventListener("keydown",function(e){ fetch("/x" ;;; }}}`,
		`var o={onKeyDown:function(e){return e;}};fetch("/x");`,
		`el["onkeyup"]=function(e){return e;};navigator.sendBeacon("/x","d");`,
		strings.Repeat("{", 5000) + `keydown fetch`,
		strings.Repeat("(", 5000) + `keydown fetch`,
		"keydown\x00fetch",
		"\xff\xfe keydown fetch",
		strings.Repeat("a", MaxSourceBytes+1),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		got := Analyze(context.Background(), src)

		if got.Status > StatusPanic {
			t.Fatalf("undefined status %d", got.Status)
		}
		if got.Status != StatusAnalyzed && len(got.Results) != 0 {
			t.Fatalf("status %v carries %d results; only a completed analysis may report flows",
				got.Status, len(got.Results))
		}
		if len(got.Reason) > MaxReasonBytes {
			t.Fatalf("Reason is %d bytes, want at most %d", len(got.Reason), MaxReasonBytes)
		}

		again := Analyze(context.Background(), src)
		if again.Status != got.Status || len(again.Results) != len(got.Results) {
			t.Fatalf("nondeterministic: first %v/%d, second %v/%d",
				got.Status, len(got.Results), again.Status, len(again.Results))
		}
	})
}
