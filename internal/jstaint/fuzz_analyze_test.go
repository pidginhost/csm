package jstaint

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// FuzzAnalyze asserts the invariants every caller depends on: the analyzer
// never panics, never returns an undefined status, never reports results
// without having completed an analysis, keeps Reason bounded, and is
// deterministic. With a live context, cancellation and panic are bugs rather
// than valid fuzz outcomes.
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
		string(nestedUnaryCandidate(maxAnalysisDepth - 4)),
		`var f = ({a} = {a: 1}) => a;/* keydown fetch */`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		got := Analyze(context.Background(), src)

		if got.Status > StatusPanic {
			t.Fatalf("undefined status %d", got.Status)
		}
		if got.Status == StatusCanceled || got.Status == StatusPanic {
			t.Fatalf("live-context analysis returned %v (%s)", got.Status, got.Reason)
		}
		if got.Status != StatusAnalyzed && len(got.Results) != 0 {
			t.Fatalf("status %v carries %d results; only a completed analysis may report flows",
				got.Status, len(got.Results))
		}
		if got.Status != StatusAnalyzed && got.TotalResults != 0 {
			t.Fatalf("status %v carries TotalResults=%d; only a completed analysis may count flows",
				got.Status, got.TotalResults)
		}
		if got.Status != StatusAnalyzed && got.EvidenceTruncated {
			t.Fatalf("status %v reports truncated evidence without a completed analysis", got.Status)
		}
		if got.Status == StatusAnalyzed && got.Reason != "" {
			t.Fatalf("completed analysis carries failure reason %q", got.Reason)
		}
		if got.Status != StatusAnalyzed && got.Reason == "" {
			t.Fatalf("status %v has no stable reason label", got.Status)
		}
		if len(got.Reason) > MaxReasonBytes {
			t.Fatalf("Reason is %d bytes, want at most %d", len(got.Reason), MaxReasonBytes)
		}

		again := Analyze(context.Background(), src)
		if !reflect.DeepEqual(again, got) {
			t.Fatalf("nondeterministic: first %#v, second %#v", got, again)
		}
	})
}
