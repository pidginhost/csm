package jstaint

import (
	"context"
	"strings"
	"testing"
)

// candidateSrc passes the content pre-filter: it carries a key-handler token
// and a sink token. Phase 1 makes no detection claim about it.
const candidateSrc = `document.addEventListener("keydown",function(e){var c=e.key;});` +
	`fetch("/api/collect",{method:"POST"});`

func TestAnalyze_NonCandidateContentIsNotParsed(t *testing.T) {
	got := Analyze(context.Background(), []byte(`var total=1+2;console.log(total);`))
	if got.Status != StatusNotCandidate {
		t.Errorf("Status = %v, want StatusNotCandidate", got.Status)
	}
	if len(got.Results) != 0 {
		t.Errorf("Results = %d, want 0", len(got.Results))
	}
}

func TestAnalyze_KeyHandlerWithoutSinkIsNotCandidate(t *testing.T) {
	src := `document.addEventListener("keydown",function(e){e.preventDefault();});`
	if got := Analyze(context.Background(), []byte(src)); got.Status != StatusNotCandidate {
		t.Errorf("Status = %v, want StatusNotCandidate (no sink token)", got.Status)
	}
}

func TestAnalyze_SinkWithoutKeyHandlerIsNotCandidate(t *testing.T) {
	src := `fetch("/api/collect",{method:"POST"}).then(function(r){return r.json();});`
	if got := Analyze(context.Background(), []byte(src)); got.Status != StatusNotCandidate {
		t.Errorf("Status = %v, want StatusNotCandidate (no key handler token)", got.Status)
	}
}

func TestAnalyze_CandidateContentIsAnalyzed(t *testing.T) {
	if got := Analyze(context.Background(), []byte(candidateSrc)); got.Status != StatusAnalyzed {
		t.Errorf("Status = %v (%s), want StatusAnalyzed", got.Status, got.Reason)
	}
}

// The pre-filter must survive the shapes real bundles use: comments between
// tokens, mixed-case React props, and static bracket access.
func TestAnalyze_PreFilterAcceptsRealBundleSpellings(t *testing.T) {
	cases := map[string]string{
		"react prop":          `var o={onKeyDown:function(e){return e;}};fetch("/x");`,
		"bracket handler":     `el["onkeyup"]=function(e){return e;};fetch("/x");`,
		"comment between":     "document.addEventListener(/* type */\"keypress\",f);\nnavigator.sendBeacon(\"/x\",\"d\");",
		"uppercase eventname": `document.addEventListener("KeyDown",f);fetch("/x");`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Analyze(context.Background(), []byte(src)); got.Status == StatusNotCandidate {
				t.Errorf("Status = StatusNotCandidate, want the content admitted for analysis")
			}
		})
	}
}

func TestAnalyze_OversizeInputIsRejectedBeforePreFilter(t *testing.T) {
	// Padding alone is not a candidate, so an oversize non-candidate proves the
	// size gate runs first rather than the pre-filter short-circuiting it.
	oversize := []byte(strings.Repeat("a", MaxSourceBytes+1))
	if got := Analyze(context.Background(), oversize); got.Status != StatusOversize {
		t.Errorf("Status = %v, want StatusOversize", got.Status)
	}
}

func TestAnalyze_ExactLimitInputIsStillAnalyzed(t *testing.T) {
	src := []byte(candidateSrc + strings.Repeat(" ", MaxSourceBytes-len(candidateSrc)))
	if len(src) != MaxSourceBytes {
		t.Fatalf("fixture is %d bytes, want exactly MaxSourceBytes", len(src))
	}
	if got := Analyze(context.Background(), src); got.Status != StatusAnalyzed {
		t.Errorf("Status = %v, want StatusAnalyzed at exactly the limit", got.Status)
	}
}

func TestAnalyze_UnparseableContentReportsParseError(t *testing.T) {
	src := `document.addEventListener("keydown",function(e){ fetch("/x" ;;; }}}`
	got := Analyze(context.Background(), []byte(src))
	if got.Status != StatusParseError {
		t.Errorf("Status = %v, want StatusParseError", got.Status)
	}
	if got.Reason == "" {
		t.Error("Reason is empty; a parse failure must carry diagnostic context")
	}
}

// A parse failure must never be mistaken for a clean file.
func TestAnalyze_ParseErrorIsNotACompletedNegative(t *testing.T) {
	src := `document.addEventListener("keydown",function(e){ fetch("/x" ;;; }}}`
	if got := Analyze(context.Background(), []byte(src)); got.Status == StatusAnalyzed {
		t.Error("Status = StatusAnalyzed for unparseable content; coverage gap reported as clean")
	}
}

func TestAnalyze_CanceledContextReportsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Analyze(ctx, []byte(candidateSrc)); got.Status != StatusCanceled {
		t.Errorf("Status = %v, want StatusCanceled", got.Status)
	}
}

func TestAnalyze_ReasonIsBounded(t *testing.T) {
	src := `document.addEventListener("keydown",function(e){` +
		strings.Repeat("var averyverylongidentifiername=1;", 400) + ` fetch("/x" ;;; }}}`
	if got := Analyze(context.Background(), []byte(src)); len(got.Reason) > MaxReasonBytes {
		t.Errorf("Reason is %d bytes, want at most %d", len(got.Reason), MaxReasonBytes)
	}
}
