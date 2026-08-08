package jstaint

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2/js"
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
		"property handler":          `node.onkeydown=handler;fetch("/x");`,
		"bracket handler":           `node["onkeypress"]=handler;navigator.sendBeacon("/x",data);`,
		"listener method":           `node.addEventListener("keyup",handler);xhr.send(data);`,
		"bare listener":             `addEventListener("keydown",handler);xhr.open("POST","/x");`,
		"react prop":                `var o={onKeyDown:function(e){return e;}};image.src=data;`,
		"comment and whitespace":    "document.addEventListener /* comment */ ( \"keypress\" , f );\nnew WebSocket(url);",
		"uppercase event name":      `document.addEventListener("KeyDown",f);fetch("/x");`,
		"optional listener chain":   `node?.addEventListener?.("keyup",handler);fetch?.("/x");`,
		"static bracket sink":       `node.onkeyup=handler;image["src"]=data;`,
		"minified mixed-case props": `({onKeyPress:e=>e});navigator.sendBeacon("/x",data)`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Analyze(context.Background(), []byte(src)); got.Status == StatusNotCandidate {
				t.Errorf("Status = StatusNotCandidate, want the content admitted for analysis")
			}
		})
	}
}

func TestIsCandidate_DoesNotAllocate(t *testing.T) {
	src := []byte(`node.addEventListener("KeyDown",handler);navigator.sendBeacon("/x",data);`)
	if allocs := testing.AllocsPerRun(100, func() { isCandidate(src) }); allocs != 0 {
		t.Errorf("isCandidate allocated %.1f times per call, want 0", allocs)
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

func TestAnalyze_CancellationPrecedesSizeGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := Analyze(ctx, []byte(strings.Repeat("a", MaxSourceBytes+1)))
	if got.Status != StatusCanceled {
		t.Errorf("Status = %v, want StatusCanceled", got.Status)
	}
}

func TestAnalyze_CancellationDuringPassDiscardsResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	got := analyzeWithPass(ctx, []byte(candidateSrc),
		func(context.Context, *js.AST, *resourceBudget) ([]Result, bool, error) {
			cancel()
			return []Result{{Source: "injected"}}, true, ctx.Err()
		})
	if got.Status != StatusCanceled {
		t.Errorf("Status = %v, want StatusCanceled", got.Status)
	}
	if len(got.Results) != 0 || got.EvidenceTruncated {
		t.Errorf("cancellation carried Results=%d TotalResults=%d EvidenceTruncated=%t",
			len(got.Results), got.TotalResults, got.EvidenceTruncated)
	}
	if got.TotalResults != 0 {
		t.Errorf("cancellation carried TotalResults=%d, want 0", got.TotalResults)
	}
}

func TestAnalyze_CancellationReasonDoesNotExposeInternalText(t *testing.T) {
	const attackerText = "attacker-controlled cancellation context"
	got := analyzeWithPass(context.Background(), []byte(candidateSrc),
		func(context.Context, *js.AST, *resourceBudget) ([]Result, bool, error) {
			return nil, false, fmt.Errorf("%s: %w", attackerText, context.Canceled)
		})
	if got.Status != StatusCanceled {
		t.Fatalf("Status = %v, want StatusCanceled", got.Status)
	}
	if strings.Contains(got.Reason, attackerText) {
		t.Errorf("Reason exposes internal text: %q", got.Reason)
	}
}

func TestAnalyze_KnownArrowDefaultParserFailures(t *testing.T) {
	fixtures := []string{
		`var f = ({a} = {a: 1}) => a;`,
		`var f = ({a: {b} = {b: 1}}) => b;`,
	}
	for _, fixture := range fixtures {
		src := fixture + `/* keydown fetch */`
		if got := Analyze(context.Background(), []byte(src)); got.Status != StatusParseError {
			t.Errorf("Status = %v, want StatusParseError for %q", got.Status, fixture)
		}
	}
}

func TestAnalyze_AnalyzerRecursionLimit(t *testing.T) {
	const analysisDepthScaffold = 5 // AST, block, declaration, binding, literal.

	withinLimit := nestedUnaryCandidate(maxAnalysisDepth - analysisDepthScaffold)
	if got := Analyze(context.Background(), withinLimit); got.Status != StatusAnalyzed {
		t.Errorf("depth %d Status = %v (%s), want StatusAnalyzed",
			maxAnalysisDepth, got.Status, got.Reason)
	}

	overLimit := nestedUnaryCandidate(maxAnalysisDepth - analysisDepthScaffold + 1)
	if got := Analyze(context.Background(), overLimit); got.Status != StatusResourceLimit {
		t.Errorf("depth %d Status = %v (%s), want StatusResourceLimit",
			maxAnalysisDepth+1, got.Status, got.Reason)
	}
}

func TestAnalyze_AnalyzerNodeLimit(t *testing.T) {
	// Each array entry contributes an Element and LiteralExpr node, so this stays
	// well below the byte limit while crossing the independent AST node ceiling.
	src := []byte(`var values=[` + strings.Repeat("0,", maxASTNodes/2+1) + `];/* keydown fetch */`)
	if len(src) > MaxSourceBytes {
		t.Fatalf("fixture is %d bytes, want at most %d", len(src), MaxSourceBytes)
	}
	got := Analyze(context.Background(), src)
	if got.Status != StatusResourceLimit {
		t.Fatalf("Status = %v (%s), want StatusResourceLimit", got.Status, got.Reason)
	}
}

func TestAnalyze_ParserDepthLimitDoesNotCrash(t *testing.T) {
	if os.Getenv("CSM_JSTAINT_DEPTH_CHILD") == "1" {
		got := Analyze(context.Background(), nestedUnaryCandidate(1100))
		if got.Status != StatusParseError {
			t.Fatalf("Status = %v (%s), want StatusParseError", got.Status, got.Reason)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAnalyze_ParserDepthLimitDoesNotCrash$")
	cmd.Env = append(os.Environ(), "CSM_JSTAINT_DEPTH_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("deep parser input crashed child process: %v\n%s", err, output)
	}
}

func TestAnalyze_FactLimitReportsResourceLimitWithoutResults(t *testing.T) {
	got := analyzeWithPass(context.Background(), []byte(candidateSrc),
		func(_ context.Context, _ *js.AST, budget *resourceBudget) ([]Result, bool, error) {
			for i := 0; i < maxPropagatedFacts; i++ {
				if err := budget.addFact(); err != nil {
					t.Fatalf("fact %d returned an early error: %v", i+1, err)
				}
			}
			return []Result{{Source: "injected"}}, true, budget.addFact()
		})
	if got.Status != StatusResourceLimit {
		t.Errorf("Status = %v, want StatusResourceLimit", got.Status)
	}
	if len(got.Results) != 0 || got.EvidenceTruncated {
		t.Errorf("resource failure carried Results=%d TotalResults=%d EvidenceTruncated=%t",
			len(got.Results), got.TotalResults, got.EvidenceTruncated)
	}
	if got.TotalResults != 0 {
		t.Errorf("resource failure carried TotalResults=%d, want 0", got.TotalResults)
	}
}

func TestAnalyze_InternalPanicReportsPanicWithoutResults(t *testing.T) {
	got := analyzeWithPass(context.Background(), []byte(candidateSrc),
		func(context.Context, *js.AST, *resourceBudget) ([]Result, bool, error) {
			panic("injected panic")
		})
	if got.Status != StatusPanic {
		t.Errorf("Status = %v, want StatusPanic", got.Status)
	}
	if len(got.Results) != 0 || got.EvidenceTruncated {
		t.Errorf("panic carried Results=%d TotalResults=%d EvidenceTruncated=%t",
			len(got.Results), got.TotalResults, got.EvidenceTruncated)
	}
	if got.TotalResults != 0 {
		t.Errorf("panic carried TotalResults=%d, want 0", got.TotalResults)
	}
}

func TestAnalyze_ReasonIsBounded(t *testing.T) {
	identifier := strings.Repeat("attacker_identifier_", 40)
	src := `let ` + identifier + `;let ` + identifier + `;/* keydown fetch */`
	got := Analyze(context.Background(), []byte(src))
	if got.Status != StatusParseError {
		t.Fatalf("Status = %v, want StatusParseError", got.Status)
	}
	if len(got.Reason) > MaxReasonBytes {
		t.Errorf("Reason is %d bytes, want at most %d", len(got.Reason), MaxReasonBytes)
	}
	if !utf8.ValidString(got.Reason) {
		t.Errorf("Reason is not valid UTF-8: %q", got.Reason)
	}
	if strings.Contains(got.Reason, "attacker_identifier") || strings.ContainsRune(got.Reason, '\n') {
		t.Errorf("Reason contains attacker-controlled source text: %q", got.Reason)
	}
	if !strings.HasPrefix(got.Reason, StatusParseError.String()+":") {
		t.Errorf("Reason = %q, want stable %q prefix", got.Reason, StatusParseError.String()+":")
	}
}

func TestBoundReasonPreservesUTF8AtByteLimit(t *testing.T) {
	got := boundReason(strings.Repeat("界", MaxReasonBytes))
	if len(got) > MaxReasonBytes {
		t.Errorf("Reason is %d bytes, want at most %d", len(got), MaxReasonBytes)
	}
	if !utf8.ValidString(got) {
		t.Errorf("Reason is not valid UTF-8: %q", got)
	}
}

func nestedUnaryCandidate(depth int) []byte {
	return []byte(`var value=` + strings.Repeat("!", depth) + `0;/* keydown fetch */`)
}
