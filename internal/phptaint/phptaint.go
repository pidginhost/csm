// Package phptaint reports remotely-fetched content that reaches a PHP
// code-execution sink.
//
// It exists because binding an executed variable to a fetched one requires a
// backreference, which neither YARA-X nor Go's RE2 provides. See
// docs/superpowers/specs/2026-08-18-php-remote-source-taint-analyzer-design.md.
//
// The package is pure: bytes in, report out. It touches no filesystem,
// config, store, or process global that any caller can observe or that
// carries state across calls -- the one exception is declTreeBuilds, a
// package-level counter incremented on every Analyze purely so a same-package
// test can assert a structural invariant; see its doc comment.
package phptaint

import (
	"context"
	"sort"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// Status is the outcome of an analysis attempt. Callers must not infer a
// clean file from an empty result slice. StatusAnalyzed and StatusNotCandidate
// are the two completed outcomes; every other status is a coverage gap and must
// be accounted for as such rather than counted as a clean file.
type Status uint8

const (
	// StatusNotCandidate means the pre-filter alone proved the content
	// cannot contain a flow this analyzer reports.
	StatusNotCandidate Status = iota
	// StatusAnalyzed means the content parsed cleanly and the data-flow pass
	// ran to completion.
	StatusAnalyzed
	StatusOversize
	// StatusParseError means no usable tree was produced.
	StatusParseError
	// StatusPartialParse means the parser recovered from syntax errors and
	// returned an incomplete tree. Analysing it would under-report silently,
	// so it is a coverage gap rather than a result.
	StatusPartialParse
	StatusResourceLimit
	StatusCanceled
	StatusPanic
)

// String names the status for metrics labels and operator-facing text.
func (s Status) String() string {
	switch s {
	case StatusNotCandidate:
		return "not_candidate"
	case StatusAnalyzed:
		return "analyzed"
	case StatusOversize:
		return "oversize"
	case StatusParseError:
		return "parse_error"
	case StatusPartialParse:
		return "partial_parse"
	case StatusResourceLimit:
		return "resource_limit"
	case StatusCanceled:
		return "canceled"
	case StatusPanic:
		return "panic"
	}
	return "unknown"
}

// Confidence grades how firmly the source was shown to be remote.
type Confidence uint8

const (
	// ConfidenceLow means the source function also reads local files and its
	// argument could not be proven either way.
	ConfidenceLow Confidence = iota
	// ConfidenceHigh means the argument carries a remote scheme.
	ConfidenceHigh
	// ConfidenceCertain means a remote source additionally passed through a
	// decoder before reaching the sink.
	ConfidenceCertain
)

// String names the confidence for operator-facing text.
func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceHigh:
		return "high"
	case ConfidenceCertain:
		return "certain"
	}
	return "unknown"
}

// MaxSourceBytes bounds the complete source an analysis accepts. Callers
// should read one byte past it to tell an exact-limit file from a truncated
// prefix.
const MaxSourceBytes = 2 << 20

// MaxReasonBytes bounds Report.Reason. Parser diagnostics can contain
// attacker-controlled text, so reports retain only sanitized, bounded context.
const MaxReasonBytes = 256

// Analyzer budgets. These bound work regardless of the parser's own
// resilience: a Go stack overflow is fatal and cannot be recovered, so
// analyzer recursion is capped explicitly.
const (
	// maxCollectedNodes bounds nodes of interest recorded per scope. Total
	// traversal work is separately bounded by MaxSourceBytes.
	maxCollectedNodes  = 800_000
	maxSummarizedFuncs = 2_000
	maxAnalysisDepth   = 256
	// maxEvidenceResults bounds returned evidence paths; TotalResults still
	// reports the full count.
	maxEvidenceResults = 8
	// maxDeclarations bounds how many functions/methods/classes one file's
	// declaration tree is built from. declarationTree is linearithmic in
	// this count (not quadratic -- see its doc comment), so this exists as
	// defence in depth against a future regression rather than as the
	// primary complexity fix, and is set far above any real single PHP
	// file's declaration count.
	maxDeclarations = 20_000
)

// Result is one remote-source-to-sink flow.
type Result struct {
	// Source is the acquiring call, such as "curl_exec".
	Source string
	// Identifiers lists every distinct variable and call name that appears
	// in the sink's own expression, sorted alphabetically. This is context
	// for a reviewer reading the report, not a laundering path: it includes
	// names that never carried the tainted value, and carries no ordering
	// information about how the value actually moved.
	Identifiers []string
	// Sink names the executing construct, such as "eval".
	Sink string
	// Confidence grades how firmly the source was shown to be remote.
	Confidence Confidence
}

// Report is the outcome of analysing one source file.
type Report struct {
	Status Status
	// Results is non-empty only when Status is StatusAnalyzed.
	Results []Result
	// TotalResults counts every distinct source-sink endpoint pair before
	// evidence truncation. It is non-zero only when Status is StatusAnalyzed.
	TotalResults int
	// Reason carries a stable status label plus bounded sanitized context.
	// It never contains source excerpts.
	Reason string
	// PrecisionLoss names constructs that defeat variable identity, such as
	// variable variables or extract(). Recorded, never silently ignored.
	PrecisionLoss []string
	// EvidenceTruncated reports that displayed evidence was shortened.
	EvidenceTruncated bool
}

// recovered recovers a panic at the package boundary so a parser or analyzer
// defect degrades to a coverage gap instead of taking down the caller.
func recovered(fn func() Report) (report Report) {
	defer func() {
		if r := recover(); r != nil {
			// A panic value may contain parser tokens or source text. The status
			// is actionable without reflecting that attacker-controlled value.
			report = Report{Status: StatusPanic, Reason: "recovered panic during analysis"}
		}
		report = finalizeReport(report)
	}()
	return fn()
}

// finalizeReport enforces the package boundary invariants in one place. Only a
// completed analysis may carry findings; every evidence segment leaving the
// package is printable and bounded even if an internal producer misses a cap.
func finalizeReport(report Report) Report {
	if report.Status == StatusAnalyzed {
		report.Reason = ""
		for i := range report.Results {
			var cutSource, cutSink, cutIdentifiers bool
			report.Results[i].Source, cutSource = sanitize(report.Results[i].Source, maxSegmentBytes)
			report.Results[i].Sink, cutSink = sanitize(report.Results[i].Sink, maxSegmentBytes)
			report.Results[i].Identifiers, cutIdentifiers = truncateChain(report.Results[i].Identifiers)
			report.EvidenceTruncated = report.EvidenceTruncated || cutSource || cutSink || cutIdentifiers
		}
		for i := range report.PrecisionLoss {
			report.PrecisionLoss[i] = sanitizeSegment(report.PrecisionLoss[i])
		}
		return report
	}

	report.Results = nil
	report.TotalResults = 0
	report.PrecisionLoss = nil
	report.EvidenceTruncated = false
	if report.Status == StatusNotCandidate {
		report.Reason = ""
		return report
	}

	detail := sanitizeReason(report.Reason)
	report.Reason = report.Status.String()
	if detail != "" {
		report.Reason += ": " + detail
	}
	report.Reason = sanitizeReason(report.Reason)
	return report
}

// Analyze owns the size check, pre-filter, parse, and data-flow pass. It
// recovers a panic at the package boundary via the recovered helper.
func Analyze(ctx context.Context, src []byte) Report {
	return recovered(func() Report { return analyze(ctx, src) })
}

func analyze(ctx context.Context, src []byte) Report {
	if len(src) > MaxSourceBytes {
		return Report{Status: StatusOversize, Reason: "source exceeds maximum analyzed size"}
	}
	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}
	if !isCandidate(src) {
		return Report{Status: StatusNotCandidate}
	}
	root, status, reason := parseSource(src)
	if status != StatusAnalyzed {
		return Report{Status: status, Reason: reason}
	}
	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}

	// all: whole-file inventory, used for the declaration list and the
	// budget. top: the file's top-level statements only, collected below via
	// collectTopLevel. These MUST stay separate. A single flat taint map over
	// the whole file lets a function-local variable taint an unrelated
	// top-level variable that merely shares its name, which fires on clean
	// code -- names like $data and $content are ubiquitous in real PHP.
	// Function and method bodies get their own state below.
	all := collectScope(root)
	if all.budgetExceeded {
		return Report{Status: StatusResourceLimit, Reason: "collection budget exceeded"}
	}
	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}

	// tree indexes every declaration in the file once (see declarationTree
	// for why this must happen exactly once, not once per declaration), so
	// each scope below can derive its own exclusion index by lookup.
	// functionSummaries calls f.declarationTree() again on this same all;
	// that hits scopeFacts' own cache rather than rebuilding. Check the
	// defence-in-depth cap before any further work, including
	// functionSummaries, so a file that trips it does no summarization work
	// either. This is a coverage gap, not a silent skip: StatusResourceLimit
	// means the file was not examined, matching the same contract already
	// used for a collection-budget overrun above.
	tree := all.declarationTree()
	if tree.count > maxDeclarations {
		return Report{Status: StatusResourceLimit, Reason: "too many declarations to analyze"}
	}
	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}
	callIndex := newResolvedCallIndex(all)

	summaries, loss, err := functionSummaries(ctx, all)
	if err != nil {
		if err == errSummaryLimit {
			return Report{Status: StatusResourceLimit, Reason: err.Error()}
		}
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}

	// Each scope below excludes every declaration nested inside it except,
	// when the scope IS a declaration's own body, that declaration's own
	// span -- otherwise a function would exclude its own statements from
	// itself. exclusionFor derives this from tree by lookup rather than by
	// rescanning the file's declarations for every scope.
	topExclude := tree.exclusionFor(nil)
	top := callIndex.apply(collectTopLevel(root, &topExclude))
	// factsByScope keeps the facts each loop below already builds, keyed by the
	// declaration they belong to (nil for the top level). Nothing here
	// re-collects: this only retains what would otherwise be discarded, so a
	// closure can later ask what its enclosing scope held.
	factsByScope := map[ast.Vertex]*scopeFacts{nil: top}
	flows, err := findFlows(ctx, top, summaries)
	if err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}
	// droppedTaint tracks whether ANY scope assigns tainted content to a
	// target this package cannot key (see hasUnresolvableTaintedTarget):
	// method-call-chain, static-property, list()-destructuring, and
	// variable-variable targets all silently drop the flow rather than
	// risk a false positive by guessing. Checked per scope (top level, each
	// function, each method) using the SAME scope-isolated facts already
	// collected here for findFlows, so "tainted" means tainted within that
	// specific scope's own taint state -- never a same-named variable
	// leaking taint in from an unrelated scope. Direct call origins come from
	// all so namespace-level `use function` aliases stay resolved inside
	// separately collected declaration bodies; source positions still limit
	// them to the exact RHS being checked.
	droppedTaint, err := hasUnresolvableTaintedTarget(ctx, top, summaries)
	if err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}

	// Sinks inside function bodies count too, each against its own state.
	// collectOwnStmts (not collectAll) skips any function/class/method/
	// closure/arrow-function nested inside this body, for the same reason
	// collectTopLevel skips declarations at the file level: a nested
	// declaration's locals must not taint an identically-named local in the
	// enclosing body.
	for _, fn := range all.funcs {
		if err := ctx.Err(); err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		fnExclude := tree.exclusionFor(fn)
		body := callIndex.apply(collectOwnStmts(fn.Stmts, &fnExclude))
		factsByScope[fn] = body
		bodyFlows, err := findFlows(ctx, body, summaries)
		if err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		flows = append(flows, bodyFlows...)
		if !droppedTaint {
			droppedTaint, err = hasUnresolvableTaintedTarget(ctx, body, summaries)
			if err != nil {
				return Report{Status: StatusCanceled, Reason: err.Error()}
			}
		}
	}
	for _, m := range all.methods {
		if err := ctx.Err(); err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		// StmtClassMethod carries ONE Stmt vertex, not a Stmts slice.
		mExclude := tree.exclusionFor(m)
		body := callIndex.apply(collectOwnStmts(methodStmts(m.Stmt), &mExclude))
		factsByScope[m] = body
		bodyFlows, err := findFlows(ctx, body, summaries)
		if err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		flows = append(flows, bodyFlows...)
		if !droppedTaint {
			droppedTaint, err = hasUnresolvableTaintedTarget(ctx, body, summaries)
			if err != nil {
				return Report{Status: StatusCanceled, Reason: err.Error()}
			}
		}
	}
	// Closures are the most common nested scope in real PHP (WordPress hooks,
	// shutdown/callback registration, ...), so they get the exact same
	// treatment as a named function's body: excluded from the enclosing
	// scope above via declarationTree, analysed here in their own. Recording
	// the span without this loop (or the reverse) would either let a closure
	// local borrow an unrelated outer variable's taint or stop examining the
	// closure's own sinks entirely -- see the closures field doc in facts.go.
	for _, cl := range all.closures {
		if err := ctx.Err(); err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		clExclude := tree.exclusionFor(cl)
		body := callIndex.apply(collectOwnStmts(cl.Stmts, &clExclude))
		factsByScope[cl] = body
		bodyFlows, err := findFlows(ctx, body, summaries)
		if err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		flows = append(flows, bodyFlows...)
		if !droppedTaint {
			droppedTaint, err = hasUnresolvableTaintedTarget(ctx, body, summaries)
			if err != nil {
				return Report{Status: StatusCanceled, Reason: err.Error()}
			}
		}
	}
	// An arrow function's body is a single implicit-return expression rather
	// than a statement list (see arrowFunctionBody), but it is the same kind
	// of nested scope as a closure and needs the same two-sided treatment.
	for _, af := range all.arrowFuncs {
		if err := ctx.Err(); err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		afExclude := tree.exclusionFor(af)
		body := callIndex.apply(collectOwnStmts(arrowFunctionBody(af), &afExclude))
		factsByScope[af] = body
		bodyFlows, err := findFlows(ctx, body, summaries)
		if err != nil {
			return Report{Status: StatusCanceled, Reason: err.Error()}
		}
		flows = append(flows, bodyFlows...)
		if !droppedTaint {
			droppedTaint, err = hasUnresolvableTaintedTarget(ctx, body, summaries)
			if err != nil {
				return Report{Status: StatusCanceled, Reason: err.Error()}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: err.Error()}
	}

	capturedTaint, captureErr := hasDroppedCapture(ctx, all, tree, factsByScope, summaries)
	if captureErr != nil {
		return Report{Status: StatusCanceled, Reason: captureErr.Error()}
	}
	if droppedTaint {
		loss = append(loss, "unresolvable-assign-target")
	}
	if capturedTaint {
		loss = append(loss, "closure-capture")
	}
	if droppedTaint || capturedTaint {
		// loss is already sorted (functionSummaries sorts it); re-sort once
		// after appending rather than inserting in place, so this stays a
		// single obviously-correct call regardless of where the appended
		// markers fall alphabetically among the other markers.
		sort.Strings(loss)
	}

	flows = dedupeAndSort(flows)
	total := len(flows)
	truncated := false
	if len(flows) > maxEvidenceResults {
		flows = flows[:maxEvidenceResults]
		truncated = true
	}
	results := make([]Result, len(flows))
	for i, flow := range flows {
		results[i] = flow.Result
		truncated = truncated || flow.evidenceTruncated
	}
	return Report{
		Status:            StatusAnalyzed,
		Results:           results,
		TotalResults:      total,
		PrecisionLoss:     loss,
		EvidenceTruncated: truncated,
	}
}
