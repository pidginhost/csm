// Package jstaint reports keystroke values that reach a network sink in a
// JavaScript source file.
//
// It exists because the regex keylogger rule can only match a syntactically
// direct capture. A keylogger that moves the keystroke through variables needs
// variable identity to detect, which requires backreferences that neither
// YARA-X nor RE2 provides. See
// docs/superpowers/specs/2026-08-07-js-keystroke-taint-analyzer-design.md.
//
// The package is pure: bytes in, report out. It touches no filesystem, config,
// store, or process global, so callers own every I/O and persistence decision.
package jstaint

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// Status is the outcome of an analysis attempt. Callers must not infer a clean
// file from an empty result slice: only StatusAnalyzed means the content was
// examined end to end. Every other status is a coverage gap and must be
// accounted for as such rather than counted as a clean file.
type Status uint8

const (
	// StatusNotCandidate means the content cannot contain a flow this analyzer
	// reports, decided by the content pre-filter alone.
	StatusNotCandidate Status = iota
	// StatusAnalyzed means the content was parsed and examined to completion.
	StatusAnalyzed
	StatusOversize
	StatusParseError
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
	case StatusResourceLimit:
		return "resource_limit"
	case StatusCanceled:
		return "canceled"
	case StatusPanic:
		return "panic"
	}
	return "unknown"
}

// MaxSourceBytes bounds the complete source an analysis accepts. Parsing
// allocates on the order of 18x the input, so this also bounds transient
// memory. Callers should read one byte past it to tell an exact-limit file
// from a truncated prefix.
const MaxSourceBytes = 2 << 20

// MaxReasonBytes bounds Report.Reason. Parser diagnostics can contain
// attacker-controlled text, so reports retain only sanitized, bounded context.
const MaxReasonBytes = 256

const (
	// maxAnalysisDepth must cover real minified bundles, whose parse trees
	// reach depth 905, while staying below the parser's pinned 1000 nesting
	// limit so a parseable fixture can still distinguish this limit from a
	// parser error.
	maxAnalysisDepth   = 950
	maxPropagatedFacts = 200_000
)

type analysisLimitError uint8

const (
	errAnalysisDepthLimit analysisLimitError = iota
	errFactLimit
	errNodeLimit
)

func (e analysisLimitError) Error() string {
	switch e {
	case errAnalysisDepthLimit:
		return "maximum AST recursion depth exceeded"
	case errNodeLimit:
		return "maximum AST node count exceeded"
	default:
		return "maximum propagated fact count exceeded"
	}
}

// Result is one keystroke-to-sink flow.
type Result struct {
	// Source is the keyboard property read, such as "e.which".
	Source string
	// Via lists the canonical names the value passed through, in order.
	Via []string
	// Sink names the network operation that received the value.
	Sink string
}

// Report is the outcome of analysing one source file.
type Report struct {
	Status Status
	// Results is non-empty only when Status is StatusAnalyzed.
	Results []Result
	// TotalResults counts every distinct flow before evidence truncation. It is
	// non-zero only when Status is StatusAnalyzed.
	TotalResults int
	// Reason carries bounded diagnostic context for a non-analyzed status.
	Reason string
	// EvidenceTruncated reports that a flow or display segment exceeded an
	// evidence limit.
	EvidenceTruncated bool
}

// Analyze examines src for keystroke data reaching a network sink.
//
// It never panics: a panic anywhere inside is converted to StatusPanic so one
// malformed input cannot take down a scan.
func Analyze(ctx context.Context, src []byte) Report {
	return analyzeWithPass(ctx, src, taintPass)
}

type analysisPass func(context.Context, *js.AST, *resourceBudget) (results []Result, total int, truncated bool, err error)

func analyzeWithPass(ctx context.Context, src []byte, pass analysisPass) (report Report) {
	defer func() {
		if r := recover(); r != nil {
			report = Report{Status: StatusPanic, Reason: "recovered panic during analysis"}
		}
		report = finalizeReport(report)
	}()

	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: cancellationReason(err)}
	}

	// The size gate runs before the pre-filter so an oversize file is reported
	// as a coverage gap even when its first bytes look uninteresting. Deciding
	// "not a candidate" from a prefix would let padding hide a payload.
	if len(src) > MaxSourceBytes {
		return Report{Status: StatusOversize}
	}

	if !isCandidate(src) {
		return Report{Status: StatusNotCandidate}
	}

	ast, err := js.Parse(parse.NewInputBytes(src), js.Options{})
	if err != nil {
		return Report{Status: StatusParseError, Reason: parseFailureContext(err)}
	}

	results, total, evidenceTruncated, err := pass(ctx, ast, &resourceBudget{})
	if err != nil {
		status := analysisErrorStatus(err)
		return Report{
			Status:            status,
			Results:           results,
			TotalResults:      total,
			Reason:            analysisErrorReason(status, err),
			EvidenceTruncated: evidenceTruncated,
		}
	}

	return Report{
		Status:            StatusAnalyzed,
		Results:           results,
		TotalResults:      total,
		EvidenceTruncated: evidenceTruncated,
	}
}

// isCandidate reports whether src carries both a key-handler token and a sink
// token. Matching is ASCII-case-insensitive so React's onKeyDown and a quoted
// "KeyDown" event name are admitted alongside the lowercase spellings.
func isCandidate(src []byte) bool {
	return containsAnyASCIIFold(src, "keydown", "keypress", "keyup") &&
		containsAnyASCIIFold(src, "fetch", "sendbeacon", "send", "open", "src", "websocket")
}

func containsAnyASCIIFold(src []byte, tokens ...string) bool {
	for i, c := range src {
		c = asciiLower(c)
		for _, token := range tokens {
			if c != token[0] || len(src)-i < len(token) {
				continue
			}
			matched := true
			for j := 1; j < len(token); j++ {
				if asciiLower(src[i+j]) != token[j] {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

type resourceBudget struct {
	depth int
	facts int
	nodes int
}

func (b *resourceBudget) enterAST() error {
	if b.depth >= maxAnalysisDepth {
		return errAnalysisDepthLimit
	}
	b.depth++
	return nil
}

func (b *resourceBudget) leaveAST() {
	b.depth--
}

func (b *resourceBudget) addFact() error {
	if b.facts >= maxPropagatedFacts {
		return errFactLimit
	}
	b.facts++
	return nil
}

type limitVisitor struct {
	ctx    context.Context
	budget *resourceBudget
	err    error
}

func (v *limitVisitor) Enter(node js.INode) js.IVisitor {
	if v.err != nil {
		return nil
	}
	if err := v.ctx.Err(); err != nil {
		v.err = err
		return nil
	}
	if err := v.budget.enterAST(); err != nil {
		v.err = err
		return nil
	}
	// Count each parser node once, here, so the taint pass need not recount as it
	// revisits basic blocks during fixed-point iteration.
	v.budget.nodes++
	if v.budget.nodes > maxASTNodes {
		v.err = errNodeLimit
		v.budget.leaveAST()
		return nil
	}
	walkComputedClassName(v, node)
	return v
}

func (v *limitVisitor) Exit(js.INode) {
	v.budget.leaveAST()
}

func analysisErrorStatus(err error) Status {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return StatusCanceled
	case errors.Is(err, errAnalysisDepthLimit), errors.Is(err, errFactLimit), errors.Is(err, errNodeLimit):
		return StatusResourceLimit
	default:
		panic(fmt.Sprintf("unexpected analyzer error: %v", err))
	}
}

func analysisErrorReason(status Status, err error) string {
	if status == StatusCanceled {
		return cancellationReason(err)
	}
	return err.Error()
}

func cancellationReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded.Error()
	}
	return context.Canceled.Error()
}

func parseFailureContext(err error) string {
	var parseErr *parse.Error
	if errors.As(err, &parseErr) {
		return fmt.Sprintf("invalid JavaScript at line %d, column %d", parseErr.Line, parseErr.Column)
	}
	return "invalid JavaScript"
}

func finalizeReport(report Report) Report {
	if report.Status == StatusAnalyzed {
		report.Reason = ""
		return report
	}

	report.Results = nil
	report.TotalResults = 0
	report.EvidenceTruncated = false
	detail := sanitizeReason(report.Reason)
	report.Reason = report.Status.String()
	if detail != "" {
		report.Reason += ": " + detail
	}
	report.Reason = boundReason(report.Reason)
	return report
}

func sanitizeReason(reason string) string {
	reason = strings.ToValidUTF8(reason, "?")
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, reason)
	return strings.Join(strings.Fields(reason), " ")
}

func boundReason(reason string) string {
	reason = sanitizeReason(reason)
	if len(reason) <= MaxReasonBytes {
		return reason
	}
	cut := MaxReasonBytes - 3
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "..."
}
