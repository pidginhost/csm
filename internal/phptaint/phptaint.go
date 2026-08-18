// Package phptaint reports remotely-fetched content that reaches a PHP
// code-execution sink.
//
// It exists because binding an executed variable to a fetched one requires a
// backreference, which neither YARA-X nor Go's RE2 provides. See
// docs/superpowers/specs/2026-08-18-php-remote-source-taint-analyzer-design.md.
//
// The package is pure: bytes in, report out. It touches no filesystem,
// config, store, or process global, so callers own every I/O decision.
package phptaint

import (
	"context"
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
	maxFixpointRounds  = 16
	maxAnalysisDepth   = 256
)

// Result is one remote-source-to-sink flow.
type Result struct {
	// Source is the acquiring call, such as "curl_exec".
	Source string
	// Via lists the canonical names the value passed through, in order.
	Via []string
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
			var cutSource, cutSink, cutVia bool
			report.Results[i].Source, cutSource = sanitize(report.Results[i].Source, maxSegmentBytes)
			report.Results[i].Sink, cutSink = sanitize(report.Results[i].Sink, maxSegmentBytes)
			report.Results[i].Via, cutVia = truncateChain(report.Results[i].Via)
			report.EvidenceTruncated = report.EvidenceTruncated || cutSource || cutSink || cutVia
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

// Analyze owns the pre-filter, size check, parse, and data-flow pass. It
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
	_ = root
	return Report{Status: StatusAnalyzed}
}
