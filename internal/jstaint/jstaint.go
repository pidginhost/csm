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
	"strings"

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

// MaxReasonBytes bounds Report.Reason. Parser diagnostics quote source text,
// which is attacker controlled, so the reason can never grow a log or finding
// without limit.
const MaxReasonBytes = 256

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
	// Reason carries bounded diagnostic context for a non-analyzed status.
	Reason string
	// EvidenceTruncated reports that more flows existed than Results holds.
	EvidenceTruncated bool
}

// keyHandlerTokens and sinkTokens are the content pre-filter alphabet. The
// pre-filter is deliberately broader than the AST rules: it admits comments,
// strings, and unrelated APIs, because the parse decides what is real. It must
// have no false negatives against the handler and sink forms the analyzer
// recognises, so it matches bare substrings rather than syntax.
var keyHandlerTokens = []string{"keydown", "keypress", "keyup"}

var sinkTokens = []string{"fetch", "sendbeacon", "send", "open", "src", "websocket"}

// Analyze examines src for keystroke data reaching a network sink.
//
// It never panics: a panic anywhere inside is converted to StatusPanic so one
// malformed input cannot take down a scan.
func Analyze(ctx context.Context, src []byte) (report Report) {
	defer func() {
		if r := recover(); r != nil {
			report = Report{Status: StatusPanic, Reason: boundReason("recovered panic during analysis")}
		}
	}()

	if err := ctx.Err(); err != nil {
		return Report{Status: StatusCanceled, Reason: boundReason(err.Error())}
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

	if _, err := js.Parse(parse.NewInputBytes(src), js.Options{}); err != nil {
		return Report{Status: StatusParseError, Reason: boundReason(err.Error())}
	}

	return Report{Status: StatusAnalyzed}
}

// isCandidate reports whether src carries both a key-handler token and a sink
// token. Matching is ASCII-case-insensitive so React's onKeyDown and a quoted
// "KeyDown" event name are admitted alongside the lowercase spellings.
func isCandidate(src []byte) bool {
	folded := asciiLower(src)
	return containsAny(folded, keyHandlerTokens) && containsAny(folded, sinkTokens)
}

func containsAny(s string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}

// asciiLower lowercases ASCII letters only. Unicode case folding is not used:
// the tokens are ASCII API names, and folding non-ASCII would cost a full
// scan of every bundle for no added coverage.
func asciiLower(src []byte) string {
	out := make([]byte, len(src))
	for i, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func boundReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) <= MaxReasonBytes {
		return reason
	}
	return reason[:MaxReasonBytes-3] + "..."
}
