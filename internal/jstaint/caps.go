package jstaint

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxEvidencePaths bounds the returned evidence flows. TotalResults still
	// reports the true count, so a caller can name the additional paths.
	maxEvidencePaths = 8
	// maxViaSegments bounds a displayed laundering chain: the first headViaSegments
	// segments, one omission marker, and the final tailViaSegments segments.
	maxViaSegments  = 32
	headViaSegments = 16
	tailViaSegments = 15
	// maxSegmentBytes bounds one displayed source, via, or sink segment so a long
	// attacker-controlled identifier cannot create unbounded findings.
	maxSegmentBytes = 64
)

// finalizeResults returns the sorted evidence flows capped to maxEvidencePaths,
// the true pre-cap flow count, and whether any evidence was shortened. Every
// displayed segment is sanitized and length-bounded, and a chain longer than
// maxViaSegments keeps its head and tail around one omission marker.
func (a *analysis) finalizeResults() ([]Result, int, bool) {
	sorted := a.sortedResults()
	total := len(sorted)
	truncated := false
	if total > maxEvidencePaths {
		truncated = true
		sorted = sorted[:maxEvidencePaths]
	}
	for i := range sorted {
		source, cutSource := boundSegment(sorted[i].Source)
		sink, cutSink := boundSegment(sorted[i].Sink)
		via, cutVia := truncateVia(sorted[i].Via)
		sorted[i].Source = source
		sorted[i].Sink = sink
		sorted[i].Via = via
		truncated = truncated || cutSource || cutSink || cutVia
	}
	return sorted, total, truncated
}

// truncateVia bounds each segment and, for a chain longer than maxViaSegments,
// retains the head and tail around one marker that names the omitted count.
func truncateVia(via []string) ([]string, bool) {
	if len(via) == 0 {
		return via, false
	}
	truncated := false
	bounded := make([]string, len(via))
	for i, s := range via {
		seg, cut := boundSegment(s)
		bounded[i] = seg
		truncated = truncated || cut
	}
	if len(bounded) <= maxViaSegments {
		return bounded, truncated
	}
	omitted := len(bounded) - (headViaSegments + tailViaSegments)
	out := make([]string, 0, maxViaSegments)
	out = append(out, bounded[:headViaSegments]...)
	out = append(out, "["+strconv.Itoa(omitted)+" segments omitted]")
	out = append(out, bounded[len(bounded)-tailViaSegments:]...)
	return out, true
}

// boundSegment sanitizes one display segment and bounds it to maxSegmentBytes at a
// rune boundary. It reports whether the length bound shortened the segment;
// sanitizing invalid bytes alone does not count as truncation.
func boundSegment(s string) (string, bool) {
	clean := sanitizeSegment(s)
	if len(clean) <= maxSegmentBytes {
		return clean, false
	}
	const marker = "..."
	cut := maxSegmentBytes - len(marker)
	for cut > 0 && !utf8.RuneStart(clean[cut]) {
		cut--
	}
	return clean[:cut] + marker, true
}

// sanitizeSegment emits valid UTF-8 and replaces control bytes so evidence text
// stays printable and searchable.
func sanitizeSegment(s string) string {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) {
			var clean strings.Builder
			clean.Grow(len(s))
			clean.WriteString(s[:i])
			for i < len(s) {
				r, size = utf8.DecodeRuneInString(s[i:])
				if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) {
					clean.WriteByte('?')
				} else {
					clean.WriteString(s[i : i+size])
				}
				i += size
			}
			return clean.String()
		}
		i += size
	}
	return s
}
