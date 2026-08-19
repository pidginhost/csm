package phptaint

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Display bounds. Attacker-controlled identifiers must not be able to
// produce unbounded findings or logs.
const (
	maxSegmentBytes  = 64
	maxChainSegments = 32
	chainHeadKeep    = 16
	chainTailKeep    = 15
)

// sanitizeSegment renders one untrusted display segment: valid UTF-8,
// non-printing and invalid bytes become '?', truncation happens at a rune
// boundary and the marker counts into the cap.
func sanitizeSegment(s string) string {
	clean, _ := sanitize(s, maxSegmentBytes)
	return clean
}

// sanitizeReason bounds Report.Reason the same way.
func sanitizeReason(s string) string {
	clean, _ := sanitize(s, MaxReasonBytes)
	return clean
}

func sanitize(s string, maxBytes int) (string, bool) {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		// IsPrint excludes format controls (including bidi overrides) and the
		// Unicode line/paragraph separators as well as ordinary control bytes.
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) <= maxBytes {
		return s, false
	}
	cut := maxBytes - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...", true
}

// truncateChain sanitizes and bounds every segment, then keeps a bounded head
// and tail with one marker naming any omitted segments.
func truncateChain(via []string) ([]string, bool) {
	bounded := make([]string, len(via))
	truncated := false
	for i, segment := range via {
		var cut bool
		bounded[i], cut = sanitize(segment, maxSegmentBytes)
		truncated = truncated || cut
	}
	if len(bounded) <= maxChainSegments {
		return bounded, truncated
	}
	omitted := len(bounded) - chainHeadKeep - chainTailKeep
	out := make([]string, 0, maxChainSegments)
	out = append(out, bounded[:chainHeadKeep]...)
	out = append(out, fmt.Sprintf("... %d segment(s) omitted ...", omitted))
	out = append(out, bounded[len(bounded)-chainTailKeep:]...)
	return out, true
}
