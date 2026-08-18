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
// control and invalid bytes become '?', truncation happens at a rune
// boundary and the marker counts into the cap.
func sanitizeSegment(s string) string { return sanitize(s, maxSegmentBytes) }

// sanitizeReason bounds Report.Reason the same way.
func sanitizeReason(s string) string { return sanitize(s, MaxReasonBytes) }

func sanitize(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// truncateChain keeps a bounded head and tail with one marker naming the
// omitted count, so a long laundering chain cannot blow the display budget.
func truncateChain(via []string) ([]string, bool) {
	if len(via) <= maxChainSegments {
		return via, false
	}
	omitted := len(via) - chainHeadKeep - chainTailKeep
	out := make([]string, 0, maxChainSegments)
	out = append(out, via[:chainHeadKeep]...)
	out = append(out, fmt.Sprintf("... %d segment(s) omitted ...", omitted))
	out = append(out, via[len(via)-chainTailKeep:]...)
	return out, true
}
