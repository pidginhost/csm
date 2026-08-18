package phptaint

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeReplacesControlAndInvalidBytes(t *testing.T) {
	got := sanitizeSegment("a\x00b\x1bc\xffd\u2028e\u202ef")
	if strings.ContainsAny(got, "\x00\x1b\u2028\u202e") {
		t.Errorf("non-printing bytes survived: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("output is not valid UTF-8: %q", got)
	}
}

func TestSanitizeTruncatesAtRuneBoundary(t *testing.T) {
	got := sanitizeSegment(strings.Repeat("é", 200))
	if len(got) > maxSegmentBytes {
		t.Errorf("segment is %d bytes, want <= %d", len(got), maxSegmentBytes)
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a rune: %q", got)
	}
}

func TestReasonBoundIncludesMarker(t *testing.T) {
	got := sanitizeReason(strings.Repeat("x", MaxReasonBytes*3))
	if len(got) > MaxReasonBytes {
		t.Errorf("reason is %d bytes, want <= %d", len(got), MaxReasonBytes)
	}
}

func TestTruncateChainKeepsHeadAndTailWithMarker(t *testing.T) {
	via := make([]string, 100)
	for i := range via {
		via[i] = "v"
	}
	got, truncated := truncateChain(via)
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(got) > maxChainSegments {
		t.Errorf("chain has %d segments, want <= %d", len(got), maxChainSegments)
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "omitted") {
		t.Errorf("no omission marker in %q", joined)
	}
}

func TestTruncateChainLeavesShortChainsAlone(t *testing.T) {
	via := []string{"a", "b", "c"}
	got, truncated := truncateChain(via)
	if truncated || len(got) != 3 {
		t.Errorf("short chain was altered: %v truncated=%v", got, truncated)
	}
}

func TestTruncateChainSanitizesAndReportsLongSegments(t *testing.T) {
	via := []string{"safe", "bad\n" + strings.Repeat("x", maxSegmentBytes*2)}
	got, truncated := truncateChain(via)
	if !truncated {
		t.Fatal("truncated = false, want true for a shortened segment")
	}
	if len(got) != len(via) || len(got[1]) > maxSegmentBytes {
		t.Fatalf("bounded chain = %#v", got)
	}
	if strings.ContainsRune(got[1], '\n') {
		t.Errorf("control byte survived in %q", got[1])
	}
}
