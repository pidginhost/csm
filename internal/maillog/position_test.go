package maillog

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Restarting the process cannot reuse a file stream when its offset returns.
func TestFileReaderLinePositionsAcrossProcessEpochs(t *testing.T) {
	a := fileStream(42, alert.NewObservationEpoch(), 0)
	b := fileStream(42, alert.NewObservationEpoch(), 0)
	if a == b || len(a) == 0 || len(a) > 128 || len(b) > 128 {
		t.Fatalf("file epochs reused %q as %q", a, b)
	}
}

// A journald cursor grows past admission's 128-byte bound on a busy host.
// The encoded cursor is bounded, a printable token, the same for the same
// cursor and different for another one.
func TestJournalCursorIsBoundedAndStable(t *testing.T) {
	raw := "s=" + strings.Repeat("a", 32) + ";i=" + strings.Repeat("f", 16) + ";b=" + strings.Repeat("b", 32) +
		";m=" + strings.Repeat("e", 16) + ";t=" + strings.Repeat("c", 16) + ";x=" + strings.Repeat("d", 16)
	if len(raw) <= 128 {
		t.Fatalf("fixture cursor is %d bytes, want one over the bound", len(raw))
	}
	got := journalCursor(raw)
	if len(got) > 128 || !strings.HasPrefix(got, "jc1:") || got != journalCursor(raw) || got == journalCursor(raw+"0") {
		t.Fatalf("encoded cursor %q is not bounded, versioned, stable and distinct", got)
	}
	for i := 0; i < len(got); i++ {
		if got[i] < 0x21 || got[i] > 0x7e {
			t.Fatalf("encoded cursor %q has a byte admission refuses", got)
		}
	}
	if journalCursor("") != "" {
		t.Fatal("an entry without a cursor got a position")
	}
}
