package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A scan re-emits every finding it still sees, and the merge replaces the
// stored row wholesale, so Timestamp answers "when was this last reported",
// never "when did this start". Correlation needs the latter: without it a
// condition found months ago keeps re-entering a recent-activity window on
// every scan.
func TestPurgeAndMergeKeepsTheEarliestFirstSeen(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	later := first.Add(72 * time.Hour)

	stored := alert.Finding{Check: "webshell", Message: "same condition", Severity: alert.Critical, Timestamp: first}
	reported := alert.Finding{Check: "webshell", Message: "same condition", Severity: alert.Critical, Timestamp: later}

	merged := purgeAndMergeLatest([]alert.Finding{stored}, nil, []alert.Finding{reported}, nil)
	if len(merged) != 1 {
		t.Fatalf("merged %d findings, want 1", len(merged))
	}
	if got := merged[0].Timestamp; !got.Equal(later) {
		t.Errorf("Timestamp = %v, want the latest report %v", got, later)
	}
	if got := merged[0].FirstSeen; !got.Equal(first) {
		t.Errorf("FirstSeen = %v, want the original observation %v", got, first)
	}
}

// A finding nobody stored before starts its own history.
func TestPurgeAndMergeStampsFirstSeenOnANewFinding(t *testing.T) {
	at := time.Unix(1_770_000_000, 0)
	fresh := alert.Finding{Check: "webshell", Message: "new", Severity: alert.Critical, Timestamp: at}

	merged := purgeAndMergeLatest(nil, nil, []alert.Finding{fresh}, nil)
	if len(merged) != 1 {
		t.Fatalf("merged %d findings, want 1", len(merged))
	}
	if got := merged[0].FirstSeen; !got.Equal(at) {
		t.Errorf("FirstSeen = %v, want the finding's own timestamp %v", got, at)
	}
}

// Rows written before this field existed carry no FirstSeen. The merge must
// adopt the stored Timestamp rather than treating the condition as new, which
// would reset every long-lived finding's history on upgrade.
func TestPurgeAndMergeAdoptsStoredTimestampAsFirstSeen(t *testing.T) {
	old := time.Unix(1_770_000_000, 0)
	now := old.Add(48 * time.Hour)

	legacy := alert.Finding{Check: "webshell", Message: "legacy", Severity: alert.Critical, Timestamp: old}
	reported := alert.Finding{Check: "webshell", Message: "legacy", Severity: alert.Critical, Timestamp: now}

	merged := purgeAndMergeLatest([]alert.Finding{legacy}, nil, []alert.Finding{reported}, nil)
	if got := merged[0].FirstSeen; !got.Equal(old) {
		t.Errorf("FirstSeen = %v, want the legacy row's timestamp %v", got, old)
	}
}
