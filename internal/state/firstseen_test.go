package state

import (
	"fmt"
	"reflect"
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

// A completed owner is purged before its replacement is installed. That must
// retire missing keys without discarding the history of keys reported again.
func TestPurgeAndMergeFirstSeenSurvivesOwnerReplacement(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	later := first.Add(72 * time.Hour)
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			stored := alert.Finding{Check: "webshell", Message: "same", Severity: alert.Critical, Timestamp: first.Add(time.Hour), FirstSeen: first}
			if legacy {
				stored.FirstSeen = time.Time{}
				stored.Timestamp = first
			}
			missing := stored
			missing.Message = "resolved"
			reported := stored
			reported.FirstSeen = later
			reported.Timestamp = later
			merged := purgeAndMergeLatest([]alert.Finding{stored, missing}, []string{"webshell"}, []alert.Finding{reported}, nil)
			if len(merged) != 1 || merged[0].Key() != stored.Key() || !merged[0].Timestamp.Equal(later) || !merged[0].FirstSeen.Equal(first) {
				t.Fatalf("owner replacement lost history or retained resolved evidence: %+v", merged)
			}
			// Once actually absent from a completed scan, a later detection
			// starts a new observation instead of retaining a hidden tombstone.
			merged = purgeAndMergeLatest(merged, []string{"webshell"}, nil, nil)
			merged = purgeAndMergeLatest(merged, []string{"webshell"}, []alert.Finding{reported}, nil)
			if len(merged) != 1 || !merged[0].FirstSeen.Equal(later) {
				t.Fatalf("resolved finding did not start a new observation: %+v", merged)
			}
		})
	}
}

func TestPurgeAndMergeFirstSeenSurvivesCarryAndDemotion(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	current := alert.Finding{Check: "webshell", Message: "same", FilePath: "/home/alice/site.php", Severity: alert.Warning, DemotedFrom: alert.Critical, Timestamp: first.Add(time.Hour), FirstSeen: first}
	stale := current
	stale.FirstSeen = first.Add(2 * time.Hour)
	stale.Timestamp = stale.FirstSeen
	stale.Severity = alert.Critical
	stale.DemotedFrom = 0
	stale.ScanCarryForward = true
	gaps := map[string]map[string]bool{"webshell": {current.FilePath: true}}
	merged := purgeAndMergeLatest([]alert.Finding{current}, []string{"webshell"}, []alert.Finding{stale}, gaps)
	if !reflect.DeepEqual(merged, []alert.Finding{current}) {
		t.Fatalf("stale carry overwrote authoritative demotion or history: %+v", merged)
	}
	merged = purgeAndMergeLatest(merged, []string{"webshell"}, nil, nil)
	if !reflect.DeepEqual(merged, []alert.Finding{current}) {
		t.Fatalf("negative scan lost demotion or history: %+v", merged)
	}
	stale.ScanCarryForward = false
	merged = purgeAndMergeLatest(merged, []string{"webshell"}, []alert.Finding{stale}, nil)
	if len(merged) != 1 || !merged[0].FirstSeen.Equal(first) || merged[0].Severity != alert.Critical || !merged[0].Timestamp.Equal(stale.Timestamp) {
		t.Fatalf("fresh detection reset demoted history: %+v", merged)
	}
}

func TestPurgeAndMergeFirstSeenKeepsEarlierIncomingObservation(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	stored := alert.Finding{Check: "webshell", Message: "same", Timestamp: first.Add(2 * time.Hour), FirstSeen: first.Add(time.Hour)}
	for _, stamped := range []bool{false, true} {
		reported := stored
		reported.FirstSeen = time.Time{}
		reported.Timestamp = first
		if stamped {
			reported.FirstSeen = first
			reported.Timestamp = first.Add(3 * time.Hour)
		}
		merged := purgeAndMergeLatest([]alert.Finding{stored}, nil, []alert.Finding{reported, stored}, nil)
		if len(merged) != 1 || !merged[0].FirstSeen.Equal(first) || !merged[0].Timestamp.Equal(stored.Timestamp) {
			t.Fatalf("stamped=%v: repeated key lost earliest observation: %+v", stamped, merged)
		}
	}
}

func TestPurgeAndMergeFirstSeenDoesNotChangeCapRecency(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	rows := make([]alert.Finding, latestFindingsCap+1)
	for i := range rows {
		rows[i] = alert.Finding{Check: "webshell", Message: fmt.Sprint(i), Severity: alert.Critical, Timestamp: first.Add(time.Duration(i) * time.Second), FirstSeen: first.Add(-time.Duration(i) * time.Hour)}
	}
	merged := purgeAndMergeLatest(nil, nil, rows, nil)
	if len(merged) != latestFindingsCap {
		t.Fatalf("cap kept %d rows, want %d", len(merged), latestFindingsCap)
	}
	for i, f := range merged {
		want := rows[len(rows)-1-i]
		if f.Key() != want.Key() || !f.FirstSeen.Equal(want.FirstSeen) {
			t.Fatalf("cap row %d = %+v, want %+v", i, f, want)
		}
	}
}
