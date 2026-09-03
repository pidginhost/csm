package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Demotion keeps the finding and its key. The key includes Check, Message and
// a digest of Details, so none of those fields may change.
func TestDemoteLatestFindingLowersSeverityAndKeepsTheKey(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{
		Check:    "suspicious_php_content",
		Message:  "suspicious PHP content in index.php",
		Details:  "original detail",
		Severity: alert.Critical,
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})

	s.DemoteLatestFinding(f, alert.Warning)

	got := s.LatestFindings()
	if len(got) != 1 {
		t.Fatalf("demotion must keep the finding, got %d", len(got))
	}
	if got[0].Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning", got[0].Severity)
	}
	if got[0].Key() != f.Key() {
		t.Fatalf("key changed: %q -> %q", f.Key(), got[0].Key())
	}
	// Details must survive byte-for-byte: Key() hashes them, so any edit here
	// would re-identify the finding and orphan its dismissal and dedup state.
	if got[0].Details != "original detail" {
		t.Fatalf("details must not change, got %q", got[0].Details)
	}
	if got[0].Check != f.Check || got[0].Message != f.Message {
		t.Fatalf("demotion changed identity fields: %+v", got[0])
	}
	if got[0].DemotedFrom != alert.Critical {
		t.Fatalf("original severity was not retained: %+v", got[0])
	}
}

// A sweep runs repeatedly, so a second pass must change nothing.
func TestDemoteLatestFindingIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m", Details: "d", Severity: alert.Critical}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})

	s.DemoteLatestFinding(f, alert.Warning)
	first := s.LatestFindings()[0]
	s.DemoteLatestFinding(first, alert.Warning)
	second := s.LatestFindings()[0]

	if first.Severity != alert.Warning || second.Severity != alert.Warning {
		t.Fatalf("severity drifted: %v then %v", first.Severity, second.Severity)
	}
	if second.Details != first.Details || second.Key() != first.Key() {
		t.Fatalf("second demotion changed the finding: %+v -> %+v", first, second)
	}
}

func TestDemoteLatestFindingReordersLatestResults(t *testing.T) {
	s := openTestStore(t)
	demoted := alert.Finding{
		Check: "a", Message: "demoted", Severity: alert.Critical, Timestamp: time.Unix(200, 0),
	}
	live := alert.Finding{
		Check: "b", Message: "live", Severity: alert.Critical, Timestamp: time.Unix(100, 0),
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{demoted, live})
	s.DemoteLatestFinding(demoted, alert.Warning)

	got := s.LatestFindings()
	if len(got) != 2 || got[0].Key() != live.Key() || got[1].Key() != demoted.Key() {
		t.Fatalf("demotion left latest findings out of severity order: %+v", got)
	}
}

func TestDemotedSeveritySurvivesStoreReopen(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m", Details: "d", Severity: alert.Critical}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})
	s.DemoteLatestFinding(f, alert.Warning)

	reopened, err := Open(s.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got := reopened.LatestFindings()
	if len(got) != 1 || got[0].DemotedFrom != alert.Critical {
		t.Fatalf("reopened demotion state = %+v", got)
	}
}

func TestDemotedFindingSurvivesScanPurgeUntilReverified(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{
		Check: "suspicious_php_content", Message: "m", Details: "d",
		Severity: alert.Critical, Timestamp: time.Unix(100, 0),
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})
	s.DemoteLatestFinding(f, alert.Warning)

	s.PurgeAndMergeFindings([]string{f.Check}, nil)
	got := s.LatestFindings()
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].DemotedFrom != alert.Critical {
		t.Fatalf("scan purge removed an unconfirmed demotion: %+v", got)
	}

	// Fresh positive detection owns the same key and must replace the saved
	// demotion state, returning the finding to its live severity.
	fresh := f
	fresh.Timestamp = time.Unix(200, 0)
	s.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{fresh})
	got = s.LatestFindings()
	if len(got) != 1 || got[0].Severity != alert.Critical || got[0].DemotedFrom != alert.Warning {
		t.Fatalf("fresh detection did not replace the demoted finding: %+v", got)
	}
}

func TestInvalidDemotionMetadataCannotPinOrDowngradeAFinding(t *testing.T) {
	for name, f := range map[string]alert.Finding{
		"non-warning finding": {
			Check: "suspicious_php_content", Message: "m", Severity: alert.Critical,
			DemotedFrom: alert.Critical,
		},
		"out-of-range original severity": {
			Check: "suspicious_php_content", Message: "m", Severity: alert.Warning,
			DemotedFrom: alert.Critical + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTestStore(t)
			s.PurgeAndMergeFindings(nil, []alert.Finding{f})

			if s.RestoreLatestFindingSeverity(f) {
				t.Fatal("invalid metadata was treated as an automatic demotion")
			}
			s.PurgeAndMergeFindings([]string{f.Check}, nil)
			if got := s.LatestFindings(); len(got) != 0 {
				t.Fatalf("invalid demotion metadata pinned a stale finding: %+v", got)
			}
		})
	}
}

func TestDemoteLatestFindingIgnoresAnUnknownKey(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "c", Message: "m", Severity: alert.Critical}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})

	unknown := f
	unknown.Message = "missing"
	s.DemoteLatestFinding(unknown, alert.Warning)

	got := s.LatestFindings()
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("an unknown key must change nothing, got %+v", got)
	}
}

func TestDemoteLatestFindingDoesNotRaceARefreshedFinding(t *testing.T) {
	s := openTestStore(t)
	old := alert.Finding{
		Check: "c", Message: "m", Details: "d", Severity: alert.Critical,
		Timestamp: time.Unix(100, 0), ContentSHA256: "old-hash",
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{old})
	fresh := old
	fresh.Timestamp = time.Unix(200, 0)
	fresh.ContentSHA256 = "fresh-hash"
	s.SetLatestFindings([]alert.Finding{fresh})

	if s.DemoteLatestFinding(old, alert.Warning) {
		t.Fatal("stale verification demoted a refreshed finding")
	}
	got := s.LatestFindings()[0]
	if got.Severity != alert.Critical || got.DemotedFrom != alert.Warning || got.ContentSHA256 != "fresh-hash" {
		t.Fatalf("refreshed finding was changed: %+v", got)
	}
}

func TestDismissFindingIfLatestDoesNotRaceARefreshedFinding(t *testing.T) {
	s := openTestStore(t)
	old := alert.Finding{
		Check: "c", Message: "m", Details: "d", Severity: alert.Critical,
		Timestamp: time.Unix(100, 0), ContentSHA256: "old-hash",
	}
	s.Update([]alert.Finding{old})
	s.PurgeAndMergeFindings(nil, []alert.Finding{old})
	fresh := old
	fresh.Timestamp = time.Unix(200, 0)
	fresh.ContentSHA256 = "fresh-hash"
	s.SetLatestFindings([]alert.Finding{fresh})

	if s.DismissFindingIfLatest(old) {
		t.Fatal("stale verification dismissed a refreshed finding")
	}
	got := s.LatestFindings()
	if len(got) != 1 || got[0].ContentSHA256 != "fresh-hash" {
		t.Fatalf("refreshed finding was removed: %+v", got)
	}
	entry, ok := s.EntryForKey(fresh.Key())
	if !ok || entry.IsBaseline {
		t.Fatalf("refreshed finding was baselined: %+v, present=%v", entry, ok)
	}
}

func TestRestoreLatestFindingSeverityKeepsIdentity(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{
		Check: "c", Message: "m", Details: "d", Severity: alert.Critical,
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{f})
	s.DemoteLatestFinding(f, alert.Warning)

	demoted := s.LatestFindings()[0]
	if !s.RestoreLatestFindingSeverity(demoted) {
		t.Fatal("demoted finding was not restored")
	}
	got := s.LatestFindings()[0]
	if got.Severity != alert.Critical || got.DemotedFrom != alert.Warning {
		t.Fatalf("restored finding = %+v", got)
	}
	if got.Check != f.Check || got.Message != f.Message || got.Details != f.Details || got.Key() != f.Key() {
		t.Fatalf("restoration changed finding identity: %+v", got)
	}
}
