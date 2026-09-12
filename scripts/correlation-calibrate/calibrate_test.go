package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func critical(account, check, detail string, at time.Time) Event {
	return Event{At: at, Finding: alert.Finding{
		Severity:  alert.Critical,
		Check:     check,
		Message:   "finding on /home/" + account + "/public_html/x.php",
		Details:   detail,
		Timestamp: at,
	}}
}

func TestBatchesSplitOnArrivalGap(t *testing.T) {
	base := time.Unix(1_770_000_000, 0)
	events := []Event{
		critical("a", "webshell", "1", base),
		critical("b", "webshell", "2", base.Add(200*time.Millisecond)),
		critical("c", "webshell", "3", base.Add(5*time.Second)),
	}
	got := Batches(events, time.Second)
	if len(got) != 2 {
		t.Fatalf("Batches() = %d batches, want 2", len(got))
	}
	if len(got[0]) != 2 || len(got[1]) != 1 {
		t.Fatalf("batch sizes = %d,%d, want 2,1", len(got[0]), len(got[1]))
	}
}

// The persisted active set is keyed like the state store: a repeat of the same
// finding replaces the stored row instead of adding a second one. That is why a
// long-lived condition re-reported every scan keeps looking current.
func TestPersistedActiveSetReplacesRepeatsByKey(t *testing.T) {
	base := time.Unix(1_770_000_000, 0)
	set := NewActiveSet(0)
	first := critical("a", "webshell", "same", base)
	set.Admit(first.Finding)
	repeat := critical("a", "webshell", "same", base.Add(time.Hour))
	set.Admit(repeat.Finding)
	if got := len(set.Findings()); got != 1 {
		t.Fatalf("active set holds %d findings, want 1 after a repeat", got)
	}
	if got := set.Findings()[0].Timestamp; !got.Equal(base.Add(time.Hour)) {
		t.Fatalf("repeat kept timestamp %v, want the refreshed %v", got, base.Add(time.Hour))
	}
	set.Admit(critical("a", "webshell", "different", base.Add(2*time.Hour)).Finding)
	if got := len(set.Findings()); got != 2 {
		t.Fatalf("active set holds %d findings, want 2 for a distinct finding", got)
	}
}

// An unbounded active set never forgets, so accounts accumulate for as long as
// the recording runs. A window drops rows that aged out of it.
func TestActiveSetWindowEvictsAgedRows(t *testing.T) {
	base := time.Unix(1_770_000_000, 0)
	set := NewActiveSet(24 * time.Hour)
	set.Admit(critical("a", "webshell", "1", base).Finding)
	set.Admit(critical("b", "webshell", "2", base.Add(time.Hour)).Finding)
	set.Admit(critical("c", "webshell", "3", base.Add(48*time.Hour)).Finding)
	got := set.Findings()
	if len(got) != 1 {
		t.Fatalf("windowed active set holds %d findings, want 1", len(got))
	}
	if got[0].Details != "3" {
		t.Fatalf("windowed active set kept %q, want the most recent row", got[0].Details)
	}
}

func TestActiveSetWindowRetainsUnstampedRows(t *testing.T) {
	set := NewActiveSet(time.Hour)
	legacy := critical("a", "webshell", "legacy", time.Time{}).Finding
	set.Admit(legacy)
	set.Admit(critical("b", "webshell", "current", time.Now()).Finding)
	if got := set.Findings(); len(got) != 2 || !got[1].Timestamp.IsZero() {
		t.Fatalf("unstamped evidence was evicted: %+v", got)
	}
}

func TestPairsCountsDistinctAccountAndCheck(t *testing.T) {
	base := time.Unix(1_770_000_000, 0)
	events := []Event{
		critical("a", "webshell", "1", base),
		critical("a", "webshell", "2", base.Add(time.Minute)),
		critical("a", "phishing_php", "3", base.Add(2*time.Minute)),
		critical("b", "webshell", "4", base.Add(3*time.Minute)),
	}
	rows, pairs := Pairs(events)
	if rows != 4 || pairs != 3 {
		t.Fatalf("Pairs() = %d rows, %d pairs; want 4, 3", rows, pairs)
	}
}

// The threshold sweep is the evidence the roadmap asks for: it has to answer
// "what would N accounts have done" from one replay, not one replay per N.
func TestSpreadSweepCountsPointsAtOrAboveEachThreshold(t *testing.T) {
	s := Spread{}
	for _, n := range []int{0, 1, 2, 3, 3, 5, 9} {
		s.Observe(n)
	}
	for _, tc := range []struct {
		threshold int
		want      int
	}{
		{2, 5},
		{3, 4},
		{4, 2},
		{6, 1},
		{10, 0},
	} {
		if got := s.AtLeast(tc.threshold); got != tc.want {
			t.Errorf("AtLeast(%d) = %d, want %d", tc.threshold, got, tc.want)
		}
	}
	if got := s.Max(); got != 9 {
		t.Errorf("Max() = %d, want 9", got)
	}
	if got := s.Points(); got != 7 {
		t.Errorf("Points() = %d, want 7", got)
	}
}

// The store carries a condition's first observation across re-reports. The
// replay has to do the same or it measures a behaviour production no longer
// has.
func TestActiveSetCarriesFirstSeenAcrossRepeats(t *testing.T) {
	base := time.Unix(1_770_000_000, 0)
	set := NewActiveSet(0)
	set.Admit(critical("a", "webshell", "same", base).Finding)
	set.Admit(critical("a", "webshell", "same", base.Add(72*time.Hour)).Finding)

	got := set.Findings()
	if len(got) != 1 {
		t.Fatalf("active set holds %d findings, want 1", len(got))
	}
	if !got[0].Timestamp.Equal(base.Add(72 * time.Hour)) {
		t.Errorf("Timestamp = %v, want the latest report", got[0].Timestamp)
	}
	if !got[0].FirstSeen.Equal(base) {
		t.Errorf("FirstSeen = %v, want the first observation %v", got[0].FirstSeen, base)
	}
}

// Compare actual owner replacement with replay instead of testing two copies
// of the timestamp rule independently: purge ordering can invalidate the rule.
func TestActiveSetFirstSeenMatchesCompletedScans(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	set := NewActiveSet(0)
	first := time.Unix(1_770_000_000, 0)
	for _, offset := range []time.Duration{0, 72 * time.Hour, 73 * time.Hour} {
		rows := []alert.Finding{
			critical("a", "webshell", "same", first.Add(offset)).Finding,
			critical("b", "webshell", "same", first.Add(offset)).Finding,
			critical("c", "webshell", "same", first.Add(offset)).Finding,
		}
		for _, f := range rows {
			set.Admit(f)
		}
		st.PurgeAndMergeFindings([]string{"webshell"}, rows)
		if got, want := set.Findings(), st.LatestFindings(); !reflect.DeepEqual(got, want) {
			t.Fatalf("after %s: replay %+v differs from completed scan %+v", offset, got, want)
		}
		_, accounts := Derive(first.Add(offset), set.Snapshot(), time.Hour)
		wantAccounts := 0
		if offset == 0 {
			wantAccounts = 3
		}
		if accounts != wantAccounts {
			t.Fatalf("after %s: replay accounts = %d, want %d", offset, accounts, wantAccounts)
		}
	}
}

func TestActiveSetFirstSeenDoesNotChangeEvictionRecency(t *testing.T) {
	first := time.Unix(1_770_000_000, 0)
	for _, window := range []time.Duration{0, time.Hour} {
		set := NewActiveSet(window)
		set.cap = 1
		freshReport := critical("a", "webshell", "longstanding", first).Finding
		freshReport.FirstSeen = first.Add(-30 * 24 * time.Hour)
		set.Admit(freshReport)
		set.Admit(critical("b", "webshell", "recently observed", first.Add(-time.Minute)).Finding)
		if got := set.Findings(); len(got) != 1 || got[0].Key() != freshReport.Key() || !got[0].FirstSeen.Equal(freshReport.FirstSeen) {
			t.Fatalf("window %s: eviction ignored report recency: %+v", window, got)
		}
	}
}
