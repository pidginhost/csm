package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestParseHistoryBoundCalendarDayCoversTheWholeDay(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Bucharest")
	if err != nil {
		t.Skip("zoneinfo unavailable:", err)
	}
	// 2026-10-25 has 25 hours in this zone: clocks go back at 04:00.
	start, err := parseHistoryBoundIn("2026-10-25", false, loc)
	if err != nil {
		t.Fatal(err)
	}
	end, err := parseHistoryBoundIn("2026-10-25", true, loc)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC); !start.Equal(want) {
		t.Errorf("start = %s, want %s", start.UTC(), want)
	}
	if want := time.Date(2026, 10, 25, 22, 0, 0, 0, time.UTC); !end.Equal(want) {
		t.Errorf("end = %s, want %s (the next local midnight)", end.UTC(), want)
	}
}

func TestParseHistoryBoundInstantIsUsedAsIs(t *testing.T) {
	for _, end := range []bool{false, true} {
		got, err := ParseHistoryBound("2026-09-22T11:15:00Z", end)
		if err != nil {
			t.Fatal(err)
		}
		if want := time.Date(2026, 9, 22, 11, 15, 0, 0, time.UTC); !got.Equal(want) {
			t.Errorf("end=%v: got %s, want %s", end, got, want)
		}
	}
}

func TestParseHistoryBoundRejectsGarbage(t *testing.T) {
	for _, in := range []string{"yesterday", "2026-02-30", "2026-9-1", "20260901"} {
		if _, err := ParseHistoryBound(in, false); err == nil {
			t.Errorf("%q parsed; want an error", in)
		}
	}
	if got, err := ParseHistoryBound("", true); err != nil || !got.IsZero() {
		t.Errorf("empty bound = %v, %v; want zero time, nil", got, err)
	}
}

// The web UI asks for a day in the operator's zone as two instants; the
// end instant is exclusive.
func TestReadHistoryFilteredByInstants(t *testing.T) {
	db := openTestDB(t)
	start := time.Date(2026, 9, 22, 11, 15, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: start.Add(-time.Second), Severity: alert.High, Check: "before"},
		{Timestamp: start, Severity: alert.High, Check: "first"},
		{Timestamp: end.Add(-time.Second), Severity: alert.High, Check: "last"},
		{Timestamp: end, Severity: alert.High, Check: "after"},
	})
	results, matched := db.ReadHistoryFiltered(10, 0, start.Format(time.RFC3339), end.Format(time.RFC3339), -1, "")
	if matched != 2 || len(results) != 2 || results[0].Check != "last" || results[1].Check != "first" {
		t.Fatalf("results = %+v (matched %d), want last and first", results, matched)
	}
}

func TestParseHistoryBoundMidnightTransitions(t *testing.T) {
	for _, tc := range []struct{ zone, day, from, to string }{
		{"America/Santiago", "2026-09-06", "2026-09-06T04:00:00Z", "2026-09-07T03:00:00Z"},
		{"America/Havana", "2026-11-01", "2026-11-01T04:00:00Z", "2026-11-02T05:00:00Z"},
		{"America/Sao_Paulo", "2018-11-04", "2018-11-04T03:00:00Z", "2018-11-05T02:00:00Z"},
		{"Pacific/Apia", "2011-12-30", "2011-12-30T10:00:00Z", "2011-12-30T10:00:00Z"},
		{"Europe/Bucharest", "2026-03-29", "2026-03-28T22:00:00Z", "2026-03-29T21:00:00Z"},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.zone)
			if err != nil {
				t.Fatal(err)
			}
			for _, end := range []bool{false, true} {
				got, err := parseHistoryBoundIn(tc.day, end, loc)
				want := tc.from
				if end {
					want = tc.to
				}
				if err != nil || got.UTC().Format(time.RFC3339) != want {
					t.Errorf("end=%v: got %s, %v; want %s", end, got.UTC(), err, want)
				}
			}
		})
	}
}

func TestReadHistoryFilteredWhitespaceBounds(t *testing.T) {
	db := openTestDB(t)
	writeFindings(t, db, []alert.Finding{{Timestamp: time.Now(), Check: "webshell"}})
	got, total := db.ReadHistoryFiltered(10, 0, " ", " \t", -1, "")
	if total != 1 || len(got) != 1 {
		t.Fatalf("got %v, total %d; want one finding", got, total)
	}
}
