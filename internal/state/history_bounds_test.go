package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func TestHistoryBoundParityAcrossBackends(t *testing.T) {
	previous := store.Global()
	t.Cleanup(func() { store.SetGlobal(previous) })
	base := time.Date(2026, 9, 23, 10, 0, 0, 123000000, time.UTC)
	findings := []alert.Finding{
		{Check: "before", Timestamp: base.Add(-time.Nanosecond)},
		{Check: "first", Timestamp: base},
		{Check: "last", Timestamp: base.Add(time.Millisecond - time.Nanosecond)},
		{Check: "after", Timestamp: base.Add(time.Millisecond)},
	}
	for _, backend := range []string{"jsonl", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			store.SetGlobal(nil)
			s := openTestStore(t)
			if backend == "bbolt" {
				db, err := store.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.SetGlobal(nil); _ = db.Close() })
				store.SetGlobal(db)
			}
			s.AppendHistory(findings)
			for _, tc := range []struct {
				from, to string
				want     []string
			}{
				{"2026-09-23T10:00:00.123Z", "2026-09-23T10:00:00.124Z", []string{"last", "first"}},
				{" \t", " ", []string{"after", "last", "first", "before"}},
				{"bad", "bad", []string{"after", "last", "first", "before"}},
			} {
				got, total := s.ReadHistoryFiltered(10, 0, tc.from, tc.to, -1, "")
				if len(got) != len(tc.want) || total != len(tc.want) {
					t.Fatalf("%q..%q: got %+v, total %d", tc.from, tc.to, got, total)
				}
				for i, want := range tc.want {
					if got[i].Check != want {
						t.Errorf("row %d = %s; want %s", i, got[i].Check, want)
					}
				}
			}
		})
	}
}
