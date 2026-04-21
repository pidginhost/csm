package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAggregateByDayNReturnsRequestedSize(t *testing.T) {
	db := openTestDB(t)
	for _, want := range []int{1, 7, 30, 90} {
		if got := db.AggregateByDayN(want); len(got) != want {
			t.Errorf("AggregateByDayN(%d) len = %d, want %d", want, len(got), want)
		}
	}
}

func TestAggregateByDayNClampsTooSmall(t *testing.T) {
	db := openTestDB(t)
	for _, bad := range []int{0, -1, -30} {
		got := db.AggregateByDayN(bad)
		if len(got) != 1 {
			t.Errorf("AggregateByDayN(%d) len = %d, want 1 (clamped)", bad, len(got))
		}
	}
}

func TestAggregateByDayNClampsTooLarge(t *testing.T) {
	db := openTestDB(t)
	got := db.AggregateByDayN(dailyRetentionDays + 1000)
	if len(got) != dailyRetentionDays {
		t.Errorf("AggregateByDayN(>retention) len = %d, want %d", len(got), dailyRetentionDays)
	}
}

func TestAggregateByDayNPopulatesRequestedWindow(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	// Finding 60 days ago must appear when asking for 90-day window but
	// not when asking for 30.
	writeFindings(t, db, []alert.Finding{
		{Timestamp: now.Add(-60 * 24 * time.Hour), Severity: alert.Critical, Check: "old"},
		{Timestamp: now, Severity: alert.Warning, Check: "today"},
	})

	sum := func(bs []DayBucket) int {
		n := 0
		for _, b := range bs {
			n += b.Total
		}
		return n
	}

	if got := sum(db.AggregateByDayN(30)); got != 1 {
		t.Errorf("30-day window total = %d, want 1 (only 'today')", got)
	}
	if got := sum(db.AggregateByDayN(90)); got != 2 {
		t.Errorf("90-day window total = %d, want 2 (both entries)", got)
	}
}
