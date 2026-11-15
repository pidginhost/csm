package attackdb

import (
	"testing"
	"time"
)

func TestPendingEvictionAndVerdictReportEachDropOnce(t *testing.T) {
	for _, order := range []string{"pending first", "verdict first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			for range 100 {
				db := NewForTest(nil)
				db.SetMailBudget(1)
				db.RecordMailVerdict("192.0.2.1", true, mailNow)
				if ev := db.RecordMailVerdict("192.0.2.2", true, mailNow); ev == nil || ev.Dropped != 2 {
					t.Fatalf("first report = %+v, want 2 drops", ev)
				}
				for _, ip := range []string{"192.0.2.3", "192.0.2.4", "192.0.2.5"} {
					if ev := db.RecordMailVerdict(ip, true, mailNow.Add(time.Hour)); ev != nil {
						t.Fatalf("early report: %+v", ev)
					}
				}
				at := mailNow.Add(day)
				results := make(chan *Eviction, 2)
				pending := func() { results <- db.PendingEviction(at) }
				verdict := func() { results <- db.RecordMailVerdict("192.0.2.6", true, at) }
				switch order {
				case "pending first":
					pending()
					verdict()
				case "verdict first":
					verdict()
					pending()
				case "concurrent":
					start := make(chan struct{})
					go func() { <-start; pending() }()
					go func() { <-start; verdict() }()
					close(start)
				}
				reports, dropped := 0, 0
				for range 2 {
					if ev := <-results; ev != nil {
						reports++
						dropped += ev.Dropped
					}
				}
				if reports != 1 || dropped != 2 && dropped != 4 {
					t.Fatalf("got %d reports with %d drops, want one with 2 or 4", reports, dropped)
				}
				if ev := db.PendingEviction(at.Add(day - time.Nanosecond)); ev != nil {
					t.Fatalf("second report inside the shared window: %+v", ev)
				}
				if ev := db.PendingEviction(at.Add(day)); ev != nil {
					dropped += ev.Dropped
				}
				if dropped != 4 || db.computeStats().MailEvicted != 6 {
					t.Fatalf("reported %d of 4 remaining drops; total evictions %d", dropped, db.computeStats().MailEvicted)
				}
				if ev := db.PendingEviction(at.Add(2 * day)); ev != nil {
					t.Fatalf("duplicate final report: %+v", ev)
				}
			}
		})
	}
}
