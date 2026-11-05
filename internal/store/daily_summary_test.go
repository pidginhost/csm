package store

import (
	"bytes"
	"testing"
)

func TestDailySummaryRoundTrip(t *testing.T) {
	db := openTestDB(t)
	got, err := db.LoadDailySummary()
	if err != nil || got != nil {
		t.Fatalf("empty store = %q, %v; want nil, nil", got, err)
	}
	first := []byte(`{"since":"2026-06-10T08:00:00Z","blocks":3}`)
	if saveErr := db.SaveDailySummary(first); saveErr != nil {
		t.Fatalf("save: %v", saveErr)
	}
	second := []byte(`{"since":"2026-06-11T08:00:00Z","blocks":0}`)
	if saveErr := db.SaveDailySummary(second); saveErr != nil {
		t.Fatalf("replace: %v", saveErr)
	}
	got, err = db.LoadDailySummary()
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("load = %q, %v; want the replacement", got, err)
	}
	got[0] = 'X'
	again, err := db.LoadDailySummary()
	if err != nil || !bytes.Equal(again, second) {
		t.Fatalf("returned bytes alias the database: %q, %v", again, err)
	}
	if v := db.GetMetaString("alerts:daily_summary"); v != string(second) {
		t.Fatalf("summary not under its meta key: %q", v)
	}
}
