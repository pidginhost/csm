package mailstats

import (
	"errors"
	"testing"
	"time"
)

func TestSetStartUpdatesCountingSinceBeforeLoad(t *testing.T) {
	built := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	started := built.Add(5 * time.Minute)
	c := New(func() time.Time { return built })
	c.SetStart(started)
	db := newFakeStore()
	db.readErr = errors.New("read failed")
	if err := c.Load(db, started); err == nil {
		t.Fatal("Load succeeded on a failing store")
	}
	if got := c.Overview(built, started.Add(time.Hour)).CountingSince; !got.Equal(started) {
		t.Errorf("memory counting since %v, want reader start %v", got, started)
	}
	db.readErr = nil
	mustLoad(t, c, db, started.Add(time.Minute))
	if got := db.meta[metaSince]; got != started.Format(time.RFC3339) {
		t.Errorf("stored counting since %q, want reader start %v", got, started)
	}
}

func TestSetStartPreservesStoredCountingSince(t *testing.T) {
	built := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	original := built.Add(-time.Hour)
	started := built.Add(5 * time.Minute)
	db := newFakeStore()
	db.meta[metaSince] = original.Format(time.RFC3339)
	c := New(func() time.Time { return built })
	c.SetStart(started)
	mustLoad(t, c, db, started)
	c.SetStart(started.Add(time.Minute))
	if got := c.Overview(original, started.Add(time.Hour)).CountingSince; !got.Equal(original) {
		t.Errorf("counting since %v, want original start %v", got, original)
	}
	if !c.start.Equal(started) {
		t.Errorf("start after successful Load = %v, want %v", c.start, started)
	}
}
