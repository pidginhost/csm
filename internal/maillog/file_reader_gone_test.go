package maillog

import (
	"errors"
	"io/fs"
	"testing"
	"time"
)

// TestFileReaderRecordStatFiresGoneAfterGrace pins the missing-source
// state machine: onGone fires exactly once after the path stays missing
// past the grace period, re-arms when the path returns, and never fires
// on a transient miss inside the grace window.
func TestFileReaderRecordStatFiresGoneAfterGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var fires int
	var restores int
	var lastErr error
	r := &FileReader{
		path:       "/var/log/maillog",
		goneGrace:  90 * time.Second,
		nowFn:      func() time.Time { return now },
		onGone:     func(err error) { fires++; lastErr = err },
		onRestored: func() { restores++ },
	}

	missErr := &fs.PathError{Op: "stat", Path: r.path, Err: errors.New("no such file")}

	// First miss: starts the clock, no fire yet.
	r.recordStat(true, missErr)
	if fires != 0 {
		t.Fatalf("fired %d times on first miss, want 0", fires)
	}

	// Still missing but inside grace: no fire.
	now = now.Add(60 * time.Second)
	r.recordStat(true, missErr)
	if fires != 0 {
		t.Fatalf("fired %d times inside grace, want 0", fires)
	}

	// Past grace: fire once.
	now = now.Add(31 * time.Second) // total 91s missing
	r.recordStat(true, missErr)
	if fires != 1 {
		t.Fatalf("fired %d times past grace, want 1", fires)
	}
	if lastErr == nil {
		t.Error("onGone should receive the stat error")
	}

	// Still missing: must not fire again (one ping per gone state).
	now = now.Add(5 * time.Minute)
	r.recordStat(true, missErr)
	if fires != 1 {
		t.Fatalf("fired %d times while still gone, want 1", fires)
	}

	// Path returns and the reader can use it again: re-arm.
	r.recordStat(false, nil)
	r.recordRestored()
	if restores != 1 {
		t.Fatalf("restored callback fired %d times, want 1", restores)
	}

	// Missing again from scratch: clock restarts, no immediate fire.
	r.recordStat(true, missErr)
	if fires != 1 {
		t.Fatalf("fired %d on re-miss start, want 1", fires)
	}
	now = now.Add(91 * time.Second)
	r.recordStat(true, missErr)
	if fires != 2 {
		t.Fatalf("fired %d after re-arm + grace, want 2", fires)
	}
}

func TestFileReaderRecordStatPresentResets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fires := 0
	r := &FileReader{
		path:      "/var/log/maillog",
		goneGrace: 10 * time.Second,
		nowFn:     func() time.Time { return now },
		onGone:    func(error) { fires++ },
	}
	r.recordStat(true, errors.New("gone"))
	r.recordStat(false, nil) // present resets before grace elapses
	now = now.Add(time.Hour)
	r.recordStat(false, nil)
	if fires != 0 {
		t.Fatalf("present-resets path fired %d times, want 0", fires)
	}
}

func TestFileReaderRecordStatDoesNotDoubleFireBeforeRestore(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fires := 0
	restores := 0
	r := &FileReader{
		path:       "/var/log/maillog",
		goneGrace:  10 * time.Second,
		nowFn:      func() time.Time { return now },
		onGone:     func(error) { fires++ },
		onRestored: func() { restores++ },
	}

	r.recordStat(true, errors.New("gone"))
	now = now.Add(11 * time.Second)
	r.recordStat(true, errors.New("still gone"))
	if fires != 1 {
		t.Fatalf("fires after first gone state = %d, want 1", fires)
	}

	r.recordStat(false, nil)
	r.recordStat(true, errors.New("missing again before readable restore"))
	now = now.Add(11 * time.Second)
	r.recordStat(true, errors.New("missing again before readable restore"))
	if fires != 1 {
		t.Fatalf("fires before restore = %d, want 1", fires)
	}

	r.recordRestored()
	if restores != 1 {
		t.Fatalf("restores = %d, want 1", restores)
	}
	r.recordStat(true, errors.New("gone after restore"))
	now = now.Add(11 * time.Second)
	r.recordStat(true, errors.New("gone after restore"))
	if fires != 2 {
		t.Fatalf("fires after restore/rearm = %d, want 2", fires)
	}
}
