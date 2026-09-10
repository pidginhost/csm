//go:build linux

package attackdb

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAttackEventQueueBlockedFlushKeepsNewArrivals(t *testing.T) {
	db := eventQueueFlatDB(t)
	for i := 0; i < 3; i++ {
		db.RecordFinding(findingFromIP("198.51.100.23"))
	}
	path := filepath.Join(db.dbPath, eventsFile)
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	first := make(chan struct{})
	go func() { _ = db.Flush(); close(first) }()
	var reader *os.File
	var second chan struct{}
	t.Cleanup(func() {
		if reader == nil {
			var err error
			reader, err = os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0600)
			if err != nil {
				t.Error(err)
				return
			}
		}
		defer func() { _ = reader.Close() }()
		for _, done := range []chan struct{}{first, second} {
			if done == nil {
				continue
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("blocked flush did not finish")
			}
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := eventQueueStatus(t, db, time.Now())
		if s.InFlight == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flush did not take ownership: %+v", s)
		}
		runtime.Gosched()
	}
	if s := eventQueueStatus(t, db, time.Now().Add(2*time.Minute)); s.Depth != 0 || s.InFlight != 3 || s.Reason != "processing_lag" || s.DroppedTotal != 0 {
		t.Fatalf("blocked append concealed: %+v", s)
	}
	db.RecordFinding(findingFromIP("203.0.113.24"))
	second = make(chan struct{})
	go func() { _ = db.Flush(); close(second) }()
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 1 || s.InFlight != 3 || s.DroppedTotal != 0 {
		t.Fatalf("new arrival displaced active batch: %+v", s)
	}
	select {
	case <-second:
		t.Fatal("second flush bypassed the first")
	case <-time.After(50 * time.Millisecond):
	}
	var err error
	reader, err = os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("flush did not finish after opening reader")
		}
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte{'\n'}); n != 4 {
		t.Fatalf("wrote %d event records, want 4", n)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 || s.Status != "ok" {
		t.Fatalf("completed interleaved flushes: %+v", s)
	}
}

func TestAttackEventQueueBufferedWriteFailure(t *testing.T) {
	db := eventQueueFlatDB(t)
	if err := os.Symlink("/dev/full", filepath.Join(db.dbPath, eventsFile)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		db.RecordFinding(findingFromIP("198.51.100.23"))
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.Reason != "dropped_work" || s.DroppedLowerBound {
		t.Fatalf("buffered writes mistaken for persisted events: %+v", s)
	}
}
