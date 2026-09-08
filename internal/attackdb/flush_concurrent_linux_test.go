//go:build linux

package attackdb

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
	"golang.org/x/sys/unix"
)

// A command flush must wait for an in-flight background flush, otherwise an
// older snapshot can overwrite the command's deletion after it reports success.
func TestFlushWaitsForEarlierPersistence(t *testing.T) {
	previous := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previous) })
	db := newTestDB(t)
	db.RecordFinding(findingFromIP("198.51.100.23"))
	path := filepath.Join(db.dbPath, eventsFile)
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan struct{})
	go func() { _ = db.Flush(); close(firstDone) }()
	// Opening a reader releases the first writer. Keep it open until both
	// flushes finish; the single small event fits in the FIFO without draining.
	release := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0600)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Cleanup(func() {
		f := release()
		defer func() { _ = f.Close() }()
		select {
		case <-firstDone:
		case <-time.After(5 * time.Second):
			t.Error("first flush did not finish")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		db.mu.RLock()
		started := len(db.pendingEvents) == 0
		db.mu.RUnlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first flush did not start")
		}
		runtime.Gosched()
	}
	db.RemoveIP("198.51.100.23")
	secondDone := make(chan struct{})
	go func() { _ = db.Flush(); close(secondDone) }()
	select {
	case <-secondDone:
		t.Error("second flush returned while earlier persistence was blocked")
	case <-time.After(100 * time.Millisecond):
	}
	f := release()
	defer func() { _ = f.Close() }()
	for _, done := range []chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("flush did not finish after releasing persistence")
		}
	}
	reloaded := NewForTest(nil)
	reloaded.dbPath = db.dbPath
	reloaded.load()
	if reloaded.LookupIP("198.51.100.23") != nil {
		t.Fatal("forgotten record survived completed flushes")
	}
}
