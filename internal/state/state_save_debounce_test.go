package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// captureStateWrites records the bytes of every state.json write and still
// writes them to disk.
func captureStateWrites(t *testing.T) *[][]byte {
	t.Helper()
	old := stateFileWriter
	var writes [][]byte
	stateFileWriter = func(path string, perm os.FileMode, data []byte) error {
		writes = append(writes, bytes.Clone(data))
		return old(path, perm, data)
	}
	t.Cleanup(func() { stateFileWriter = old })
	return &writes
}

func TestSaveWritesHashedBytes(t *testing.T) {
	st := openTestStore(t)
	legacyTmp := filepath.Join(st.path, "state.json.tmp")
	if err := os.WriteFile(legacyTmp, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	writes := captureStateWrites(t)

	st.Update([]alert.Finding{{Check: "save_bytes", Message: "one", Severity: alert.High}})
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}

	if len(*writes) != 1 {
		t.Fatalf("state.json writes = %d, want 1 carrying the hashed bytes", len(*writes))
	}
	written := (*writes)[0]
	if got := fmt.Sprintf("%x", sha256.Sum256(written)); got != st.savedHash {
		t.Fatalf("written bytes hash %s, saved hash %s", got, st.savedHash)
	}
	onDisk, err := os.ReadFile(filepath.Join(st.path, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, written) {
		t.Fatal("state.json on disk differs from the bytes handed to the writer")
	}
	if _, err := os.Stat(legacyTmp); !os.IsNotExist(err) {
		t.Fatalf("legacy state.json.tmp survived a save: %v", err)
	}
}

// debounceStore opens a store whose save clock reads *clk.
func debounceStore(t *testing.T, clk *time.Time) *Store {
	t.Helper()
	st := openTestStore(t)
	st.now = func() time.Time { return *clk }
	return st
}

func onDiskKeys(t *testing.T, dir string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]*Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]bool, len(entries))
	for k := range entries {
		keys[k] = true
	}
	return keys
}

var (
	debounceA = alert.Finding{Check: "debounce_probe", Message: "first", Severity: alert.High}
	debounceB = alert.Finding{Check: "debounce_probe", Message: "second", Severity: alert.High}
)

func TestUpdateAndMarkAlertedOnlyMarkDirty(t *testing.T) {
	t0 := time.Now()
	clk := t0
	st := debounceStore(t, &clk)
	writes := captureStateWrites(t)

	st.Update([]alert.Finding{debounceA})
	clk = t0.Add(10 * time.Second)
	st.Update([]alert.Finding{debounceA, debounceB})
	st.MarkAlerted([]alert.Finding{debounceB})
	clk = t0.Add(2 * saveInterval)
	st.Update([]alert.Finding{debounceA, debounceB})
	st.MarkAlerted([]alert.Finding{debounceB})
	if len(*writes) != 0 {
		t.Fatalf("mutations wrote state.json %d times before a flush", len(*writes))
	}
	if !st.dirty || len(st.FilterNew([]alert.Finding{debounceA, debounceB})) != 0 {
		t.Fatal("mutations must update live dedup state and leave it dirty")
	}
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	if len(*writes) != 1 {
		t.Fatalf("FlushDue wrote state.json %d times, want 1", len(*writes))
	}
	keys := onDiskKeys(t, st.path)
	if len(keys) != 2 || !keys[debounceA.Key()] || !keys[debounceB.Key()] {
		t.Fatalf("flush did not carry all pending changes: %v", keys)
	}
}

func TestFlushDueWritesAfterInterval(t *testing.T) {
	t0 := time.Now()
	clk := t0
	st := debounceStore(t, &clk)
	writes := captureStateWrites(t)

	st.Update([]alert.Finding{debounceA})
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	clk = t0.Add(5 * time.Second)
	st.Update([]alert.Finding{debounceA, debounceB})

	if err := st.FlushDue(t0.Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(*writes) != 1 {
		t.Fatalf("FlushDue inside the interval wrote: %d writes, want 1", len(*writes))
	}
	clk = t0.Add(61 * time.Second)
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	if len(*writes) != 2 {
		t.Fatalf("FlushDue after the interval did not write: %d writes, want 2", len(*writes))
	}
	if !onDiskKeys(t, st.path)[debounceB.Key()] {
		t.Fatal("FlushDue did not persist the pending change")
	}
	if err := st.FlushDue(t0.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(*writes) != 2 {
		t.Fatalf("FlushDue rewrote a clean store: %d writes, want 2", len(*writes))
	}
}

func TestCloseWritesPending(t *testing.T) {
	t0 := time.Now()
	clk := t0
	st := debounceStore(t, &clk)

	st.Update([]alert.Finding{debounceA})
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	clk = t0.Add(5 * time.Second)
	st.Update([]alert.Finding{debounceA, debounceB})
	if onDiskKeys(t, st.path)[debounceB.Key()] {
		t.Fatal("precondition: the second update should still be pending")
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(st.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.entries[debounceB.Key()]; !ok {
		t.Fatal("Close dropped the pending change")
	}
}

func TestFlushWritesPendingInsideInterval(t *testing.T) {
	t0 := time.Now()
	clk := t0
	st := debounceStore(t, &clk)

	st.Update([]alert.Finding{debounceA})
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	clk = t0.Add(5 * time.Second)
	st.Update([]alert.Finding{debounceA, debounceB})
	if onDiskKeys(t, st.path)[debounceB.Key()] {
		t.Fatal("precondition: the second update should still be pending")
	}

	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	if !onDiskKeys(t, st.path)[debounceB.Key()] {
		t.Fatal("Flush did not persist the pending change")
	}
}

// A write that keeps failing (a full disk) must not turn every alert batch
// into another marshal of the whole map; it retries at the next interval.
func TestFailedSaveRetriesAtNextInterval(t *testing.T) {
	t0 := time.Now()
	clk := t0
	st := debounceStore(t, &clk)
	old := stateFileWriter
	attempts := 0
	stateFileWriter = func(string, os.FileMode, []byte) error {
		attempts++
		return errors.New("no space left on device")
	}
	t.Cleanup(func() { stateFileWriter = old })

	st.Update([]alert.Finding{debounceA})
	if err := st.FlushDue(clk); err == nil {
		t.Fatal("FlushDue hid the write error")
	}
	clk = t0.Add(10 * time.Second)
	st.Update([]alert.Finding{debounceA, debounceB})
	st.MarkAlerted([]alert.Finding{debounceB})
	_ = st.FlushDue(clk)
	if attempts != 1 {
		t.Fatalf("failing write attempted %d times inside the interval, want 1", attempts)
	}
	clk = t0.Add(saveInterval)
	if err := st.FlushDue(clk); err == nil {
		t.Fatal("FlushDue hid the write error")
	}
	if attempts != 2 {
		t.Fatalf("failing write attempted %d times after the interval, want 2", attempts)
	}
	if !st.dirty {
		t.Fatal("failed save cleared pending changes")
	}
	stateFileWriter = old
	clk = clk.Add(saveInterval)
	if err := st.FlushDue(clk); err != nil {
		t.Fatal(err)
	}
	keys := onDiskKeys(t, st.path)
	if len(keys) != 2 || !keys[debounceA.Key()] || !keys[debounceB.Key()] {
		t.Fatalf("retry lost pending changes: %v", keys)
	}
}
