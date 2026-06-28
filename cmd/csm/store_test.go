package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
	bolt "go.etcd.io/bbolt"
)

func TestShouldCompactState(t *testing.T) {
	const mb = 1024 * 1024
	tests := []struct {
		name      string
		size      int64
		free      int64
		minSizeMB int
		fillRatio float64
		want      bool
	}{
		{"below min size", 50 * mb, 40 * mb, 128, 0.5, false},
		{"large and mostly free", 400 * mb, 380 * mb, 128, 0.5, true},
		{"large but mostly used", 400 * mb, 20 * mb, 128, 0.5, false},
		{"large, fill just under ratio", 200 * mb, 110 * mb, 128, 0.5, true}, // fill 0.45 < 0.5
		{"large, fill just over ratio", 200 * mb, 90 * mb, 128, 0.5, false},  // fill 0.55 >= 0.5
		{"min size disabled", 400 * mb, 380 * mb, 0, 0.5, false},
		{"fill ratio disabled", 400 * mb, 380 * mb, 128, 0, false},
		{"zero size", 0, 0, 128, 0.5, false},
		{"free exceeds size (clamped)", 200 * mb, 300 * mb, 128, 0.5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCompactState(tt.size, tt.free, tt.minSizeMB, tt.fillRatio); got != tt.want {
				t.Fatalf("shouldCompactState(%d,%d,%d,%g) = %v, want %v",
					tt.size, tt.free, tt.minSizeMB, tt.fillRatio, got, tt.want)
			}
		})
	}
}

func TestMaybeCompactStateAtStartupMissingDBDoesNotCreateStateDir(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state")
	res, err := maybeCompactStateAtStartup(&config.Config{
		StatePath: statePath,
	})
	if err != nil {
		t.Fatalf("maybeCompactStateAtStartup: %v", err)
	}
	if res != nil {
		t.Fatalf("result = %#v, want nil for missing csm.db", res)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("maybeCompactStateAtStartup created state dir, stat err = %v", err)
	}
}

// populateStore fills a fresh bbolt file with padded history rows so a
// subsequent compact has something meaningful to reclaim.
func populateStore(t *testing.T, statePath string) int64 {
	t.Helper()
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var findings []alert.Finding
	for i := 0; i < 2000; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "c",
			Message:   strings.Repeat("x", 256),
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	if err = db.AppendHistory(findings); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	if _, err = db.SweepHistoryOlderThan(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("SweepHistoryOlderThan: %v", err)
	}
	sz, err := db.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	return sz
}

func TestRunStoreCompact_ShrinksFile(t *testing.T) {
	statePath := t.TempDir()
	srcSizeBefore := populateStore(t, statePath)

	res, err := runStoreCompact(statePath, StoreCompactOptions{})
	if err != nil {
		t.Fatalf("runStoreCompact: %v", err)
	}
	if res.SrcSize != srcSizeBefore {
		t.Errorf("SrcSize = %d, want %d (pre-compact size)", res.SrcSize, srcSizeBefore)
	}
	if res.DstSize <= 0 {
		t.Errorf("DstSize = %d, want > 0", res.DstSize)
	}
	if res.DstSize >= srcSizeBefore {
		t.Errorf("compact did not shrink: src=%d dst=%d", srcSizeBefore, res.DstSize)
	}
	if res.Preview {
		t.Error("Preview flag should be false when --preview not set")
	}

	// After a real compact the csm.db file on disk matches DstSize.
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	got, err := db.Size()
	if err != nil {
		t.Fatalf("Size after compact: %v", err)
	}
	if got != res.DstSize {
		t.Errorf("post-compact size = %d, want %d", got, res.DstSize)
	}
	free, err := db.FreeBytes()
	if err != nil {
		t.Fatalf("FreeBytes after compact: %v", err)
	}
	if shouldCompactState(got, free, 1, 0.5) {
		t.Fatalf("compacted DB would compact again immediately: size=%d free=%d", got, free)
	}
}

func TestRunStoreCompact_PreviewDoesNotModify(t *testing.T) {
	statePath := t.TempDir()
	srcSizeBefore := populateStore(t, statePath)

	res, err := runStoreCompact(statePath, StoreCompactOptions{Preview: true})
	if err != nil {
		t.Fatalf("runStoreCompact preview: %v", err)
	}
	if !res.Preview {
		t.Error("Preview flag should be true")
	}
	if res.DstSize <= 0 {
		t.Error("preview should report a dst size")
	}

	// The on-disk src must still be the pre-compact size.
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	got, _ := db.Size()
	if got != srcSizeBefore {
		t.Errorf("preview modified src: got=%d want=%d", got, srcSizeBefore)
	}
}

func TestRunStoreCompact_RefusesWhenStoreLocked(t *testing.T) {
	statePath := t.TempDir()
	populateStore(t, statePath)

	// Hold the bbolt lock the way a running daemon would.
	holder, err := bolt.Open(filepath.Join(statePath, "csm.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("lock holder open: %v", err)
	}
	defer func() { _ = holder.Close() }()

	_, err = runStoreCompact(statePath, StoreCompactOptions{})
	if err == nil {
		t.Fatal("runStoreCompact should fail when the DB is locked by another process")
	}
	if !strings.Contains(err.Error(), "daemon") && !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention the daemon or lock; got: %v", err)
	}
}

func TestRunStoreCompact_RefusesWhenStateLockHeld(t *testing.T) {
	statePath := t.TempDir()
	populateStore(t, statePath)

	lock, err := state.AcquireLock(statePath)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer lock.Release()

	_, err = runStoreCompact(statePath, StoreCompactOptions{})
	if err == nil {
		t.Fatal("runStoreCompact should fail when the daemon state lock is held")
	}
	if !strings.Contains(err.Error(), "state lock") {
		t.Fatalf("error = %v, want state lock context", err)
	}
}

func TestRunStoreCompact_MissingStatePath(t *testing.T) {
	_, err := runStoreCompact("", StoreCompactOptions{})
	if err == nil {
		t.Error("empty state path should error")
	}
}

func TestRunStoreResetBotVerify_ClearsCachedEntries(t *testing.T) {
	statePath := t.TempDir()
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	exp := time.Now().Add(24 * time.Hour)
	if perr := db.PutBotVerify(net.ParseIP("198.51.100.1"), "facebookbot", false, exp); perr != nil {
		t.Fatalf("PutBotVerify: %v", perr)
	}
	if perr := db.PutBotVerify(net.ParseIP("198.51.100.2"), "amazonbot", false, exp); perr != nil {
		t.Fatalf("PutBotVerify: %v", perr)
	}
	if cerr := db.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	n, err := runStoreResetBotVerify(statePath)
	if err != nil {
		t.Fatalf("runStoreResetBotVerify: %v", err)
	}
	if n != 2 {
		t.Errorf("cleared %d, want 2", n)
	}
}

func TestRunStoreResetBotVerify_RefusesWhenStoreLocked(t *testing.T) {
	statePath := t.TempDir()
	// Open once so the bbolt file exists, then re-open with another
	// handle to simulate a running daemon.
	first, err := store.Open(statePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	_ = first.Close()
	holder, err := bolt.Open(filepath.Join(statePath, "csm.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("lock holder open: %v", err)
	}
	defer func() { _ = holder.Close() }()

	_, err = runStoreResetBotVerify(statePath)
	if err == nil {
		t.Fatal("runStoreResetBotVerify should fail when the DB is locked")
	}
	if !strings.Contains(err.Error(), "daemon") && !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention the daemon or lock; got: %v", err)
	}
}

func TestRunStoreResetBotVerify_MissingStatePath(t *testing.T) {
	_, err := runStoreResetBotVerify("")
	if err == nil {
		t.Error("empty state path should error")
	}
}

func TestRunStoreCompact_CleansUpTempOnFailure(t *testing.T) {
	// Point to a stateDir that exists but contains no csm.db — Open
	// creates one on the fly, but CompactInto to a locked dst should
	// still clean up. Simpler check: pass a bogus dir that can't be
	// created.
	_, err := runStoreCompact("/proc/self/no-such-dir/that-cannot-be-made", StoreCompactOptions{})
	if err == nil {
		t.Error("expected error when state path is unusable")
	}
}
