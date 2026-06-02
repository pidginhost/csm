package processctx

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fillProcReadSlots(t *testing.T) {
	t.Helper()
	acquired := 0
	t.Cleanup(func() {
		for i := 0; i < acquired; i++ {
			releaseProcReadSlot()
		}
	})
	for i := 0; i < procReadConcurrency; i++ {
		if !acquireProcReadSlot() {
			t.Fatalf("could not acquire slot %d while filling the semaphore", i)
		}
		acquired++
	}
}

func waitForProcReadSlots(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if got := len(procReadSem); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("proc read slots in use = %d, want %d", len(procReadSem), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func testSymlink(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return target, link
}

// A blocked-syscall goroutine cannot be cancelled, so deadline-bound /proc
// reads are capped. When the cap is saturated, further reads must fail fast --
// without running the work and without spawning another abandonable goroutine.
func TestProcReadConcurrencyCapFailsFast(t *testing.T) {
	_, link := testSymlink(t)
	fillProcReadSlots(t)

	called := false
	start := time.Now()
	data, ok := runBytesWithDeadline(5*time.Second, func() ([]byte, error) {
		called = true
		return []byte("x"), nil
	})
	if ok || data != nil {
		t.Fatalf("expected fail-fast at cap, got ok=%v data=%q", ok, data)
	}
	if called {
		t.Error("work function must not run when no slot is available (no goroutine spawned)")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("must fail fast at cap, took %s", elapsed)
	}

	if _, ok := readlinkWithDeadline(link, time.Second); ok {
		t.Error("readlinkWithDeadline should also fail fast at cap")
	}
}

func TestReadlinkWithoutDeadlineBypassesDeadlineCap(t *testing.T) {
	target, link := testSymlink(t)
	fillProcReadSlots(t)

	got, ok := readlinkWithDeadline(link, 0)
	if !ok || got != target {
		t.Fatalf("readlink without deadline failed: ok=%v target=%q", ok, got)
	}
}

// With slots available, a deadline read runs normally.
func TestRunBytesWithDeadlineNormalRead(t *testing.T) {
	data, ok := runBytesWithDeadline(time.Second, func() ([]byte, error) {
		return []byte("hello"), nil
	})
	if !ok || string(data) != "hello" {
		t.Fatalf("normal read failed: ok=%v data=%q", ok, data)
	}
}
