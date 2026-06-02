package processctx

import (
	"testing"
	"time"
)

// A blocked-syscall goroutine cannot be cancelled, so deadline-bound /proc
// reads are capped. When the cap is saturated, further reads must fail fast --
// without running the work and without spawning another abandonable goroutine.
func TestProcReadConcurrencyCapFailsFast(t *testing.T) {
	for i := 0; i < procReadConcurrency; i++ {
		if !acquireProcReadSlot() {
			t.Fatalf("could not acquire slot %d while filling the semaphore", i)
		}
	}
	t.Cleanup(func() {
		for i := 0; i < procReadConcurrency; i++ {
			releaseProcReadSlot()
		}
	})

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

	if _, ok := readlinkWithDeadline("/proc/self/exe", time.Second); ok {
		t.Error("readlinkWithDeadline should also fail fast at cap")
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
