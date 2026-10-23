package workerproc

import (
	"os"
	"testing"
	"time"
)

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count descriptors: %v", err)
	}
	return len(entries)
}

func assertNoFDLeak(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		now := openFDs(t)
		if now <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descriptor leak: %d open, want %d", now, before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
