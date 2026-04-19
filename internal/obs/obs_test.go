package obs

import (
	"errors"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// TestInitDisabled verifies the zero-config case is a true no-op: Init
// returns nil, Enabled stays false, and capture helpers don't panic.
func TestInitDisabled(t *testing.T) {
	if err := Init(nil, "dev", ""); err != nil {
		t.Fatalf("Init(nil) returned error: %v", err)
	}
	if Enabled() {
		t.Fatal("Enabled() true after nil Init")
	}

	cfg := &config.Config{}
	if err := Init(cfg, "dev", ""); err != nil {
		t.Fatalf("Init(empty) returned error: %v", err)
	}
	if Enabled() {
		t.Fatal("Enabled() true after empty-DSN Init")
	}

	// Capture helpers are no-ops when disabled.
	Capture("test", errors.New("ignored"))
	CaptureMsg("test", "ignored")
	Flush()
}

// TestSafeGoSwallowsPanic verifies SafeGo runs fn in a goroutine and
// swallows a panic without crashing the test process. Also exercises
// the disabled-SDK path in report().
func TestSafeGoSwallowsPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	SafeGo("test", func() {
		defer wg.Done()
		panic("boom")
	})
	wg.Wait()
}

// TestGoRunsNormally verifies Go runs fn to completion on the happy
// path (no panic) — a smoke test that the wrapper doesn't swallow
// normal return.
func TestGoRunsNormally(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	ran := false
	Go("test", func() {
		defer wg.Done()
		ran = true
	})
	wg.Wait()
	if !ran {
		t.Fatal("Go did not run fn")
	}
}
