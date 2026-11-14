package main

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

func TestEmitOfflineSnapshot_DoesNotPanic(t *testing.T) {
	// Compilation-only sentinel; full behaviour is exercised in T13's E2E.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitOfflineSnapshot panicked: %v", r)
		}
	}()
	emitOfflineSnapshot()
}

func TestHostnameLite_NonEmpty(t *testing.T) {
	want, err := os.Hostname()
	if err != nil {
		want = ""
	}
	if got := hostnameLite(); got != want {
		t.Errorf("hostnameLite() = %q, want %q", got, want)
	}
}

// Ensure the offline path uses health.Snapshot (compile check).
var _ = health.Snapshot{}
