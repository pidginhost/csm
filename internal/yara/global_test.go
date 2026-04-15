package yara

import (
	"sync"
	"testing"
)

// These tests are build-tag agnostic: they assert the documented contract
// of Init/Global. Under the default (no `yara` build tag) build, Available()
// is false and Init short-circuits. Under the `yara` build tag, Init actually
// attempts to compile rules - but a non-existent directory is a no-op that
// yields no global scanner.

func TestGlobalInitIdempotentConcurrent(t *testing.T) {
	// Init is protected by a sync.Once. Running it concurrently many times
	// must not panic and must return consistent results.
	var wg sync.WaitGroup
	const N = 20
	results := make([]*Scanner, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = Init("/nonexistent-rules-dir")
		}(i)
	}
	wg.Wait()

	// All calls must return the same thing (either nil when Available() is
	// false, or the same scanner pointer under the yara build tag).
	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("Init call %d returned different pointer: %v vs %v", i, r, first)
		}
	}
}

func TestGlobalMatchesInit(t *testing.T) {
	// After Init, Global() must return the same value (including nil when
	// Available() is false).
	got := Init("/also-nonexistent")
	if g := Global(); g != got {
		t.Errorf("Global() = %v, Init() = %v (must match)", g, got)
	}
}
