package checks

import (
	"context"
	"sync"
	"testing"
)

// TestAccountScopeConcurrentDoesNotBleed validates that two parallel
// goroutines each reading a context-scoped account never see each
// other's scope. Before P4, RunAccountScan wrote to a single global
// (`ScanAccount`) and held a process-wide mutex for the entire scan
// to keep scope coherent; that serialised every operator-driven
// account scan. With context-scoped scope the global is gone and
// scans can run in parallel.
func TestAccountScopeConcurrentDoesNotBleed(t *testing.T) {
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)

	aliceErr := make(chan string, iterations)
	bobErr := make(chan string, iterations)

	go func() {
		defer wg.Done()
		ctx := ContextWithAccountScope(context.Background(), "alice")
		for i := 0; i < iterations; i++ {
			got := AccountFromContext(ctx)
			if got != "alice" {
				aliceErr <- got
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		ctx := ContextWithAccountScope(context.Background(), "bob")
		for i := 0; i < iterations; i++ {
			got := AccountFromContext(ctx)
			if got != "bob" {
				bobErr <- got
				return
			}
		}
	}()

	wg.Wait()
	close(aliceErr)
	close(bobErr)
	if leak, ok := <-aliceErr; ok {
		t.Fatalf("alice scope leaked to %q", leak)
	}
	if leak, ok := <-bobErr; ok {
		t.Fatalf("bob scope leaked to %q", leak)
	}
}

func TestAccountScopeEmptyIsHostWide(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "")
	if got := AccountFromContext(ctx); got != "" {
		t.Fatalf("empty account scope should be host-wide, got %q", got)
	}
}

func TestAccountScopeNilContext(t *testing.T) {
	//nolint:staticcheck // SA1012 intentional: tests nil-context tolerance
	if got := AccountFromContext(nil); got != "" {
		t.Fatalf("nil ctx must report empty scope, got %q", got)
	}
	//nolint:staticcheck // SA1012 intentional: tests nil-context tolerance
	ctx := ContextWithAccountScope(nil, "carol")
	if got := AccountFromContext(ctx); got != "carol" {
		t.Fatalf("nil parent ctx should still carry scope, got %q", got)
	}
}
