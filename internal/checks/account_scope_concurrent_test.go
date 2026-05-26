package checks

import (
	"context"
	"sync"
	"testing"
)

// TestAccountScopeConcurrentDoesNotBleed validates that two parallel
// goroutines each reading a context-scoped account never see each
// other's scope. Account scope used to live in a single process-wide
// value, which forced account scans to serialize. With context-scoped
// scope, each scan carries its own immutable account value.
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
