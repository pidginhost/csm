package firewall

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// newTestResolver creates a DynDNSResolver with a no-op engine, ready for
// unit testing. lookupFn defaults to returning NXDOMAIN until overridden.
func newTestResolver(t *testing.T) *DynDNSResolver {
	t.Helper()
	eng := &mockEngine{}
	r := NewDynDNSResolver(nil, eng)
	// Suppress the real net.LookupHost so tests are hermetic.
	r.lookupFn = func(_ context.Context, host string) ([]string, error) {
		return nil, errors.New("NXDOMAIN")
	}
	return r
}

func TestDynDNSResolver_EmptyResolutionEmitsFinding(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 10 * time.Millisecond

	// Seed a successful resolution so lastSuccess is set.
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return []string{"203.0.113.42"}, nil }
	r.AddHost("panel.example.com")
	r.tickOnce(context.Background())

	// Now flip to NXDOMAIN and wait past grace period.
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return nil, errors.New("NXDOMAIN") }
	time.Sleep(20 * time.Millisecond)
	r.tickOnce(context.Background())

	if got := r.UnresolvableHosts(); len(got) != 1 || got[0] != "panel.example.com" {
		t.Fatalf("expected unresolvable hosts list to contain panel.example.com, got %v", got)
	}
}

func TestDynDNSResolver_NeverResolvedHostEmitsFindingAfterGrace(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 5 * time.Millisecond

	var emitted []string
	var mu sync.Mutex
	r.SetFindingSink(func(host string) {
		mu.Lock()
		defer mu.Unlock()
		emitted = append(emitted, host)
	})

	r.AddHost("panel.example.com")
	r.tickOnce(context.Background())
	time.Sleep(10 * time.Millisecond)
	r.tickOnce(context.Background())

	if got := r.UnresolvableHosts(); len(got) != 1 || got[0] != "panel.example.com" {
		t.Fatalf("expected never-resolved host to become unresolvable, got %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != 1 || emitted[0] != "panel.example.com" {
		t.Fatalf("expected finding sink invoked once for never-resolved host, got %v", emitted)
	}
}

func TestDynDNSResolver_RecoversWhenResolutionReturns(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 5 * time.Millisecond

	calls := 0
	var mu sync.Mutex
	r.lookupFn = func(_ context.Context, host string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls < 3 {
			return nil, errors.New("NXDOMAIN")
		}
		return []string{"203.0.113.42"}, nil
	}

	// Seed lastSuccess so the grace clock has something to tick from.
	r.AddHost("panel.example.com")
	r.markLastSuccess("panel.example.com")
	for i := 0; i < 5; i++ {
		r.tickOnce(context.Background())
		time.Sleep(2 * time.Millisecond)
	}
	if got := r.UnresolvableHosts(); len(got) != 0 {
		t.Fatalf("expected recovery to clear unresolvable list, got %v", got)
	}
}

func TestDynDNSResolver_FindingSinkInvoked(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 5 * time.Millisecond

	var emitted []string
	var mu sync.Mutex
	r.SetFindingSink(func(host string) {
		mu.Lock()
		defer mu.Unlock()
		emitted = append(emitted, host)
	})

	// Seed lastSuccess, then fail repeatedly past grace period.
	r.AddHost("panel.example.com")
	r.markLastSuccess("panel.example.com")
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return nil, errors.New("NXDOMAIN") }
	time.Sleep(10 * time.Millisecond)
	r.tickOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != 1 || emitted[0] != "panel.example.com" {
		t.Fatalf("expected finding sink invoked once for panel.example.com, got %v", emitted)
	}
}

func TestDynDNSResolver_FindingSinkNotInvokedBeforeGrace(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 10 * time.Second // very long, should not fire

	var emitted []string
	var mu sync.Mutex
	r.SetFindingSink(func(host string) {
		mu.Lock()
		defer mu.Unlock()
		emitted = append(emitted, host)
	})

	r.AddHost("panel.example.com")
	r.markLastSuccess("panel.example.com")
	// Fail immediately - well within grace period.
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return nil, errors.New("NXDOMAIN") }
	r.tickOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != 0 {
		t.Fatalf("finding sink should not fire within grace period, got %v", emitted)
	}
}

func TestDynDNSResolver_FindingSinkOnlyOnce(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 5 * time.Millisecond

	var count int
	var mu sync.Mutex
	r.SetFindingSink(func(host string) {
		mu.Lock()
		defer mu.Unlock()
		count++
	})

	r.AddHost("panel.example.com")
	r.markLastSuccess("panel.example.com")
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return nil, errors.New("NXDOMAIN") }
	time.Sleep(10 * time.Millisecond)

	// Multiple ticks should only emit once.
	r.tickOnce(context.Background())
	r.tickOnce(context.Background())
	r.tickOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("finding sink should only fire once per failure period, fired %d times", count)
	}
}

func TestDynDNSResolver_NilSinkNoPanic(t *testing.T) {
	r := newTestResolver(t)
	r.gracePeriod = 5 * time.Millisecond

	r.AddHost("panel.example.com")
	r.markLastSuccess("panel.example.com")
	r.lookupFn = func(_ context.Context, host string) ([]string, error) { return nil, errors.New("NXDOMAIN") }
	time.Sleep(10 * time.Millisecond)

	// Should not panic with a nil sink.
	r.tickOnce(context.Background())
}
