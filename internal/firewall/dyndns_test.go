package firewall

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockEngine records AllowIP/RemoveAllowIPBySource calls.
type mockEngine struct {
	allowed []string
	removed []string
}

func (m *mockEngine) AllowIP(ip string, reason string) error {
	m.allowed = append(m.allowed, ip)
	return nil
}

func (m *mockEngine) RemoveAllowIPBySource(ip string, source string) error {
	m.removed = append(m.removed, ip)
	return nil
}

type rejectingAllowEngine struct{}

func (r *rejectingAllowEngine) AllowIP(ip string, reason string) error {
	return errors.New("allow rejected")
}

func (r *rejectingAllowEngine) RemoveAllowIPBySource(ip string, source string) error {
	return nil
}

type recordingInfraEngine struct {
	updates []struct {
		host string
		ips  []string
	}
}

func (r *recordingInfraEngine) UpdateInfraResolved(host string, ips []string) {
	r.updates = append(r.updates, struct {
		host string
		ips  []string
	}{host, ips})
}

func (r *recordingInfraEngine) DropInfraResolved(host string) {
	r.updates = append(r.updates, struct {
		host string
		ips  []string
	}{host, nil})
}

func TestNewDynDNSResolver(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	if d == nil {
		t.Fatal("expected non-nil resolver")
	}
	if len(d.hosts) != 1 {
		t.Errorf("hosts = %v", d.hosts)
	}
}

func TestDynDNSResolverResolveAll(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	d.resolveAll()

	// localhost should resolve to at least 127.0.0.1
	if len(eng.allowed) == 0 {
		t.Error("expected at least one AllowIP call for localhost")
	}
}

func TestDynDNSResolverResolveTwiceDeduplicates(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	d.resolveAll()
	firstCount := len(eng.allowed)
	eng.allowed = nil

	d.resolveAll()
	// Second resolve should not re-add the same IPs (already in resolved map)
	if len(eng.allowed) != 0 {
		t.Errorf("second resolve should not re-add IPs, got %d new allows", len(eng.allowed))
	}
	_ = firstCount
}

func TestDynDNSResolverInfraUpdateDoesNotDependOnAllowSuccess(t *testing.T) {
	allow := &rejectingAllowEngine{}
	infra := &recordingInfraEngine{}
	d := NewDynDNSResolver([]string{"panel.example.net"}, allow)
	d.RegisterInfraHost("panel.example.net")
	d.SetInfraEngine(infra)
	d.lookupFn = func(_ context.Context, host string) ([]string, error) {
		return []string{"198.51.100.70"}, nil
	}

	d.resolveAll()

	if len(infra.updates) != 1 {
		t.Fatalf("expected one infra update, got %d (%+v)", len(infra.updates), infra.updates)
	}
	if infra.updates[0].host != "panel.example.net" {
		t.Fatalf("host = %q, want panel.example.net", infra.updates[0].host)
	}
	if len(infra.updates[0].ips) != 1 || infra.updates[0].ips[0] != "198.51.100.70" {
		t.Fatalf("ips = %v, want [198.51.100.70]", infra.updates[0].ips)
	}

	d.mu.Lock()
	resolved := append([]string(nil), d.resolved["panel.example.net"]...)
	d.mu.Unlock()
	if len(resolved) != 0 {
		t.Fatalf("failed allow should not mark IP as resolved for retry, got %v", resolved)
	}
}

func TestDynDNSResolverRunStops(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	stopCh := make(chan struct{})
	close(stopCh) // close immediately
	d.Run(stopCh) // should return immediately
}

func TestDynDNSResolverRunClosedStopSkipsInitialLookup(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"panel.example.net"}, eng)

	calls := 0
	d.lookupFn = func(_ context.Context, _ string) ([]string, error) {
		calls++
		return []string{"203.0.113.10"}, nil
	}

	stopCh := make(chan struct{})
	close(stopCh)
	d.Run(stopCh)

	if calls != 0 {
		t.Fatalf("lookupFn called %d times after stopCh was already closed", calls)
	}
}

// A hung DNS server must not block the tick longer than the tick's
// context deadline. Without ctx propagation, a stuck LookupHost on one
// host can hold the tick until Go's resolver gives up (typically 30s),
// stacking the next 5-minute tick on top.
func TestDynDNSResolver_TickRespectsContextCancellation(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"slow.example.net"}, eng)

	started := make(chan struct{})
	d.lookupFn = func(ctx context.Context, _ string) ([]string, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.tickOnce(ctx)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookupFn was not called within 1s")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tickOnce did not exit within 1s after ctx cancel")
	}
}

func TestDynDNSResolver_CanceledLookupDoesNotRecordFailure(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"panel.example.net"}, eng)
	d.gracePeriod = time.Millisecond
	d.markLastSuccess("panel.example.net")

	findingCount := 0
	d.SetFindingSink(func(_ string) {
		findingCount++
	})

	time.Sleep(2 * time.Millisecond)

	started := make(chan struct{})
	d.lookupFn = func(ctx context.Context, _ string) ([]string, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.tickOnce(ctx)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookupFn was not called within 1s")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tickOnce did not exit within 1s after ctx cancel")
	}

	if got := d.UnresolvableHosts(); len(got) != 0 {
		t.Fatalf("canceled lookup should not mark host unresolvable, got %v", got)
	}
	if findingCount != 0 {
		t.Fatalf("canceled lookup emitted %d findings, want 0", findingCount)
	}
}
