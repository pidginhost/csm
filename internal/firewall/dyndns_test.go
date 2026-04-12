package firewall

import (
	"testing"
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

func TestDynDNSResolverRunStops(t *testing.T) {
	eng := &mockEngine{}
	d := NewDynDNSResolver([]string{"localhost"}, eng)
	stopCh := make(chan struct{})
	close(stopCh) // close immediately
	d.Run(stopCh) // should return immediately
}
