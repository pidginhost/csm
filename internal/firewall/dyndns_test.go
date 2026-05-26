package firewall

import (
	"errors"
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
	d.lookupFn = func(host string) ([]string, error) {
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
