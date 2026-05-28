//go:build linux

package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEngineUpdateInfraResolved_StoresAndBlocks(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.5", "198.51.100.6"})

	host, ok := e.infraIPResolvedHostLocked("198.51.100.5")
	if !ok || host != "panel.example.net" {
		t.Fatalf("infraResolved lookup miss: host=%q ok=%v", host, ok)
	}
}

func TestEngineUpdateInfraResolved_ReplacesPriorIPs(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.5"})
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.7"})

	if _, ok := e.infraIPResolvedHostLocked("198.51.100.5"); ok {
		t.Error("prior IP not evicted after re-resolve")
	}
	if _, ok := e.infraIPResolvedHostLocked("198.51.100.7"); !ok {
		t.Error("new IP not stored after re-resolve")
	}
}

// X18 regression: UpdateInfraResolved canonicalizes IPs via net.ParseIP
// before storing them, so a lookup by an IPv4-mapped-IPv6 form or an
// uncanonical IPv6 must still match the stored canonical address. Without
// the normalization on lookup, a caller passing "::ffff:198.51.100.5"
// bypasses the infra block guard for the same numeric address.
func TestEngineInfraIPResolvedHostLocked_NormalizesLookupIP(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{
		"198.51.100.5",
		"2001:DB8::1",
	})

	cases := []string{
		"::ffff:198.51.100.5",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::1",
	}
	for _, lookup := range cases {
		if _, ok := e.infraIPResolvedHostLocked(lookup); !ok {
			t.Errorf("infraIPResolvedHostLocked(%q) returned ok=false; canonical IPs are stored", lookup)
		}
	}
}

func TestEngineDropInfraResolved_ClearsHost(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.8"})
	e.DropInfraResolved("panel.example.net")

	if _, ok := e.infraIPResolvedHostLocked("198.51.100.8"); ok {
		t.Error("infra IP not cleared after DropInfraResolved")
	}
}

// TestBlockIPOutcome_RefusesResolvedInfraIP: an IP that is not in the
// static cfg.InfraIPs literal list but is the current resolution of an
// infra hostname must still be refused. This is the failure mode the
// audit flagged: hostnames in infra_ips: yaml were silently dropped
// from the lockout guard because the engine never re-resolved them.
func TestBlockIPOutcome_RefusesResolvedInfraIP(t *testing.T) {
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true},
		statePath:     t.TempDir(),
		dryRunEnabled: func() bool { return false },
	}
	e.UpdateInfraResolved("panel.example.net", []string{"198.51.100.99"})

	outcome, err := e.BlockIPOutcome("198.51.100.99", "test", time.Hour)
	if err == nil {
		t.Fatalf("expected infra refusal, got outcome=%q err=nil", outcome)
	}
	if !strings.Contains(err.Error(), "infra IP") {
		t.Errorf("error should mention infra IP, got %v", err)
	}
	if outcome != BlockOutcomeNoop {
		t.Errorf("expected BlockOutcomeNoop, got %q", outcome)
	}
}

// TestDynDNSResolver_RoutesInfraHosts: when a host is registered as
// infra and an infra engine is wired, the resolver's successful
// resolution must call UpdateInfraResolved with the resolved IPs.
type fakeAllowEngine struct {
	allows  []string
	removes []string
}

func (f *fakeAllowEngine) AllowIP(ip, reason string) error {
	f.allows = append(f.allows, ip)
	return nil
}
func (f *fakeAllowEngine) RemoveAllowIPBySource(ip, source string) error {
	f.removes = append(f.removes, ip+":"+source)
	return nil
}

type fakeInfraEngine struct {
	updates []struct {
		host string
		ips  []string
	}
}

func (f *fakeInfraEngine) UpdateInfraResolved(host string, ips []string) {
	f.updates = append(f.updates, struct {
		host string
		ips  []string
	}{host, ips})
}
func (f *fakeInfraEngine) DropInfraResolved(host string) {
	f.updates = append(f.updates, struct {
		host string
		ips  []string
	}{host, nil})
}

func TestDynDNSResolver_RoutesInfraHosts(t *testing.T) {
	allow := &fakeAllowEngine{}
	infra := &fakeInfraEngine{}
	r := NewDynDNSResolver([]string{"panel.example.net"}, allow)
	r.RegisterInfraHost("panel.example.net")
	r.SetInfraEngine(infra)
	r.lookupFn = func(_ context.Context, host string) ([]string, error) {
		if host != "panel.example.net" {
			return nil, errors.New("unexpected host")
		}
		return []string{"198.51.100.50"}, nil
	}

	r.resolveAll()

	if len(infra.updates) != 1 {
		t.Fatalf("expected 1 infra update, got %d (%+v)", len(infra.updates), infra.updates)
	}
	if infra.updates[0].host != "panel.example.net" {
		t.Errorf("host = %q, want panel.example.net", infra.updates[0].host)
	}
	if len(infra.updates[0].ips) != 1 || infra.updates[0].ips[0] != "198.51.100.50" {
		t.Errorf("ips = %+v, want [198.51.100.50]", infra.updates[0].ips)
	}
}

func TestDynDNSResolver_SkipsInfraWhenHostNotRegistered(t *testing.T) {
	allow := &fakeAllowEngine{}
	infra := &fakeInfraEngine{}
	r := NewDynDNSResolver([]string{"backup.example.net"}, allow)
	r.SetInfraEngine(infra)
	r.lookupFn = func(_ context.Context, host string) ([]string, error) {
		return []string{"198.51.100.60"}, nil
	}

	r.resolveAll()

	if len(infra.updates) != 0 {
		t.Errorf("non-infra host should not call UpdateInfraResolved, got %+v", infra.updates)
	}
}
