package firewall

import (
	"reflect"
	"testing"
)

func TestEffectiveIPv6PortsUseExplicitListOrIPv4Fallback(t *testing.T) {
	if got := effectiveIPv6Ports([]int{25, 443}, []int{587}); !reflect.DeepEqual(got, []int{587}) {
		t.Fatalf("explicit IPv6 ports = %v, want [587]", got)
	}
	if got := effectiveIPv6Ports([]int{25, 443}, nil); !reflect.DeepEqual(got, []int{25, 443}) {
		t.Fatalf("fallback IPv6 ports = %v, want IPv4 list", got)
	}
}

func TestRestrictedOutputNeedsIPv4Bypass(t *testing.T) {
	// The bug: IPv6 egress restricted, no IPv4 egress ports configured. The
	// shared inet OUTPUT chain has a DROP policy, so without a bypass every new
	// IPv4 connection (DNS, HTTP, updates) is silently dropped.
	if !(&FirewallConfig{IPv6: true, TCP6Out: []int{443}}).restrictedOutputNeedsIPv4Bypass() {
		t.Error("IPv6-only egress config must bypass IPv4 egress, not drop it")
	}
	// IPv4 egress configured: it is managed, so it must not be bypassed.
	if (&FirewallConfig{IPv6: true, TCPOut: []int{443}}).restrictedOutputNeedsIPv4Bypass() {
		t.Error("configured IPv4 egress must stay restricted, not bypassed")
	}
	if (&FirewallConfig{UDPOut: []int{53}}).restrictedOutputNeedsIPv4Bypass() {
		t.Error("configured IPv4 UDP egress must stay restricted, not bypassed")
	}
}
