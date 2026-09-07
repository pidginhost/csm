//go:build linux

package firewall

import (
	"net"
	"testing"
)

// The engine refuses to block an address bound to a local interface, but the
// set it checks against is built by localAddrGuardKey, which deliberately
// drops loopback and link-local. So the one address that can never be an
// attacker was the one address the guard did not cover, and a block of
// 127.0.0.1 was accepted rather than refused.
//
// Nothing broke in practice only because the input chain accepts "iifname lo"
// before reaching the blocked set -- so the entry sat there looking effective
// while doing nothing, and any logic keyed on blocked-set membership treated
// the host's own loopback as hostile.
func TestLocalAddrGuardKeyRejectsUnblockableAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1",
		"127.0.0.53",
		"::1",
		"169.254.1.1",
		"fe80::1",
		"0.0.0.0",
		"::",
		"not-an-ip",
	} {
		if _, ok := localAddrGuardKey(raw); ok {
			t.Errorf("localAddrGuardKey(%q) accepted an address that must never be blockable", raw)
		}
	}
}

// Routable addresses still key normally, so the existing guard behaviour for
// a host's own public address is unchanged.
func TestLocalAddrGuardKeyKeepsRoutableAddresses(t *testing.T) {
	for _, raw := range []string{"203.0.113.10", "2001:db8::1"} {
		key, ok := localAddrGuardKey(raw)
		if !ok {
			t.Errorf("localAddrGuardKey(%q) rejected a routable address", raw)
			continue
		}
		if key != net.ParseIP(raw).String() {
			t.Errorf("localAddrGuardKey(%q) = %q, want normalized form", raw, key)
		}
	}
}

// The block path itself must refuse loopback regardless of what the interface
// enumeration returned.
func TestIsUnblockableAddress(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "169.254.1.1", "fe80::1"} {
		if !isUnblockableAddress(raw) {
			t.Errorf("isUnblockableAddress(%q) = false, want true", raw)
		}
	}
	for _, raw := range []string{"198.51.100.7", "2001:db8::99"} {
		if isUnblockableAddress(raw) {
			t.Errorf("isUnblockableAddress(%q) = true, want false", raw)
		}
	}
}
