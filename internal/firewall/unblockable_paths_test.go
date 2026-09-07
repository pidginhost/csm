//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
)

// The single-IP block path refuses non-routable addresses, but two other
// paths reach the blocked sets without going through it.
//
// subnetSafetyGuardLocked checks infra ranges and e.localAddrs, and
// localAddrGuardKey deliberately drops loopback from that set -- so a subnet
// containing loopback was not refused even though the single address was.
func TestSubnetSafetyGuardRefusesNonRoutableRanges(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	for _, cidr := range []string{
		"127.0.0.0/8",
		"127.0.0.1/32",
		"::1/128",
		"169.254.0.0/16",
		"fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		err = e.subnetSafetyGuardLocked(network)
		if err == nil {
			t.Errorf("subnetSafetyGuardLocked(%s) allowed a non-routable range", cidr)
			continue
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("subnetSafetyGuardLocked(%s) error = %q, want a refusal", cidr, err)
		}
	}
}

// A routable range must still be blockable, or subnet blocking stops working.
func TestSubnetSafetyGuardAllowsRoutableRange(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	_, network, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.subnetSafetyGuardLocked(network); err != nil {
		t.Errorf("subnetSafetyGuardLocked refused a routable range: %v", err)
	}
}

// PromoteToPermanentBlock deliberately bypasses the ordinary block path,
// because that path skips an already-blocked IP. It therefore also bypassed
// the address guard, so an entry that reached the set before the guard
// existed could still be promoted to permanent.
func TestPromoteToPermanentBlockRefusesNonRoutable(t *testing.T) {
	e := &Engine{}
	e.cfg = &FirewallConfig{}

	for _, ip := range []string{"127.0.0.1", "::1", "169.254.1.1"} {
		err := e.PromoteToPermanentBlock(ip, "test")
		if err == nil {
			t.Errorf("PromoteToPermanentBlock(%q) returned no error; a non-routable address was promotable", ip)
			continue
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("PromoteToPermanentBlock(%q) error = %q, want a refusal", ip, err)
		}
	}
}
