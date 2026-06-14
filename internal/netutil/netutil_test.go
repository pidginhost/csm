package netutil

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	public := []string{
		"18.97.9.100",        // published PerplexityBot address
		"2606:4700:4700::64", // public IPv6
	}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = false, want true", s)
		}
	}

	nonPublic := []string{
		"10.0.0.1",     // private
		"192.168.1.1",  // private
		"0.1.2.3",      // "this network"
		"100.64.0.1",   // CGNAT
		"169.254.0.1",  // link-local
		"224.0.0.1",    // multicast
		"192.0.2.5",    // documentation (RFC 5737)
		"192.88.99.1",  // deprecated 6to4 relay anycast
		"198.51.100.5", // documentation
		"203.0.113.5",  // documentation
		"198.18.0.5",   // benchmarking
		"240.0.0.1",    // reserved
		"2001:db8::1",  // documentation (RFC 3849)
		"fe80::1",      // link-local
		"::1",          // loopback
	}
	for _, s := range nonPublic {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = true, want false", s)
		}
	}

	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}

func TestIPInAnyNet(t *testing.T) {
	_, n1, _ := net.ParseCIDR("203.0.113.0/24")
	_, n2, _ := net.ParseCIDR("198.51.100.0/24")
	nets := []*net.IPNet{n1, n2}

	if !IPInAnyNet(net.ParseIP("203.0.113.7"), nets) {
		t.Error("203.0.113.7 should be in the set")
	}
	if IPInAnyNet(net.ParseIP("192.0.2.7"), nets) {
		t.Error("192.0.2.7 should not be in the set")
	}
}

func TestParseCIDROrIP(t *testing.T) {
	if n := ParseCIDROrIP("203.0.113.0/24"); n == nil || n.String() != "203.0.113.0/24" {
		t.Errorf("ParseCIDROrIP(CIDR) = %v, want 203.0.113.0/24", n)
	}
	// A bare IPv4 becomes a /32.
	if n := ParseCIDROrIP("18.97.1.229"); n == nil || n.String() != "18.97.1.229/32" {
		t.Errorf("ParseCIDROrIP(IPv4) = %v, want /32", n)
	}
	// A bare IPv6 becomes a /128.
	if n := ParseCIDROrIP("2001:db8::1"); n == nil || n.String() != "2001:db8::1/128" {
		t.Errorf("ParseCIDROrIP(IPv6) = %v, want /128", n)
	}
	if n := ParseCIDROrIP("not-an-ip"); n != nil {
		t.Errorf("ParseCIDROrIP(garbage) = %v, want nil", n)
	}
}

// An IPv4-mapped IPv6 CIDR must normalize to its effective IPv4 prefix so
// Contains matches on the IPv4 form.
func TestNormalizeIPNet_IPv4Mapped(t *testing.T) {
	_, n, err := net.ParseCIDR("::ffff:203.0.113.0/120")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	got := NormalizeIPNet(n)
	if got == nil {
		t.Fatal("NormalizeIPNet returned nil")
	}
	if !got.Contains(net.ParseIP("203.0.113.7")) {
		t.Errorf("normalized %v should contain the effective IPv4 address", got)
	}
}

func TestNormalizeIPNetRejectsMalformedMasks(t *testing.T) {
	cases := []*net.IPNet{
		{IP: net.ParseIP("18.97.9.100"), Mask: net.IPMask{0xff, 0x00, 0xff, 0x00}},
		{
			IP: net.ParseIP("18.97.9.100"),
			Mask: net.IPMask{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00,
			},
		},
		{IP: net.ParseIP("2606:4700:4700::64"), Mask: net.IPMask{0xff, 0x00, 0xff, 0x00}},
	}
	for _, tc := range cases {
		if got := NormalizeIPNet(tc); got != nil {
			t.Errorf("NormalizeIPNet(%v) = %v, want nil", tc, got)
		}
	}
}
