package firewall

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNextIPv4(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	got := nextIP(ip)
	if !got.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("got %s, want 192.168.1.2", got)
	}
}

func TestNextIPv4Overflow(t *testing.T) {
	ip := net.ParseIP("192.168.1.255").To4()
	got := nextIP(ip)
	if !got.Equal(net.ParseIP("192.168.2.0")) {
		t.Errorf("got %s, want 192.168.2.0", got)
	}
}

func TestNextIPv4MappedAddress(t *testing.T) {
	ip := net.ParseIP("192.168.1.255")
	got := nextIP(ip)
	if !got.Equal(net.ParseIP("192.168.2.0").To4()) {
		t.Errorf("got %s, want 192.168.2.0", got)
	}
	if len(got) != net.IPv4len {
		t.Errorf("got length = %d, want %d", len(got), net.IPv4len)
	}
}

func TestNextIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	got := nextIP(ip)
	if !got.Equal(net.ParseIP("2001:db8::2")) {
		t.Errorf("got %s, want 2001:db8::2", got)
	}
}

// TestNextIPv4Broadcast: the all-ones IPv4 address has no successor.
// nextIP must clamp to 255.255.255.255 so an interval-set end marker
// never wraps to 0.0.0.0, which would silently widen the range to the
// entire IPv4 space.
func TestNextIPv4Broadcast(t *testing.T) {
	ip := net.ParseIP("255.255.255.255").To4()
	if got := nextIP(ip); !got.Equal(ip) {
		t.Errorf("nextIP(255.255.255.255) = %s, want 255.255.255.255", got)
	}
	got, ok := nextIPSafe(ip)
	if ok {
		t.Errorf("nextIPSafe(255.255.255.255) ok = true, want false (saturated)")
	}
	if !got.Equal(net.ParseIP("255.255.255.255").To4()) {
		t.Errorf("clamped result = %s, want 255.255.255.255", got)
	}
}

// TestNextIPv6AllOnes: same property for IPv6. nextIPSafe must clamp
// at the all-ones address rather than wrap to ::.
func TestNextIPv6AllOnes(t *testing.T) {
	ip := net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	if got := nextIP(ip); !got.Equal(ip) {
		t.Errorf("nextIP(all-ones IPv6) = %s, want %s", got, ip)
	}
	got, ok := nextIPSafe(ip)
	if ok {
		t.Errorf("nextIPSafe(all-ones IPv6) ok = true, want false (saturated)")
	}
	if !got.Equal(ip) {
		t.Errorf("clamped result = %s, want %s", got, ip)
	}
}

func TestLastIPInRangeIPv4(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	got := lastIPInRange(network)
	if !got.Equal(net.ParseIP("192.168.1.255").To4()) {
		t.Errorf("got %s, want 192.168.1.255", got)
	}
}

func TestLastIPInRangeSlash16(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/16")
	got := lastIPInRange(network)
	if !got.Equal(net.ParseIP("10.0.255.255").To4()) {
		t.Errorf("got %s, want 10.0.255.255", got)
	}
}

func TestLastIPInRangeNil(t *testing.T) {
	got := lastIPInRange(&net.IPNet{IP: nil, Mask: nil})
	if got != nil {
		t.Errorf("nil IP should return nil, got %s", got)
	}
}

func TestFileExistsFirewallTrue(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test")
	_ = os.WriteFile(f, []byte("x"), 0600)
	if !fileExistsFirewall(f) {
		t.Error("existing file should return true")
	}
}

func TestFileExistsFirewallFalse(t *testing.T) {
	if fileExistsFirewall(filepath.Join(t.TempDir(), "nope")) {
		t.Error("missing file should return false")
	}
}
