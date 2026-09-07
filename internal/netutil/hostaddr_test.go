package netutil

import (
	"net"
	"testing"
	"time"
)

func TestIsHostAddress(t *testing.T) {
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.10"),
			net.ParseIP("2001:db8::1"),
		}, nil
	})

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"own IPv4", "203.0.113.10", true},
		{"own IPv6", "2001:db8::1", true},
		{"own IPv6 non-canonical form", "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"own IPv4 as v4-mapped v6", "::ffff:203.0.113.10", true},
		{"foreign IPv4", "203.0.113.11", false},
		{"foreign IPv6", "2001:db8::2", false},
		{"empty", "", false},
		{"garbage", "not-an-ip", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHostAddress(tc.ip); got != tc.want {
				t.Errorf("IsHostAddress(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// Loopback is handled by callers that accept local traffic outright, and
// treating it as a host address here would let a check silently ignore
// findings that genuinely originated on the box.
func TestIsHostAddressIgnoresLoopbackAndLinkLocal(t *testing.T) {
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("169.254.1.1"),
			net.ParseIP("fe80::1"),
			net.ParseIP("203.0.113.10"),
		}, nil
	})

	for _, ip := range []string{"127.0.0.1", "::1", "169.254.1.1", "fe80::1"} {
		if IsHostAddress(ip) {
			t.Errorf("IsHostAddress(%q) = true, want false (loopback/link-local must not count)", ip)
		}
	}
	if !IsHostAddress("203.0.113.10") {
		t.Error("IsHostAddress(203.0.113.10) = false, want true")
	}
}

// A syscall failure must not turn every address into "the host", which would
// suppress real findings.
func TestIsHostAddressLookupErrorFailsOpen(t *testing.T) {
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		return nil, net.UnknownNetworkError("boom")
	})

	if IsHostAddress("203.0.113.10") {
		t.Error("IsHostAddress on lookup error = true, want false")
	}
}

func TestHostAddressesCachesBetweenCalls(t *testing.T) {
	var calls int
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})

	for i := 0; i < 5; i++ {
		IsHostAddress("203.0.113.10")
	}
	if calls != 1 {
		t.Errorf("lookup called %d times, want 1 (result must be cached)", calls)
	}
}

func TestHostAddressesRefreshesAfterTTL(t *testing.T) {
	var calls int
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})

	IsHostAddress("203.0.113.10")
	expireHostAddressCacheForTest(time.Now().Add(-2 * hostAddrCacheTTL))
	IsHostAddress("203.0.113.10")

	if calls != 2 {
		t.Errorf("lookup called %d times, want 2 (cache must expire)", calls)
	}
}
