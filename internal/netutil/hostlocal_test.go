package netutil

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func pinHostLocal(t *testing.T, addrs ...string) {
	t.Helper()
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	})
}

func failHostLocal(t *testing.T) {
	t.Helper()
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) { return nil, errors.New("netlink down") })
}

func TestIsHostLocalStaticWithoutLookup(t *testing.T) {
	failHostLocal(t)
	for _, ip := range []string{"127.0.0.5", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"} {
		local, known := IsHostLocal(net.ParseIP(ip))
		if !local || !known {
			t.Errorf("IsHostLocal(%s) = (%v, %v), want (true, true)", ip, local, known)
		}
	}
}

func TestIsHostLocalInterfaceAddresses(t *testing.T) {
	pinHostLocal(t, "203.0.113.10", "fe80::1")
	for _, tc := range []struct {
		ip    string
		local bool
	}{
		{"203.0.113.10", true},
		{"::ffff:203.0.113.10", true},
		{"fe80::1", true},
		{"198.51.100.7", false},
	} {
		local, known := IsHostLocal(net.ParseIP(tc.ip))
		if local != tc.local || !known {
			t.Errorf("IsHostLocal(%s) = (%v, %v), want (%v, true)", tc.ip, local, known, tc.local)
		}
	}
}

func TestIsHostLocalUnknownWhenNeverRead(t *testing.T) {
	failHostLocal(t)
	local, known := IsHostLocal(net.ParseIP("198.51.100.7"))
	if local || known {
		t.Fatalf("IsHostLocal = (%v, %v), want (false, false)", local, known)
	}
	if local, known := IsHostLocal(nil); local || known {
		t.Fatalf("IsHostLocal(nil) = (%v, %v), want (false, false)", local, known)
	}
}

func TestIsHostLocalKeepsLastGoodSet(t *testing.T) {
	var fail atomic.Bool
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		if fail.Load() {
			return nil, errors.New("netlink down")
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); !local || !known {
		t.Fatalf("first read = (%v, %v), want (true, true)", local, known)
	}
	fail.Store(true)
	expireHostLocalCacheForTest(time.Now().Add(-2 * hostAddrCacheTTL))
	if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); !local || !known {
		t.Fatalf("after failed refresh = (%v, %v), want last good (true, true)", local, known)
	}
}

func TestIsHostLocalRefreshesAfterTTL(t *testing.T) {
	var second atomic.Bool
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		if second.Load() {
			return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.11")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); local || !known {
		t.Fatalf("before add = (%v, %v), want (false, true)", local, known)
	}
	second.Store(true)
	if local, _ := IsHostLocal(net.ParseIP("203.0.113.11")); local {
		t.Fatal("cache refreshed before its TTL")
	}
	expireHostLocalCacheForTest(time.Now().Add(-2 * hostAddrCacheTTL))
	if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); !local || !known {
		t.Fatalf("after TTL = (%v, %v), want (true, true)", local, known)
	}
}

func TestHostLocalProxyEntry(t *testing.T) {
	pinHostLocal(t, "203.0.113.10", "fe80::1")
	for _, tc := range []struct {
		entries        []string
		entry, covered string
	}{
		{[]string{"198.51.100.7"}, "", ""},
		{[]string{"127.0.0.1"}, "127.0.0.1", "127.0.0.0/8"},
		{[]string{"::1"}, "::1", "::1"},
		{[]string{"198.51.100.7", "203.0.113.0/24"}, "203.0.113.0/24", "203.0.113.10"},
		{[]string{"0.0.0.0/0"}, "0.0.0.0/0", "127.0.0.0/8"},
		{[]string{"::/0"}, "::/0", "::1"},
		{[]string{"::ffff:127.0.0.1"}, "::ffff:127.0.0.1", "127.0.0.0/8"},
		{[]string{"::ffff:0:0/96"}, "::ffff:0:0/96", "127.0.0.0/8"},
		{[]string{"126.0.0.0/7"}, "126.0.0.0/7", "127.0.0.0/8"},
		{[]string{"0.0.0.0"}, "0.0.0.0", "0.0.0.0"},
		{[]string{"fe80::/10"}, "fe80::/10", "fe80::1"},
		{[]string{" 203.0.113.10 "}, "203.0.113.10", "203.0.113.10"},
		{[]string{"", " ", "garbage", "192.0.2.0/99"}, "", ""},
	} {
		entry, covered, err := HostLocalProxyEntry(tc.entries)
		if err != nil {
			t.Errorf("%v: unexpected error %v", tc.entries, err)
			continue
		}
		if entry != tc.entry || covered != tc.covered {
			t.Errorf("%v: got (%q, %q), want (%q, %q)", tc.entries, entry, covered, tc.entry, tc.covered)
		}
	}
}

func TestHostLocalProxyEntryLookupFailure(t *testing.T) {
	failHostLocal(t)
	if _, _, err := HostLocalProxyEntry([]string{"198.51.100.7"}); err == nil {
		t.Fatal("lookup failure with a remote entry: want error")
	}
	entry, covered, err := HostLocalProxyEntry([]string{"198.51.100.7", "127.0.0.1"})
	if err != nil || entry != "127.0.0.1" || covered != "127.0.0.0/8" {
		t.Fatalf("static hit = (%q, %q, %v), want loopback without lookup", entry, covered, err)
	}
	if entry, _, err := HostLocalProxyEntry(nil); entry != "" || err != nil {
		t.Fatalf("no entries = (%q, %v), want nothing", entry, err)
	}
	if entry, _, err := HostLocalProxyEntry([]string{"garbage"}); entry != "" || err != nil {
		t.Fatalf("unparseable only = (%q, %v), want nothing and no lookup", entry, err)
	}
}
