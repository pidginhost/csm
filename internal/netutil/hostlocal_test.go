package netutil

import (
	"errors"
	"net"
	"strconv"
	"sync"
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
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		t.Error("static addresses must not need an interface lookup")
		return nil, errors.New("unexpected lookup")
	})
	for _, ip := range []string{"127.0.0.5", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::ffff:0.0.0.0", "::"} {
		local, known := IsHostLocal(net.ParseIP(ip))
		if !local || !known {
			t.Errorf("IsHostLocal(%s) = (%v, %v), want (true, true)", ip, local, known)
		}
	}
}

func TestIsHostLocalInterfaceAddresses(t *testing.T) {
	pinHostLocal(t, "203.0.113.10", "fe80::1", "2001:db8::1")
	for _, tc := range []struct {
		ip    string
		local bool
	}{
		{"203.0.113.10", true},
		{"::ffff:203.0.113.10", true},
		{"fe80::1", true},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
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
	if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); local || !known {
		t.Fatalf("before TTL = (%v, %v), want cached (false, true)", local, known)
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
		{[]string{"127.0.0.1/7"}, "127.0.0.1/7", "127.0.0.0/8"},
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

func TestHostLocalProxyEntryMappedPrefixes(t *testing.T) {
	// Even a mapped CIDR shorter than /96 contains mapped loopback. It
	// must be rejected without relying on a successful interface lookup.
	for _, lookupFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(lookupFails), func(t *testing.T) {
			if lookupFails {
				failHostLocal(t)
			} else {
				pinHostLocal(t)
			}
			for bits := 0; bits <= 128; bits++ {
				raw := "::ffff:127.0.0.5/" + strconv.Itoa(bits)
				entry, covered, err := HostLocalProxyEntry([]string{raw})
				wantCovered := "127.0.0.0/8"
				if bits <= 80 {
					wantCovered = "::1"
				}
				if err != nil || entry != raw || covered != wantCovered {
					t.Errorf("%s: got (%q, %q, %v), want (%q, %q, nil)", raw, entry, covered, err, raw, wantCovered)
				}
			}
		})
	}
}

func TestHostLocalProxyEntryInterfaceForms(t *testing.T) {
	pinHostLocal(t, "::ffff:203.0.113.10", "2001:db8::1", "fe80::1")
	for _, tc := range []struct {
		entry, covered string
	}{
		{"203.0.113.10/32", "203.0.113.10"},
		{"::ffff:203.0.113.10", "203.0.113.10"},
		{"::ffff:203.0.113.10/128", "203.0.113.10"},
		{"::ffff:203.0.113.0/120", "203.0.113.10"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::/32", "2001:db8::1"},
		{"fe80::1", "fe80::1"},
		{"fe80::/10", "fe80::1"},
		{"::ffff:0.0.0.0/128", "0.0.0.0"},
		{"::ffff:198.51.100.0/120", ""},
		{"2001:db8:1::/48", ""},
	} {
		entry, covered, err := HostLocalProxyEntry([]string{tc.entry})
		wantEntry := tc.entry
		if tc.covered == "" {
			wantEntry = ""
		}
		if err != nil || entry != wantEntry || covered != tc.covered {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, nil)", tc.entry, entry, covered, err, wantEntry, tc.covered)
		}
	}
}

func TestHostLocalProxyEntryDoesNotUseStaleCache(t *testing.T) {
	wantErr := errors.New("interface lookup failed")
	var fail bool
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		if fail {
			return nil, wantErr
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); !local || !known {
		t.Fatalf("initial read = (%v, %v), want (true, true)", local, known)
	}
	fail = true
	entry, covered, err := HostLocalProxyEntry([]string{"203.0.113.10"})
	if entry != "" || covered != "" || !errors.Is(err, wantErr) {
		t.Fatalf("fresh lookup = (%q, %q, %v), want empty result and lookup error", entry, covered, err)
	}
}

func TestIsHostLocalLookupReplacementResetsCache(t *testing.T) {
	pinHostLocal(t, "203.0.113.10")
	if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); !local || !known {
		t.Fatalf("initial read = (%v, %v), want (true, true)", local, known)
	}
	restore := SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, errors.New("replacement failed")
	})
	defer restore()
	if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); local || known {
		t.Fatalf("replacement read = (%v, %v), want (false, false)", local, known)
	}
}

func TestIsHostLocalDiscardsReplacedLookup(t *testing.T) {
	for _, populateReplacement := range []bool{false, true} {
		t.Run(strconv.FormatBool(populateReplacement), func(t *testing.T) {
			SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
				if !hostAddrMu.TryLock() {
					t.Error("lookup called while holding the cache mutex")
					return nil, errors.New("cache locked")
				}
				hostAddrMu.Unlock()
				SetHostAddressLookup(func() ([]net.IP, error) {
					return []net.IP{net.ParseIP("203.0.113.11")}, nil
				})
				if populateReplacement {
					if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); !local || !known {
						t.Errorf("replacement read = (%v, %v), want (true, true)", local, known)
					}
				}
				return []net.IP{net.ParseIP("203.0.113.10")}, nil
			})
			if local, known := IsHostLocal(net.ParseIP("203.0.113.10")); local || known != populateReplacement {
				t.Errorf("obsolete read = (%v, %v), want (false, %v)", local, known, populateReplacement)
			}
			if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); !local || !known {
				t.Errorf("replacement address = (%v, %v), want (true, true)", local, known)
			}
		})
	}
}

func TestIsHostLocalConcurrentRefreshKeepsNewerSet(t *testing.T) {
	for _, expireNewer := range []bool{false, true} {
		t.Run(strconv.FormatBool(expireNewer), func(t *testing.T) {
			testHostLocalConcurrentRefresh(t, expireNewer)
		})
	}
}

func testHostLocalConcurrentRefresh(t *testing.T, expireNewer bool) {
	t.Helper()
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var calls atomic.Int32
	SetHostAddressLookupForTest(t, func() ([]net.IP, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.11")}, nil
	})
	done := make(chan struct{})
	var got [2]bool
	go func() {
		local, known := IsHostLocal(net.ParseIP("203.0.113.11"))
		got = [2]bool{local, known}
		close(done)
	}()
	t.Cleanup(func() {
		unblock()
		<-done
	})
	<-started
	if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); !local || !known {
		t.Fatalf("newer read = (%v, %v), want (true, true)", local, known)
	}
	if expireNewer {
		expireHostLocalCacheForTest(time.Now().Add(-2 * hostAddrCacheTTL))
	}
	unblock()
	<-done
	if got != [2]bool{true, true} {
		t.Errorf("older read = %v, want [true true] from newer set", got)
	}
	if local, known := IsHostLocal(net.ParseIP("203.0.113.11")); !local || !known {
		t.Errorf("cached read = (%v, %v), want newer set (true, true)", local, known)
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
