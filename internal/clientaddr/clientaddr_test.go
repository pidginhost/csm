package clientaddr

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/netutil"
)

func mustParse(t *testing.T, entries ...string) Trusted {
	t.Helper()
	trusted, err := Parse(entries)
	if err != nil {
		t.Fatalf("Parse(%q): %v", entries, err)
	}
	return trusted
}

func TestResolveUsesTheDirectPeerWhenItIsNotTrusted(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	got, err := Resolve("198.51.100.7:443", "203.0.113.9", true, trusted)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := Result{Client: netip.MustParseAddr("198.51.100.7"), Peer: netip.MustParseAddr("198.51.100.7")}
	if got != want {
		t.Fatalf("Resolve = %+v, want %+v: an untrusted peer's forwarded header is client text", got, want)
	}
}

func TestResolveWalksPastTrustedHops(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	got, err := Resolve("192.0.2.10", "203.0.113.9, 198.51.100.4, 192.0.2.11", true, trusted)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := Result{Client: netip.MustParseAddr("198.51.100.4"), Peer: netip.MustParseAddr("192.0.2.10"), Chained: true}
	if got != want {
		t.Fatalf("Resolve = %+v, want %+v: the first untrusted hop from the right is the client", got, want)
	}
}

func TestResolveRefusesChainsItCannotTrust(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "127.0.0.1")
	hops := strings.TrimSuffix(strings.Repeat("192.0.2.11,", MaxHops), ",")
	cases := []struct {
		name     string
		peer     string
		xff      string
		complete bool
		want     error
	}{
		{"unusable peer", "proxy.example", "203.0.113.9", true, ErrPeer},
		{"zoned peer", "2001:db8::1%eth0", "", true, ErrPeer},
		{"trusted peer without a chain", "192.0.2.10", "", true, ErrNoChain},
		{"trusted peer with a blank chain", "192.0.2.10", "  ", true, ErrNoChain},
		{"bad token right of the client", "192.0.2.10", "203.0.113.9, bogus", true, ErrMalformed},
		{"empty hop", "192.0.2.10", "203.0.113.9,,192.0.2.11", true, ErrMalformed},
		{"zoned hop", "192.0.2.10", "2001:db8::1%eth0", true, ErrMalformed},
		{"hop with a port", "192.0.2.10", "203.0.113.9:4711", true, ErrMalformed},
		{"only trusted hops", "192.0.2.10", "192.0.2.11, 192.0.2.12", true, ErrAllTrusted},
		{"more than 32 hops", "192.0.2.10", "203.0.113.9," + hops, true, ErrOverlong},
		{"more than 4 KiB", "192.0.2.10", strings.Repeat(" ", MaxChainBytes) + "203.0.113.9", true, ErrOverlong},
		{"cut before its client", "192.0.2.10", "192.0.2.11", false, ErrTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.peer, tc.xff, tc.complete, trusted)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Resolve(%q, %q) = %+v, %v; want %v", tc.peer, tc.xff, got, err, tc.want)
			}
			if got != (Result{}) {
				t.Fatalf("refused Resolve returned %+v; a refusal names no address", got)
			}
		})
	}
}

// Whether a loopback client may act is the caller's rule: the resolver names
// it, and an address of this host is still never trusted as a proxy.
func TestResolveLeavesLoopbackClientsToTheCaller(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "127.0.0.1")
	got, err := Resolve("192.0.2.10", "127.0.0.2", true, trusted)
	if err != nil || got.Client != netip.MustParseAddr("127.0.0.2") || !got.Chained {
		t.Fatalf("loopback hop = %+v, %v; want chained client 127.0.0.2", got, err)
	}
	got, err = Resolve("127.0.0.1:443", "203.0.113.9", true, trusted)
	if err != nil || got.Client != netip.MustParseAddr("127.0.0.1") || got.Chained {
		t.Fatalf("listed loopback peer = %+v, %v; want the untrusted peer itself", got, err)
	}
}

func TestResolveAcceptsExactlyTheLimits(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	hops := "203.0.113.9," + strings.TrimSuffix(strings.Repeat("192.0.2.11,", MaxHops-1), ",")
	if _, err := Resolve("192.0.2.10", hops, true, trusted); err != nil {
		t.Fatalf("32 hops: %v", err)
	}
	padded := strings.Repeat(" ", MaxChainBytes-len("203.0.113.9")) + "203.0.113.9"
	if _, err := Resolve("192.0.2.10", padded, true, trusted); err != nil {
		t.Fatalf("4 KiB chain: %v", err)
	}
}

func TestResolveReadsTheKeptEndOfACutChain(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	got, err := Resolve("192.0.2.10", "203.0.113.9, 192.0.2.11", false, trusted)
	if err != nil {
		t.Fatalf("Resolve: %v; the hops a log cut lie left of the client the proxies appended", err)
	}
	if got.Client != netip.MustParseAddr("203.0.113.9") || !got.Chained {
		t.Fatalf("Resolve = %+v, want chained client 203.0.113.9", got)
	}
}

func TestResolveCanonicalizesMappedAddresses(t *testing.T) {
	trusted := mustParse(t, "192.0.2.10")
	got, err := Resolve("[::ffff:192.0.2.10]:443", "::ffff:203.0.113.9", true, trusted)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := Result{Client: netip.MustParseAddr("203.0.113.9"), Peer: netip.MustParseAddr("192.0.2.10"), Chained: true}
	if got != want {
		t.Fatalf("Resolve = %+v, want %+v", got, want)
	}
	got, err = Resolve("::ffff:198.51.100.7", "", true, trusted)
	if err != nil || got.Client != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("untrusted mapped peer = %+v, %v; want 198.51.100.7", got, err)
	}
}

func TestResolveAcceptsIPv6Chains(t *testing.T) {
	trusted := mustParse(t, "2001:db8::/64")
	got, err := Resolve("[2001:db8::10]:8443", "2001:db8:1::9, 2001:db8::11", true, trusted)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Client != netip.MustParseAddr("2001:db8:1::9") || !got.Chained {
		t.Fatalf("Resolve = %+v, want chained client 2001:db8:1::9", got)
	}
}

func TestTrustedNeverIncludesAnAddressOfThisHost(t *testing.T) {
	trusted := mustParse(t, "127.0.0.0/8", "::1", "192.0.2.10")
	for _, addr := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if trusted.Has(netip.MustParseAddr(addr)) {
			t.Fatalf("Has(%s) = true: any local account can connect from it and write the forwarded header", addr)
		}
	}
	if !trusted.Has(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("Has(192.0.2.10) = false, want true")
	}
}

func TestParseRejectsInvalidEntries(t *testing.T) {
	cases := map[string][]string{
		"not an address": {"192.0.2.0/24", "proxy.example"},
		"empty entry":    {" "},
		"default route":  {"0.0.0.0/0"},
		"IPv6 default":   {"::/0"},
		"zoned address":  {"2001:db8::1%eth0"},
		"bad mask":       {"192.0.2.0/33"},
	}
	for name, entries := range cases {
		if _, err := Parse(entries); err == nil {
			t.Errorf("%s: Parse(%q) = nil error", name, entries)
		}
	}
	_, err := Parse([]string{"192.0.2.0/24", "proxy.example"})
	if err == nil || !strings.Contains(err.Error(), "[1]") || !strings.Contains(err.Error(), "proxy.example") {
		t.Fatalf("Parse error = %v; want the entry index and text", err)
	}
}

func TestParseAcceptsAddressesAndRanges(t *testing.T) {
	trusted := mustParse(t, " 192.0.2.10 ", "198.51.100.0/24", "2001:db8::/48", "::ffff:203.0.113.0/120")
	for _, addr := range []string{"192.0.2.10", "198.51.100.200", "2001:db8:0:5::1", "203.0.113.77", "::ffff:198.51.100.1"} {
		if !trusted.Has(netip.MustParseAddr(addr)) {
			t.Errorf("Has(%s) = false, want true", addr)
		}
	}
	for _, addr := range []string{"192.0.2.11", "192.0.2.12", "2001:db8:1::1"} {
		if trusted.Has(netip.MustParseAddr(addr)) {
			t.Errorf("Has(%s) = true, want false", addr)
		}
	}
	if mustParse(t).Len() != 0 || trusted.Len() != 4 {
		t.Fatalf("Len = %d, want 4", trusted.Len())
	}
}

func TestResolveBehindProxyReadsTheChainOfAnAddresslessPeer(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	got, err := ResolveBehindProxy("198.51.100.7, 203.0.113.10, 192.0.2.2", trusted)
	if err != nil {
		t.Fatalf("ResolveBehindProxy: %v", err)
	}
	if want := (Result{Client: netip.MustParseAddr("203.0.113.10"), Chained: true}); got != want {
		t.Fatalf("ResolveBehindProxy = %+v, want %+v", got, want)
	}
	for xff, want := range map[string]error{"": ErrNoChain, "unknown": ErrMalformed, "192.0.2.2": ErrAllTrusted} {
		if got, err := ResolveBehindProxy(xff, trusted); !errors.Is(err, want) || got != (Result{}) {
			t.Errorf("ResolveBehindProxy(%q) = %+v, %v; want %v", xff, got, err, want)
		}
	}
}

func TestCoversIncludesListedAddressesOfThisHost(t *testing.T) {
	trusted := mustParse(t, "127.0.0.0/8", "192.0.2.10")
	for _, addr := range []string{"127.0.0.1", "::ffff:127.0.0.1", "192.0.2.10"} {
		if !trusted.Covers(netip.MustParseAddr(addr)) {
			t.Errorf("Covers(%s) = false; a listed address is never a client", addr)
		}
	}
	if trusted.Covers(netip.MustParseAddr("203.0.113.10")) {
		t.Error("Covers(203.0.113.10) = true")
	}
}

// Membership and header trust are separate questions: a listed address of
// this host, or any listed address while the interface set cannot be read,
// is covered but its header is never trusted.
func TestTrustedSeparatesMembershipFromHostTrust(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "2001:db8::/64")
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}, nil
	}))
	for _, addr := range []string{"192.0.2.10", "::ffff:192.0.2.10", "2001:db8::10"} {
		a := netip.MustParseAddr(addr)
		if !trusted.Covers(a) || trusted.Has(a) {
			t.Errorf("host address %s: Covers %v, Has %v; want covered and untrusted", addr, trusted.Covers(a), trusted.Has(a))
		}
	}
	if a := netip.MustParseAddr("192.0.2.11"); !trusted.Covers(a) || !trusted.Has(a) {
		t.Errorf("listed remote proxy: Covers %v, Has %v; want both", trusted.Covers(a), trusted.Has(a))
	}
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("no interface list") }))
	for _, addr := range []string{"192.0.2.11", "2001:db8::11"} {
		a := netip.MustParseAddr(addr)
		if !trusted.Covers(a) || trusted.Has(a) {
			t.Errorf("unread interface set, %s: Covers %v, Has %v; want covered and untrusted", addr, trusted.Covers(a), trusted.Has(a))
		}
	}
	if a := netip.MustParseAddr("203.0.113.9"); trusted.Covers(a) || trusted.Has(a) {
		t.Errorf("unlisted address: Covers %v, Has %v; want neither", trusted.Covers(a), trusted.Has(a))
	}
}

// A peer with unmatched brackets, or brackets around IPv4, is not a spelling
// a web server or socket writes; a bracketed IPv6 address with or without a
// port is.
func TestResolveRejectsBrokenPeerSyntax(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	for _, peer := range []string{"[192.0.2.10", "192.0.2.10]", "[192.0.2.10]", "[192.0.2.10]:443", "[2001:db8::10", "2001:db8::10]"} {
		if got, err := Resolve(peer, "203.0.113.9", true, trusted); !errors.Is(err, ErrPeer) || got != (Result{}) {
			t.Errorf("Resolve(%q) = %+v, %v; want ErrPeer", peer, got, err)
		}
	}
	for peer, want := range map[string]string{
		"192.0.2.10:443":     "203.0.113.9",
		"198.51.100.7":       "198.51.100.7",
		"2001:db8::10":       "2001:db8::10",
		"[2001:db8::10]":     "2001:db8::10",
		"[2001:db8::10]:443": "2001:db8::10",
	} {
		if got, err := Resolve(peer, "203.0.113.9", true, trusted); err != nil || got.Client.String() != want {
			t.Errorf("Resolve(%q) = %+v, %v; want client %s", peer, got, err, want)
		}
	}
}

// Only the hops the walk reads count toward the bound. Text a client writes
// left of its own address, however many short hops it holds, never decides
// whether it resolves; more than 32 hops read before a client does.
func TestResolveBoundsOnlyTheHopsItReads(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24")
	padded := strings.Repeat("::,", 90) + "203.0.113.9, 192.0.2.11"
	got, err := Resolve("192.0.2.10", padded, false, trusted)
	if err != nil || got.Client != netip.MustParseAddr("203.0.113.9") || !got.Chained {
		t.Fatalf("Resolve(90 padding hops) = %+v, %v; want chained client 203.0.113.9", got, err)
	}
	deep := "203.0.113.9," + strings.TrimSuffix(strings.Repeat("192.0.2.11,", MaxHops), ",")
	if got, err := Resolve("192.0.2.10", deep, true, trusted); !errors.Is(err, ErrOverlong) || got != (Result{}) {
		t.Fatalf("Resolve(32 trusted hops before the client) = %+v, %v; want ErrOverlong", got, err)
	}
}
