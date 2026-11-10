package clientaddr

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
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
// whether it resolves; needing more than 32 hops to reach a client does.
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

func TestResolveRejectsPeerWhitespace(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "2001:db8::/64")
	for _, peer := range []string{"192.0.2.10", "198.51.100.7:443", "[2001:db8::10]", "[::ffff:192.0.2.10]:443"} {
		for _, space := range []string{" ", "\t", "\r", "\n", "\v", "\f", "\u0085", "\u00a0", "\u2028"} {
			for _, input := range []string{space + peer, peer + space} {
				if got, err := Resolve(input, "203.0.113.9", true, trusted); !errors.Is(err, ErrPeer) || got != (Result{}) {
					t.Errorf("Resolve(%q) = %+v, %v; want ErrPeer", input, got, err)
				}
			}
		}
	}
}

func TestResolveRejectsNonWirePeerPorts(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "2001:db8::/64")
	for _, host := range []string{"192.0.2.10", "[2001:db8::10]", "[::ffff:192.0.2.10]"} {
		for _, port := range []string{"", "+443", "-1", "0443", "00", "65536", "https", "0x1bb", "4_43"} {
			peer := host + ":" + port
			if got, err := Resolve(peer, "203.0.113.9", true, trusted); !errors.Is(err, ErrPeer) || got != (Result{}) {
				t.Errorf("Resolve(%q) = %+v, %v; want ErrPeer", peer, got, err)
			}
		}
		for _, port := range []string{"0", "443", "65535"} {
			peer := host + ":" + port
			got, err := Resolve(peer, "203.0.113.9", true, trusted)
			if err != nil || got.Client != netip.MustParseAddr("203.0.113.9") || !got.Chained {
				t.Errorf("Resolve(%q) = %+v, %v; want chained client 203.0.113.9", peer, got, err)
			}
		}
	}
}

func TestResolveRefusesNonHTTPHopWhitespace(t *testing.T) {
	trusted := mustParse(t, "192.0.2.0/24", "2001:db8::/64")
	for _, hop := range []string{"192.0.2.11", "198.51.100.7", "2001:db8::11", "2001:db8:1::7"} {
		for _, space := range []string{"\r", "\n", "\v", "\f", "\u0085", "\u00a0", "\u2028"} {
			for _, token := range []string{space + hop, hop + space} {
				xff := "203.0.113.9," + token
				if got, err := Resolve("192.0.2.10", xff, true, trusted); !errors.Is(err, ErrMalformed) || got != (Result{}) {
					t.Errorf("Resolve chain %q = %+v, %v; want ErrMalformed", xff, got, err)
				}
			}
		}
	}
	got, err := Resolve("192.0.2.10", " \t203.0.113.9\t ,\t 192.0.2.11 \t", true, trusted)
	want := Result{Client: netip.MustParseAddr("203.0.113.9"), Peer: netip.MustParseAddr("192.0.2.10"), Chained: true}
	if err != nil || got != want {
		t.Fatalf("HTTP whitespace: Resolve = %+v, %v; want %+v", got, err, want)
	}
}

func TestParseRejectsMappedRangesCoveringAllIPv4(t *testing.T) {
	for bits := 0; bits <= 96; bits++ {
		entry := "::ffff:192.0.2.10/" + strconv.Itoa(bits)
		got, err := Parse([]string{"198.51.100.7", entry})
		if err == nil || got.Len() != 0 {
			t.Errorf("Parse(%q) = %v, %v; want no trust and an error", entry, got, err)
		} else if !strings.Contains(err.Error(), "[1]") || !strings.Contains(err.Error(), entry) {
			t.Errorf("Parse(%q) error = %v; want entry index and text", entry, err)
		}
	}
}

func TestParsePreservesNarrowMappedRanges(t *testing.T) {
	for _, tc := range []struct {
		entry   string
		inside  []string
		outside string
	}{
		{"::ffff:192.0.2.10/97", []string{"192.0.2.10", "203.0.113.9"}, "2001:db8::1"},
		{"::ffff:192.0.2.129/121", []string{"192.0.2.128", "192.0.2.255"}, "192.0.2.127"},
		{"::ffff:192.0.2.10/128", []string{"192.0.2.10"}, "192.0.2.11"},
		{"::ffff:192.0.2.10", []string{"192.0.2.10"}, "192.0.2.11"},
	} {
		trusted := mustParse(t, tc.entry)
		for _, ip := range tc.inside {
			for _, spelling := range []string{ip, "::ffff:" + ip} {
				if !trusted.Covers(netip.MustParseAddr(spelling)) {
					t.Errorf("%s does not cover %s", tc.entry, spelling)
				}
			}
		}
		if trusted.Covers(netip.MustParseAddr(tc.outside)) {
			t.Errorf("%s covers unrelated address %s", tc.entry, tc.outside)
		}
	}
}

// A running daemon skips an unusable entry on its own: the entries around it
// keep working, and each refusal names its index.
func TestParseUsableSkipsEachUnusableEntry(t *testing.T) {
	trusted, errs := ParseUsable([]string{"192.0.2.10", "", "proxy.example", "198.51.100.0/24"})
	if trusted.Len() != 2 {
		t.Fatalf("Len = %d, want the two readable entries kept", trusted.Len())
	}
	for _, addr := range []string{"192.0.2.10", "198.51.100.9"} {
		if !trusted.Covers(netip.MustParseAddr(addr)) {
			t.Fatalf("the readable entry covering %s was dropped", addr)
		}
	}
	if len(errs) != 2 || !strings.Contains(errs[0].Error(), `[1]: "" is empty`) || !strings.Contains(errs[1].Error(), `[2]: "proxy.example"`) {
		t.Fatalf("errs = %v, want each skipped entry named by index", errs)
	}
	got, err := Resolve("203.0.113.5", "198.51.100.9", true, trusted)
	if err != nil || got.Client != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("Resolve = %+v, %v; without a catch-all an unlisted peer's header stays client text", got, err)
	}
}

// A catch-all entry trusted every peer's forwarded header. It is never
// trusted, and a forwarded chain from a peer it covered names nobody: the
// operator put a proxy in front, so that peer is not a visitor either.
func TestRefusedCatchAllNamesNobodyBehindAForwardedChain(t *testing.T) {
	for _, tc := range []struct{ entry, peer, otherFamily string }{
		{"0.0.0.0/0", "203.0.113.5", "2001:db8::5"},
		{"::/0", "2001:db8::5", "203.0.113.5"},
		{"::ffff:0:0/96", "203.0.113.5", "2001:db8::5"},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			trusted, errs := ParseUsable([]string{tc.entry, "192.0.2.10"})
			if len(errs) != 1 || trusted.Len() != 1 || trusted.Covers(netip.MustParseAddr(tc.peer)) {
				t.Fatalf("ParseUsable kept %d entries, errs %v; want only the catch-all refused", trusted.Len(), errs)
			}
			if _, err := Resolve(tc.peer, "198.51.100.9", true, trusted); !errors.Is(err, ErrCatchAllChain) {
				t.Fatalf("Resolve with a chain: err = %v, want ErrCatchAllChain", err)
			}
			got, err := Resolve(tc.peer, " ", true, trusted)
			if err != nil || got.Client != netip.MustParseAddr(tc.peer) {
				t.Fatalf("Resolve without a chain = %+v, %v; want the peer as client", got, err)
			}
			got, err = Resolve(tc.otherFamily, "198.51.100.9", true, trusted)
			if err != nil || got.Client != netip.MustParseAddr(tc.otherFamily) {
				t.Fatalf("Resolve for a peer the catch-all never covered = %+v, %v; want that peer", got, err)
			}
		})
	}
}

// A broad mapped catch-all can cover native IPv6 peers too. Refusing it
// must not turn those shared transports into visitors.
func TestRefusedMappedCatchAllKeepsItsIPv6Coverage(t *testing.T) {
	for bits := 0; bits <= 96; bits++ {
		entry := "::ffff:192.0.2.10/" + strconv.Itoa(bits)
		t.Run(entry, func(t *testing.T) {
			trusted, errs := ParseUsable([]string{entry, "192.0.2.10"})
			if len(errs) != 1 || !errors.Is(errs[0], ErrCatchAllEntry) || trusted.Len() != 1 {
				t.Fatalf("ParseUsable = %+v, %v; want only the narrow entry kept", trusted, errs)
			}
			prefix := netip.MustParsePrefix(entry)
			for _, peer := range []string{"203.0.113.5", "::ffff:203.0.113.5", "2001:db8::5"} {
				addr := netip.MustParseAddr(peer).Unmap()
				got, err := Resolve(peer, "198.51.100.9", true, trusted)
				if addr.Is4() || prefix.Contains(addr) {
					if !errors.Is(err, ErrCatchAllChain) || got != (Result{}) {
						t.Errorf("Resolve(%s) = %+v, %v; want no client", peer, got, err)
					}
				} else if err != nil || got.Client != addr || got.Chained {
					t.Errorf("Resolve(%s) = %+v, %v; an uncovered peer is its own client", peer, got, err)
				}
				got, err = Resolve(peer, "", true, trusted)
				if err != nil || got.Client != addr || got.Chained {
					t.Errorf("direct Resolve(%s) = %+v, %v; want its peer", peer, got, err)
				}
			}
			got, err := Resolve("192.0.2.10", "198.51.100.9", true, trusted)
			if err != nil || got.Client.String() != "198.51.100.9" || !got.Chained {
				t.Fatalf("explicit proxy = %+v, %v; want its visitor", got, err)
			}
		})
	}
}

func TestRefusedCatchAllDoesNotTreatACutChainAsDirect(t *testing.T) {
	trusted, _ := ParseUsable([]string{"0.0.0.0/0"})
	for _, xff := range []string{"", " \t"} {
		if got, err := Resolve("203.0.113.5", xff, false, trusted); !errors.Is(err, ErrCatchAllChain) || got != (Result{}) {
			t.Errorf("cut chain %q = %+v, %v; want no client", xff, got, err)
		}
	}
}

// The legacy CIDR parser accepted zero-padded prefix lengths. They must
// still identify proxies, including catch-alls whose headers we refuse.
func TestLegacyPaddedProxyPrefixes(t *testing.T) {
	for _, tc := range []struct {
		entry, peer string
		catchAll    bool
	}{
		{"192.0.2.0/024", "192.0.2.10", false},
		{"2001:db8::/064", "2001:db8::10", false},
		{"::ffff:192.0.2.0/0120", "192.0.2.10", false},
		{"0.0.0.0/00", "192.0.2.10", true},
		{"::/00", "2001:db8::10", true},
		{"::ffff:192.0.2.0/096", "192.0.2.10", true},
		{"::ffff:192.0.2.0/080", "192.0.2.10", true},
		{"::ffff:192.0.2.0/00", "2001:db8::10", true},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			if _, _, err := net.ParseCIDR(tc.entry); err != nil {
				t.Fatalf("legacy parser did not accept entry: %v", err)
			}
			trusted, errs := ParseUsable([]string{tc.entry})
			got, err := Resolve(tc.peer, "198.51.100.9", true, trusted)
			if tc.catchAll {
				if len(errs) != 1 || !errors.Is(errs[0], ErrCatchAllEntry) || trusted.Len() != 0 {
					t.Fatalf("ParseUsable = %+v, %v; want a refused catch-all", trusted, errs)
				}
				if !errors.Is(err, ErrCatchAllChain) || got != (Result{}) {
					t.Fatalf("forwarded request = %+v, %v; want no client", got, err)
				}
				got, err = Resolve(tc.peer, "", true, trusted)
				if err != nil || got.Client.String() != tc.peer || got.Chained {
					t.Fatalf("direct request = %+v, %v; want the peer", got, err)
				}
			} else if len(errs) != 0 || trusted.Len() != 1 || err != nil || got.Client.String() != "198.51.100.9" || !got.Chained {
				t.Fatalf("usable proxy = %+v, %v (parse errors %v); want its visitor", got, err, errs)
			}
		})
	}
}
