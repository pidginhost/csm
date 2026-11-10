package clientaddr

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// FuzzResolveNeverInjects checks the resolver's one promise: the address it
// names is the untrusted direct peer, or the first untrusted hop of a chain
// that only trusted proxies appended after it. Nothing a client writes left
// of that hop, and no trusted proxy, can become the client.
func FuzzResolveNeverInjects(f *testing.F) {
	for _, seed := range []struct {
		peer, xff string
		complete  bool
	}{
		{"192.0.2.10", "203.0.113.9, 198.51.100.4, 192.0.2.11", true},
		{"198.51.100.7:443", "203.0.113.9", true},
		{"192.0.2.10", "203.0.113.9, bogus", true},
		{"192.0.2.10", "192.0.2.11, 192.0.2.12", true},
		{"[::ffff:192.0.2.10]:443", "::ffff:203.0.113.9", true},
		{"[2001:db8::10]:8443", "2001:db8:1::9, 2001:db8::11", true},
		{"192.0.2.10", "203.0.113.9", false},
		{"192.0.2.10", "", true},
		{"\n192.0.2.10", "203.0.113.9", true},
		{"192.0.2.10:0443", "203.0.113.9", true},
		{"192.0.2.10", "203.0.113.9,\u00a0192.0.2.11", true},
		{"192.0.2.10", "203.0.113.9,192.0.2.11\r", true},
	} {
		f.Add(seed.peer, seed.xff, seed.complete)
	}
	trusted, err := Parse([]string{"192.0.2.0/24", "2001:db8::/64"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, peer, xff string, complete bool) {
		got, err := Resolve(peer, xff, complete, trusted)
		if err != nil {
			if got != (Result{}) {
				t.Fatalf("refusal %v returned %+v", err, got)
			}
			return
		}
		if !got.Client.IsValid() || got.Client.Is4In6() || got.Client.Zone() != "" {
			t.Fatalf("client %v is not a canonical usable address", got.Client)
		}
		if peer != strings.TrimSpace(peer) {
			t.Fatalf("resolved whitespace-padded peer %q", peer)
		}
		if ap, err := netip.ParseAddrPort(peer); err == nil {
			if peer[strings.LastIndexByte(peer, ':')+1:] != strconv.Itoa(int(ap.Port())) {
				t.Fatalf("resolved peer with a noncanonical port %q", peer)
			}
		}
		if trusted.Has(got.Client) {
			t.Fatalf("client %v is a trusted proxy", got.Client)
		}
		if !got.Chained {
			if got.Client != got.Peer || trusted.Has(got.Peer) {
				t.Fatalf("unchained result %+v must name the untrusted peer", got)
			}
			return
		}
		if !trusted.Has(got.Peer) || len(xff) > MaxChainBytes {
			t.Fatalf("chained result %+v from peer %q, %d bytes", got, peer, len(xff))
		}
		hops := strings.Split(xff, ",")
		// Right of the client only trusted proxies may appear; the client
		// is the first hop from the right that is not one, within the
		// bound on hops read.
		for i := len(hops) - 1; i >= 0; i-- {
			if len(hops)-i > MaxHops {
				t.Fatalf("chained result after reading more than %d hops", MaxHops)
			}
			hop, perr := netip.ParseAddr(strings.Trim(hops[i], " \t"))
			if perr != nil || hop.Zone() != "" {
				t.Fatalf("hop %q right of the client did not parse: %v", hops[i], perr)
			}
			hop = hop.Unmap()
			if trusted.Has(hop) {
				continue
			}
			if hop != got.Client {
				t.Fatalf("client %v, but the first untrusted hop from the right is %v", got.Client, hop)
			}
			return
		}
		t.Fatalf("client %v does not appear in chain %q", got.Client, xff)
	})
}
