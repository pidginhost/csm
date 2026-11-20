package checks

import (
	"net/netip"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// withWebPeers gives a test its own peer index and bound.
func withWebPeers(t *testing.T, maxClients int) {
	t.Helper()
	prevIndex, prevMax := webPeers, webPeerMaxClients
	webPeers = newWebPeerIndex()
	webPeerMaxClients = maxClients
	t.Cleanup(func() { webPeers, webPeerMaxClients = prevIndex, prevMax })
}

func TestParseWebPeerLine(t *testing.T) {
	at, vhost, peer, client, ok := ParseWebPeerLine("1795204579 site.example 203.0.113.5 203.0.113.5")
	if !ok || !at.Equal(time.Unix(1795204579, 0)) || vhost != "site.example" ||
		peer != netip.MustParseAddr("203.0.113.5") || client != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("parsed %v %q %v %v %v", at, vhost, peer, client, ok)
	}
	for _, line := range []string{
		"x site.example 203.0.113.5 203.0.113.5",
		"1795204579 site.example 203.0.113.5",
		"1795204579 site.example 203.0.113.5 203.0.113.5 extra",
		"1795204579 site.example peer.example 203.0.113.5",
		"1795204579 site.example 203.0.113.5 client.example",
		"1795204579 site.example fe80::1%eth0 203.0.113.5",
		"0 site.example 203.0.113.5 203.0.113.5",
		"",
	} {
		if _, _, _, _, ok := ParseWebPeerLine(line); ok {
			t.Errorf("ParseWebPeerLine(%q) accepted a malformed line", line)
		}
	}
}

func TestParseWebPeerLineCanonicalizes(t *testing.T) {
	for _, tc := range []struct{ line, peer, client string }{
		{"1795204579 site.example [2001:db8::5]:443 2001:db8::5", "2001:db8::5", "2001:db8::5"},
		{"1795204579 site.example 192.0.2.7:51234 ::ffff:192.0.2.7", "192.0.2.7", "192.0.2.7"},
		{"1795204579 site.example ::ffff:192.0.2.7 192.0.2.7", "192.0.2.7", "192.0.2.7"},
		{"1795204579 site.example 2001:0DB8::0005 2001:db8::5", "2001:db8::5", "2001:db8::5"},
	} {
		_, _, peer, client, ok := ParseWebPeerLine(tc.line)
		if !ok || peer.String() != tc.peer || client.String() != tc.client || peer != client {
			t.Errorf("ParseWebPeerLine(%q) = %v %v %v; want %s and %s, equal", tc.line, peer, client, ok, tc.peer, tc.client)
		}
	}
}

func TestWebPeerVerdictClasses(t *testing.T) {
	withWebPeers(t, 500000)
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.200"}
	t0 := time.Unix(1795200000, 0)
	direct, proxied, forged := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("192.0.2.9")
	if got := ObserveWebPeer(t0, direct, direct, cfg); got != PeerDirect {
		t.Fatalf("direct line classed %v", got)
	}
	if got := ObserveWebPeer(t0, netip.MustParseAddr("198.51.100.200"), proxied, cfg); got != PeerProxied {
		t.Fatalf("trusted proxy line classed %v", got)
	}
	if got := ObserveWebPeer(t0, netip.MustParseAddr("127.0.0.1"), forged, cfg); got != PeerForged {
		t.Fatalf("loopback line classed %v", got)
	}
	for client, want := range map[netip.Addr]PeerVerdict{direct: PeerDirect, proxied: PeerProxied, forged: PeerForged, netip.MustParseAddr("203.0.113.99"): PeerUnknown} {
		if got := WebPeerVerdict(client, t0.Add(time.Minute)); got != want {
			t.Errorf("WebPeerVerdict(%v) = %v, want %v", client, got, want)
		}
	}
	// A line older than the window says nothing about a later finding.
	if got := WebPeerVerdict(direct, t0.Add(time.Hour+time.Minute)); got != PeerUnknown {
		t.Errorf("a line over an hour old gave %v, want unknown", got)
	}
	// A finding may be minted a little before the line it rests on is read.
	if got := WebPeerVerdict(direct, t0.Add(-time.Minute)); got != PeerDirect {
		t.Errorf("a line within the clock skew gave %v, want direct", got)
	}
	if got := WebPeerVerdict(direct, t0.Add(-3*time.Minute)); got != PeerUnknown {
		t.Errorf("a line after the skew allowance gave %v, want unknown", got)
	}
	for v, s := range map[PeerVerdict]string{PeerUnknown: "unknown", PeerDirect: "direct", PeerProxied: "proxied", PeerForged: "forged"} {
		if v.String() != s {
			t.Errorf("%d.String() = %q, want %q", v, v.String(), s)
		}
	}
}

func TestWebPeerVerdictMixedIsProxied(t *testing.T) {
	withWebPeers(t, 500000)
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"198.51.100.200"}
	t0 := time.Unix(1795200000, 0)
	a, b := netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("203.0.113.21")
	ObserveWebPeer(t0, a, a, cfg)
	ObserveWebPeer(t0.Add(time.Minute), netip.MustParseAddr("198.51.100.200"), a, cfg)
	if got := WebPeerVerdict(a, t0.Add(2*time.Minute)); got != PeerProxied {
		t.Errorf("direct and proxied gave %v, want proxied", got)
	}
	ObserveWebPeer(t0, b, b, cfg)
	ObserveWebPeer(t0.Add(time.Minute), netip.MustParseAddr("203.0.113.250"), b, cfg)
	ObserveWebPeer(t0.Add(time.Minute), netip.MustParseAddr("198.51.100.200"), b, cfg)
	if got := WebPeerVerdict(b, t0.Add(2*time.Minute)); got != PeerForged {
		t.Errorf("direct, proxied and forged gave %v, want forged", got)
	}
}

func TestWebPeerIndexOverflowIsUnknown(t *testing.T) {
	withWebPeers(t, 2)
	cfg := &config.Config{}
	t0 := time.Unix(1795200000, 0)
	first := netip.MustParseAddr("203.0.113.30")
	for _, c := range []netip.Addr{first, netip.MustParseAddr("203.0.113.31"), netip.MustParseAddr("203.0.113.32")} {
		ObserveWebPeer(t0, c, c, cfg)
	}
	for _, at := range []time.Duration{0, time.Minute, time.Hour} {
		if got := WebPeerVerdict(first, t0.Add(at)); got != PeerUnknown {
			t.Errorf("after an overflow, verdict at +%v = %v, want unknown", at, got)
		}
	}
	later := t0.Add(time.Hour + 2*time.Minute)
	ObserveWebPeer(later, first, first, cfg)
	if got := WebPeerVerdict(first, later); got != PeerDirect {
		t.Errorf("a full window after the overflow, verdict = %v, want direct", got)
	}
}

// A web server writes a line when its request ends, stamped with the time
// it began, so lines arrive out of order. An earlier line still counts.
func TestWebPeerVerdictOutOfOrderLines(t *testing.T) {
	withWebPeers(t, 500000)
	cfg := &config.Config{}
	t0 := time.Unix(1795200000, 0)
	victim := netip.MustParseAddr("203.0.113.40")
	ObserveWebPeer(t0.Add(10*time.Minute), netip.MustParseAddr("127.0.0.1"), victim, cfg)
	ObserveWebPeer(t0, netip.MustParseAddr("127.0.0.1"), victim, cfg)
	ObserveWebPeer(t0, victim, victim, cfg)
	if got := WebPeerVerdict(victim, t0); got != PeerForged {
		t.Errorf("an earlier forged line read later gave %v, want forged", got)
	}
}
