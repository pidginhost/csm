package checks

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// withWebPeers gives a test its own peer index and bound.
func withWebPeers(t *testing.T, maxClients int) {
	t.Helper()
	prevMax := webPeerMaxClients
	webPeerMaxClients = maxClients
	t.Cleanup(ResetWebPeersForTest())
	t.Cleanup(func() { webPeerMaxClients = prevMax })
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
		"1795204579 site.example 2001:db8::1%eth0 203.0.113.5",
		"0 site.example 203.0.113.5 203.0.113.5",
		"-1 site.example 203.0.113.5 203.0.113.5",
		"1795204579 site.example [2001:db8::5%eth0]:443 203.0.113.5",
		"1795204579 site.example 203.0.113.5 2001:db8::5%eth0",
		"1795204579 site.example 203.0.113.5:65536 203.0.113.5",
		"1795204579 site.example 203.0.113.5 203.0.113.5:443",
		"1795204579 site.example [2001:db8::5 2001:db8::5",
		"",
	} {
		if _, _, _, _, ok := ParseWebPeerLine(line); ok {
			t.Errorf("ParseWebPeerLine(%q) accepted a malformed line", line)
		}
	}
}

func TestParseWebPeerLineCanonicalizes(t *testing.T) {
	for _, tc := range []struct{ line, peer, client string }{
		{"1795204579 site.example [2001:db8::5] 2001:db8::5", "2001:db8::5", "2001:db8::5"},
		{"1795204579 site.example [::ffff:192.0.2.7]:443 192.0.2.7", "192.0.2.7", "192.0.2.7"},
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
	if got := ObserveWebPeer(t0, netip.MustParseAddr("198.51.100.9"), forged, cfg); got != PeerForged {
		t.Fatalf("untrusted peer line classed %v", got)
	}
	for client, want := range map[netip.Addr]PeerVerdict{direct: PeerDirect, proxied: PeerProxied, forged: PeerForged, netip.MustParseAddr("203.0.113.99"): PeerUnknown} {
		if got := WebPeerVerdict(client, t0); got != want {
			t.Errorf("WebPeerVerdict(%v) = %v, want %v", client, got, want)
		}
	}
	// A minute later only refusals carry over: a direct verdict needs the
	// finding's own line or a later direct one.
	for client, want := range map[netip.Addr]PeerVerdict{direct: PeerUnknown, proxied: PeerProxied, forged: PeerForged} {
		if got := WebPeerVerdict(client, t0.Add(time.Minute)); got != want {
			t.Errorf("a minute later WebPeerVerdict(%v) = %v, want %v", client, got, want)
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
	ObserveWebPeer(t0.Add(10*time.Minute), netip.MustParseAddr("198.51.100.9"), victim, cfg)
	ObserveWebPeer(t0, netip.MustParseAddr("198.51.100.9"), victim, cfg)
	ObserveWebPeer(t0, victim, victim, cfg)
	if got := WebPeerVerdict(victim, t0); got != PeerForged {
		t.Errorf("an earlier forged line read later gave %v, want forged", got)
	}
}

func TestWebPeerVerdictRunReplacement(t *testing.T) {
	for _, class := range []PeerVerdict{PeerProxied, PeerForged} {
		t.Run(class.String(), func(t *testing.T) {
			x := newWebPeerIndex()
			client := netip.MustParseAddr("203.0.113.40")
			t0 := time.Unix(1795200000, 0)
			x.observe(t0, client, class)
			x.observe(t0.Add(2*time.Hour), client, class)
			x.observe(t0, client, PeerDirect)
			if got := x.verdict(client, t0); got != class && got != PeerUnknown {
				t.Fatalf("replacing %v evidence allowed %v", class, got)
			}
			if got := x.verdict(client, t0.Add(2*time.Hour)); got != class {
				t.Fatalf("new run = %v, want %v", got, class)
			}
		})
	}
}

func TestWebPeerVerdictPrunedEvidence(t *testing.T) {
	x := newWebPeerIndex()
	client := netip.MustParseAddr("203.0.113.40")
	other := netip.MustParseAddr("203.0.113.41")
	t0 := time.Unix(1795200000, 0)
	x.observe(t0, client, PeerForged)
	for range webPeerPruneEvery - 1 {
		x.observe(t0.Add(3*time.Hour), other, PeerDirect)
	}
	if _, retained := x.clients[client]; retained {
		t.Fatal("expired client was not pruned")
	}
	x.observe(t0, client, PeerDirect)
	if got := x.verdict(client, t0); got != PeerUnknown {
		t.Fatalf("direct replay after pruning forged evidence = %v", got)
	}
	if got := x.verdict(other, t0.Add(3*time.Hour)); got != PeerDirect {
		t.Fatalf("pruning expired evidence tainted the current window: %v", got)
	}
}

func TestWebPeerVerdictOutOfOrderGap(t *testing.T) {
	for _, class := range []PeerVerdict{PeerDirect, PeerProxied, PeerForged} {
		t.Run(class.String(), func(t *testing.T) {
			x := newWebPeerIndex()
			client := netip.MustParseAddr("203.0.113.40")
			t0 := time.Unix(1795200000, 0)
			x.observe(t0.Add(3*time.Hour), client, class)
			x.observe(t0, client, class)
			if got := x.verdict(client, t0.Add(2*time.Hour)); got != PeerUnknown {
				t.Fatalf("window without any observations = %v", got)
			}
			if got := x.verdict(client, t0.Add(3*time.Hour)); got != class {
				t.Fatalf("old line displaced current evidence: %v", got)
			}
		})
	}
}

func TestObserveWebPeerCanonicalizes(t *testing.T) {
	for _, tc := range []struct {
		peer, client string
		want         PeerVerdict
	}{
		{"::ffff:192.0.2.7", "192.0.2.7", PeerDirect},
		{"192.0.2.7", "::ffff:192.0.2.7", PeerDirect},
		{"::ffff:192.0.2.7", "::ffff:192.0.2.7", PeerDirect},
		{"198.51.100.8", "::ffff:192.0.2.7", PeerForged},
	} {
		t.Run(tc.peer+"/"+tc.client, func(t *testing.T) {
			withWebPeers(t, 500000)
			t0 := time.Unix(1795200000, 0)
			peer, client := netip.MustParseAddr(tc.peer), netip.MustParseAddr(tc.client)
			if got := ObserveWebPeer(t0, peer, client, nil); got != tc.want {
				t.Fatalf("observation = %v, want %v", got, tc.want)
			}
			if got := WebPeerVerdict(client, t0); got != tc.want {
				t.Fatalf("lookup = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every non-unknown verdict must agree with the full, unbounded history.
// Unknown is permitted when bounded storage has discarded evidence.
func TestWebPeerVerdictMatchesHistory(t *testing.T) {
	type observation struct {
		at    time.Time
		class PeerVerdict
	}
	rng := rand.New(rand.NewPCG(1, 2))
	client := netip.MustParseAddr("203.0.113.40")
	t0 := time.Unix(1795200000, 0)
	for range 100 {
		x := newWebPeerIndex()
		var history []observation
		for range 30 {
			o := observation{t0.Add(time.Duration(rng.IntN(240)) * time.Minute), PeerVerdict(1 + rng.IntN(3))}
			x.observe(o.at, client, o.class)
			history = append(history, o)
			for minute := -5; minute <= 305; minute += 5 {
				at := t0.Add(time.Duration(minute) * time.Minute)
				want := PeerUnknown
				for _, h := range history {
					if !h.at.Before(at.Add(-webPeerWindow)) && !h.at.After(at.Add(webPeerSkew)) && h.class > want &&
						(h.class != PeerDirect || !h.at.Before(at.Truncate(time.Second))) {
						want = h.class
					}
				}
				if got := x.verdict(client, at); got != PeerUnknown && got != want {
					t.Fatalf("verdict at minute %d = %v, history says %v: %+v", minute, got, want, history)
				}
			}
		}
	}
}

func TestWebPeerVerdictConcurrent(t *testing.T) {
	x := newWebPeerIndex()
	client := netip.MustParseAddr("203.0.113.40")
	t0 := time.Unix(1795200000, 0)
	var wg sync.WaitGroup
	for _, class := range []PeerVerdict{PeerDirect, PeerProxied, PeerForged} {
		wg.Go(func() {
			for i := range 100 {
				x.observe(t0.Add(time.Duration(i)*time.Second), client, class)
				got := x.verdict(client, t0.Add(time.Duration(i)*time.Second))
				if got < class {
					t.Errorf("after observing %v, verdict = %v", class, got)
				}
			}
		})
	}
	wg.Wait()
	if got := x.verdict(client, t0.Add(2*time.Minute)); got != PeerForged {
		t.Fatalf("concurrent observations = %v, want forged", got)
	}
}

func TestWebPeerVerdictRunIncludesSkew(t *testing.T) {
	x := newWebPeerIndex()
	client := netip.MustParseAddr("203.0.113.40")
	t0 := time.Unix(1795200000, 0)
	x.observe(t0, client, PeerDirect)
	x.observe(t0.Add(webPeerSkew), client, PeerDirect)
	for _, at := range []time.Time{t0, t0.Add(webPeerSkew), t0.Add(time.Nanosecond)} {
		if got := x.verdict(client, at); got != PeerDirect {
			t.Errorf("continuous window coverage at %v = %v, want direct", at, got)
		}
	}
}

func TestParseWebPeerLineBound(t *testing.T) {
	line := "1795204579 site.example 203.0.113.5 203.0.113.5"
	line += strings.Repeat(" ", webPeerMaxLine-len(line))
	if _, _, _, _, ok := ParseWebPeerLine(line); !ok {
		t.Fatal("rejected a valid line at the length bound")
	}
	if _, _, _, _, ok := ParseWebPeerLine(line + " "); ok {
		t.Fatal("accepted a line over the length bound")
	}
}

func TestWebPeerVerdictKnownProxy(t *testing.T) {
	withWebPeers(t, 500000)
	previous := knownProxyPrefixes
	knownProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	t.Cleanup(func() { knownProxyPrefixes = previous })
	t0 := time.Unix(1795200000, 0)
	client := netip.MustParseAddr("203.0.113.40")
	if got := ObserveWebPeer(t0, netip.MustParseAddr("198.51.100.9"), client, nil); got != PeerProxied {
		t.Fatalf("known proxy observation = %v, want proxied", got)
	}
	if got := WebPeerVerdict(client, t0); got != PeerProxied {
		t.Fatalf("known proxy verdict = %v, want proxied", got)
	}
}

func TestWebPeerIndexOverflowOutOfOrder(t *testing.T) {
	withWebPeers(t, 2)
	t0 := time.Unix(1795200000, 0)
	clients := []netip.Addr{
		netip.MustParseAddr("203.0.113.30"),
		netip.MustParseAddr("203.0.113.31"),
		netip.MustParseAddr("203.0.113.32"),
	}
	newest := t0.Add(2 * time.Hour)
	webPeers.observe(newest, clients[0], PeerForged)
	webPeers.observe(t0, clients[1], PeerDirect)
	webPeers.observe(t0, clients[2], PeerDirect)
	for _, client := range clients {
		webPeers.observe(newest, client, PeerDirect)
		for _, at := range []time.Time{t0, newest, newest.Add(webPeerWindow)} {
			if got := WebPeerVerdict(client, at); got != PeerUnknown {
				t.Fatalf("overflow allowed %v for %v at %v", got, client, at)
			}
		}
		if len(webPeers.clients) > webPeerMaxClients {
			t.Fatal("client bound exceeded")
		}
	}
	later := newest.Add(webPeerWindow + time.Nanosecond)
	webPeers.observe(later, clients[0], PeerDirect)
	if got := WebPeerVerdict(clients[0], later); got != PeerDirect {
		t.Fatalf("after the lost evidence expires = %v, want direct", got)
	}
}

// Routine pruning on a busy host must not reach a live verdict window: a
// finding is judged minutes after its lines while traffic keeps arriving.
func TestWebPeerVerdictBusyIndexStaysUsable(t *testing.T) {
	x := newWebPeerIndex()
	t0 := time.Unix(1795200000, 0)
	for i := range 4000 {
		x.observe(t0.Add(time.Duration(i)*time.Second), netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)}), PeerDirect)
	}
	target := netip.MustParseAddr("203.0.113.50")
	x.observe(t0.Add(2*time.Hour), target, PeerDirect)
	other := netip.MustParseAddr("203.0.113.51")
	for x.observed%webPeerPruneEvery != 0 {
		x.observe(t0.Add(2*time.Hour+10*time.Minute), other, PeerDirect)
	}
	if got := x.verdict(target, t0.Add(2*time.Hour)); got != PeerDirect {
		t.Fatalf("a direct client judged ten minutes behind the newest line = %v, want direct", got)
	}
}

// A reader that started late or a log that was truncated or rotated may
// have lost lines: a verdict whose window reaches that point is unknown,
// and a later window is judged normally.
func TestMarkWebPeerLossMakesEarlierWindowsUnknown(t *testing.T) {
	restore := ResetWebPeersForTest()
	t.Cleanup(restore)
	t0 := time.Unix(1795200000, 0)
	client := netip.MustParseAddr("203.0.113.60")
	ObserveWebPeer(t0, client, client, &config.Config{})
	MarkWebPeerLoss(t0.Add(time.Minute))
	if got := WebPeerVerdict(client, t0); got != PeerUnknown {
		t.Fatalf("a window reaching the loss = %v, want unknown", got)
	}
	later := t0.Add(2 * time.Hour)
	ObserveWebPeer(later, client, client, &config.Config{})
	if got := WebPeerVerdict(client, later); got != PeerDirect {
		t.Fatalf("a window after the loss = %v, want direct", got)
	}
}

// Overflow while reading an old backlog must not undo a reader's newer loss.
func TestWebPeerOverflowPreservesReaderLoss(t *testing.T) {
	withWebPeers(t, 1)
	at := time.Unix(1795200000, 0)
	MarkWebPeerLoss(at)
	client := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("192.0.2.11")
	ObserveWebPeer(at.Add(-2*time.Hour), client, client, &config.Config{})
	ObserveWebPeer(at.Add(-2*time.Hour), other, other, &config.Config{})
	ObserveWebPeer(at, client, client, &config.Config{})
	if got := WebPeerVerdict(client, at); got != PeerUnknown {
		t.Fatalf("overflow rolled back loss: %v, want unknown", got)
	}
}

// A refusal needs no settle wait: later lines cannot turn forged or proxied
// into direct. Without a reader, or when the reader fails, nothing is direct.
func TestSettledPeerVerdictEdges(t *testing.T) {
	withWebPeers(t, 500000)
	cfg := &config.Config{}
	at := time.Unix(1795200000, 0)
	waits := 0
	webPeerSleep = func(time.Duration) { waits++ }
	webPeerClock = func() time.Time { return at }
	forged := netip.MustParseAddr("203.0.113.75")
	ObserveWebPeer(at, netip.MustParseAddr("127.0.0.1"), forged, cfg)
	if got := settledWebPeerVerdict(forged, at, at); got != PeerForged || waits != 0 {
		t.Fatalf("forged verdict = %v after %d waits, want forged without waiting", got, waits)
	}
	direct := netip.MustParseAddr("203.0.113.76")
	ObserveWebPeer(at, direct, direct, cfg)
	SetWebPeerDrain(nil)
	if got := settledWebPeerVerdict(direct, at, at); got != PeerUnknown {
		t.Fatalf("verdict without a reader = %v, want unknown", got)
	}
	SetWebPeerDrain(func(time.Duration) bool { return false })
	if got := settledWebPeerVerdict(direct, at, at); got != PeerUnknown {
		t.Fatalf("verdict after a failed read = %v, want unknown", got)
	}
	SetWebPeerDrain(func(time.Duration) bool { return true })
	settled := handoffSample(t, "csm_web_peer_settle_seconds_count")
	if got := settledWebPeerVerdict(direct, at, at); got != PeerDirect || waits != 1 {
		t.Fatalf("settled verdict = %v after %d waits, want direct after one wait", got, waits)
	}
	if got := handoffSample(t, "csm_web_peer_settle_seconds_count"); got != settled+1 {
		t.Fatalf("settle waits counted %v, want %v", got, settled+1)
	}
	// Where the refusal is final anyway, an unknown verdict does not hold
	// the alert dispatcher; where the legacy path would act on it, it waits
	// for a forged line that may still arrive.
	withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed})
	if got := settledWebPeerVerdict(netip.MustParseAddr("203.0.113.77"), at, at); got != PeerUnknown || waits != 1 {
		t.Fatalf("unknown verdict on LiteSpeed = %v after %d waits, want unknown without waiting", got, waits)
	}
	withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: platform.WSApache})
	if got := settledWebPeerVerdict(netip.MustParseAddr("203.0.113.77"), at, at); got != PeerUnknown || waits != 2 {
		t.Fatalf("unknown verdict on Apache = %v after %d waits, want unknown after waiting", got, waits)
	}
}

// A direct verdict needs the client seen connecting for itself at or after
// the finding's own request: earlier direct lines cannot vouch for a request
// whose peer line never arrived (log removed, disk full, server switched).
func TestWebPeerDirectNeedsTheRequestsOwnLine(t *testing.T) {
	withWebPeers(t, 500000)
	cfg := &config.Config{}
	at := time.Unix(1795200000, 0)
	c := netip.MustParseAddr("203.0.113.90")
	ObserveWebPeer(at.Add(-20*time.Minute), c, c, cfg)
	if got := WebPeerVerdict(c, at); got != PeerUnknown {
		t.Fatalf("only an earlier direct line = %v, want unknown", got)
	}
	ObserveWebPeer(at, c, c, cfg)
	if got := WebPeerVerdict(c, at); got != PeerDirect {
		t.Fatalf("with the request's own direct line = %v, want direct", got)
	}
}

// The request's own line counts at second precision: an error log can stamp
// the same request with a fraction of a second the peer log does not carry.
func TestWebPeerDirectOwnLineAtSecondPrecision(t *testing.T) {
	withWebPeers(t, 500000)
	at := time.Unix(1795200000, 0)
	c := netip.MustParseAddr("203.0.113.92")
	ObserveWebPeer(at, c, c, &config.Config{})
	if got := WebPeerVerdict(c, at.Add(250*time.Millisecond)); got != PeerDirect {
		t.Fatalf("own line within the same second = %v, want direct", got)
	}
	if got := WebPeerVerdict(c, at.Add(time.Second)); got != PeerUnknown {
		t.Fatalf("a request a second later = %v, want unknown", got)
	}
}

// A pair of direct lines must not fill a request's otherwise empty forward
// window, even though both lines fit in the broader refusal window.
func TestWebPeerDirectDoesNotBridgeRequestGap(t *testing.T) {
	x := newWebPeerIndex()
	at := time.Unix(1795200000, 0)
	client := netip.MustParseAddr("203.0.113.93")
	x.observe(at.Add(-time.Minute), client, PeerDirect)
	x.observe(at.Add(3*time.Minute), client, PeerDirect)
	if got := x.verdict(client, at); got != PeerUnknown {
		t.Fatalf("no direct line in the request window: got %v, want unknown", got)
	}
	if got := x.verdict(client, at.Add(3*time.Minute)); got != PeerDirect {
		t.Fatalf("the newest direct request: got %v, want direct", got)
	}
}
