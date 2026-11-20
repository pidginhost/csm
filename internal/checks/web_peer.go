package checks

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// PeerVerdict is what the web peer log says about the requests a client
// address made: whether the web server logged it for a direct peer, for a
// client behind a trusted proxy, or for a peer that chose it.
type PeerVerdict uint8

const (
	// PeerUnknown: no peer log line for the address in the window, or the
	// index lost lines in it.
	PeerUnknown PeerVerdict = iota
	// PeerDirect: every line logged the address for its own connection.
	PeerDirect
	// PeerProxied: a trusted proxy or a known CDN edge forwarded it.
	PeerProxied
	// PeerForged: another peer, one this host must not trust for a
	// forwarded address, made the web server log it.
	PeerForged
)

func (v PeerVerdict) String() string {
	switch v {
	case PeerDirect:
		return "direct"
	case PeerProxied:
		return "proxied"
	case PeerForged:
		return "forged"
	}
	return "unknown"
}

const (
	// webPeerWindow is how far back a verdict reads the peer log.
	webPeerWindow = time.Hour
	// webPeerSkew lets a finding be judged a little before the lines it
	// rests on were read.
	webPeerSkew = 2 * time.Minute
	// webPeerPruneEvery amortizes pruning over observations.
	webPeerPruneEvery = 4096
	// webPeerMaxLine bounds the line a parser reads.
	webPeerMaxLine = 512
)

// webPeerMaxClients bounds the distinct addresses one window holds.
var webPeerMaxClients = 500000

// ParseWebPeerLine reads one peer log line, "<unix seconds> <vhost> <peer>
// <client>": the connection's peer, with or without a port, and the client
// address the web server logged. Both come back canonical and unmapped.
func ParseWebPeerLine(line string) (at time.Time, vhost string, peer, client netip.Addr, ok bool) {
	if len(line) > webPeerMaxLine {
		return
	}
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return
	}
	secs, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || secs <= 0 {
		return
	}
	peer, okPeer := parseWebPeerAddr(fields[2], true)
	client, okClient := parseWebPeerAddr(fields[3], false)
	if !okPeer || !okClient {
		return time.Time{}, "", netip.Addr{}, netip.Addr{}, false
	}
	return time.Unix(secs, 0), fields[1], peer, client, true
}

// parseWebPeerAddr reads an address, with a port when withPort allows one.
func parseWebPeerAddr(s string, withPort bool) (netip.Addr, bool) {
	if withPort {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			s = ap.Addr().String()
		} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = s[1 : len(s)-1]
		}
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// peerRun is the first and last time one class of line named a client.
type peerRun struct{ first, last time.Time }

// add extends the run to at. Lines arrive out of order, so an earlier line
// moves the start back; a line over a window after the run starts anew.
func (r *peerRun) add(at time.Time) {
	switch {
	case r.first.IsZero() || at.After(r.last.Add(webPeerWindow)):
		r.first, r.last = at, at
	case at.Before(r.first):
		r.first = at
	case at.After(r.last):
		r.last = at
	}
}

// within reports whether the run overlaps [from, to].
func (r peerRun) within(from, to time.Time) bool {
	return !r.first.IsZero() && !r.first.After(to) && !r.last.Before(from)
}

type peerSeen struct{ direct, proxied, forged peerRun }

type webPeerIndex struct {
	mu      sync.Mutex
	clients map[netip.Addr]*peerSeen
	// lostThrough is the newest line time when the index last dropped
	// lines: a window that reaches it is unknown.
	lostThrough time.Time
	newest      time.Time
	observed    int
}

func newWebPeerIndex() *webPeerIndex {
	return &webPeerIndex{clients: make(map[netip.Addr]*peerSeen)}
}

var webPeers = newWebPeerIndex()

// ObserveWebPeer records one peer log line for client and returns its
// class: the same address is a direct peer; a trusted proxy or a known CDN
// edge forwarded a client behind it; any other peer chose the address.
func ObserveWebPeer(at time.Time, peer, client netip.Addr, cfg *config.Config) PeerVerdict {
	class := PeerForged
	switch {
	case peer == client:
		class = PeerDirect
	case IsTrustedProxy(peer.String(), cfg) || KnownProxyPeer(peer.String(), cfg):
		class = PeerProxied
	}
	webPeers.observe(at, client, class)
	return class
}

func (x *webPeerIndex) observe(at time.Time, client netip.Addr, class PeerVerdict) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if at.After(x.newest) {
		x.newest = at
	}
	x.observed++
	if x.observed%webPeerPruneEvery == 0 {
		x.pruneLocked()
	}
	seen := x.clients[client]
	if seen == nil {
		if len(x.clients) >= webPeerMaxClients {
			// Dropping one client could hide a forged line behind a
			// direct one: drop the whole window instead.
			x.clients = make(map[netip.Addr]*peerSeen)
			x.lostThrough = x.newest
			return
		}
		seen = &peerSeen{}
		x.clients[client] = seen
	}
	switch class {
	case PeerDirect:
		seen.direct.add(at)
	case PeerProxied:
		seen.proxied.add(at)
	default:
		seen.forged.add(at)
	}
}

// pruneLocked forgets clients no line named within a window of the newest.
func (x *webPeerIndex) pruneLocked() {
	cutoff := x.newest.Add(-webPeerWindow)
	for c, s := range x.clients {
		if s.direct.last.Before(cutoff) && s.proxied.last.Before(cutoff) && s.forged.last.Before(cutoff) {
			delete(x.clients, c)
		}
	}
}

// WebPeerVerdict is what the peer log says about client's requests in the
// hour before at, and the skew after it: forged over proxied over direct,
// and unknown without a line or when the index lost lines in that window.
func WebPeerVerdict(client netip.Addr, at time.Time) PeerVerdict {
	return webPeers.verdict(client.Unmap(), at)
}

func (x *webPeerIndex) verdict(client netip.Addr, at time.Time) PeerVerdict {
	x.mu.Lock()
	defer x.mu.Unlock()
	from, to := at.Add(-webPeerWindow), at.Add(webPeerSkew)
	if !x.lostThrough.IsZero() && !from.After(x.lostThrough) {
		return PeerUnknown
	}
	seen := x.clients[client]
	switch {
	case seen == nil:
		return PeerUnknown
	case seen.forged.within(from, to):
		return PeerForged
	case seen.proxied.within(from, to):
		return PeerProxied
	case seen.direct.within(from, to):
		return PeerDirect
	}
	return PeerUnknown
}
