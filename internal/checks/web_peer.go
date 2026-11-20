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
	// webPeerRetention is how long a client outlives its newest line. A
	// finding is judged minutes after its lines while traffic keeps
	// arriving, so pruning keeps a second window: routine pruning then never
	// reaches a live verdict window, and the loss mark it leaves only covers
	// findings judged over a window late.
	webPeerRetention = 2 * webPeerWindow
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

// peerRun bounds observations of one class with no gap wider than a verdict
// window (including skew). Any verdict window overlapping it contains a line.
type peerRun struct{ first, last time.Time }

// add returns the latest discarded observation, if any. Disjoint runs cannot
// be joined: their empty gap could otherwise prove a client direct without data.
func (r *peerRun) add(at time.Time) (lostThrough time.Time) {
	span := webPeerWindow + webPeerSkew
	switch {
	case r.first.IsZero():
		r.first, r.last = at, at
	case at.After(r.last.Add(span)):
		lostThrough = r.last
		r.first, r.last = at, at
	case at.Before(r.first.Add(-span)):
		// Keep the newer run, but remember that older verdicts are incomplete.
		lostThrough = at
	case at.Before(r.first):
		r.first = at
	case at.After(r.last):
		r.last = at
	}
	return
}

// within reports whether the run overlaps [from, to].
func (r peerRun) within(from, to time.Time) bool {
	return !r.first.IsZero() && !r.first.After(to) && !r.last.Before(from)
}

type peerSeen struct {
	direct, proxied, forged peerRun
	lostThrough             time.Time
}

type webPeerIndex struct {
	mu      sync.Mutex
	clients map[netip.Addr]*peerSeen
	// lostThrough covers discarded clients, including pruning. Delayed
	// lines must not recreate a client as direct after its other classes vanish.
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
	peer, client = peer.Unmap(), client.Unmap()
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
			if x.newest.After(x.lostThrough) {
				x.lostThrough = x.newest
			}
			return
		}
		seen = &peerSeen{}
		x.clients[client] = seen
	}
	var lostThrough time.Time
	switch class {
	case PeerDirect:
		lostThrough = seen.direct.add(at)
	case PeerProxied:
		lostThrough = seen.proxied.add(at)
	default:
		lostThrough = seen.forged.add(at)
	}
	if lostThrough.After(seen.lostThrough) {
		seen.lostThrough = lostThrough
	}
}

// pruneLocked forgets clients no line named within the retention of the
// newest line.
func (x *webPeerIndex) pruneLocked() {
	cutoff := x.newest.Add(-webPeerRetention)
	for c, s := range x.clients {
		if s.direct.last.Before(cutoff) && s.proxied.last.Before(cutoff) && s.forged.last.Before(cutoff) {
			for _, at := range []time.Time{s.direct.last, s.proxied.last, s.forged.last, s.lostThrough} {
				if at.After(x.lostThrough) {
					x.lostThrough = at
				}
			}
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
	case !seen.lostThrough.IsZero() && !from.After(seen.lostThrough):
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

// webPeerDirect reports whether the peer log shows ip connected for itself
// around at.
func webPeerDirect(ip string, at time.Time) bool {
	client, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && WebPeerVerdict(client, at) == PeerDirect
}

// MarkWebPeerLoss records that peer log lines up to at may be missing: the
// reader started late, or the log was truncated or rotated. A verdict whose
// window reaches that point, or the newest line already read, is unknown.
func MarkWebPeerLoss(at time.Time) { webPeers.markLoss(at) }

func (x *webPeerIndex) markLoss(at time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.newest.After(at) {
		at = x.newest
	}
	if at.After(x.lostThrough) {
		x.lostThrough = at
	}
}

// ResetWebPeersForTest gives a test an empty peer index and returns the
// function that restores the previous one.
func ResetWebPeersForTest() func() {
	prev := webPeers
	webPeers = newWebPeerIndex()
	return func() { webPeers = prev }
}
