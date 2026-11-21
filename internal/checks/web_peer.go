package checks

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
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
	// webPeerSettle is how long after a finding's line was read the web
	// server may still hold the peer line it wrote for the same request:
	// LiteSpeed flushes its logs about once a second.
	webPeerSettle = 2 * time.Second
	// webPeerDrainTimeout bounds one read of the peer log to its end.
	webPeerDrainTimeout = 5 * time.Second
)

var (
	webPeerDrainMu      sync.Mutex
	webPeerDrainVersion uint64
	webPeerDrain        func(timeout time.Duration) bool
	webPeerTrust        func() bool
	webPeerSleep        = time.Sleep
	webPeerClock        = time.Now
)

// SetWebPeerDrain registers the reader that brings the peer index to the end
// of the peer log before it returns, or reports false when it cannot; nil
// when the daemon reads no peer log.
func SetWebPeerDrain(drain func(timeout time.Duration) bool) {
	webPeerDrainMu.Lock()
	defer webPeerDrainMu.Unlock()
	webPeerDrain = drain
	webPeerDrainVersion++
}

// SetWebPeerTrust registers whether the daemon currently trusts the peer
// log it reads; nil when it reads none.
func SetWebPeerTrust(trust func() bool) {
	webPeerDrainMu.Lock()
	defer webPeerDrainMu.Unlock()
	webPeerTrust = trust
}

// WebPeerLogActive reports that the daemon reads a peer log and trusts it:
// an address it cannot verify is then refused for good.
func WebPeerLogActive() bool {
	webPeerDrainMu.Lock()
	drain, trust := webPeerDrain, webPeerTrust
	webPeerDrainMu.Unlock()
	return drain != nil && trust != nil && trust()
}

func currentWebPeerDrain() (func(time.Duration) bool, uint64) {
	webPeerDrainMu.Lock()
	defer webPeerDrainMu.Unlock()
	return webPeerDrain, webPeerDrainVersion
}

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
	case seen.direct.within(from, to) && !seen.direct.last.Before(at.Truncate(time.Second)):
		// Direct lines before the request cannot vouch for it: its own peer
		// line, or a later direct one, must have been read. Peer lines carry
		// whole seconds; error logs can stamp the same request finer.
		return PeerDirect
	}
	return PeerUnknown
}

// settledWebPeerVerdict is WebPeerVerdict for a finding whose line was read
// at seenAt. The web server writes a request's peer line with its access line
// but may flush it later, and the two logs are read on separate polls. So the
// peer log is read to its end first, and anything but a refusal is decided
// again after a read that starts a settle period after seenAt: a forged line
// still on its way must not be outvoted by the client's earlier direct lines.
func settledWebPeerVerdict(client netip.Addr, at, seenAt time.Time) PeerVerdict {
	started := webPeerClock()
	drain, version := currentWebPeerDrain()
	if drain != nil && !drain(webPeerDrainTimeout) {
		return PeerUnknown
	}
	v := drainedWebPeerVerdict(client, at, version)
	switch {
	case v == PeerForged || v == PeerProxied:
		return v
	case v == PeerUnknown && (rewrittenRefusalFinal(CurrentHTTPRewrite()) || WebPeerLogActive()):
		// The refusal is final whatever later lines say; waiting would only
		// hold the alert dispatcher. Elsewhere a forged line that arrives
		// late turns an unknown refusal the legacy path would act on into
		// a final one.
		return v
	case drain == nil || seenAt.IsZero() || seenAt.After(started):
		// An invalid read time cannot establish when the request's peer
		// line will be visible. Refuse without delaying each batch item.
		return PeerUnknown
	}
	deadline := seenAt.Add(webPeerSettle)
	if !started.Before(deadline) {
		return v
	}
	defer observeWebPeerSettle(time.Now())
	if wait := deadline.Sub(webPeerClock()); wait > 0 {
		webPeerSleep(wait)
	}
	// Even if the first drain took the entire wait, its EOF may predate
	// the flush. Only a read started after the deadline can prove direct.
	if !drain(webPeerDrainTimeout) {
		return PeerUnknown
	}
	return drainedWebPeerVerdict(client, at, version)
}

var (
	webPeerSettleOnce    sync.Once
	webPeerSettleSeconds *metrics.Histogram
)

// observeWebPeerSettle times a direct verdict's wait for the peer log.
func observeWebPeerSettle(start time.Time) {
	webPeerSettleOnce.Do(func() {
		webPeerSettleSeconds = metrics.NewHistogram("csm_web_peer_settle_seconds",
			"Time a direct web peer verdict waited for the web server to flush its peer log.",
			[]float64{.01, .1, .5, 1, 2, 3, 5})
		metrics.MustRegister("csm_web_peer_settle_seconds", webPeerSettleSeconds)
	})
	webPeerSettleSeconds.Observe(time.Since(start).Seconds())
}

// A replacement watcher has not been drained by this caller. Keep the
// registration stable through the verdict so an old reader cannot vouch
// for the new one, including a replacement during the settle wait.
func drainedWebPeerVerdict(client netip.Addr, at time.Time, version uint64) PeerVerdict {
	webPeerDrainMu.Lock()
	defer webPeerDrainMu.Unlock()
	if version != webPeerDrainVersion {
		return PeerUnknown
	}
	return WebPeerVerdict(client, at)
}

// webPeerDirect requires a settled read before a reputation sighting can
// become derived evidence and bypass HTTP verification at mint time.
func webPeerDirect(ip string, at, seenAt time.Time) bool {
	client, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && settledWebPeerVerdict(client, at, seenAt) == PeerDirect
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

// ResetWebPeersForTest gives a test an empty, complete peer index: reads of
// the log succeed at once and settle waits do not sleep. It returns the
// function that restores the previous state.
func ResetWebPeersForTest() func() {
	prevDrain, _ := currentWebPeerDrain()
	webPeerDrainMu.Lock()
	prevTrust := webPeerTrust
	webPeerDrainMu.Unlock()
	prev, prevSleep, prevClock := webPeers, webPeerSleep, webPeerClock
	webPeers = newWebPeerIndex()
	SetWebPeerDrain(func(time.Duration) bool { return true })
	webPeerSleep, webPeerClock = func(time.Duration) {}, time.Now
	return func() {
		webPeers = prev
		SetWebPeerDrain(prevDrain)
		SetWebPeerTrust(prevTrust)
		webPeerSleep, webPeerClock = prevSleep, prevClock
	}
}
