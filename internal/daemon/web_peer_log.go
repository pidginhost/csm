package daemon

import (
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integration/webserver"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/netutil"
)

// webPeerLogPath is the log the CSM snippet makes the web server write:
// "<unix seconds> <vhost> <peer> <client>" per request.
const webPeerLogPath = webserver.PeerLogFile

// webPeerLogMaxBytes is the size past which the daemon empties the peer log
// once it has read it all. Every truncation leaves an hour of unknown
// verdicts, so the cap keeps it rare on a busy host.
var webPeerLogMaxBytes int64 = 256 << 20

// webPeerAlertEvery is how often one vhost raises a forgery alert.
const webPeerAlertEvery = time.Hour

// Keep live entries on saturation: evicting one would let a busy tenant
// trigger repeated alerts for it. Peer classification is never suppressed.
const webPeerAlertMaxVhosts = 10000

// webPeerLog feeds the peer index and raises one forgery alert per vhost
// per hour: a tenant script can forge thousands of requests a minute.
type webPeerLog struct {
	mu        sync.Mutex
	alertedAt map[string]time.Time
	now       func() time.Time
	pruneAt   time.Time
	saturated bool
}

func newWebPeerLog() *webPeerLog {
	return &webPeerLog{alertedAt: make(map[string]time.Time), now: time.Now}
}

// spec is the watch of path: optional, emptied past the cap, every gap in
// what it read is a loss in the index, and verdicts can read it to its end.
func (p *webPeerLog) spec(path string) logWatchSpec {
	return logWatchSpec{
		name: "web_peer_log", path: path, handler: p.handle,
		optional: true, truncateAt: webPeerLogMaxBytes,
		reset:   func() { checks.MarkWebPeerLoss(time.Now()) },
		onWatch: func(w *LogWatcher) { checks.SetWebPeerDrain(w.Drain) },
	}
}

func (p *webPeerLog) handle(line string, cfg *config.Config) []alert.Finding {
	at, vhost, peer, client, ok := checks.ParseWebPeerLine(line)
	if !ok {
		checks.MarkWebPeerLoss(p.now())
		return nil
	}
	if checks.ObserveWebPeer(at, peer, client, cfg) != checks.PeerForged || !p.due(vhost, p.now()) {
		return nil
	}
	origin := "remote"
	if peer.IsLoopback() || netutil.IsHostAddress(peer.String()) {
		origin = "local"
	}
	return []alert.Finding{{
		Severity: alert.Critical,
		Check:    "http_client_forged",
		Message:  fmt.Sprintf("Web server %s logged a client address chosen by a %s peer", vhost, origin),
		Details: fmt.Sprintf("Peer: %s\nLogged client: %s\n"+
			"The web server applied a forwarding header from a connection that is neither the client nor a trusted proxy. "+
			"CSM does not block addresses chosen this way. A local peer is a process on this server, such as a site's script.",
			peer, client),
	}}
}

// due uses emission time: request start times arrive out of order and a
// backlog must not produce an hour's worth of alerts in one read.
func (p *webPeerLog) due(vhost string, at time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.alertedAt[vhost]; ok && at.Sub(last) < webPeerAlertEvery {
		return false
	}
	if !at.Before(p.pruneAt) {
		p.pruneAt = at.Add(webPeerAlertEvery)
		for v, last := range p.alertedAt {
			expires := last.Add(webPeerAlertEvery)
			if !at.Before(expires) {
				delete(p.alertedAt, v)
			} else if expires.Before(p.pruneAt) {
				p.pruneAt = expires
			}
		}
		p.saturated = false
	}
	if len(p.alertedAt) >= webPeerAlertMaxVhosts {
		if !p.saturated {
			csmlog.Warn("web peer forgery alert dedup is full; alerts for new virtual hosts are suppressed until an entry expires")
			p.saturated = true
		}
		return false
	}
	p.alertedAt[vhost] = at
	return true
}
