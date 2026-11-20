package daemon

import (
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// webPeerLogPath is the log the web server writes "<unix seconds> <vhost>
// <peer> <client>" to for every request, through the CSM peer log snippet.
const webPeerLogPath = "/var/log/csm/web-peer.log"

// webPeerLogMaxBytes is the size past which the daemon empties the peer log
// once it has read it all. Every truncation leaves an hour of unknown
// verdicts, so the cap keeps it rare on a busy host.
var webPeerLogMaxBytes int64 = 256 << 20

// webPeerAlertEvery is how often one vhost raises a forgery alert.
const webPeerAlertEvery = time.Hour

// webPeerLog feeds the peer index and raises one forgery alert per vhost
// per hour: a tenant script can forge thousands of requests a minute.
type webPeerLog struct {
	mu        sync.Mutex
	alertedAt map[string]time.Time
}

func newWebPeerLog() *webPeerLog {
	return &webPeerLog{alertedAt: make(map[string]time.Time)}
}

// spec is the watch of path: optional, emptied past the cap, and every
// gap in what it read is a loss in the index.
func (p *webPeerLog) spec(path string) logWatchSpec {
	return logWatchSpec{
		name: "web_peer_log", path: path, handler: p.handle,
		optional: true, truncateAt: webPeerLogMaxBytes,
		reset: func() { checks.MarkWebPeerLoss(time.Now()) },
	}
}

func (p *webPeerLog) handle(line string, cfg *config.Config) []alert.Finding {
	at, vhost, peer, client, ok := checks.ParseWebPeerLine(line)
	if !ok || checks.ObserveWebPeer(at, peer, client, cfg) != checks.PeerForged || !p.due(vhost, at) {
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

// due reports whether vhost may raise an alert for a line at at, and
// records it when so.
func (p *webPeerLog) due(vhost string, at time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.alertedAt[vhost]; ok && at.Sub(last) < webPeerAlertEvery {
		return false
	}
	for v, last := range p.alertedAt {
		if at.Sub(last) >= webPeerAlertEvery {
			delete(p.alertedAt, v)
		}
	}
	p.alertedAt[vhost] = at
	return true
}
