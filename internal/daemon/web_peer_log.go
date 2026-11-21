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
	"github.com/pidginhost/csm/internal/platform"
)

// webPeerLogPath is the log the CSM snippet makes the web server write:
// "<unix seconds> <vhost> <peer> <client>" per request.
const webPeerLogPath = webserver.PeerLogFile

// webPeerLogMaxBytes is the size past which the daemon empties the peer log
// once it has read it all. Every truncation leaves an hour of unknown
// verdicts, so the cap keeps it rare on a busy host.
var webPeerLogMaxBytes int64 = 256 << 20

// webPeerClockSkew is how far ahead of the daemon's clock a peer line may be
// stamped and still count: a clock step, not a request from the future.
const webPeerClockSkew = 5 * time.Minute

// webPeerAlertEvery is how often each peer origin raises a forgery alert.
const webPeerAlertEvery = time.Hour

// Keep live entries on saturation: evicting one would let its key alert
// again at once. Peer classification is never suppressed.
const webPeerAlertMaxVhosts = 10000

// webPeerLog feeds the peer index and raises one forgery alert per vhost
// per hour: a tenant script can forge thousands of requests a minute.
type webPeerLog struct {
	serverRunsSiteCode func(platform.WebServer) bool
	mu                 sync.Mutex
	alertedAt          map[string]time.Time
	now                func() time.Time
	pruneAt            time.Time
	saturated          bool
}

func newWebPeerLog() *webPeerLog {
	return &webPeerLog{alertedAt: make(map[string]time.Time), now: time.Now, serverRunsSiteCode: platform.ServerRunsSiteCode}
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

// hostSpec keeps draining an untrusted log for its size bound. Once site code
// could have changed the log, a later safe setting cannot authenticate backlog;
// trust stays revoked until a new daemon starts at EOF.
func (p *webPeerLog) hostSpec(path string, info platform.Info) logWatchSpec {
	spec := p.spec(path)
	var mu sync.Mutex
	blocked := info.FrontProxied || info.ServerRunsSiteCode
	trusted := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if !blocked {
			blocked = p.serverRunsSiteCode(info.WebServer) || checks.CurrentHTTPRewrite().BufferedLogs
		}
		if blocked {
			checks.MarkWebPeerLoss(p.now())
		}
		return !blocked
	}
	spec.beforeRead = func() { trusted() }
	spec.handler = func(line string, cfg *config.Config) []alert.Finding {
		mu.Lock()
		defer mu.Unlock()
		if blocked {
			return nil
		}
		return p.handle(line, cfg)
	}
	spec.onWatch = func(w *LogWatcher) {
		trusted()
		checks.SetWebPeerDrain(func(timeout time.Duration) bool {
			// Check even an idle log: cached direct evidence is unsafe as
			// soon as PHP can write it. Recheck after a concurrent read too.
			return trusted() && w.Drain(timeout) && trusted()
		})
	}
	return spec
}

func (p *webPeerLog) handle(line string, cfg *config.Config) []alert.Finding {
	now := p.now()
	at, vhost, peer, client, ok := checks.ParseWebPeerLine(line)
	// A request starts before its line is written, so a line from the future
	// is corrupt: code able to append could glue digits onto the next line
	// and move it out of every verdict window.
	// Compare Unix seconds: large positive integers can wrap time.Time's
	// internal seconds and appear earlier than now to Time.After.
	if !ok || at.Unix() > now.Add(webPeerClockSkew).Unix() {
		checks.MarkWebPeerLoss(now)
		return nil
	}
	if checks.ObserveWebPeer(at, peer, client, cfg) != checks.PeerForged {
		return nil
	}
	origin, advice := "remote", "If this peer is a proxy you run or use, list it in web_server.trusted_proxies."
	if peer.IsLoopback() || netutil.IsHostAddress(peer.String()) {
		origin, advice = "local", "A local peer is a process on this server, such as a site's script, or a proxy running in front of the web server."
	}
	// One alert per origin and hour: a front proxy or a forging tenant
	// touches every virtual host.
	if !p.due(origin, now) {
		return nil
	}
	return []alert.Finding{{
		Severity: alert.Critical,
		Check:    "http_client_forged",
		Message:  fmt.Sprintf("Web server %s logged a client address chosen by a %s peer", vhost, origin),
		Details: fmt.Sprintf("Peer: %s\nLogged client: %s\nVirtual host: %s\n"+
			"The web server applied a forwarding header from a connection that is neither the client nor a trusted proxy. "+
			"CSM does not block addresses chosen this way. %s "+
			"The virtual host comes from the request, which the peer chooses, so it does not identify the account responsible. "+
			"Further forgeries from %s peers within the hour raise no new alert.",
			peer, client, vhost, advice, origin),
	}}
}

// due reports whether key may alert at at, using emission time: request
// start times arrive out of order and a backlog must not produce an hour's
// worth of alerts in one read.
func (p *webPeerLog) due(key string, at time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.alertedAt[key]; ok && at.Sub(last) < webPeerAlertEvery {
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
			csmlog.Warn("web peer forgery alert dedup is full; new alert keys are suppressed until an entry expires")
			p.saturated = true
		}
		return false
	}
	p.alertedAt[key] = at
	return true
}
