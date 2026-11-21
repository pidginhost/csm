package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func peerLine(at time.Time, vhost, peer, client string) string {
	return fmt.Sprintf("%d %s %s %s", at.Unix(), vhost, peer, client)
}

func TestWebPeerLogHandlerRecordsLines(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	p := newWebPeerLog()
	at := time.Unix(1795200000, 0)
	if got := p.handle(peerLine(at, "site.example", "203.0.113.80", "203.0.113.80"), &config.Config{}); len(got) != 0 {
		t.Fatalf("a direct line raised %+v", got)
	}
	if got := checks.WebPeerVerdict(netip.MustParseAddr("203.0.113.80"), at); got != checks.PeerDirect {
		t.Fatalf("verdict after a direct line = %v, want direct", got)
	}
	if got := p.handle("not a peer line", &config.Config{}); len(got) != 0 {
		t.Fatalf("a malformed line raised %+v", got)
	}
}

// One alert per vhost and hour: a tenant script can forge thousands of
// requests a minute.
func TestWebPeerLogHandlerAlertsForgeryOncePerVhostHour(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	p := newWebPeerLog()
	cfg := &config.Config{}
	t0 := time.Unix(1795200000, 0)
	now := t0
	p.now = func() time.Time { return now }
	first := p.handle(peerLine(t0, "site.example", "127.0.0.1", "192.0.2.90"), cfg)
	if len(first) != 1 || first[0].Check != "http_client_forged" || first[0].Severity != alert.Critical ||
		!strings.Contains(first[0].Message, "site.example") || !strings.Contains(first[0].Message, "local") || first[0].SourceIP != "" {
		t.Fatalf("first forged line = %+v, want one Critical local alert naming the vhost and no source address", first)
	}
	now = t0.Add(10 * time.Minute)
	if again := p.handle(peerLine(t0.Add(10*time.Minute), "site.example", "127.0.0.1", "192.0.2.91"), cfg); len(again) != 0 {
		t.Fatalf("a second forgery within the hour alerted again: %+v", again)
	}
	if other := p.handle(peerLine(t0.Add(10*time.Minute), "other.example", "203.0.113.250", "192.0.2.92"), cfg); len(other) != 1 || !strings.Contains(other[0].Message, "remote") {
		t.Fatalf("another vhost's forgery = %+v, want one remote alert", other)
	}
	now = t0.Add(61 * time.Minute)
	if later := p.handle(peerLine(t0.Add(61*time.Minute), "site.example", "127.0.0.1", "192.0.2.93"), cfg); len(later) != 1 {
		t.Fatalf("a forgery an hour later = %+v, want a new alert", later)
	}
}

// The daemon empties the peer log once it has read past the cap and caught
// up. A line the web server appends meanwhile may be lost, so windows that
// reach the truncation are unknown; later lines are read once.
func TestWebPeerLogTruncationMarksLoss(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	path := filepath.Join(t.TempDir(), "web-peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := newWebPeerLog()
	spec := p.spec(path)
	spec.truncateAt = 10
	w, err := newObservedLogWatcher(spec, &config.Config{}, make(chan alert.Finding, 4))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	client := netip.MustParseAddr("203.0.113.81")
	before := time.Now().Add(-10 * time.Minute)
	appendLine(t, path, peerLine(before, "site.example", "203.0.113.81", "203.0.113.81"))
	w.readNewLines()
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("peer log after the cap = %v, %v; want emptied", info, err)
	}
	if got := checks.WebPeerVerdict(client, before); got != checks.PeerUnknown {
		t.Fatalf("a window reaching the truncation = %v, want unknown", got)
	}
	// A second line past the tiny cap would truncate again; that loss is
	// right, but this test reads the next window.
	w.truncateAt = 1 << 30
	after := time.Now().Add(3 * time.Hour)
	p.now = func() time.Time { return after }
	appendLine(t, path, peerLine(after, "site.example", "203.0.113.81", "203.0.113.81"))
	w.readNewLines()
	if got := checks.WebPeerVerdict(client, after); got != checks.PeerDirect {
		t.Fatalf("a later window = %v, want direct", got)
	}
}

// A watcher starts at the end of the log, so lines written before it
// attached were never read.
func TestWebPeerWatcherStartMarksLoss(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	client := netip.MustParseAddr("203.0.113.82")
	at := time.Now().Add(-5 * time.Minute)
	checks.ObserveWebPeer(at, client, client, &config.Config{})
	path := filepath.Join(t.TempDir(), "web-peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := newObservedLogWatcher(newWebPeerLog().spec(path), &config.Config{}, make(chan alert.Finding, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
		t.Fatalf("a window before the watcher attached = %v, want unknown", got)
	}
}

// Apache and LiteSpeed write the peer log; nginx does not in this version.
func TestFixedLogSpecsWatchThePeerLog(t *testing.T) {
	d := &Daemon{webPeer: newWebPeerLog()}
	for server, want := range map[platform.WebServer]bool{platform.WSApache: true, platform.WSLiteSpeed: true, platform.WSNginx: false, platform.WSNone: false} {
		found := false
		// The snippet exists only for Apache and LiteSpeed on cPanel.
		for _, s := range d.fixedLogSpecs(platform.Info{Panel: platform.PanelCPanel, WebServer: server}, nil, false) {
			if s.path == webPeerLogPath {
				found = true
				if !s.optional || s.truncateAt != webPeerLogMaxBytes || s.reset == nil {
					t.Errorf("%s peer log spec = %+v, want optional, capped and loss-marking", server, s)
				}
			}
		}
		if found != want {
			t.Errorf("%s watches the peer log = %v, want %v", server, found, want)
		}
	}
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// Behind a local nginx every peer is this host, and where LiteSpeed runs PHP
// as its own user site code can rewrite the log. The daemon still reads the
// peer log there, so it stays bounded, but takes no verdict or forgery alert
// from it.
func TestFrontProxiedHostDisablesPeerVerdicts(t *testing.T) {
	for _, info := range []platform.Info{
		{Panel: platform.PanelCPanel, WebServer: platform.WSApache, FrontProxied: true},
		{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed, ServerRunsSiteCode: true},
	} {
		t.Cleanup(checks.ResetWebPeersForTest())
		d := &Daemon{webPeer: newWebPeerLog()}
		var spec *logWatchSpec
		for _, s := range d.fixedLogSpecs(info, nil, false) {
			if s.path == webPeerLogPath {
				spec = &s
			}
		}
		if spec == nil || spec.truncateAt == 0 {
			t.Fatalf("%+v does not read and bound the peer log: %+v", info, spec)
		}
		at := time.Unix(1795200000, 0)
		for _, line := range []string{
			peerLine(at, "site.example", "127.0.0.1:41000", "192.0.2.60"),
			peerLine(at, "site.example", "203.0.113.80:41000", "203.0.113.80"),
		} {
			if got := spec.handler(line, &config.Config{}); len(got) != 0 {
				t.Fatalf("%+v: peer log line %q raised %+v", info, line, got)
			}
		}
		for _, ip := range []string{"192.0.2.60", "203.0.113.80"} {
			if got := checks.WebPeerVerdict(netip.MustParseAddr(ip), at); got != checks.PeerUnknown {
				t.Fatalf("%+v: verdict for %s = %v, want unknown", info, ip, got)
			}
		}
	}
}

func TestFrontProxiedPeerWatcherBoundsLog(t *testing.T) {
	for _, info := range []platform.Info{
		{WebServer: platform.WSApache, FrontProxied: true},
		{WebServer: platform.WSLiteSpeed, FrontProxied: true},
		{WebServer: platform.WSNginx, FrontProxied: true},
		{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed, ServerRunsSiteCode: true},
	} {
		for _, backlog := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/front=%v/backlog=%v", info.WebServer, info.FrontProxied, backlog), func(t *testing.T) {
				t.Cleanup(checks.ResetWebPeersForTest())
				d := &Daemon{webPeer: newWebPeerLog()}
				var spec *logWatchSpec
				for _, s := range d.fixedLogSpecs(info, nil, false) {
					if s.path == webPeerLogPath {
						spec = &s
					}
				}
				if spec == nil {
					t.Fatal("front-proxied host has no peer log watcher")
				}
				path := filepath.Join(t.TempDir(), "web-peer.log")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				spec.path, spec.truncateAt = path, 1<<30
				// A future window avoids startup loss hiding an accidental observation.
				at := time.Now().Add(3 * time.Hour)
				d.webPeer.now = func() time.Time { return at }
				appendRecords := func() {
					appendLine(t, path, peerLine(at, "site.example", "203.0.113.80", "203.0.113.80"))
					appendLine(t, path, peerLine(at, "site.example", "192.0.2.10", "192.0.2.60"))
				}
				if backlog {
					appendRecords()
				}
				findings := make(chan alert.Finding, 4)
				w, err := newObservedLogWatcher(*spec, &config.Config{}, findings)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(w.Stop)
				if !backlog {
					appendRecords()
				}
				w.readNewLines()
				if len(findings) != 0 {
					t.Fatalf("front-proxied log emitted %d findings", len(findings))
				}
				for _, ip := range []string{"203.0.113.80", "192.0.2.60"} {
					if got := checks.WebPeerVerdict(netip.MustParseAddr(ip), at); got != checks.PeerUnknown {
						t.Fatalf("unexpected verdict %v for %s", got, ip)
					}
				}

				// Check evidence before truncation can mask a recorded verdict.
				w.truncateAt = 1
				w.readNewLines()
				if st, err := os.Stat(path); err != nil || st.Size() != 0 {
					t.Fatalf("log not bounded: %v, %v", st, err)
				}
			})
		}
	}
}

// The peer log watcher registers a reader that brings the index to the end
// of the log at once, so a verdict does not depend on the next poll.
func TestWebPeerWatcherDrainsForVerdicts(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	previous := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSLiteSpeed, Directive: "useIpInProxyHeader 2"})
	t.Cleanup(func() { checks.SetHTTPRewrite(previous) })
	path := filepath.Join(t.TempDir(), "peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := newWebPeerLog()
	// The lines below sit past the loss marked at attach; the reader's clock
	// has moved on with them.
	p.now = func() time.Time { return time.Now().Add(8 * time.Hour) }
	w, err := newObservedLogWatcher(p.spec(path), &config.Config{}, make(chan alert.Finding, 4))
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { w.Run(stop); close(done) }()
	t.Cleanup(func() { close(stop); <-done })
	// Past the loss the watcher marked when it attached at the end of the log.
	at := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	appendLine(t, path, peerLine(at, "site.example", "203.0.113.77", "203.0.113.77"))
	f := alert.Finding{
		Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "203.0.113.77",
		Attribution: admission.AttributionHTTPPeer, Timestamp: time.Now(),
		Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: at},
	}
	if _, _, err := checks.AdmissionEvidence(f); err != nil {
		t.Fatalf("AdmissionEvidence = %v, want the direct line read without waiting for a poll", err)
	}
}

func TestWebPeerLateRetryReplacesStoppedDrain(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	previous := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSLiteSpeed})
	t.Cleanup(func() { checks.SetHTTPRewrite(previous) })
	oldInterval := logWatcherRetryInterval
	logWatcherRetryInterval = time.Millisecond
	t.Cleanup(func() { logWatcherRetryInterval = oldInterval })
	path := filepath.Join(t.TempDir(), "peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	peerLog := newWebPeerLog()
	peerLog.now = func() time.Time { return time.Now().Add(8 * time.Hour) }
	spec := peerLog.spec(path)
	old, err := newObservedLogWatcher(spec, &config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	old.Stop()

	d := New(&config.Config{}, nil, nil, "")
	d.wg.Add(1)
	attached := make(chan struct{})
	go func() { d.retryLogWatcherNamed(spec); close(attached) }()
	stop := sync.OnceFunc(func() { close(d.stopCh); d.wg.Wait() })
	t.Cleanup(stop)
	select {
	case <-attached:
	case <-time.After(time.Second):
		t.Fatal("retry did not attach")
	}
	// Beyond the startup loss window, as in TestWebPeerWatcherDrainsForVerdicts.
	at := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	appendLine(t, path, peerLine(at, "site.example", "203.0.113.92", "203.0.113.92"))
	f := alert.Finding{
		Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "203.0.113.92",
		Attribution: admission.AttributionHTTPPeer, Timestamp: time.Now().Add(-time.Minute),
		Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: at},
	}
	if _, _, err := checks.AdmissionEvidence(f); err != nil {
		t.Fatalf("replacement reader: %v", err)
	}
	stop()
	if _, _, err := checks.AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("stopped reader admitted direct evidence: %v", err)
	}
}

// Revoking suEXEC must stop both observations and previously cached evidence,
// even when the platform snapshot still says it is enabled.
func TestWebPeerSuExecRevokedWhileRunning(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	previous := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSLiteSpeed})
	t.Cleanup(func() { checks.SetHTTPRewrite(previous) })
	var unsafe atomic.Bool
	p := newWebPeerLog()
	p.now = func() time.Time { return time.Now().Add(8 * time.Hour) }
	p.serverRunsSiteCode = func(platform.WebServer) bool { return unsafe.Load() }
	d := &Daemon{webPeer: p}
	var spec logWatchSpec
	for _, s := range d.fixedLogSpecs(platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}, nil, false) {
		if s.path == webPeerLogPath {
			spec = s
		}
	}
	path := filepath.Join(t.TempDir(), "peer.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spec.path = path
	findings := make(chan alert.Finding, 4)
	w, err := newObservedLogWatcher(spec, &config.Config{}, findings)
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { w.Run(stop); close(done) }()
	t.Cleanup(func() { close(stop); <-done })
	at := time.Now().Add(3 * time.Hour).Truncate(time.Second)
	appendLine(t, path, peerLine(at, "site.example", "203.0.113.80", "203.0.113.80"))
	f := alert.Finding{
		Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "203.0.113.80",
		Attribution: admission.AttributionHTTPPeer, Timestamp: time.Now().Add(-time.Minute),
		Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: at},
	}
	if _, _, err := checks.AdmissionEvidence(f); err != nil {
		t.Fatalf("safe peer rejected: %v", err)
	}
	unsafe.Store(true)
	// No new log line: the cached direct verdict must be revoked too.
	if _, _, err := checks.AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("cached peer survived suEXEC revocation: %v", err)
	}
	appendLine(t, path, peerLine(at, "site.example", "192.0.2.10", "192.0.2.60"))
	if !w.Drain(time.Second) {
		t.Fatal("unsafe log was not drained")
	}
	if len(findings) != 0 {
		t.Fatalf("unsafe log raised %d forgery alerts", len(findings))
	}
	for _, ip := range []string{"203.0.113.80", "192.0.2.60"} {
		if got := checks.WebPeerVerdict(netip.MustParseAddr(ip), at); got != checks.PeerUnknown {
			t.Fatalf("unsafe verdict: %v", got)
		}
	}
	// Re-enabling the setting cannot authenticate backlog written while off.
	unsafe.Store(false)
	appendLine(t, path, peerLine(at.Add(3*time.Hour), "site.example", "203.0.113.80", "203.0.113.80"))
	f.Observation.ObservedAt = at.Add(3 * time.Hour)
	if _, _, err := checks.AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("untrusted backlog admitted: %v", err)
	}
}

func TestWebPeerSuExecPollRevokesAndBounds(t *testing.T) {
	for _, unsafeAtStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("unsafeAtStart=%v", unsafeAtStart), func(t *testing.T) {
			t.Cleanup(checks.ResetWebPeersForTest())
			unsafe := unsafeAtStart
			p := newWebPeerLog()
			p.now = func() time.Time { return time.Now().Add(8 * time.Hour) }
			p.serverRunsSiteCode = func(platform.WebServer) bool { return unsafe }
			path := filepath.Join(t.TempDir(), "peer.log")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			// The startup snapshot can predate a change to the XML file.
			spec := p.hostSpec(path, platform.Info{WebServer: platform.WSLiteSpeed})
			findings := make(chan alert.Finding, 4)
			w, err := newObservedLogWatcher(spec, &config.Config{}, findings)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(w.Stop)
			at := time.Now().Add(3 * time.Hour)
			client := netip.MustParseAddr("203.0.113.80")
			appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
			w.readNewLines()
			want := checks.PeerDirect
			if unsafeAtStart {
				want = checks.PeerUnknown
			}
			if got := checks.WebPeerVerdict(client, at); got != want {
				t.Fatalf("initial verdict = %v, want %v", got, want)
			}
			unsafe = true
			w.readNewLines() // Empty polls must revoke previously cached evidence.
			if got := checks.WebPeerVerdict(client, at); got != checks.PeerUnknown {
				t.Fatalf("idle poll retained verdict %v", got)
			}
			at = at.Add(3 * time.Hour)
			appendLine(t, path, peerLine(at, "site.example", client.String(), client.String()))
			appendLine(t, path, peerLine(at, "site.example", "192.0.2.10", "192.0.2.60"))
			w.readNewLines()
			for _, ip := range []string{client.String(), "192.0.2.60"} {
				if got := checks.WebPeerVerdict(netip.MustParseAddr(ip), at); got != checks.PeerUnknown {
					t.Fatalf("unsafe observation produced verdict %v", got)
				}
			}
			if len(findings) != 0 {
				t.Fatalf("unsafe log raised %d findings", len(findings))
			}
			w.truncateAt = 1
			w.readNewLines()
			if st, err := os.Stat(path); err != nil || st.Size() != 0 {
				t.Fatalf("revoked log not bounded: %v, %v", st, err)
			}
		})
	}
}

// A line stamped after it was read cannot be a request's start. Site code
// that can append to the log could otherwise glue digits onto the front of
// the web server's next line, throwing a forged line far into the future and
// out of every verdict window while the victim's direct lines stay.
func TestWebPeerLogRejectsLinesFromTheFuture(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	now := time.Unix(1795200000, 0)
	p := newWebPeerLog()
	p.now = func() time.Time { return now }
	victim := "203.0.113.81"
	if got := p.handle(peerLine(now.Add(-time.Minute), "site.example", victim, victim), &config.Config{}); len(got) != 0 {
		t.Fatalf("direct line raised %+v", got)
	}
	glued := "9" + peerLine(now, "site.example", "127.0.0.1", victim)
	if got := p.handle(glued, &config.Config{}); len(got) != 0 {
		t.Fatalf("a far-future line raised %+v", got)
	}
	if got := checks.WebPeerVerdict(netip.MustParseAddr(victim), now); got != checks.PeerUnknown {
		t.Fatalf("verdict after a far-future line = %v, want unknown", got)
	}
	// A clock step of a few seconds is not an attack.
	t.Cleanup(checks.ResetWebPeersForTest())
	later := netip.MustParseAddr("203.0.113.82")
	p.handle(peerLine(now.Add(30*time.Second), "site.example", later.String(), later.String()), &config.Config{})
	if got := checks.WebPeerVerdict(later, now.Add(30*time.Second)); got != checks.PeerDirect {
		t.Fatalf("a line 30s ahead of the clock = %v, want direct", got)
	}
}

// An append-only writer can join a prefix to the server's timestamp. Even
// timestamps that wrap time.Time must leave a reader-clock loss, not hide a
// forged request behind the client's earlier direct evidence.
func TestWebPeerLogRejectsJoinedTimestamps(t *testing.T) {
	now := time.Unix(1795200000, 0)
	victim := netip.MustParseAddr("203.0.113.81")
	for _, prefix := range []string{"9", "922337203", "+922337203", "000922337203", "-", "1 ", strings.Repeat("9", 512)} {
		t.Run(prefix[:min(len(prefix), 20)], func(t *testing.T) {
			t.Cleanup(checks.ResetWebPeersForTest())
			p := newWebPeerLog()
			p.now = func() time.Time { return now }
			p.handle(peerLine(now.Add(-time.Minute), "site.example", victim.String(), victim.String()), nil)
			if got := checks.WebPeerVerdict(victim, now.Add(-time.Minute)); got != checks.PeerDirect {
				t.Fatalf("before joined line = %v, want direct", got)
			}
			line := prefix + peerLine(now, "site.example", "192.0.2.10", victim.String())
			if got := p.handle(line, nil); len(got) != 0 {
				t.Errorf("invalid timestamp raised %d findings", len(got))
			}
			// Later direct records cannot repair the missing forged record.
			p.handle(peerLine(now, "site.example", victim.String(), victim.String()), nil)
			for _, at := range []time.Time{now, now.Add(time.Hour)} {
				if got := checks.WebPeerVerdict(victim, at); got != checks.PeerUnknown {
					t.Errorf("after joined timestamp at %v = %v, want unknown", at, got)
				}
			}
		})
	}
}

// Refused timestamps must neither advance retention nor move a loss beyond
// the reader's clock. Flood invalid records, then require a fresh window to recover.
func TestWebPeerLogTimestampBoundsAndRecovery(t *testing.T) {
	now := time.Unix(1795200000, 0)
	for _, stamp := range []string{
		"9223372036854775807", // Largest parsed integer, outside time.Time's range.
		"9223371974719179007", // Last second before time.Time wraps internally.
		"9223371974719179008", // First second after the wrap.
		fmt.Sprint(now.Add(webPeerClockSkew + time.Second).Unix()),
	} {
		t.Run(stamp, func(t *testing.T) {
			now := now
			t.Cleanup(checks.ResetWebPeersForTest())
			p := newWebPeerLog()
			p.now = func() time.Time { return now }
			victim := netip.MustParseAddr("203.0.113.81")
			p.handle(peerLine(now, "site.example", "192.0.2.10", victim.String()), nil)
			for range 4096 {
				p.handle(stamp+" site.example 203.0.113.82 203.0.113.82", nil)
			}
			p.handle(peerLine(now, "site.example", victim.String(), victim.String()), nil)
			if got := checks.WebPeerVerdict(victim, now); got != checks.PeerUnknown {
				t.Errorf("refused timestamp left verdict %v, want unknown", got)
			}
			now = now.Add(time.Hour + time.Second)
			p.handle(peerLine(now, "site.example", victim.String(), victim.String()), nil)
			if got := checks.WebPeerVerdict(victim, now); got != checks.PeerDirect {
				t.Errorf("after the loss window = %v, want direct", got)
			}
		})
	}
}

// Accepted clock skew must not prune a current request's forged evidence.
func TestWebPeerLogAcceptedSkewPreservesEvidence(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	now := time.Unix(1795200000, 0)
	p := newWebPeerLog()
	p.now = func() time.Time { return now }
	victim := netip.MustParseAddr("203.0.113.81")
	p.handle(peerLine(now.Add(-time.Minute), "site.example", victim.String(), victim.String()), nil)
	p.handle(peerLine(now, "site.example", "192.0.2.10", victim.String()), nil)
	later := now.Add(webPeerClockSkew)
	for range 4096 {
		p.handle(peerLine(later, "site.example", "203.0.113.82", "203.0.113.82"), nil)
	}
	if got := checks.WebPeerVerdict(victim, now); got != checks.PeerForged {
		t.Fatalf("accepted clock skew displaced forged evidence: %v", got)
	}
	if got := checks.WebPeerVerdict(netip.MustParseAddr("203.0.113.82"), later); got != checks.PeerDirect {
		t.Fatalf("clock skew boundary = %v, want direct", got)
	}
}

// A host without the peer log snippet has no peer log, and that is not a
// detached watcher: health and doctor must not report it as a failure.
func TestMissingOptionalLogIsNotDetached(t *testing.T) {
	d := &Daemon{stopCh: make(chan struct{}), webPeer: newWebPeerLog()}
	spec := d.webPeer.spec(filepath.Join(t.TempDir(), "absent", "peer.log"))
	d.startLogWatch(spec)
	close(d.stopCh)
	d.wg.Wait()
	if attached, seen := d.WatcherStatuses()[spec.name]; seen && !attached {
		t.Fatalf("an absent optional log marked %s detached", spec.name)
	}
}

// The peer log is watched only where the snippet can exist: Apache, cPanel
// LiteSpeed, and cPanel hosts behind nginx that may keep an earlier snippet.
// Standalone LiteSpeed and plain nginx get no watch.
func TestPeerLogWatchedOnlyWhereTheSnippetCanExist(t *testing.T) {
	for _, tc := range []struct {
		info platform.Info
		want bool
	}{
		{platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}, true},
		{platform.Info{OS: platform.OSDebian, WebServer: platform.WSApache}, true},
		{platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSNginx, FrontProxied: true}, true},
		{platform.Info{WebServer: platform.WSLiteSpeed}, false},
		{platform.Info{WebServer: platform.WSNginx}, false},
	} {
		d := &Daemon{webPeer: newWebPeerLog()}
		got := false
		for _, s := range d.fixedLogSpecs(tc.info, nil, false) {
			got = got || s.path == webPeerLogPath
		}
		if got != tc.want {
			t.Errorf("%+v: peer log watched = %v, want %v", tc.info, got, tc.want)
		}
	}
}

// Apache with BufferedLogs On can hold the forged peer line while the access
// line is read: the daemon reads the log only to bound it.
func TestBufferedApacheLogsDisablePeerVerdicts(t *testing.T) {
	t.Cleanup(checks.ResetWebPeersForTest())
	previous := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSApache, Directive: "RemoteIPHeader X-Forwarded-For", BufferedLogs: true})
	t.Cleanup(func() { checks.SetHTTPRewrite(previous) })
	d := &Daemon{webPeer: newWebPeerLog()}
	var spec *logWatchSpec
	for _, s := range d.fixedLogSpecs(platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}, nil, false) {
		if s.path == webPeerLogPath {
			spec = &s
		}
	}
	if spec == nil {
		t.Fatal("no peer log watch")
	}
	if spec.beforeRead != nil {
		spec.beforeRead()
	}
	at := time.Unix(1795200000, 0)
	if got := spec.handler(peerLine(at, "site.example", "127.0.0.1", "192.0.2.69"), &config.Config{}); len(got) != 0 {
		t.Fatalf("buffered Apache raised %+v", got)
	}
	if got := checks.WebPeerVerdict(netip.MustParseAddr("192.0.2.69"), at); got != checks.PeerUnknown {
		t.Fatalf("verdict with buffered logs = %v, want unknown", got)
	}
}
