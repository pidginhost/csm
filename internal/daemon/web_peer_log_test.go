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
		for _, s := range d.fixedLogSpecs(platform.Info{WebServer: server}, nil, false) {
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
		{WebServer: platform.WSLiteSpeed, ServerRunsSiteCode: true},
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
	w, err := newObservedLogWatcher(newWebPeerLog().spec(path), &config.Config{}, make(chan alert.Finding, 4))
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
	spec := newWebPeerLog().spec(path)
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
	p.serverRunsSiteCode = func(platform.WebServer) bool { return unsafe.Load() }
	d := &Daemon{webPeer: p}
	var spec logWatchSpec
	for _, s := range d.fixedLogSpecs(platform.Info{WebServer: platform.WSLiteSpeed}, nil, false) {
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
