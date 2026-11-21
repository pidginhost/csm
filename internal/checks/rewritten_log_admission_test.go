package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func withHTTPRewrite(t *testing.T, r HTTPRewrite) {
	t.Helper()
	prev := httpRewrite.Load()
	SetHTTPRewrite(r)
	t.Cleanup(func() { httpRewrite.Store(prev) })
}

// initialHTTPRewrite is the state before TestMain pins a direct one: what a
// process holds before the daemon first reads its web server.
var initialHTTPRewrite = CurrentHTTPRewrite()

func TestHTTPRewriteProductionDefaultUnknown(t *testing.T) {
	if initialHTTPRewrite != (HTTPRewrite{}) {
		t.Fatalf("initial rewrite state = %+v, want the unknown zero value", initialHTTPRewrite)
	}
}

// Readers always see one complete published value, and changing a copy
// they got changes nothing published.
func TestHTTPRewriteConcurrentSnapshots(t *testing.T) {
	prev := httpRewrite.Load()
	t.Cleanup(func() { httpRewrite.Store(prev) })
	a := HTTPRewrite{State: RewriteActive, Server: "nginx", Directive: "set_real_ip_from 192.0.2.0/24", File: "/etc/nginx/a.conf"}
	b := HTTPRewrite{State: RewriteUnknown, Server: "apache", Reason: "unreadable"}
	SetHTTPRewrite(a)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				SetHTTPRewrite(b)
			} else {
				SetHTTPRewrite(a)
			}
		}
	}()
	errs := make(chan string, 4)
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				got := CurrentHTTPRewrite()
				if got != a && got != b {
					errs <- fmt.Sprintf("read a mixed value %+v", got)
					return
				}
				got.File = "changed"
				if CurrentHTTPRewrite() == got {
					errs <- "a change to a returned copy reached the published state"
					return
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	SetHTTPRewrite(a)
	got := CurrentHTTPRewrite()
	got.File = "changed"
	if CurrentHTTPRewrite() != a || got == a {
		t.Fatal("changing a returned copy changed the published state")
	}
}

var activeRewrite = HTTPRewrite{State: RewriteActive, Server: "apache", Directive: "RemoteIPHeader CF-Connecting-IP", File: "/etc/apache2/conf.d/remoteip.conf"}

// Before the daemon has read the web server's configuration, the logged
// address is not known to be the connecting peer.
func TestHTTPRewriteStartsUnknown(t *testing.T) {
	prev := httpRewrite.Load()
	t.Cleanup(func() { httpRewrite.Store(prev) })
	httpRewrite.Store(nil)
	if got := CurrentHTTPRewrite(); got.State != RewriteUnknown {
		t.Fatalf("unset rewrite state = %+v, want unknown", got)
	}
	SetHTTPRewrite(activeRewrite)
	if got := CurrentHTTPRewrite(); got != activeRewrite {
		t.Fatalf("published rewrite state = %+v, want %+v", got, activeRewrite)
	}
}

// A web log whose server replaced the client address mints nothing for any
// HTTP producer, before the trusted-chain check, whether rewriting is
// detected or cannot be ruled out. A known edge is refused as an edge
// first, so no path blocks it. Session and cpsrvd peers are read by their
// own servers and keep their evidence.
func TestAdmissionEvidenceRefusesRewrittenLogs(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	for _, rw := range []HTTPRewrite{activeRewrite, {State: RewriteUnknown, Reason: "unreadable"}} {
		withHTTPRewrite(t, rw)
		for _, tc := range []struct {
			producer admission.ProducerID
			check    string
		}{
			{ProducerAccessLog, "wp_login_bruteforce"},
			{ProducerDomlogScan, "wp_login_bruteforce"},
			{ProducerModSecLog, "modsec_block_escalation"},
			{ProducerModSecAuditScan, "waf_attack_blocked"},
		} {
			f := httpPeerFinding("203.0.113.9")
			f.Check, f.Observation.Producer = tc.check, string(tc.producer)
			requireKnownProxyGateOutcome(t, f, admission.CauseRewrittenLog)
			f.SourceIP = "198.51.100.7"
			requireKnownProxyGateOutcome(t, f, admission.CauseProxyPeer)
		}
		chain := httpPeerFinding("203.0.113.9")
		chain.Attribution = admission.AttributionTrustedHTTPChain
		requireKnownProxyGateOutcome(t, chain, admission.CauseRewrittenLog)
		for _, tc := range []struct {
			producer admission.ProducerID
			check    string
		}{
			{ProducerSSHLog, "ssh_login_unknown_ip"},
			{ProducerSSHLoginScan, "ssh_login_unknown_ip"},
			{ProducerPAMSocket, "pam_bruteforce"},
			{ProducerEximLog, "smtp_bruteforce"},
			{ProducerMailLog, "mail_bruteforce"},
			{ProducerFTPLog, "ftp_auth_failure_realtime"},
			{ProducerFTPScan, "ftp_bruteforce"},
			{ProducerCpanelAccessLog, "api_auth_failure_realtime"},
			{ProducerCpanelScan, "api_auth_failure"},
		} {
			f := httpPeerFinding("203.0.113.9")
			f.Check, f.Attribution = tc.check, admission.AttributionPeer
			f.Observation.Producer = string(tc.producer)
			requireKnownProxyGateOutcome(t, f, 0)
		}
	}
	// A cPanel finding from a known edge is a proxy edge, never a rewritten
	// web log.
	cpanel := httpPeerFinding("198.51.100.7")
	cpanel.Check, cpanel.Attribution = "api_auth_failure", admission.AttributionPeer
	cpanel.Observation.Producer = string(ProducerCpanelScan)
	requireKnownProxyGateOutcome(t, cpanel, admission.CauseProxyPeer)
	withHTTPRewrite(t, HTTPRewrite{State: RewriteNone})
	requireKnownProxyGateOutcome(t, httpPeerFinding("203.0.113.9"), 0)
}

// A rewritten remote address in a vhost log keeps its legacy finding, and
// admission refuses it.
func TestDomlogScanFindingFromARewrittenLogIsRefused(t *testing.T) {
	withHTTPRewrite(t, activeRewrite)
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(`203.0.113.9 - - [09/Nov/2026:12:01:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, i))
	}
	_, findings := scanDomlogFile(t, &config.Config{}, nopBotClassifier{}, lines)
	f := oneScanFinding(t, findings, "wp_login_bruteforce")
	if f.SourceIP != "203.0.113.9" || f.Attribution != admission.AttributionHTTPPeer {
		t.Fatalf("legacy finding changed: %s read as %s", f.SourceIP, f.Attribution)
	}
	if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("mint: %v, want the rewritten_log cause", err)
	}
}

// An access-log line from a rewriting web server, or one whose rewriting is
// unknown, is not a sighting of the address it names: the finding is
// refused for the rewrite, not for a missing record. A cPanel access line
// is a sighting in every state. The legacy finding stays either way.
func TestReputationIgnoresRewrittenAccessLogSightings(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := sightingLines("203.0.113.60", at)
	for _, step := range []struct {
		name string
		rw   HTTPRewrite
		http admission.Cause
	}{
		{"direct", HTTPRewrite{State: RewriteNone}, 0},
		{"rewritten", activeRewrite, admission.CauseRewrittenLog},
		{"unknown", HTTPRewrite{State: RewriteUnknown, Reason: "unreadable"}, admission.CauseRewrittenLog},
		{"direct again", HTTPRewrite{State: RewriteNone}, 0},
	} {
		for kind, want := range map[string]admission.Cause{"HTTP request": step.http, "cPanel access": 0} {
			t.Run(step.name+"/"+kind, func(t *testing.T) {
				withHTTPRewrite(t, step.rw)
				cfg := listIPs(t, "203.0.113.60")
				sightingLogs(t, map[string]string{logPathFor[kind]: lines[kind] + "\n"})
				f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.60")
				if f.SourceIP != "203.0.113.60" {
					t.Fatalf("legacy finding changed: %+v", f)
				}
				_, _, err := mintScanFinding(t, f)
				if admission.CauseOf(err) != want || (want == 0 && err != nil) {
					t.Fatalf("mint of a %s sighting: %v, want cause %v", kind, err, want)
				}
			})
		}
	}
}

// An untrusted web address must not hide independent cpsrvd evidence for
// the same address. Neither the legacy finding nor its severity changes.
func TestReputationRewrittenLogKeepsIndependentSighting(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := sightingLines("203.0.113.60", at)
	for _, rw := range []HTTPRewrite{activeRewrite, {State: RewriteUnknown}} {
		t.Run(rw.State.String(), func(t *testing.T) {
			withHTTPRewrite(t, rw)
			cfg := listIPs(t, "203.0.113.60")
			paths := sightingLogs(t, map[string]string{
				logPathFor["HTTP request"]:  lines["HTTP request"] + "\n",
				logPathFor["cPanel access"]: lines["cPanel access"] + "\n",
			})
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.60")
			if _, _, err := mintScanFinding(t, f); err != nil {
				t.Fatalf("independent cPanel sighting refused: %v", err)
			}
			want := syslogTestRef(t, paths[logPathFor["cPanel access"]], 0, lines["cPanel access"])
			if f.Observation.Stream != want.Stream || f.Observation.Cursor != want.Cursor || !f.Observation.ObservedAt.Equal(at) {
				t.Fatalf("observation = %+v, want the cPanel record %+v at %v", f.Observation, want, at)
			}
			if f.Severity != reputationSightingSeverity("HTTP request") || !strings.Contains(f.Details, "Detected via: HTTP request") {
				t.Fatalf("legacy finding changed: %+v", f)
			}
		})
	}
}

// An HTTP finding a rewriting web server's log named is refused for the
// rewrite even when no observation was kept for it, so the response can
// tell the rewrite from a missing record. On a direct host the missing
// record is the refusal. A known CDN edge is refused as an edge first, in
// every state: no path blocks it.
func TestAdmissionEvidenceRefusesRewrittenBeforeMissingRecord(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	unstamped := alert.Finding{Check: "waf_attack_blocked", SourceIP: "203.0.113.64", Attribution: admission.AttributionHTTPPeer}
	edge := unstamped
	edge.SourceIP = "198.51.100.7"
	chainEdge := edge
	chainEdge.Attribution = admission.AttributionTrustedHTTPChain
	for _, tc := range []struct {
		name string
		rw   HTTPRewrite
		f    alert.Finding
		want admission.Cause
	}{
		{"rewritten", activeRewrite, unstamped, admission.CauseRewrittenLog},
		{"unknown", HTTPRewrite{State: RewriteUnknown, Reason: "unreadable"}, unstamped, admission.CauseRewrittenLog},
		{"direct", HTTPRewrite{State: RewriteNone}, unstamped, admission.CauseNoObservation},
		{"edge on a rewriting host", activeRewrite, edge, admission.CauseProxyPeer},
		{"edge on a direct host", HTTPRewrite{State: RewriteNone}, edge, admission.CauseProxyPeer},
		{"forwarded edge on a rewriting host", activeRewrite, chainEdge, admission.CauseProxyPeer},
		{"forwarded edge on an unknown host", HTTPRewrite{State: RewriteUnknown}, chainEdge, admission.CauseProxyPeer},
		{"forwarded edge on a direct host", HTTPRewrite{State: RewriteNone}, chainEdge, admission.CauseProxyPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHTTPRewrite(t, tc.rw)
			if _, _, err := AdmissionEvidence(tc.f); admission.CauseOf(err) != tc.want {
				t.Fatalf("AdmissionEvidence = %v, want cause %v", err, tc.want)
			}
		})
	}
}

// A reputation finding with a recorded sighting is derived evidence even
// when a rewritten web log also named its address; one only a rewritten web
// log named is read as that log's client, so admission refuses it for the
// rewrite; one with neither names nothing.
func TestReputationStampPrefersARecordOverARewrittenLog(t *testing.T) {
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	record := scanRecord{stream: "f:1:2", cursor: "o=1", at: at}
	findings := []alert.Finding{
		{Check: "ip_reputation", SourceIP: "203.0.113.65"},
		{Check: "ip_reputation", SourceIP: "203.0.113.66"},
		{Check: "ip_reputation", SourceIP: "203.0.113.67"},
	}
	stampReputationSightings(findings,
		map[string]scanRecord{"203.0.113.65": record},
		map[string]bool{"203.0.113.65": true, "203.0.113.66": true})
	if f := findings[0]; f.Attribution != admission.AttributionDerived || f.Observation.Stream != record.stream {
		t.Fatalf("recorded sighting = %+v, want derived evidence on its record", f)
	}
	if f := findings[1]; f.Attribution != admission.AttributionHTTPPeer || f.Observation != (alert.Observation{}) {
		t.Fatalf("rewritten-only sighting = %+v, want an HTTP client with no observation", f)
	}
	if f := findings[2]; f.Attribution != admission.AttributionUnknown || f.Observation != (alert.Observation{}) {
		t.Fatalf("unseen address = %+v, want nothing", f)
	}
}

// On a rewriting host the peer log decides: a client logged for its own
// connection mints as on a direct host, one behind a trusted proxy or a CDN
// edge is unreachable, and one another peer chose is forged. Apache and
// LiteSpeed alike.
func TestAdmissionEvidenceUsesThePeerVerdict(t *testing.T) {
	for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
		for _, tc := range []struct {
			name string
			peer string
			want admission.Cause
		}{
			{"direct", "203.0.113.70", 0},
			{"proxied", "198.51.100.200", admission.CauseUnreachable},
			{"forged", "127.0.0.1", admission.CauseForgedClient},
		} {
			t.Run(string(server)+"/"+tc.name, func(t *testing.T) {
				withWebPeers(t, 500000)
				withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: server, Directive: "useIpInProxyHeader 2"})
				cfg := &config.Config{}
				cfg.WebServer.TrustedProxies = []string{"198.51.100.200"}
				f := httpPeerFinding("203.0.113.70")
				ObserveWebPeer(f.Observation.ObservedAt, netip.MustParseAddr(tc.peer), netip.MustParseAddr("203.0.113.70"), cfg)
				producer, in, err := AdmissionEvidence(f)
				if tc.want != 0 {
					if admission.CauseOf(err) != tc.want {
						t.Fatalf("AdmissionEvidence = %v, want cause %v", err, tc.want)
					}
					return
				}
				if err != nil || producer != ProducerAccessLog || in.Attribution != admission.AttributionHTTPPeer || in.Target.Key() != "ip:203.0.113.70" {
					t.Fatalf("AdmissionEvidence = %s %+v, %v; want the direct peer minted", producer, in, err)
				}
			})
		}
	}
}

// Without a peer log line the rewrite still cannot be verified.
func TestAdmissionEvidenceUnknownVerdictKeepsRewrittenRefusal(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	if _, _, err := AdmissionEvidence(httpPeerFinding("203.0.113.71")); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("AdmissionEvidence = %v, want rewritten_log", err)
	}
}

// A trusted chain names a client behind a proxy whatever the peer log says.
func TestAdmissionEvidenceChainIgnoresVerdict(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	f := httpPeerFinding("203.0.113.72")
	f.Attribution = admission.AttributionTrustedHTTPChain
	ObserveWebPeer(f.Observation.ObservedAt, netip.MustParseAddr("203.0.113.72"), netip.MustParseAddr("203.0.113.72"), &config.Config{})
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("AdmissionEvidence = %v, want rewritten_log", err)
	}
}

// A rewritten access-log sighting the peer log verifies as direct is a
// sighting like a direct host's; otherwise it stays the rewritten log's.
func TestReputationVerifiedRewrittenSighting(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	for _, direct := range []bool{true, false} {
		t.Run(map[bool]string{true: "direct", false: "unverified"}[direct], func(t *testing.T) {
			withWebPeers(t, 500000)
			withHTTPRewrite(t, activeRewrite)
			if direct {
				ObserveWebPeer(at, netip.MustParseAddr("203.0.113.73"), netip.MustParseAddr("203.0.113.73"), &config.Config{})
			}
			cfg := listIPs(t, "203.0.113.73")
			sightingLogs(t, map[string]string{sightingAccessLog: sightingLines("203.0.113.73", at)["HTTP request"] + "\n"})
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "203.0.113.73")
			if direct {
				if f.Attribution != admission.AttributionDerived || f.Observation.Producer != string(ProducerReputationScan) {
					t.Fatalf("verified sighting = %+v, want derived evidence", f)
				}
				return
			}
			if f.Attribution != admission.AttributionHTTPPeer || f.Observation != (alert.Observation{}) {
				t.Fatalf("unverified sighting = %+v, want the rewritten log's client", f)
			}
		})
	}
}

// The scan clock and newer traffic cannot change the peer window of a
// request read by the scheduled domlog scan.
func TestDomlogPeerVerdictUsesRequestTime(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	const ip = "203.0.113.74"
	client := netip.MustParseAddr(ip)
	cfg := &config.Config{}
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, domlogTestLine(ip, i, "POST", "/wp-login.php", 200, "Mozilla/5.0"))
	}
	ObserveWebPeer(domlogTestTime(19), netip.MustParseAddr("192.0.2.250"), client, cfg)
	ObserveWebPeer(domlogTestTime(19).Add(90*time.Minute), client, client, cfg)
	_, findings := scanDomlogFile(t, cfg, nopBotClassifier{}, lines)
	f := oneScanFinding(t, findings, "wp_login_bruteforce")
	if !f.Observation.ObservedAt.Equal(domlogTestTime(19)) {
		t.Fatalf("observation time = %v, want request time", f.Observation.ObservedAt)
	}
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseForgedClient {
		t.Fatalf("admission = %v, want forged_client", err)
	}
}

// Reputation must verify the line's time, not the scan time or the time
// of another line from the same address.
func TestReputationPeerVerdictUsesEachRequestTime(t *testing.T) {
	const ip = "203.0.113.75"
	client := netip.MustParseAddr(ip)
	at := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	for _, direct := range []bool{true, false} {
		t.Run(fmt.Sprintf("direct=%v", direct), func(t *testing.T) {
			withWebPeers(t, 500000)
			withHTTPRewrite(t, activeRewrite)
			cfg := listIPs(t, ip)
			other := netip.MustParseAddr("192.0.2.250")
			oldPeer, recentPeer := other, client
			if direct {
				oldPeer, recentPeer = client, other
			}
			ObserveWebPeer(at, oldPeer, client, cfg)
			ObserveWebPeer(time.Now(), recentPeer, client, cfg)
			lines := sightingLines(ip, at)["HTTP request"] + "\n"
			if direct {
				// The newer forged request cannot supply a record or erase the
				// independent older direct sighting.
				lines += sightingLines(ip, time.Now().Add(-time.Second))["HTTP request"] + "\n"
			}
			sightingLogs(t, map[string]string{sightingAccessLog: lines})
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), ip)
			if direct {
				if f.Attribution != admission.AttributionDerived || !f.Observation.ObservedAt.Equal(at) {
					t.Fatalf("finding = %+v, want the older direct sighting", f)
				}
			} else if f.Attribution != admission.AttributionHTTPPeer || f.Observation != (alert.Observation{}) {
				t.Fatalf("finding = %+v, want unverified rewritten client", f)
			}
		})
	}
}

func TestAdmissionPeerVerdictKeepsCDNEdgeRefusalFirst(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	f := httpPeerFinding("198.51.100.75")
	client := netip.MustParseAddr(f.SourceIP)
	ObserveWebPeer(f.Observation.ObservedAt, client, client, &config.Config{})
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("admission = %v, want proxy_peer before direct verdict", err)
	}
}

// The web server writes a request's peer line with its access line but may
// flush it later, and CSM reads the two logs on separate polls. A direct
// verdict stands only after the peer log is read again a settle period after
// the finding's line was read, so a forged line still on its way is not
// outvoted by the client's earlier direct lines.
func TestAdmissionEvidenceWaitsForTheRequestsOwnPeerLine(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed, Directive: "useIpInProxyHeader 2"})
	cfg := &config.Config{}
	f := httpPeerFinding("203.0.113.74")
	f.Timestamp = f.Observation.ObservedAt.Add(time.Second)
	client := netip.MustParseAddr("203.0.113.74")
	// The victim's own later request was read; the forged one is in flight.
	ObserveWebPeer(f.Observation.ObservedAt.Add(time.Second), client, client, cfg)
	var slept []time.Duration
	webPeerSleep = func(d time.Duration) { slept = append(slept, d) }
	webPeerClock = func() time.Time { return f.Timestamp }
	drains := 0
	SetWebPeerDrain(func(time.Duration) bool {
		if drains++; drains == 2 {
			ObserveWebPeer(f.Observation.ObservedAt, netip.MustParseAddr("127.0.0.1"), client, cfg)
		}
		return true
	})
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseForgedClient {
		t.Fatalf("AdmissionEvidence = %v, want the request's own forged line to decide", err)
	}
	if len(slept) != 1 || slept[0] != webPeerSettle || drains != 2 {
		t.Fatalf("slept %v over %d drains, want one %v wait between two drains", slept, drains, webPeerSettle)
	}
}

// A reputation scan must not turn an unsettled HTTP sighting into derived
// evidence, which bypasses HTTP verification when it is later minted.
func TestReputationWaitsForSightingPeerFlush(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	const ip = "203.0.113.84"
	cfg := listIPs(t, ip)
	now := time.Now().Truncate(time.Second)
	at := now.Add(-time.Second)
	sightingLogs(t, map[string]string{sightingAccessLog: sightingLines(ip, at)["HTTP request"] + "\n"})
	client := netip.MustParseAddr(ip)
	ObserveWebPeer(at.Add(-time.Minute), client, client, cfg)
	webPeerClock = func() time.Time { return now }
	webPeerSleep = func(d time.Duration) { now = now.Add(d) }
	reads := 0
	SetWebPeerDrain(func(time.Duration) bool {
		reads++
		if reads == 2 {
			ObserveWebPeer(at, netip.MustParseAddr("192.0.2.84"), client, cfg)
		}
		return true
	})
	f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), ip)
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("unsettled reputation sighting minted: %v, attribution %v", err, f.Attribution)
	}
	if reads != 2 {
		t.Fatalf("peer reads = %d, want 2", reads)
	}
}

func TestAutoBlockPeerFindingsShareSettleWait(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	withBlocker(t)
	withChallengeList(t, nil)
	a := withAdmission(t)
	cfg := liveAutoBlockConfig(t)
	now := time.Now()
	at := now
	webPeerClock = func() time.Time { return now }
	var waited time.Duration
	webPeerSleep = func(d time.Duration) { waited += d; now = now.Add(d) }
	minted := 0
	a.mint = func(f alert.Finding) admission.Evidence {
		if _, _, err := AdmissionEvidence(f); err != nil {
			t.Errorf("mint: %v", err)
		}
		minted++
		return admission.Evidence{}
	}
	var findings []alert.Finding
	for _, ip := range []string{"203.0.113.85", "203.0.113.86", "203.0.113.87"} {
		f := httpPeerFinding(ip)
		f.Timestamp, f.Observation.ObservedAt = at, at
		findings = append(findings, f)
		client := netip.MustParseAddr(ip)
		ObserveWebPeer(at, client, client, cfg)
	}
	AutoBlockIPs(cfg, findings)
	if minted != len(findings) || waited != webPeerSettle {
		t.Fatalf("minted %d with wait %v, want %d with wait %v", minted, waited, len(findings), webPeerSettle)
	}
}

func TestReputationPeerSightingsShareReadDeadline(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, activeRewrite)
	now := time.Now().Truncate(time.Second)
	at := now.Add(-time.Minute)
	cfg := &config.Config{}
	var lines []string
	for _, ip := range []string{"203.0.113.88", "203.0.113.89", "203.0.113.90"} {
		lines = append(lines, sightingLines(ip, at)["HTTP request"])
		client := netip.MustParseAddr(ip)
		ObserveWebPeer(at, client, client, cfg)
	}
	sightingLogs(t, map[string]string{sightingAccessLog: strings.Join(lines, "\n") + "\n"})
	webPeerClock = func() time.Time { return now }
	var waited time.Duration
	webPeerSleep = func(d time.Duration) { waited += d; now = now.Add(d) }
	_, records, _ := collectRecentSightings(cfg, now)
	if len(records) != 3 || waited != webPeerSettle {
		t.Fatalf("got %d records with wait %v, want 3 with wait %v", len(records), waited, webPeerSettle)
	}
}

// A forged request whose peer line never reached the log is not verified by
// the victim's earlier direct connections.
func TestAdmissionEvidenceRefusesWithoutTheRequestsOwnLine(t *testing.T) {
	withWebPeers(t, 500000)
	withHTTPRewrite(t, HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed, Directive: "useIpInProxyHeader 2"})
	f := httpPeerFinding("203.0.113.91")
	client := netip.MustParseAddr("203.0.113.91")
	ObserveWebPeer(f.Observation.ObservedAt.Add(-20*time.Minute), client, client, &config.Config{})
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("AdmissionEvidence = %v, want the rewritten_log refusal", err)
	}
}

// Apache that buffers its logs per process can hold a forged peer line for
// as long as it likes; such a tree, or one CSM cannot read whole, says so.
func TestApacheBufferedLogsDetected(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, conf string
		want       bool
	}{
		{"default", "LogFormat \"%a %l %u %t \\\"%r\\\" %>s %b\" combined\nCustomLog logs/access_log combined\n", false},
		{"off", "BufferedLogs Off\nCustomLog logs/access_log combined\n", false},
		{"on", "BufferedLogs On\nCustomLog logs/access_log combined\n", true},
		{"on in a section", "<IfModule log_config_module>\n  BufferedLogs on\n</IfModule>\n", true},
	} {
		conf := writeRewriteFile(t, dir, tc.name+".conf", tc.conf)
		if got := detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf}); got.BufferedLogs != tc.want {
			t.Errorf("%s: BufferedLogs = %v, want %v", tc.name, got.BufferedLogs, tc.want)
		}
	}
}
