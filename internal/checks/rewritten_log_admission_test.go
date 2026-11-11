package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
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
// HTTP producer, before the trusted-chain and known-edge checks, whether
// rewriting is detected or cannot be ruled out. Session and cpsrvd peers
// are read by their own servers and keep their evidence.
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
			requireKnownProxyGateOutcome(t, f, admission.CauseRewrittenLog)
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
// unknown, is not a sighting of the address it names; a cPanel access line
// still is in every state. The legacy finding stays either way.
func TestReputationIgnoresRewrittenAccessLogSightings(t *testing.T) {
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := sightingLines("203.0.113.60", at)
	for _, step := range []struct {
		name string
		rw   HTTPRewrite
		http admission.Cause
	}{
		{"direct", HTTPRewrite{State: RewriteNone}, 0},
		{"rewritten", activeRewrite, admission.CauseNoObservation},
		{"unknown", HTTPRewrite{State: RewriteUnknown, Reason: "unreadable"}, admission.CauseNoObservation},
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
