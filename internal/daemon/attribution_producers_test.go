package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Every finding a stamped producer emits for an evidence check says how its
// parser read the address (spec 5.8): a mail, SSH, FTP or panel parser reads
// the transport peer, an HTTP parser the direct socket peer. Each test below
// drives one emitting path.

func wantAttribution(t *testing.T, f alert.Finding, want admission.Attribution) {
	t.Helper()
	if f.Attribution != want {
		t.Errorf("%s from %s: attribution %s, want %s", f.Check, f.SourceIP, f.Attribution, want)
	}
}

func firstOf(t *testing.T, check string, record func() []alert.Finding, tries int) alert.Finding {
	t.Helper()
	for i := 0; i < tries; i++ {
		if f, ok := findingByCheck(record(), check); ok {
			return f
		}
	}
	t.Fatalf("no %s after %d records", check, tries)
	return alert.Finding{}
}

func TestMailBruteForceNamesThePeer(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	wantAttribution(t, firstOf(t, "mail_bruteforce", func() []alert.Finding { return tr.Record("192.0.2.51", "carol@example.com") }, 5), admission.AttributionPeer)
}

func TestMailSlowBruteForceNamesThePeer(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	accounts := []string{"a@example.ro", "b@example.ro", "c@example.com", "d@example.com"}
	i := 0
	f := firstOf(t, "mail_bruteforce", func() []alert.Finding {
		i++
		clock.advance(8 * time.Minute)
		return tr.Record("198.51.100.21", accounts[i%len(accounts)])
	}, 60)
	wantAttribution(t, f, admission.AttributionPeer)
}

func TestMailCompromiseNamesThePeer(t *testing.T) {
	withOwnerTable(t)
	clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("192.0.2.50", "carol@example.com")
	}
	wantAttribution(t, onlyCheck(t, tr.RecordSuccess("192.0.2.50", "carol@example.com"), "mail_account_compromised"), admission.AttributionPeer)
}

func TestSMTPBruteForceNamesThePeer(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	wantAttribution(t, firstOf(t, "smtp_bruteforce", func() []alert.Finding { return tr.Record("192.0.2.52", "carol@example.com") }, 5), admission.AttributionPeer)

	slow := newTestTracker(t, clock)
	accounts := []string{"a@example.ro", "b@example.ro", "c@example.com", "d@example.com"}
	i := 0
	f := firstOf(t, "smtp_bruteforce", func() []alert.Finding {
		i++
		clock.advance(8 * time.Minute)
		return slow.Record("198.51.100.7", accounts[i%len(accounts)])
	}, 60)
	wantAttribution(t, f, admission.AttributionPeer)
}

func TestSMTPProbeAbuseNamesThePeer(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)
	wantAttribution(t, firstOf(t, "smtp_probe_abuse", func() []alert.Finding { return tr.Record("192.0.2.53") }, 100), admission.AttributionPeer)
}

func TestCloudRelayAbuseNamesThePeer(t *testing.T) {
	withOwnerTable(t)
	resetCloudRelayState()
	t.Cleanup(resetCloudRelayState)
	cfg := cloudRelayTestConfig()
	var findings []alert.Finding
	for _, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		findings = append(findings, parseEximLogLine(gceSendLine("info@example.net", ip+".bc.googleusercontent.com", ip), cfg)...)
	}
	wantAttribution(t, onlyCheck(t, findings, "email_cloud_relay_abuse"), admission.AttributionPeer)
}

func TestMailSprayVerdictsNameThePeer(t *testing.T) {
	now := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	for _, v := range []*sprayVerdict{
		{Rule: sprayRuleBreadth, Block: true, Targets: []string{"b@example.com"}, BlockTTL: time.Hour},
		{Rule: sprayRuleCompromise, Block: true, Mailbox: "a@example.com", BlockTTL: time.Hour},
	} {
		for _, proto := range []mailProto{protoSMTP, protoMail} {
			wantAttribution(t, sprayFinding(proto, "192.0.2.54", v, sprayEnforce, now), admission.AttributionPeer)
		}
	}
}

func TestPAMFindingsNameThePeer(t *testing.T) {
	p, alertCh := observingPAMListener(t)
	p.processEvent("FAIL ip=192.0.2.60 user=alice service=sshd pid=4242 ts=1790000000.100000000")
	p.processEvent("FAIL ip=192.0.2.60 user=alice service=sshd pid=4243 ts=1790000001.200000000")
	got := drainForCheck(alertCh, "pam_bruteforce")
	if got == nil {
		t.Fatal("no pam_bruteforce finding")
	}
	wantAttribution(t, *got, admission.AttributionPeer)

	p, alertCh = observingPAMListener(t)
	p.cfg.Thresholds.PAMBruteforceThreshold = 100
	p.cfg.Thresholds.CredStuffingDistinctAccounts = 3
	for _, user := range []string{"alice", "bob", "carol"} {
		p.processEvent("FAIL ip=203.0.113.20 user=" + user + " service=sshd")
	}
	if got = drainForCheck(alertCh, "credential_stuffing"); got == nil {
		t.Fatal("no credential_stuffing finding")
	}
	wantAttribution(t, *got, admission.AttributionPeer)
}

func TestFTPAuthFailureNamesThePeer(t *testing.T) {
	f := onlyCheck(t, parseFTPLogLine("pure-ftpd: (?@198.51.100.7) [WARNING] Authentication failed for user [bob]", &config.Config{}), "ftp_auth_failure_realtime")
	wantAttribution(t, f, admission.AttributionPeer)
}

func TestCpanelAPIFailureNamesThePeer(t *testing.T) {
	line := `198.51.100.10 - - [11/Apr/2026:12:00:00 +0000] "POST /cpsess1234567/json-api/fileman/upload_files HTTP/1.1" 401 123 "-" "Mozilla/5.0"`
	wantAttribution(t, onlyCheck(t, parseAccessLogLineEnhanced(line, &config.Config{}), "api_auth_failure_realtime"), admission.AttributionPeer)
}

func TestWebBruteForceNamesTheHTTPPeer(t *testing.T) {
	for check, path := range map[string]string{
		"wp_login_bruteforce":    "/wp-login.php",
		"xmlrpc_abuse":           "/xmlrpc.php",
		"admin_panel_bruteforce": "/phpmyadmin/index.php",
	} {
		resetAccessLogTrackerState()
		cfg := &config.Config{}
		cfg.Thresholds.XMLRPCThreshold = 5
		f := firstOf(t, check, func() []alert.Finding {
			return parseAccessLogBruteForce(makeAccessLogLine("203.0.113.5", "POST", path), cfg)
		}, 50)
		wantAttribution(t, f, admission.AttributionHTTPPeer)
	}
	resetAccessLogTrackerState()
}

func TestModSecEscalationNamesTheHTTPPeer(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	line := `[Wed Apr 01 17:13:54.047783 2026] [error] [client 203.0.113.61] ModSecurity: Access denied with code 403, [Rule: 'REQUEST_URI' '/\.env'] [id "900115"] [msg "CSM VP: Blocked .env file access"] [hostname "edge.example.net"] [uri "/.env_sample"]`
	f := firstOf(t, "modsec_csm_block_escalation", func() []alert.Finding { return parseModSecLogLineDeduped(line, &config.Config{}) }, 3)
	wantAttribution(t, f, admission.AttributionHTTPPeer)
}
