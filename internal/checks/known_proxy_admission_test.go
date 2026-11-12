package checks

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func httpPeerFinding(ip string) alert.Finding {
	return alert.Finding{
		Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: ip,
		Attribution: admission.AttributionHTTPPeer,
		Observation: alert.Observation{Producer: string(ProducerAccessLog), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: time.Now()},
	}
}

// An HTTP finding that names a known CDN or website-firewall edge asks for
// nothing: that address carries every visitor behind it.
func TestAdmissionEvidenceRefusesAKnownProxyPeer(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	if _, _, err := AdmissionEvidence(httpPeerFinding("198.51.100.7")); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("known proxy edge: %v, want the proxy_peer cause", err)
	}
	if _, _, err := AdmissionEvidence(httpPeerFinding("203.0.113.9")); err != nil {
		t.Fatalf("ordinary HTTP peer: %v, want evidence", err)
	}
	ssh := httpPeerFinding("198.51.100.7")
	ssh.Check, ssh.Attribution = "ssh_login_unknown_ip", admission.AttributionPeer
	ssh.Observation.Producer = string(ProducerSSHLog)
	if _, _, err := AdmissionEvidence(ssh); admission.CauseOf(err) == admission.CauseProxyPeer {
		t.Fatal("a session peer is refused as an HTTP proxy edge")
	}
}

// The reverse-proxy ASN list is read from the live configuration, so a
// reload that changes thresholds.http_asn_crawl_reverse_proxy_asns applies.
func TestAdmissionEvidenceReadsTheLiveReverseProxyASNs(t *testing.T) {
	withKnownProxyPrefixes(t)
	SetASNLookup(func(string) (uint, string) { return 64512, "Edge" })
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := &config.Config{}
	cfg.Thresholds.HTTPASNCrawlReverseProxyASNs = []uint{64512}
	config.SetActive(cfg)
	if _, _, err := AdmissionEvidence(httpPeerFinding("203.0.113.9")); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("reverse-proxy ASN: %v, want the proxy_peer cause", err)
	}
	next := &config.Config{}
	config.SetActive(next)
	if _, _, err := AdmissionEvidence(httpPeerFinding("203.0.113.9")); err != nil {
		t.Fatalf("after the list was emptied: %v, want evidence", err)
	}
}

// The domlog scan keeps its legacy finding against a known proxy edge, and
// admission refuses it.
func TestDomlogScanFindingFromAKnownProxyIsRefused(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(`198.51.100.7 - - [09/Nov/2026:12:01:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"`, i))
	}
	_, findings := scanDomlogFile(t, &config.Config{}, nopBotClassifier{}, lines)
	f := oneScanFinding(t, findings, "wp_login_bruteforce")
	if f.SourceIP != "198.51.100.7" || f.Attribution != admission.AttributionHTTPPeer {
		t.Fatalf("legacy finding changed: %s read as %s", f.SourceIP, f.Attribution)
	}
	if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("mint: %v, want the proxy_peer cause", err)
	}
}

func requireKnownProxyGateOutcome(t *testing.T, f alert.Finding, want admission.Cause) {
	t.Helper()
	producer, in, err := AdmissionEvidence(f)
	if want != 0 {
		reason, ok := admission.ReasonOf(err)
		if !ok || reason != admission.ReasonAttribution || admission.CauseOf(err) != want {
			t.Fatalf("refusal = %v, want attribution/%s", err, want)
		}
		if producer != "" || !reflect.DeepEqual(in, admission.EvidenceInput{}) {
			t.Fatalf("refusal returned evidence input: %s %+v", producer, in)
		}
		return
	}
	if err != nil || string(producer) != f.Observation.Producer || in.Check != f.Check ||
		in.Attribution != f.Attribution || in.Target.Key() != "ip:"+f.SourceIP {
		t.Fatalf("evidence = %s %+v, %v; want the original peer", producer, in, err)
	}
}

func TestAdmissionEvidenceHandlesAbsentConfig(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(func(string) (uint, string) { return 64512, "Edge" })
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	config.SetActive(nil)
	requireKnownProxyGateOutcome(t, httpPeerFinding("198.51.100.7"), admission.CauseProxyPeer)
	requireKnownProxyGateOutcome(t, httpPeerFinding("203.0.113.9"), 0)
	for _, enabled := range []bool{false, true} {
		cfg := &config.Config{}
		cfg.Cloudflare.Enabled = enabled
		cfg.Thresholds.HTTPASNCrawlReverseProxyASNs = []uint{64512}
		config.SetActive(cfg)
		requireKnownProxyGateOutcome(t, httpPeerFinding("198.51.100.7"), admission.CauseProxyPeer)
		requireKnownProxyGateOutcome(t, httpPeerFinding("203.0.113.9"), admission.CauseProxyPeer)
		SetASNLookup(nil)
		requireKnownProxyGateOutcome(t, httpPeerFinding("198.51.100.7"), admission.CauseProxyPeer)
		requireKnownProxyGateOutcome(t, httpPeerFinding("203.0.113.9"), 0)
		SetASNLookup(func(string) (uint, string) { return 64512, "Edge" })
	}
}

func TestAdmissionEvidencePreservesSessionPeers(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	for _, tc := range []struct {
		producer admission.ProducerID
		check    string
	}{
		{ProducerSSHLog, "ssh_login_unknown_ip"},
		{ProducerSSHLoginScan, "ssh_login_unknown_ip"},
		{ProducerPAMSocket, "pam_bruteforce"},
		{ProducerEximLog, "smtp_bruteforce"},
		{ProducerEximHistory, "email_cloud_relay_abuse"},
		{ProducerMailLog, "mail_bruteforce"},
		{ProducerFTPLog, "ftp_auth_failure_realtime"},
		{ProducerFTPScan, "ftp_bruteforce"},
	} {
		t.Run(string(tc.producer), func(t *testing.T) {
			f := httpPeerFinding("198.51.100.7")
			f.Check, f.Attribution = tc.check, admission.AttributionPeer
			f.Observation.Producer = string(tc.producer)
			requireKnownProxyGateOutcome(t, f, 0)
		})
	}
}

func TestAdmissionEvidenceRefusesEveryHTTPProducer(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	for _, tc := range []struct {
		producer admission.ProducerID
		check    string
	}{
		{ProducerAccessLog, "wp_login_bruteforce"},
		{ProducerDomlogScan, "wp_login_bruteforce"},
		{ProducerModSecLog, "modsec_block_escalation"},
		{ProducerModSecAuditScan, "waf_attack_blocked"},
	} {
		t.Run(string(tc.producer), func(t *testing.T) {
			f := httpPeerFinding("198.51.100.7")
			f.Check, f.Observation.Producer = tc.check, string(tc.producer)
			requireKnownProxyGateOutcome(t, f, admission.CauseProxyPeer)
			f.SourceIP = "203.0.113.9"
			requireKnownProxyGateOutcome(t, f, 0)
		})
	}
	chain := httpPeerFinding("198.51.100.7")
	chain.Attribution = admission.AttributionTrustedHTTPChain
	requireKnownProxyGateOutcome(t, chain, admission.CauseUnreachable)
}

// A cpsrvd peer is a web server's peer too (CDNs proxy the cPanel ports),
// and reputation intel on an edge describes the address every visitor
// behind it shares: both are refused like an HTTP peer.
func TestAdmissionEvidenceRefusesPanelAndIntelEdges(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	for _, tc := range []struct {
		producer admission.ProducerID
		check    string
		kind     admission.Attribution
	}{
		{ProducerCpanelAccessLog, "api_auth_failure_realtime", admission.AttributionPeer},
		{ProducerCpanelScan, "api_auth_failure", admission.AttributionPeer},
		{ProducerCpanelScan, "webmail_bruteforce", admission.AttributionPeer},
		{ProducerReputationScan, "ip_reputation", admission.AttributionDerived},
	} {
		t.Run(tc.check, func(t *testing.T) {
			f := httpPeerFinding("198.51.100.7")
			f.Check, f.Attribution = tc.check, tc.kind
			f.Observation.Producer = string(tc.producer)
			requireKnownProxyGateOutcome(t, f, admission.CauseProxyPeer)
			f.SourceIP = "203.0.113.9"
			requireKnownProxyGateOutcome(t, f, 0)
		})
	}
}

// An IP reputation finding whose local sighting is a request from a known
// edge keeps its legacy finding, and admission refuses it.
func TestReputationFindingFromAKnownProxyIsRefused(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	cfg := listIPs(t, "198.51.100.7")
	sightingLogs(t, map[string]string{sightingAccessLog: sightingLines("198.51.100.7", at)["HTTP request"] + "\n"})
	f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), "198.51.100.7")
	if f.Attribution != admission.AttributionDerived || f.Observation.Producer != string(ProducerReputationScan) {
		t.Fatalf("legacy finding changed: %s read as %s from %q", f.SourceIP, f.Attribution, f.Observation.Producer)
	}
	if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("mint: %v, want the proxy_peer cause", err)
	}
}

// A Stalwart ban names the peer of a mail listener; a known CDN or proxy edge
// there carries other clients and is refused like a cPanel peer.
func TestAdmissionEvidenceRefusesStalwartProxyEdge(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	f := httpPeerFinding("198.51.100.7")
	f.Check, f.Severity, f.Attribution = "stalwart_ban", alert.High, admission.AttributionPeer
	f.Observation.Producer = string(ProducerStalwartLog)
	if _, _, err := AdmissionEvidence(f); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("Stalwart ban of a proxy edge: %v, want the proxy_peer cause", err)
	}
	f.SourceIP = "203.0.113.9"
	if _, _, err := AdmissionEvidence(f); err != nil {
		t.Fatalf("ordinary Stalwart ban: %v, want evidence", err)
	}
}
