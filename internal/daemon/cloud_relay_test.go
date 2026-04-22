package daemon

import (
	"strings"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func resetCloudRelayState() {
	cloudRelayWindows = sync.Map{}
}

func cloudRelayTestConfig() *config.Config {
	cfg := &config.Config{}
	// Keep rate-limit config benign so it never fires during these tests.
	cfg.EmailProtection.RateWarnThreshold = 10000
	cfg.EmailProtection.RateCritThreshold = 10001
	cfg.EmailProtection.RateWindowMin = 10
	return cfg
}

// gceSendLine builds an exim acceptance line from a GCP host for a given sender
// and source IP. Mirrors real exim_mainlog format exactly.
func gceSendLine(sender, ptr, ip string) string {
	return "2026-04-22 14:00:00 1abc-0000-AB <= " + sender +
		" H=" + ptr + " (helo.example) [" + ip + "]:44948 P=esmtpsa" +
		" X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
		" A=dovecot_plain:" + sender +
		" S=12829 id=test@occonsultingcy.com" +
		` T="cPanel Service Alert" for victim@example.com`
}

// residentialSendLine builds a line from a non-cloud ISP host.
func residentialSendLine(sender, ptr, ip string) string {
	return "2026-04-22 14:00:00 1abc-0000-AB <= " + sender +
		" H=" + ptr + " (helo.example) [" + ip + "]:44948 P=esmtpsa" +
		" X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
		" A=dovecot_plain:" + sender +
		" S=12829 id=ok@example.com" +
		` T="Regular mail" for friend@example.com`
}

func TestCloudRelay_ResidentialSenderIgnored(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// User sending from a normal residential ISP — must never alert.
	line := residentialSendLine("user@example.com", "87-175-241.netrunf.cytanet.com.cy", "87.228.175.241")
	for i := 0; i < 20; i++ {
		findings := parseEximLogLine(line, cfg)
		for _, f := range findings {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("unexpected cloud-relay finding on residential sender: %+v", f)
			}
		}
	}
}

func TestCloudRelay_SingleCloudSendDoesNotAlert(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// One send from a cloud IP is not enough — legit VPS users exist.
	line := gceSendLine("info@occonsultingcy.com", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204")
	findings := parseEximLogLine(line, cfg)
	for _, f := range findings {
		if f.Check == "email_cloud_relay_abuse" {
			t.Fatalf("single cloud send must not trigger auto-suspend: %+v", f)
		}
	}
}

func TestCloudRelay_SingleIPRepeatedlyDoesNotAlert(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// Same IP + same PTR sending 20 times = likely a legit self-hosted script.
	line := gceSendLine("info@occonsultingcy.com", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204")
	for i := 0; i < 20; i++ {
		findings := parseEximLogLine(line, cfg)
		for _, f := range findings {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("iteration %d: single-IP traffic must not fire cloud-relay: %+v", i, f)
			}
		}
	}
}

func TestCloudRelay_MultipleCloudIPsTriggersCritical(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// 3 sends from 3 distinct cloud IPs = compromised relay pattern.
	lines := []string{
		gceSendLine("info@occonsultingcy.com", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("info@occonsultingcy.com", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("info@occonsultingcy.com", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}

	var critical alert_Finding
	var haveCrit bool
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				critical = alert_Finding{Severity: f.Severity.String(), Message: f.Message}
				haveCrit = true
			}
		}
	}
	if !haveCrit {
		t.Fatalf("expected email_cloud_relay_abuse to fire after 3 distinct cloud IPs")
	}
	if critical.Severity != "CRITICAL" {
		t.Fatalf("severity = %q, want CRITICAL", critical.Severity)
	}
	// Message must include the IP so autoblock's extractIPFromFinding can pick it up.
	if !strings.Contains(critical.Message, "34.26.243.44") &&
		!strings.Contains(critical.Message, "35.237.120.4") &&
		!strings.Contains(critical.Message, "34.26.118.204") {
		t.Fatalf("message must embed a source IP for autoblock, got %q", critical.Message)
	}
}

func TestCloudRelay_DedupOneCriticalPerUserPerWindow(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// Same scenario as above, but keep feeding lines — must only alert ONCE.
	ips := []string{"34.26.118.204", "35.237.120.4", "34.26.243.44", "35.185.2.217", "104.196.13.121"}
	ptrs := []string{
		"204.118.26.34.bc.googleusercontent.com",
		"4.120.237.35.bc.googleusercontent.com",
		"44.243.26.34.bc.googleusercontent.com",
		"217.2.185.35.bc.googleusercontent.com",
		"121.13.196.104.bc.googleusercontent.com",
	}

	count := 0
	for i := 0; i < 50; i++ {
		line := gceSendLine("info@occonsultingcy.com", ptrs[i%len(ptrs)], ips[i%len(ips)])
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 critical alert across 50 lines, got %d", count)
	}
}

func TestCloudRelay_AllowlistSkips(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{"info@occonsultingcy.com"}

	lines := []string{
		gceSendLine("info@occonsultingcy.com", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("info@occonsultingcy.com", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("info@occonsultingcy.com", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("allowlisted user must not trigger cloud-relay: %+v", f)
			}
		}
	}
}

func TestCloudRelay_PerUserIsolation(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// User A sending from 3 cloud IPs — fires once. User B's single send
	// must not be affected by A's state.
	aLines := []string{
		gceSendLine("a@example.com", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("a@example.com", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("a@example.com", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	for _, l := range aLines {
		_ = parseEximLogLine(l, cfg)
	}
	bLine := gceSendLine("b@example.com", "host.compute-1.amazonaws.com", "52.1.2.3")
	for _, f := range parseEximLogLine(bLine, cfg) {
		if f.Check == "email_cloud_relay_abuse" {
			t.Fatalf("user B should not inherit user A's state: %+v", f)
		}
	}
}

func TestCloudRelay_CoversMajorProviders(t *testing.T) {
	cases := []struct {
		name string
		ptr  string
	}{
		{"GCP", "204.118.26.34.bc.googleusercontent.com"},
		{"AWS", "ec2-52-1-2-3.compute-1.amazonaws.com"},
		{"AWS-internal", "ip-10-0-0-5.compute.internal"},
		{"Azure", "vm123.cloudapp.net"},
		{"Oracle", "host123.oraclevcn.com"},
		{"DigitalOcean", "host.digitaloceanspaces.com"},
		{"Linode", "li123-45.members.linode.com"},
		{"Vultr", "123.vultrusercontent.com"},
		{"Hetzner", "static.1.2.3.4.clients.your-server.de"},
		{"OVH", "ns123.ovh.net"},
		{"Contabo", "vmi123456.contaboserver.net"},
	}
	for _, tc := range cases {
		if !isCloudProviderPTR(tc.ptr) {
			t.Errorf("%s: isCloudProviderPTR(%q) = false, want true", tc.name, tc.ptr)
		}
	}
	// Known-legit residential / transit:
	for _, ptr := range []string{
		"pool-123.rcn.example.net",
		"87-175-241.netrunf.cytanet.com.cy",
		"mail5.am0.yahoodns.net",
		"smtp.office365.com",
	} {
		if isCloudProviderPTR(ptr) {
			t.Errorf("isCloudProviderPTR(%q) = true, want false (residential/transit)", ptr)
		}
	}
}

func TestExtractEximHostname(t *testing.T) {
	cases := map[string]string{
		// Real production format: "H=hostname (helo.something) [IP]:port"
		`2026-04-22 14:55:43 1wFWBE-000000036n0-1PMK <= info@occonsultingcy.com H=204.118.26.34.bc.googleusercontent.com (occonsultingcy.com) [34.26.118.204]:47280 P=esmtpsa`: "204.118.26.34.bc.googleusercontent.com",
		// No HELO-in-parens:
		`... <= user@dom H=smtp.example.org [203.0.113.5]:25 P=esmtp`: "smtp.example.org",
		// Missing H=:
		`... <= user@dom [203.0.113.5]:25 P=esmtp`: "",
	}
	for line, want := range cases {
		got := extractEximHostname(line)
		if got != want {
			t.Errorf("extractEximHostname(%q) = %q, want %q", line, got, want)
		}
	}
}

// alert_Finding is a small shim to avoid importing alert in this test file
// (keeps test dependencies aligned with watcher_parsers_test.go style).
type alert_Finding struct {
	Severity string
	Message  string
}
