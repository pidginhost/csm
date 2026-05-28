package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

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

func TestCloudRelay_SingleIPLowVolumeStaysSilent(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// A self-hosted VPS script sending a handful of mails/hr (well under
	// the volume-burst threshold) must not trigger. Simulates a legit
	// cron job emailing daily reports through the user's cpanel mailbox.
	line := gceSendLine("user@example.com", "ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4")
	for i := 0; i < 10; i++ {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("iteration %d: 10 sends from one VPS IP must not fire: %+v", i, f)
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

func TestCloudRelay_BareAuthUserAttributesToAccount(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	lines := []string{
		gceSendLine("maxwell", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("maxwell", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("maxwell", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}

	var got bool
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check != "email_cloud_relay_abuse" {
				continue
			}
			got = true
			if f.Mailbox != "" {
				t.Errorf("Mailbox = %q, want empty for bare AUTH user", f.Mailbox)
			}
			if f.Domain != "" {
				t.Errorf("Domain = %q, want empty for bare AUTH user", f.Domain)
			}
			if f.TenantID != "maxwell" {
				t.Errorf("TenantID = %q, want maxwell", f.TenantID)
			}
		}
	}
	if !got {
		t.Fatal("expected email_cloud_relay_abuse to fire")
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

func TestCloudRelay_AllowUsersSkipsDetectorOnly(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()
	// Detector-scoped allowlist: HighVolumeSenders left empty so the rate
	// detector (or anything else keying off it) still works for this user.
	cfg.EmailProtection.CloudRelay.AllowUsers = []string{"office@madconsulting.ro"}

	lines := []string{
		gceSendLine("office@madconsulting.ro", "168.135.246.35.bc.googleusercontent.com", "35.246.135.168"),
		gceSendLine("office@madconsulting.ro", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("office@madconsulting.ro", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("allow_users mailbox must not trigger cloud-relay: %+v", f)
			}
		}
	}
	// A different user from the same domain must STILL be evaluated, since
	// AllowUsers is a per-mailbox opt-out, not a per-domain one.
	resetCloudRelayState()
	otherLines := []string{
		gceSendLine("office@otherdomain.example", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("office@otherdomain.example", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("office@otherdomain.example", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	var fired bool
	for _, line := range otherLines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("non-allowlisted user must still trigger cloud-relay detection")
	}
}

func TestCloudRelay_AllowDomainsCoversAllMailboxes(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()
	cfg.EmailProtection.CloudRelay.AllowDomains = []string{"madconsulting.ro"}

	// Three different mailboxes under the allowed domain — none should fire.
	lines := []string{
		gceSendLine("office@madconsulting.ro", "168.135.246.35.bc.googleusercontent.com", "35.246.135.168"),
		gceSendLine("steluta.ghelbereu@MADCONSULTING.RO", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("amelia.savu@madconsulting.ro", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	for _, line := range lines {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("allow_domains must cover every mailbox under the domain: %+v", f)
			}
		}
	}
}

func TestCloudRelay_AllowedUserDoesNotPrimeOtherUsers(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()
	cfg.EmailProtection.CloudRelay.AllowUsers = []string{"office@madconsulting.ro"}

	// Allowed user fires twice on cloud IPs — must NOT count toward any
	// other user's window. Then a separate user does its own 3 sends from
	// distinct cloud IPs and that one MUST fire on the third event, not
	// earlier (proving the allowed mailbox didn't poison shared state).
	allowed := []string{
		gceSendLine("office@madconsulting.ro", "168.135.246.35.bc.googleusercontent.com", "35.246.135.168"),
		gceSendLine("office@madconsulting.ro", "168.135.246.35.bc.googleusercontent.com", "35.246.135.168"),
	}
	for _, line := range allowed {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				t.Fatalf("allowed user must never fire: %+v", f)
			}
		}
	}

	other := []string{
		gceSendLine("attacker@victim.example", "204.118.26.34.bc.googleusercontent.com", "34.26.118.204"),
		gceSendLine("attacker@victim.example", "4.120.237.35.bc.googleusercontent.com", "35.237.120.4"),
		gceSendLine("attacker@victim.example", "44.243.26.34.bc.googleusercontent.com", "34.26.243.44"),
	}
	var fired bool
	for _, line := range other {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("non-allowlisted user must trigger after 3 distinct cloud IPs")
	}
}

func TestIsCloudRelayAllowed_Matching(t *testing.T) {
	cases := []struct {
		name         string
		user         string
		allowUsers   []string
		allowDomains []string
		want         bool
	}{
		{name: "empty user is never allowed", user: "", allowUsers: []string{"x@y.z"}, want: false},
		{name: "no lists, no match", user: "a@b.c", want: false},
		{name: "exact user match, mixed case", user: "Office@Madconsulting.RO", allowUsers: []string{"office@madconsulting.ro"}, want: true},
		{name: "domain match, mixed case", user: "anyone@MadConsulting.ro", allowDomains: []string{"madconsulting.ro"}, want: true},
		{name: "domain in users list does NOT match", user: "anyone@madconsulting.ro", allowUsers: []string{"madconsulting.ro"}, want: false},
		{name: "user in domains list does NOT match", user: "anyone@madconsulting.ro", allowDomains: []string{"office@madconsulting.ro"}, want: false},
		{name: "user without @ is not allowed", user: "noatsign", allowDomains: []string{"madconsulting.ro"}, want: false},
		{name: "trailing-@ user is not allowed", user: "broken@", allowDomains: []string{""}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isCloudRelayAllowed(tc.user, tc.allowUsers, tc.allowDomains)
			if got != tc.want {
				t.Fatalf("isCloudRelayAllowed(%q, %v, %v) = %v, want %v",
					tc.user, tc.allowUsers, tc.allowDomains, got, tc.want)
			}
		})
	}
}

func TestCloudRelay_VolumeBurstSingleIPTriggersCritical(t *testing.T) {
	resetCloudRelayState()
	cfg := cloudRelayTestConfig()

	// Slow-burn attack pattern: attacker uses ONE AWS IP at a time and
	// bursts 18 sends in an hour to evade the multi-IP signal. Must still
	// trigger via the high-volume threshold.
	line := gceSendLine(
		"info@wizard-design.com",
		"ec2-13-38-71-129.eu-west-3.compute.amazonaws.com",
		"13.38.71.129",
	)
	var fired bool
	for i := 0; i < 20; i++ {
		for _, f := range parseEximLogLine(line, cfg) {
			if f.Check == "email_cloud_relay_abuse" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("high-volume single-IP pattern must trigger email_cloud_relay_abuse")
	}
}

func TestCloudRelay_LegitSaaSIntegrationStaysSilent(t *testing.T) {
	// Nylas / SmartBill patterns observed in production: one or two
	// authenticated sends per hour from a stable cloud IP (or two IPs
	// across the day for Nylas). Must never false-fire.
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "SmartBill single stable AWS IP",
			lines: []string{
				gceSendLine("contact@saas-user.example",
					"ec2-34-250-125-227.eu-west-1.compute.amazonaws.com", "34.250.125.227"),
				gceSendLine("contact@saas-user.example",
					"ec2-34-250-125-227.eu-west-1.compute.amazonaws.com", "34.250.125.227"),
			},
		},
		{
			name: "Nylas: 2 GCP IPs across 8 sends in a day — but only 2/hr max",
			lines: []string{
				gceSendLine("info@nylas-user.example",
					"13.166.122.34.bc.googleusercontent.com", "34.122.166.13"),
				gceSendLine("info@nylas-user.example",
					"88.89.133.34.bc.googleusercontent.com", "34.133.89.88"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCloudRelayState()
			cfg := cloudRelayTestConfig()
			for _, line := range tc.lines {
				for _, f := range parseEximLogLine(line, cfg) {
					if f.Check == "email_cloud_relay_abuse" {
						t.Fatalf("legit SaaS pattern must not fire: %+v", f)
					}
				}
			}
		})
	}
}

func TestCloudRelay_SuspendsAUTHUserNotEnvelopeFrom(t *testing.T) {
	// Attacker uses stolen credentials for real@victim.example but
	// forges the envelope-from as innocent@bystander.example. The
	// suspension side-effect must target the AUTH identity (the
	// credential being abused), not the forged sender.
	resetCloudRelayState()
	resetEmailRateState()

	cfg := cloudRelayTestConfig()

	lineTemplate := func(ptr, ip string) string {
		return "2026-04-22 14:00:00 1abc-0000-AB <= innocent@bystander.example" +
			" H=" + ptr + " (helo) [" + ip + "]:1234 P=esmtpsa" +
			" X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
			" A=dovecot_plain:real@victim.example" +
			" S=1 id=1@local" +
			` T="forged" for target@example.com`
	}
	lines := []string{
		lineTemplate("ec2-1-2-3-4.compute-1.amazonaws.com", "1.2.3.4"),
		lineTemplate("ec2-5-6-7-8.compute-1.amazonaws.com", "5.6.7.8"),
		lineTemplate("ec2-9-10-11-12.compute-1.amazonaws.com", "9.10.11.12"),
	}
	for _, line := range lines {
		parseEximLogLine(line, cfg)
	}

	emailRateSuppressed.mu.Lock()
	_, gotVictim := emailRateSuppressed.domains["victim.example"]
	_, gotBystander := emailRateSuppressed.domains["bystander.example"]
	emailRateSuppressed.mu.Unlock()

	if !gotVictim {
		t.Fatal("AUTH user's domain (victim.example) must be marked compromised")
	}
	if gotBystander {
		t.Fatal("forged envelope-from domain (bystander.example) must NOT be marked compromised")
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
	// Known-legit residential / transit / internal:
	for _, ptr := range []string{
		"pool-123.rcn.example.net",
		"87-175-241.netrunf.cytanet.com.cy",
		"mail5.am0.yahoodns.net",
		"smtp.office365.com",
		// `.compute.internal` is intentionally not a match — it is
		// both the AWS VPC-internal PTR and a generic suffix used by
		// corporate VPN / self-hosted networks. Would false-positive.
		"ip-10-0-0-5.compute.internal",
		"nfs.compute.internal",
	} {
		if isCloudProviderPTR(ptr) {
			t.Errorf("isCloudProviderPTR(%q) = true, want false (residential/transit/internal)", ptr)
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

// X16: evictCloudRelayWindows must drop per-user entries idle past
// cloudRelayEvictWindow so the sync.Map does not grow forever after a
// burst of unique senders. Active entries (lastEvent inside the window)
// must survive so an in-progress detector window is not lost mid-attack.
func TestEvictCloudRelayWindows(t *testing.T) {
	cloudRelayWindows = sync.Map{}
	t.Cleanup(func() { cloudRelayWindows = sync.Map{} })

	now := time.Unix(1_700_000_000, 0)
	stale := &cloudRelayWindow{lastEvent: now.Add(-cloudRelayEvictWindow - time.Hour)}
	fresh := &cloudRelayWindow{lastEvent: now.Add(-5 * time.Minute)}
	cloudRelayWindows.Store("stale@example.com", stale)
	cloudRelayWindows.Store("fresh@example.com", fresh)
	cloudRelayWindows.Store("bogus", "not-a-window")

	evictCloudRelayWindows(now)

	if _, ok := cloudRelayWindows.Load("stale@example.com"); ok {
		t.Errorf("stale entry survived eviction")
	}
	if _, ok := cloudRelayWindows.Load("fresh@example.com"); !ok {
		t.Errorf("fresh entry was evicted")
	}
	if _, ok := cloudRelayWindows.Load("bogus"); ok {
		t.Errorf("non-window value survived eviction")
	}
}

func TestLockCloudRelayWindowForUpdateIgnoresEvictedWindow(t *testing.T) {
	cloudRelayWindows = sync.Map{}
	t.Cleanup(func() { cloudRelayWindows = sync.Map{} })

	now := time.Unix(1_700_000_000, 0)
	user := "stale@example.com"
	stale := &cloudRelayWindow{lastEvent: now.Add(-cloudRelayEvictWindow - time.Hour)}
	stale.mu.Lock()
	cloudRelayWindows.Store(user, stale)

	locked := make(chan *cloudRelayWindow, 1)
	go func() {
		locked <- lockCloudRelayWindowForUpdate(user, now)
	}()

	time.Sleep(10 * time.Millisecond)
	cloudRelayWindows.Delete(user)
	stale.mu.Unlock()

	var got *cloudRelayWindow
	select {
	case got = <-locked:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cloud-relay window lock")
	}
	defer got.mu.Unlock()

	if got == stale {
		t.Fatalf("lock returned an evicted window")
	}
	mapped, ok := cloudRelayWindows.Load(user)
	if !ok {
		t.Fatal("window was not restored after stale eviction")
	}
	mappedWindow, ok := mapped.(*cloudRelayWindow)
	if !ok || mappedWindow != got {
		t.Fatalf("locked window is not the mapped active window")
	}
}
