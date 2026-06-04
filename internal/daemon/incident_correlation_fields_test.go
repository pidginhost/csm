package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

// These tests guard the contract that high-volume realtime detectors
// populate the structured correlation fields on alert.Finding. Without
// them, KeyFor returns an empty key and the incident correlator drops
// the finding on the floor — which is what shipped before the fix and
// left the /incident "Correlated" tab permanently empty on production.

func TestEmailAuthFailureRealtimePopulatesCorrelationFields(t *testing.T) {
	line := `2026-05-09 19:26:23 dovecot_login authenticator failed for H=(localhost) [198.51.100.1]:55330: 535 Incorrect authentication data (set_id=alice@example.com)`
	cfg := &config.Config{}

	findings := parseEximLogLine(line, cfg)
	if len(findings) == 0 {
		t.Fatal("expected a finding for dovecot auth failure")
	}
	var f *struct {
		SourceIP, Mailbox, Domain string
	}
	for i := range findings {
		if findings[i].Check == "email_auth_failure_realtime" {
			f = &struct {
				SourceIP, Mailbox, Domain string
			}{findings[i].SourceIP, findings[i].Mailbox, findings[i].Domain}
			break
		}
	}
	if f == nil {
		t.Fatal("no email_auth_failure_realtime finding emitted")
	}
	if f.SourceIP != "198.51.100.1" {
		t.Errorf("SourceIP = %q, want 198.51.100.1", f.SourceIP)
	}
	if f.Mailbox != "alice@example.com" {
		t.Errorf("Mailbox = %q, want alice@example.com", f.Mailbox)
	}
	if f.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", f.Domain)
	}

	// Round-trip through KeyFor — the regression we are guarding against
	// is "KeyFor returns empty so correlator silently drops the finding".
	for i := range findings {
		if findings[i].Check != "email_auth_failure_realtime" {
			continue
		}
		k := incident.KeyFor(findings[i])
		if k.IsEmpty() {
			t.Fatalf("KeyFor returned empty key for %+v", findings[i])
		}
	}
}

// Bare set_id (cPanel-local mailbox without "@domain") must attribute to
// the cPanel account, not to SourceIP. Otherwise brute-force attempts
// against one local mailbox from many attacker IPs each open their own
// incident keyed by the attacker IP, instead of one incident grouped by
// the targeted account.
func TestEmailAuthFailureBareSetIDAttributesToAccount(t *testing.T) {
	line := `2026-05-09 19:26:23 dovecot_login authenticator failed for H=(localhost) [203.0.113.10]:55330: 535 Incorrect authentication data (set_id=maxwell)`
	cfg := &config.Config{}

	findings := parseEximLogLine(line, cfg)
	var f alert.Finding
	for _, x := range findings {
		if x.Check == "email_auth_failure_realtime" {
			f = x
			break
		}
	}
	if f.Check == "" {
		t.Fatal("no email_auth_failure_realtime finding emitted")
	}
	if f.Mailbox != "" {
		t.Errorf("Mailbox = %q, want empty for bare set_id", f.Mailbox)
	}
	if f.Domain != "" {
		t.Errorf("Domain = %q, want empty for bare set_id", f.Domain)
	}
	if f.TenantID != "maxwell" {
		t.Errorf("TenantID = %q, want maxwell", f.TenantID)
	}
	k := incident.KeyFor(f)
	if k.Account != "maxwell" {
		t.Errorf("KeyFor.Account = %q, want maxwell", k.Account)
	}
	if k.RemoteIP != "" {
		t.Errorf("RemoteIP = %q, want empty (account beats IP fallback)", k.RemoteIP)
	}
}

func TestSMTPProbePopulatesSourceIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tracker := newSMTPProbeTracker(1, time.Minute, time.Hour, 10, func() time.Time {
		return now
	}, nil)

	findings := tracker.Record("203.0.113.44")
	f, ok := findingByCheck(findings, "smtp_probe_abuse")
	if !ok {
		t.Fatal("no smtp_probe_abuse finding emitted")
	}
	if f.SourceIP != "203.0.113.44" {
		t.Errorf("SourceIP = %q, want 203.0.113.44", f.SourceIP)
	}
	assertCorrelates(t, f)
}

func TestSMTPAuthTrackerPopulatesCorrelationFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tracker := newSMTPAuthTracker(1, 2, 2, time.Minute, time.Hour, 10, func() time.Time {
		return now
	})

	findings := tracker.Record("203.0.113.10", "alice@example.com")
	brute, ok := findingByCheck(findings, "smtp_bruteforce")
	if !ok {
		t.Fatal("no smtp_bruteforce finding emitted")
	}
	if brute.SourceIP != "203.0.113.10" {
		t.Errorf("smtp_bruteforce SourceIP = %q, want 203.0.113.10", brute.SourceIP)
	}
	assertCorrelates(t, brute)

	now = now.Add(time.Second)
	findings = tracker.Record("203.0.113.11", "alice@example.com")
	subnet, ok := findingByCheck(findings, "smtp_subnet_spray")
	if !ok {
		t.Fatal("no smtp_subnet_spray finding emitted")
	}
	if subnet.SourceIP != "203.0.113.0/24" {
		t.Errorf("smtp_subnet_spray SourceIP = %q, want 203.0.113.0/24", subnet.SourceIP)
	}
	assertCorrelates(t, subnet)

	account, ok := findingByCheck(findings, "smtp_account_spray")
	if !ok {
		t.Fatal("no smtp_account_spray finding emitted")
	}
	if account.Mailbox != "alice@example.com" {
		t.Errorf("smtp_account_spray Mailbox = %q, want alice@example.com", account.Mailbox)
	}
	if account.Domain != "example.com" {
		t.Errorf("smtp_account_spray Domain = %q, want example.com", account.Domain)
	}
	if account.SourceIP != "203.0.113.11" {
		t.Errorf("smtp_account_spray SourceIP = %q, want 203.0.113.11", account.SourceIP)
	}
	assertCorrelates(t, account)
}

func TestMailAuthTrackerPopulatesCorrelationFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tracker := newMailAuthTracker(1, 2, 2, time.Minute, time.Hour, 10, func() time.Time {
		return now
	})

	findings := tracker.Record("198.51.100.10", "bob@example.org")
	brute, ok := findingByCheck(findings, "mail_bruteforce")
	if !ok {
		t.Fatal("no mail_bruteforce finding emitted")
	}
	if brute.SourceIP != "198.51.100.10" {
		t.Errorf("mail_bruteforce SourceIP = %q, want 198.51.100.10", brute.SourceIP)
	}
	assertCorrelates(t, brute)

	now = now.Add(time.Second)
	findings = tracker.Record("198.51.100.11", "bob@example.org")
	subnet, ok := findingByCheck(findings, "mail_subnet_spray")
	if !ok {
		t.Fatal("no mail_subnet_spray finding emitted")
	}
	if subnet.SourceIP != "198.51.100.0/24" {
		t.Errorf("mail_subnet_spray SourceIP = %q, want 198.51.100.0/24", subnet.SourceIP)
	}
	assertCorrelates(t, subnet)

	account, ok := findingByCheck(findings, "mail_account_spray")
	if !ok {
		t.Fatal("no mail_account_spray finding emitted")
	}
	if account.Mailbox != "bob@example.org" {
		t.Errorf("mail_account_spray Mailbox = %q, want bob@example.org", account.Mailbox)
	}
	if account.Domain != "example.org" {
		t.Errorf("mail_account_spray Domain = %q, want example.org", account.Domain)
	}
	if account.SourceIP != "198.51.100.11" {
		t.Errorf("mail_account_spray SourceIP = %q, want 198.51.100.11", account.SourceIP)
	}
	assertCorrelates(t, account)

	success := tracker.RecordSuccess("198.51.100.11", "bob@example.org")
	compromised, ok := findingByCheck(success, "mail_account_compromised")
	if !ok {
		t.Fatal("no mail_account_compromised finding emitted")
	}
	if compromised.SourceIP != "198.51.100.11" {
		t.Errorf("mail_account_compromised SourceIP = %q, want 198.51.100.11", compromised.SourceIP)
	}
	if compromised.Mailbox != "bob@example.org" {
		t.Errorf("mail_account_compromised Mailbox = %q, want bob@example.org", compromised.Mailbox)
	}
	assertCorrelates(t, compromised)
}

func TestSSHLoginRealtimePopulatesSourceIP(t *testing.T) {
	line := `May  9 12:00:00 host sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 55555 ssh2: RSA SHA256:xxx`
	cfg := &config.Config{}

	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].SourceIP != "203.0.113.5" {
		t.Errorf("SourceIP = %q, want 203.0.113.5", findings[0].SourceIP)
	}
	if findings[0].TenantID != "alice" {
		t.Errorf("TenantID = %q, want alice", findings[0].TenantID)
	}
	if incident.KeyFor(findings[0]).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

// When the served vhost is a raw IP address (sites served on a bare IP
// rather than a domain name), the ModSec emit must NOT promote that IP
// into Domain. Two unrelated victim sites that happen to be reachable
// over their public IP would otherwise share a Domain key and merge
// into a single incident.
func TestModSecRawIPVhostDoesNotPopulateDomain(t *testing.T) {
	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 198.51.100.10] ModSecurity: Access denied with code 403, [id "900115"] [msg "blocked"] [hostname "176.124.111.185"] [uri "/.env"]`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Domain != "" {
		t.Errorf("Domain = %q, want empty for IP-literal vhost", f.Domain)
	}
	if f.SourceIP != "198.51.100.10" {
		t.Errorf("SourceIP = %q, want 198.51.100.10", f.SourceIP)
	}
	// IPv6-bracketed form must also be rejected, since some servers log
	// the literal bracket form for raw v6 vhosts.
	line6 := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 198.51.100.10] ModSecurity: Access denied with code 403, [id "900115"] [msg "blocked"] [hostname "[2001:db8::1]"] [uri "/.env"]`
	f6 := parseModSecLogLine(line6, cfg)[0]
	if f6.Domain != "" {
		t.Errorf("Domain = %q, want empty for IPv6 bracketed vhost", f6.Domain)
	}
}

func TestModSecApacheDenyPopulatesCorrelationFields(t *testing.T) {
	line := `[Wed Apr 01 15:15:05.234401 2026] [error] [client 198.51.100.164] ModSecurity: Access denied with code 403, [Rule: 'TX:content_type' '!@within %{tx.allowed_request_content_type}'] [id "920420"] [msg "Request content type is not allowed by policy"] [logdata "|text/html|"] [severity "CRITICAL"] [hostname "www.example.com"] [uri "/xmlrpc.php"]`
	cfg := &config.Config{}

	findings := parseModSecLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SourceIP != "198.51.100.164" {
		t.Errorf("SourceIP = %q, want 198.51.100.164", f.SourceIP)
	}
	if f.Domain != "www.example.com" {
		t.Errorf("Domain = %q, want www.example.com", f.Domain)
	}
	if incident.KeyFor(f).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

func TestEmailRateLimitPopulatesMailboxAndDomain(t *testing.T) {
	resetEmailRateTracking()
	cfg := &config.Config{}
	cfg.EmailProtection.RateWindowMin = 60
	cfg.EmailProtection.RateWarnThreshold = 1
	cfg.EmailProtection.RateCritThreshold = 100

	findings := checkEmailRate("bob@example.org", cfg)
	if len(findings) == 0 {
		t.Fatal("expected at least one rate finding at warn threshold")
	}
	f := findings[0]
	if f.Mailbox != "bob@example.org" {
		t.Errorf("Mailbox = %q, want bob@example.org", f.Mailbox)
	}
	if f.Domain != "example.org" {
		t.Errorf("Domain = %q, want example.org", f.Domain)
	}
	if incident.KeyFor(f).IsEmpty() {
		t.Errorf("KeyFor returned empty key — finding will not correlate")
	}
}

func TestEmailRateLimitBareUserAttributesToAccount(t *testing.T) {
	resetEmailRateTracking()
	cfg := &config.Config{}
	cfg.EmailProtection.RateWindowMin = 60
	cfg.EmailProtection.RateWarnThreshold = 1
	cfg.EmailProtection.RateCritThreshold = 100

	findings := checkEmailRate("maxwell", cfg)
	if len(findings) == 0 {
		t.Fatal("expected at least one rate finding at warn threshold")
	}
	f := findings[0]
	if f.Mailbox != "" {
		t.Errorf("Mailbox = %q, want empty for bare account", f.Mailbox)
	}
	if f.Domain != "" {
		t.Errorf("Domain = %q, want empty for bare account", f.Domain)
	}
	if f.TenantID != "maxwell" {
		t.Errorf("TenantID = %q, want maxwell", f.TenantID)
	}
	k := incident.KeyFor(f)
	if k.Account != "maxwell" {
		t.Errorf("KeyFor.Account = %q, want maxwell", k.Account)
	}
	if k.RemoteIP != "" {
		t.Errorf("RemoteIP = %q, want empty (account beats IP fallback)", k.RemoteIP)
	}
}

func TestPAMLoginPopulatesSourceIP(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	listener := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  ch,
		failures: make(map[string]*pamFailureTracker),
	}

	listener.processEvent("OK ip=203.0.113.55 user=root service=sshd")
	f := <-ch
	if f.Check != "pam_login" {
		t.Fatalf("Check = %q, want pam_login", f.Check)
	}
	if f.SourceIP != "203.0.113.55" {
		t.Errorf("SourceIP = %q, want 203.0.113.55", f.SourceIP)
	}
	assertCorrelates(t, f)
}

func TestPasswordHijackPopulatesCorrelationFields(t *testing.T) {
	ch := make(chan alert.Finding, 2)
	detector := NewPasswordHijackDetector(&config.Config{}, ch, make(chan struct{}))

	detector.HandlePasswordChange("alice", "203.0.113.60")
	change := <-ch
	if change.SourceIP != "203.0.113.60" {
		t.Errorf("password change SourceIP = %q, want 203.0.113.60", change.SourceIP)
	}
	if change.TenantID != "alice" {
		t.Errorf("password change TenantID = %q, want alice", change.TenantID)
	}
	assertCorrelates(t, change)

	detector.HandleLogin("alice", "203.0.113.61")
	confirmed := <-ch
	if confirmed.SourceIP != "203.0.113.61" {
		t.Errorf("confirmed SourceIP = %q, want 203.0.113.61", confirmed.SourceIP)
	}
	if confirmed.TenantID != "alice" {
		t.Errorf("confirmed TenantID = %q, want alice", confirmed.TenantID)
	}
	assertCorrelates(t, confirmed)
}

func TestMailboxOnlyDistinguishesMailboxFromBareDomain(t *testing.T) {
	if got := mailboxOnly("alice@example.com"); got != "alice@example.com" {
		t.Errorf("full mailbox: got %q", got)
	}
	if got := mailboxOnly("example.com"); got != "" {
		t.Errorf("bare domain: got %q, want empty (so Domain field owns it)", got)
	}
	if got := mailboxOnly(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
}

func TestSplitMailAccountRoutesBareAccountToTenant(t *testing.T) {
	mailbox, domain, tenant := splitMailAccount("alice@example.com")
	if mailbox != "alice@example.com" || domain != "example.com" || tenant != "" {
		t.Fatalf("full mailbox split = (%q, %q, %q), want mailbox/domain only", mailbox, domain, tenant)
	}

	mailbox, domain, tenant = splitMailAccount("maxwell")
	if mailbox != "" || domain != "" || tenant != "maxwell" {
		t.Fatalf("bare account split = (%q, %q, %q), want tenant maxwell only", mailbox, domain, tenant)
	}
}

func findingByCheck(findings []alert.Finding, check string) (alert.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return alert.Finding{}, false
}

func assertCorrelates(t *testing.T, f alert.Finding) {
	t.Helper()
	if incident.KeyFor(f).IsEmpty() {
		t.Fatalf("KeyFor returned empty key for %+v", f)
	}
}

func resetEmailRateTracking() {
	emailRateWindows = sync.Map{}
	emailRateSuppressed.mu.Lock()
	defer emailRateSuppressed.mu.Unlock()
	emailRateSuppressed.domains = make(map[string]time.Time)
}
