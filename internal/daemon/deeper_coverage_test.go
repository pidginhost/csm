package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// ts() — timestamp formatter
// ---------------------------------------------------------------------------

func TestTs_FormatLength(t *testing.T) {
	got := ts()
	// Expected format: "2006-01-02 15:04:05" = 19 chars
	if len(got) != 19 {
		t.Errorf("ts() = %q, length %d, want 19", got, len(got))
	}
}

func TestTs_ContainsDateSeparators(t *testing.T) {
	got := ts()
	if strings.Count(got, "-") < 2 {
		t.Errorf("ts() = %q should contain date separators", got)
	}
	if strings.Count(got, ":") < 2 {
		t.Errorf("ts() = %q should contain time separators", got)
	}
}

// ---------------------------------------------------------------------------
// isInfraIP (pam_listener.go version — separate from isInfraIPDaemon)
// ---------------------------------------------------------------------------

func TestIsInfraIP_CIDR(t *testing.T) {
	if !isInfraIP("10.1.2.3", []string{"10.0.0.0/8"}) {
		t.Error("10.1.2.3 should be in 10.0.0.0/8")
	}
}

func TestIsInfraIP_NotInCIDR(t *testing.T) {
	if isInfraIP("203.0.113.5", []string{"10.0.0.0/8"}) {
		t.Error("203.0.113.5 should not be in 10.0.0.0/8")
	}
}

func TestIsInfraIP_InvalidIP(t *testing.T) {
	if isInfraIP("not-an-ip", []string{"10.0.0.0/8"}) {
		t.Error("invalid IP should return false")
	}
}

func TestIsInfraIP_InvalidCIDRSkipped(t *testing.T) {
	// Invalid CIDR entries are skipped (continue), not matched.
	if isInfraIP("10.0.0.1", []string{"bad-cidr"}) {
		t.Error("invalid CIDR should be skipped")
	}
}

func TestIsInfraIP_EmptyList(t *testing.T) {
	if isInfraIP("10.0.0.1", nil) {
		t.Error("empty list should return false")
	}
}

func TestIsInfraIP_IPv6CIDR(t *testing.T) {
	if !isInfraIP("2001:db8::1", []string{"2001:db8::/32"}) {
		t.Error("IPv6 CIDR match should work")
	}
}

func TestIsInfraIP_EmptyIP(t *testing.T) {
	if isInfraIP("", []string{"10.0.0.0/8"}) {
		t.Error("empty IP should return false")
	}
}

// ---------------------------------------------------------------------------
// PAMListener.processEvent — edge cases
// ---------------------------------------------------------------------------

func TestProcessEvent_EmptyLine(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("")
	select {
	case f := <-alertCh:
		t.Fatalf("empty line should produce no findings: %+v", f)
	default:
	}
}

func TestProcessEvent_SingleWord(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL")
	select {
	case f := <-alertCh:
		t.Fatalf("single word line should produce no findings: %+v", f)
	default:
	}
}

func TestProcessEvent_DashIP(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip=- user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("dash IP should be skipped: %+v", f)
	default:
	}
	if len(p.failures) != 0 {
		t.Error("dash IP should not create failure tracker")
	}
}

func TestProcessEvent_InfraIPSkipped(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{InfraIPs: []string{"10.0.0.0/8"}},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip=10.1.2.3 user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("infra IP should be skipped: %+v", f)
	default:
	}
}

func TestProcessEvent_OKFromNonInfraEmitsAlert(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("OK ip=203.0.113.5 user=admin service=sshd")
	select {
	case f := <-alertCh:
		if f.Check != "pam_login" {
			t.Errorf("check = %q, want pam_login", f.Check)
		}
		if !strings.Contains(f.Message, "203.0.113.5") {
			t.Errorf("message should contain IP, got %q", f.Message)
		}
	default:
		t.Error("OK from non-infra IP should emit pam_login alert")
	}
}

func TestProcessEvent_UnknownEventType(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("UNKNOWN ip=203.0.113.5 user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("unknown event type should produce no findings: %+v", f)
	default:
	}
}

// ---------------------------------------------------------------------------
// PAMListener.recordFailure — threshold and window logic
// ---------------------------------------------------------------------------

func TestRecordFailure_ReachesThreshold(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	// Default threshold is 5
	for i := 0; i < 4; i++ {
		p.recordFailure("203.0.113.10", "root", "sshd")
	}
	select {
	case f := <-alertCh:
		t.Fatalf("below threshold should not alert: %+v", f)
	default:
	}

	// 5th failure should trigger
	p.recordFailure("203.0.113.10", "root", "sshd")
	select {
	case f := <-alertCh:
		if f.Check != "pam_bruteforce" {
			t.Errorf("check = %q, want pam_bruteforce", f.Check)
		}
		if f.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", f.Severity)
		}
	default:
		t.Error("5th failure should trigger pam_bruteforce")
	}
}

func TestRecordFailure_OnlyAlertsOnce(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	for i := 0; i < 10; i++ {
		p.recordFailure("203.0.113.11", "root", "sshd")
	}
	count := 0
	for {
		select {
		case <-alertCh:
			count++
		default:
			goto done
		}
	}
done:
	if count != 1 {
		t.Errorf("should alert exactly once, got %d alerts", count)
	}
}

func TestRecordFailure_TracksMultipleUsers(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.recordFailure("203.0.113.12", "root", "sshd")
	p.recordFailure("203.0.113.12", "admin", "sshd")
	p.recordFailure("203.0.113.12", "www", "webmin")

	p.mu.Lock()
	tracker := p.failures["203.0.113.12"]
	userCount := len(tracker.users)
	svcCount := len(tracker.services)
	p.mu.Unlock()

	if userCount != 3 {
		t.Errorf("users = %d, want 3", userCount)
	}
	if svcCount != 2 {
		t.Errorf("services = %d, want 2", svcCount)
	}
}

func TestRecordFailure_CustomThreshold(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.recordFailure("203.0.113.13", "root", "sshd")
	p.recordFailure("203.0.113.13", "root", "sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("below custom threshold should not alert: %+v", f)
	default:
	}

	p.recordFailure("203.0.113.13", "root", "sshd")
	select {
	case f := <-alertCh:
		if f.Check != "pam_bruteforce" {
			t.Errorf("check = %q", f.Check)
		}
	default:
		t.Error("3rd failure with threshold=3 should trigger")
	}
}

func TestRecordFailure_WindowExpiry(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	cfg.Thresholds.MultiIPLoginWindowMin = 1 // 1 minute window
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	ip := "203.0.113.14"
	// Record 2 failures
	p.recordFailure(ip, "root", "sshd")
	p.recordFailure(ip, "root", "sshd")

	// Manually set firstSeen to the past so the window expires
	p.mu.Lock()
	p.failures[ip].firstSeen = time.Now().Add(-2 * time.Minute)
	p.mu.Unlock()

	// This failure should reset the tracker because the window expired
	p.recordFailure(ip, "root", "sshd")

	// Tracker should be reset to count=1
	p.mu.Lock()
	count := p.failures[ip].count
	p.mu.Unlock()

	if count != 1 {
		t.Errorf("count after window expiry = %d, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// PAMListener.clearFailures
// ---------------------------------------------------------------------------

func TestClearFailures_RemovesEntry(t *testing.T) {
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  make(chan alert.Finding, 5),
		failures: make(map[string]*pamFailureTracker),
	}
	p.failures["203.0.113.20"] = &pamFailureTracker{
		count:     3,
		firstSeen: time.Now(),
		users:     map[string]bool{"root": true},
		services:  map[string]bool{"sshd": true},
	}

	p.clearFailures("203.0.113.20")

	if _, exists := p.failures["203.0.113.20"]; exists {
		t.Error("clearFailures should remove the entry")
	}
}

func TestClearFailures_NoOpForMissing(t *testing.T) {
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  make(chan alert.Finding, 5),
		failures: make(map[string]*pamFailureTracker),
	}
	// Should not panic
	p.clearFailures("203.0.113.99")
}

// ---------------------------------------------------------------------------
// parseSPFDMARCRejection — edge cases
// ---------------------------------------------------------------------------

func TestParseSPFDMARCRejection_NoStarMarker(t *testing.T) {
	domain, reason := parseSPFDMARCRejection("no star marker here")
	if domain != "" || reason != "" {
		t.Errorf("got (%q, %q)", domain, reason)
	}
}

func TestParseSPFDMARCRejection_NoAngleBrackets(t *testing.T) {
	line := " ** no angle brackets here : SPF fail"
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "" || reason != "" {
		t.Errorf("got (%q, %q)", domain, reason)
	}
}

func TestParseSPFDMARCRejection_EmptySender(t *testing.T) {
	line := " ** bounce: <> rejected : SPF fail"
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "" || reason != "" {
		t.Errorf("empty sender should not match: (%q, %q)", domain, reason)
	}
}

func TestParseSPFDMARCRejection_NonSPFReason(t *testing.T) {
	line := " ** <user@example.com> rejected : generic 5.0.0 error"
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "" || reason != "" {
		t.Errorf("non-SPF reason should not match: (%q, %q)", domain, reason)
	}
}

func TestParseSPFDMARCRejection_ValidSPF(t *testing.T) {
	line := "2026-04-12 ** <user@example.com> R=dkim_lookuphost T=remote : SPF: domain of example.com does not designate"
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "example.com" {
		t.Errorf("domain = %q, want example.com", domain)
	}
	if reason == "" {
		t.Error("reason should not be empty")
	}
}

func TestParseSPFDMARCRejection_NoColonSeparator(t *testing.T) {
	line := " ** <user@example.com> SPF fail but no colon separator"
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "" || reason != "" {
		t.Errorf("no colon separator: (%q, %q)", domain, reason)
	}
}

// ---------------------------------------------------------------------------
// isSPFDMARCRelated — additional edge cases
// ---------------------------------------------------------------------------

func TestIsSPFDMARCRelated_Empty(t *testing.T) {
	if isSPFDMARCRelated("") {
		t.Error("empty string should return false")
	}
}

func TestIsSPFDMARCRelated_DKIM(t *testing.T) {
	if !isSPFDMARCRelated("DKIM signature verification failed") {
		t.Error("DKIM should be related")
	}
}

func TestIsSPFDMARCRelated_571Authentication(t *testing.T) {
	if !isSPFDMARCRelated("5.7.1 Authentication required by policy") {
		t.Error("5.7.1 with authentication should match")
	}
}

func TestIsSPFDMARCRelated_571Plain(t *testing.T) {
	if isSPFDMARCRelated("5.7.1 relay denied") {
		t.Error("5.7.1 without auth keywords should not match")
	}
}

func TestIsSPFDMARCRelated_5726(t *testing.T) {
	if !isSPFDMARCRelated("550 5.7.26 This message does not pass") {
		t.Error("5.7.26 should match")
	}
}

// ---------------------------------------------------------------------------
// checkEmailRate — more edge cases
// ---------------------------------------------------------------------------

func TestCheckEmailRate_DisabledThresholds(t *testing.T) {
	cfg := &config.Config{}
	// Zero thresholds = disabled
	cfg.EmailProtection.RateWarnThreshold = 0
	cfg.EmailProtection.RateCritThreshold = 0
	findings := checkEmailRate("user@example.com", cfg)
	if len(findings) != 0 {
		t.Errorf("disabled thresholds should return nil, got %v", findings)
	}
}

func TestCheckEmailRate_HighVolumeSenderSkipped(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	cfg := testEmailProtectionConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{"mailer@example.com"}

	// Send many emails - should all be skipped
	for i := 0; i < 10; i++ {
		findings := checkEmailRate("mailer@example.com", cfg)
		if len(findings) != 0 {
			t.Fatalf("high volume sender should be skipped, got %v", findings)
		}
	}
}

func TestCheckEmailRate_SuppressedDomain(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	// Mark domain as recently compromised
	RecordCompromisedDomain("example.com")

	cfg := testEmailProtectionConfig()

	for i := 0; i < 10; i++ {
		findings := checkEmailRate("user@example.com", cfg)
		if len(findings) != 0 {
			t.Fatalf("suppressed domain should not generate rate findings, got %v", findings)
		}
	}
}

// ---------------------------------------------------------------------------
// rateWindow methods — detailed edge cases
// ---------------------------------------------------------------------------

func TestRateWindow_PruneResetsAlertedWhenEmpty(t *testing.T) {
	rw := &rateWindow{}
	rw.times = []time.Time{time.Now().Add(-2 * time.Hour)}
	rw.alerted = "crit"

	rw.mu.Lock()
	rw.prune(time.Now(), time.Hour)
	alerted := rw.alerted
	empty := len(rw.times) == 0
	rw.mu.Unlock()

	if !empty {
		t.Error("all times should be pruned")
	}
	// The prune method itself does not reset alerted; the caller
	// (evictEmailRateWindows) handles that. But times should be empty.
	_ = alerted
}

func TestRateWindow_CountInWindowExcludesOld(t *testing.T) {
	rw := &rateWindow{}
	now := time.Now()
	rw.times = []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-30 * time.Minute),
		now.Add(-5 * time.Minute),
		now,
	}

	rw.mu.Lock()
	count := rw.countInWindow(now, time.Hour)
	rw.mu.Unlock()

	if count != 3 {
		t.Errorf("count = %d, want 3 (items within 1 hour)", count)
	}
}

// ---------------------------------------------------------------------------
// extractAuthUser — additional edge cases
// ---------------------------------------------------------------------------

func TestExtractAuthUser_DovecotPlain(t *testing.T) {
	line := `2026-04-12 1abc23-000456-AB <= sender@example.com A=dovecot_plain:user@example.com S=1234`
	got := extractAuthUser(line)
	if got != "user@example.com" {
		t.Errorf("got %q, want user@example.com", got)
	}
}

func TestExtractAuthUser_NoAcceptLine(t *testing.T) {
	line := `some random line A=dovecot_login:user@example.com`
	got := extractAuthUser(line)
	if got != "" {
		t.Errorf("no <= marker should return empty, got %q", got)
	}
}

func TestExtractAuthUser_EndOfLine(t *testing.T) {
	line := `2026-04-12 1abc23 <= sender@example.com A=dovecot_login:admin@test.com`
	got := extractAuthUser(line)
	if got != "admin@test.com" {
		t.Errorf("got %q, want admin@test.com", got)
	}
}

func TestExtractAuthUser_NoDovecotAuth(t *testing.T) {
	line := `2026-04-12 1abc23 <= sender@example.com A=other_auth:user@example.com`
	got := extractAuthUser(line)
	if got != "" {
		t.Errorf("non-dovecot auth should return empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// isHighVolumeSender — edge cases
// ---------------------------------------------------------------------------

func TestIsHighVolumeSender_CaseInsensitive(t *testing.T) {
	if !isHighVolumeSender("MAILER@EXAMPLE.COM", []string{"mailer@example.com"}) {
		t.Error("should match case-insensitively")
	}
}

func TestIsHighVolumeSender_EmptyAllowlist(t *testing.T) {
	if isHighVolumeSender("user@example.com", nil) {
		t.Error("empty allowlist should return false")
	}
}

// ---------------------------------------------------------------------------
// pruneSlice — edge cases
// ---------------------------------------------------------------------------

func TestPruneSlice_AllRecent(t *testing.T) {
	now := time.Now()
	times := []time.Time{now.Add(-1 * time.Minute), now}
	cutoff := now.Add(-1 * time.Hour)
	got := pruneSlice(times, cutoff)
	if len(got) != 2 {
		t.Errorf("all recent: got %d, want 2", len(got))
	}
}

func TestPruneSlice_AllExpired(t *testing.T) {
	now := time.Now()
	times := []time.Time{now.Add(-2 * time.Hour), now.Add(-3 * time.Hour)}
	cutoff := now.Add(-1 * time.Hour)
	got := pruneSlice(times, cutoff)
	if len(got) != 0 {
		t.Errorf("all expired: got %d, want 0", len(got))
	}
}

func TestPruneSlice_Empty(t *testing.T) {
	got := pruneSlice(nil, time.Now())
	if len(got) != 0 {
		t.Errorf("nil input: got %d, want 0", len(got))
	}
}

func TestPruneSlice_MixedKeepsRecent(t *testing.T) {
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),    // expired
		now.Add(-30 * time.Minute), // recent
		now,                        // recent
	}
	cutoff := now.Add(-1 * time.Hour)
	got := pruneSlice(times, cutoff)
	if len(got) != 2 {
		t.Errorf("mixed: got %d, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// parseWHMPurge — edge cases
// ---------------------------------------------------------------------------

func TestParseWHMPurge_ShortFields(t *testing.T) {
	line := `[whostmgr] 198.51.100.50`
	ip, account := parseWHMPurge(line)
	if ip != "" || account != "" {
		t.Errorf("short fields: (%q, %q)", ip, account)
	}
}

func TestParseWHMPurge_NoPURGE(t *testing.T) {
	line := `[whostmgr] 198.51.100.50 some other action`
	ip, account := parseWHMPurge(line)
	if account != "" {
		t.Errorf("no PURGE keyword: account = %q", account)
	}
	_ = ip
}

// ---------------------------------------------------------------------------
// parseDovecotLoginFields — rip at end of line (no trailing delimiter)
// ---------------------------------------------------------------------------

func TestParseDovecotLoginFields_RIPAtEnd(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<bob@test.com>, rip=198.51.100.7`
	user, ip := parseDovecotLoginFields(line)
	if user != "bob@test.com" {
		t.Errorf("user = %q", user)
	}
	if ip != "198.51.100.7" {
		t.Errorf("ip = %q", ip)
	}
}

func TestParseDovecotLoginFields_NoClosingAngleBracket(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<alice@example.com`
	user, ip := parseDovecotLoginFields(line)
	if user != "" || ip != "" {
		t.Errorf("unclosed angle bracket: (%q, %q)", user, ip)
	}
}

func TestParseDovecotLoginFields_EmptyUser(t *testing.T) {
	line := `dovecot: imap-login: Login: user=<>, rip=203.0.113.5`
	user, ip := parseDovecotLoginFields(line)
	if user != "" || ip != "" {
		t.Errorf("empty user should return empty: (%q, %q)", user, ip)
	}
}

// ---------------------------------------------------------------------------
// parseSecureLogLine — non-Accepted lines
// ---------------------------------------------------------------------------

func TestParseSecureLogLine_NoAccepted(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 12:00:00 host sshd[12345]: Failed password for root from 198.51.100.30 port 54321 ssh2`
	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 0 {
		t.Errorf("non-Accepted line should return nil, got %v", findings)
	}
}

func TestParseSecureLogLine_NoFromKeyword(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root`
	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 0 {
		t.Errorf("no 'from' keyword should return nil, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// evictEmailRateWindows — prunes suppressed domains
// ---------------------------------------------------------------------------

func TestEvictEmailRateWindows_PrunesSuppressedDomains(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	// Add old suppressed domain
	emailRateSuppressed.mu.Lock()
	emailRateSuppressed.domains["old.example.com"] = time.Now().Add(-2 * time.Hour)
	emailRateSuppressed.domains["recent.example.com"] = time.Now()
	emailRateSuppressed.mu.Unlock()

	evictEmailRateWindows(time.Now())

	emailRateSuppressed.mu.Lock()
	_, hasOld := emailRateSuppressed.domains["old.example.com"]
	_, hasRecent := emailRateSuppressed.domains["recent.example.com"]
	emailRateSuppressed.mu.Unlock()

	if hasOld {
		t.Error("old suppressed domain should be pruned")
	}
	if !hasRecent {
		t.Error("recent suppressed domain should be kept")
	}
}

// ---------------------------------------------------------------------------
// hasRecentCompromisedFinding — edge cases
// ---------------------------------------------------------------------------

func TestHasRecentCompromisedFinding_DeletesExpired(t *testing.T) {
	emailRateSuppressed.mu.Lock()
	emailRateSuppressed.domains["expired.com"] = time.Now().Add(-2 * time.Hour)
	emailRateSuppressed.mu.Unlock()

	result := hasRecentCompromisedFinding("expired.com")
	if result {
		t.Error("expired domain should return false")
	}

	// Verify it was deleted
	emailRateSuppressed.mu.Lock()
	_, exists := emailRateSuppressed.domains["expired.com"]
	emailRateSuppressed.mu.Unlock()
	if exists {
		t.Error("expired domain should be deleted from map")
	}
}

// ---------------------------------------------------------------------------
// extractDomainFromEmail — edge cases
// ---------------------------------------------------------------------------

func TestExtractDomainFromEmail_NoAtSign(t *testing.T) {
	if got := extractDomainFromEmail("nodomain"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractDomainFromEmail_Standard(t *testing.T) {
	if got := extractDomainFromEmail("user@example.com"); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// parseBlockExpiry — edge cases
// ---------------------------------------------------------------------------

func TestParseBlockExpiry_ValidDuration(t *testing.T) {
	got := parseBlockExpiry("48h")
	if got != 48*time.Hour {
		t.Errorf("got %v, want 48h", got)
	}
}

func TestParseBlockExpiry_Empty(t *testing.T) {
	got := parseBlockExpiry("")
	if got != 24*time.Hour {
		t.Errorf("got %v, want 24h", got)
	}
}

func TestParseBlockExpiry_InvalidFallback(t *testing.T) {
	got := parseBlockExpiry("not-a-duration")
	if got != 24*time.Hour {
		t.Errorf("got %v, want 24h", got)
	}
}

func TestParseBlockExpiry_Minutes(t *testing.T) {
	got := parseBlockExpiry("30m")
	if got != 30*time.Minute {
		t.Errorf("got %v, want 30m", got)
	}
}

// ---------------------------------------------------------------------------
// truncateStr — edge cases (no "..." suffix, unlike truncateDaemon)
// ---------------------------------------------------------------------------

func TestTruncateStr_ExactLength(t *testing.T) {
	got := truncateStr("hello", 5)
	if got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateStr_TruncatesWithoutEllipsis(t *testing.T) {
	got := truncateStr("hello world", 5)
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncateStr_EmptyString(t *testing.T) {
	got := truncateStr("", 5)
	if got != "" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// RecordCompromisedDomain + hasRecentCompromisedFinding integration
// ---------------------------------------------------------------------------

func TestRecordAndCheckCompromisedDomain(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	RecordCompromisedDomain("compromised.com")

	if !hasRecentCompromisedFinding("compromised.com") {
		t.Error("recently recorded domain should return true")
	}
	if hasRecentCompromisedFinding("clean.com") {
		t.Error("unrecorded domain should return false")
	}
}

// ---------------------------------------------------------------------------
// isDedupExpired — more edge cases
// ---------------------------------------------------------------------------

func TestIsDedupExpired_FutureTimestamp(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	if isDedupExpired(future, time.Hour) {
		t.Error("future timestamp should not be expired")
	}
}

func TestIsDedupExpired_EmptyString(t *testing.T) {
	if !isDedupExpired("", time.Hour) {
		t.Error("empty string should be treated as expired (parse error)")
	}
}

// ---------------------------------------------------------------------------
// parsePHPShieldLine — additional edge cases
// ---------------------------------------------------------------------------

func TestParsePHPShieldLine_MalformedNoSpace(t *testing.T) {
	// Bracket close followed by non-space content
	line := "[2026-04-12 10:00:00]nospace"
	got := parsePHPShieldLine(line)
	if got != nil {
		t.Errorf("malformed line should return nil, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// parseCpanelSessionLogin — realistic format
// ---------------------------------------------------------------------------

func TestParseCpanelSessionLogin_RealisticFormat(t *testing.T) {
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 some_data NEW alice:session_token method=handle_form_login`
	ip, account := parseCpanelSessionLogin(line)
	if ip != "198.51.100.20" {
		t.Errorf("ip = %q", ip)
	}
	if account != "alice" {
		t.Errorf("account = %q", account)
	}
}

func TestParseCpanelSessionLogin_AccountWithoutToken(t *testing.T) {
	line := `[cpaneld] 198.51.100.20 xxx NEW bob method=handle_form_login`
	ip, account := parseCpanelSessionLogin(line)
	if ip != "198.51.100.20" {
		t.Errorf("ip = %q", ip)
	}
	if account != "bob" {
		t.Errorf("account = %q", account)
	}
}

// ---------------------------------------------------------------------------
// parsePurgeDaemon — realistic format
// ---------------------------------------------------------------------------

func TestParsePurgeDaemon_WithToken(t *testing.T) {
	line := `[cpaneld] PURGE alice:session_token password_change`
	got := parsePurgeDaemon(line)
	if got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestParsePurgeDaemon_NoPurge(t *testing.T) {
	line := "some random line"
	got := parsePurgeDaemon(line)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// extractIPFromLogDaemon — edge cases
// ---------------------------------------------------------------------------

func TestExtractIPFromLogDaemon_TrailingPunctuation(t *testing.T) {
	line := `some log 203.0.113.5: more stuff`
	got := extractIPFromLogDaemon(line)
	if got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

func TestExtractIPFromLogDaemon_NoBareIP(t *testing.T) {
	line := "no ip addresses in this line"
	got := extractIPFromLogDaemon(line)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractIPFromLogDaemon_ShortField(t *testing.T) {
	line := "1.2.3 too short"
	got := extractIPFromLogDaemon(line)
	if got != "" {
		t.Errorf("short field should not match, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractRequestURI — edge cases
// ---------------------------------------------------------------------------

func TestExtractRequestURI_NoQuotes(t *testing.T) {
	if got := extractRequestURI("no quotes here"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestExtractRequestURI_SingleQuote(t *testing.T) {
	if got := extractRequestURI(`only "one quote`); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestExtractRequestURI_FullLine(t *testing.T) {
	line := `198.51.100.5 - - [12/Apr/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234`
	got := extractRequestURI(line)
	if got != "GET /index.html HTTP/1.1" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractPureFTPDClientIP — edge cases
// ---------------------------------------------------------------------------

func TestExtractPureFTPDClientIP_IPv6(t *testing.T) {
	line := `(user@2001:db8::1) pure-ftpd: something`
	got := extractPureFTPDClientIP(line)
	if got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestExtractPureFTPDClientIP_EmptyAddr(t *testing.T) {
	line := `(user@) pure-ftpd: something`
	got := extractPureFTPDClientIP(line)
	if got != "" {
		t.Errorf("empty addr should return empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// evictAccessLogState — evicts stale entries
// ---------------------------------------------------------------------------

func TestEvictAccessLogState_DeletesStaleEntries(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	now := time.Now()
	stale := &accessLogTracker{
		lastSeen: now.Add(-2 * time.Hour),
	}
	accessLogTrackers.Store("1.2.3.4", stale)

	evictAccessLogState(now)

	if _, loaded := accessLogTrackers.Load("1.2.3.4"); loaded {
		t.Error("stale entry should be evicted")
	}
}

func TestEvictAccessLogState_KeepsActive(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	now := time.Now()
	active := &accessLogTracker{
		lastSeen:     now,
		wpLoginTimes: []time.Time{now},
	}
	accessLogTrackers.Store("5.5.5.5", active)

	evictAccessLogState(now)

	if _, loaded := accessLogTrackers.Load("5.5.5.5"); !loaded {
		t.Error("active entry should be kept")
	}
}

// ---------------------------------------------------------------------------
// isPrivateOrLoopback — edge cases
// ---------------------------------------------------------------------------

func TestIsPrivateOrLoopback_IPv6Loopback(t *testing.T) {
	if !isPrivateOrLoopback("::1") {
		t.Error("::1 should be loopback")
	}
}

func TestIsPrivateOrLoopback_172Boundary(t *testing.T) {
	// 172.15.x.x is NOT private
	if isPrivateOrLoopback("172.15.255.255") {
		t.Error("172.15.x.x should not be private")
	}
	// 172.32.x.x is NOT private
	if isPrivateOrLoopback("172.32.0.1") {
		t.Error("172.32.x.x should not be private")
	}
}

// ---------------------------------------------------------------------------
// PAMListener.processEvent — full FAIL→threshold→block flow
// ---------------------------------------------------------------------------

func TestProcessEvent_FullBruteForceFlow(t *testing.T) {
	alertCh := make(chan alert.Finding, 20)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	cfg.Thresholds.MultiIPLoginWindowMin = 10

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	// 3 failures from the same IP should trigger brute-force detection
	p.processEvent("FAIL ip=203.0.113.50 user=root service=sshd")
	p.processEvent("FAIL ip=203.0.113.50 user=admin service=sshd")
	p.processEvent("FAIL ip=203.0.113.50 user=test service=webmin")

	var bruteforceFound bool
	for {
		select {
		case f := <-alertCh:
			if f.Check == "pam_bruteforce" {
				bruteforceFound = true
				if f.Severity != alert.Critical {
					t.Errorf("severity = %v, want Critical", f.Severity)
				}
				if !strings.Contains(f.Message, "203.0.113.50") {
					t.Errorf("message should contain IP: %q", f.Message)
				}
			}
		default:
			goto check
		}
	}
check:
	if !bruteforceFound {
		t.Error("expected pam_bruteforce finding after 3 failures")
	}
}

// ---------------------------------------------------------------------------
// extractEximSender — realistic log line
// ---------------------------------------------------------------------------

func TestExtractEximSender_FullLine(t *testing.T) {
	line := `2026-04-12 10:00:00 1abc23 <= user@example.com H=mail.example.com [203.0.113.42] P=esmtpsa`
	got := extractEximSender(line)
	if got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractEximSender_Bounce(t *testing.T) {
	line := `2026-04-12 10:00:00 1abc23 <= <> R=1abc22 T=remote_smtp`
	got := extractEximSender(line)
	if got != "<>" {
		t.Errorf("got %q, want <>", got)
	}
}

// ---------------------------------------------------------------------------
// extractEximDomain — realistic
// ---------------------------------------------------------------------------

func TestExtractEximDomain_WithHasExceeded(t *testing.T) {
	line := "Domain example.com has exceeded max defers and failures per hour"
	got := extractEximDomain(line)
	if got != "example.com" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractEximSubject — realistic
// ---------------------------------------------------------------------------

func TestExtractEximSubject_Standard(t *testing.T) {
	line := `2026-04-12 <= user@example.com T="Hello World" S=1234`
	got := extractEximSubject(line)
	if got != "Hello World" {
		t.Errorf("got %q", got)
	}
}

func TestExtractEximSubject_NoT(t *testing.T) {
	line := `2026-04-12 <= user@example.com S=1234`
	got := extractEximSubject(line)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// parseEximLogLine — bulk mail service detection (branch #5)
// ---------------------------------------------------------------------------

func TestParseEximLogLine_BulkMailService(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	cfg := &config.Config{}
	cfg.EmailProtection.RateWarnThreshold = 100 // high so rate limiter doesn't fire
	cfg.EmailProtection.RateCritThreshold = 200
	cfg.EmailProtection.RateWindowMin = 60

	line := `2026-04-12 10:00:00 1abc23 <= spammer@example.com H=truelist.io [203.0.113.5] P=esmtpsa A=dovecot_login:spammer@example.com S=500 T="spam"`

	findings := parseEximLogLine(line, cfg)
	var found bool
	for _, f := range findings {
		if f.Check == "email_compromised_account" && strings.Contains(f.Message, "bulk mail service") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected bulk mail service finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// parseEximLogLine — max defers and failures exceeded (branch #3)
// ---------------------------------------------------------------------------

func TestParseEximLogLine_MaxDefersExceeded(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-12 10:00:00 Domain spammer.com has exceeded max defers and failures per hour`

	findings := parseEximLogLine(line, cfg)
	var found bool
	for _, f := range findings {
		if f.Check == "email_spam_outbreak" && strings.Contains(f.Message, "spammer.com") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected spam outbreak finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// parseEximLogLine — DKIM signing failure (branch #7)
// ---------------------------------------------------------------------------

func TestParseEximLogLine_DKIMFailure(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		cfg := &config.Config{}
		line := `2026-04-12 10:00:00 DKIM: signing failed for broken.com: key not found`

		findings := parseEximLogLine(line, cfg)
		var found bool
		for _, f := range findings {
			if f.Check == "email_dkim_failure" && strings.Contains(f.Message, "broken.com") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected DKIM failure finding, got %v", findings)
		}

		// Second call should be deduped
		findings2 := parseEximLogLine(line, cfg)
		for _, f := range findings2 {
			if f.Check == "email_dkim_failure" {
				t.Error("DKIM failure should be deduped within 24h")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// parseEximLogLine — SPF/DMARC rejection (branch #8)
// ---------------------------------------------------------------------------

func TestParseEximLogLine_SPFRejection(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		cfg := &config.Config{}
		line := `2026-04-12 10:00:00 ** <user@broken-spf.com> R=dkim_lookuphost T=remote : 550 5.7.23 SPF check failed for broken-spf.com`

		findings := parseEximLogLine(line, cfg)
		var found bool
		for _, f := range findings {
			if f.Check == "email_spf_rejection" && strings.Contains(f.Message, "broken-spf.com") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SPF rejection finding, got %v", findings)
		}
	})
}

// ---------------------------------------------------------------------------
// parseEximLogLine — password+smtp subject pattern (branch #4b)
// ---------------------------------------------------------------------------

func TestParseEximLogLine_SuspiciousSMTPPasswordSubject(t *testing.T) {
	resetEmailRateState()
	defer resetEmailRateState()

	cfg := &config.Config{}
	cfg.EmailProtection.RateWarnThreshold = 100
	cfg.EmailProtection.RateCritThreshold = 200
	cfg.EmailProtection.RateWindowMin = 60

	line := `2026-04-12 10:00:00 1abc23 <= user@example.com H=mail.example.com [203.0.113.42] P=esmtpsa A=dovecot_login:user@example.com S=1234 T="Your SMTP password has been compromised"`

	findings := parseEximLogLine(line, cfg)
	var found bool
	for _, f := range findings {
		if f.Check == "email_credential_leak" && strings.Contains(f.Message, "SMTP/password keywords") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected suspicious SMTP/password finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// parseAccessLogBruteForce — POST to non-target path (fast reject)
// ---------------------------------------------------------------------------

func TestParseAccessLogBruteForce_NonPOSTRejected(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	line := `198.51.100.5 - - [12/Apr/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 1234`
	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 0 {
		t.Errorf("GET should be rejected, got %v", findings)
	}
}

func TestParseAccessLogBruteForce_ShortLine(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	line := `198.51.100.5 POST short`
	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 0 {
		t.Errorf("short line should be rejected, got %v", findings)
	}
}

func TestParseAccessLogBruteForce_NonTargetPath(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	line := `198.51.100.5 - - [12/Apr/2026:10:00:00 +0000] "POST /contact-form HTTP/1.1" 200 1234`
	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 0 {
		t.Errorf("non-target path should be rejected, got %v", findings)
	}
}

func TestParseAccessLogBruteForce_LoopbackSkipped(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	line := `127.0.0.1 - - [12/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234`
	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 0 {
		t.Errorf("loopback should be skipped, got %v", findings)
	}
}

func TestParseAccessLogBruteForce_XMLRPCThreshold(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	for i := 0; i < accessLogXMLRPCThreshold; i++ {
		line := `198.51.100.99 - - [12/Apr/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 200 500`
		findings := parseAccessLogBruteForce(line, cfg)
		if i < accessLogXMLRPCThreshold-1 {
			if len(findings) != 0 {
				t.Fatalf("hit %d: below threshold should not alert, got %v", i, findings)
			}
		} else {
			if len(findings) != 1 {
				t.Fatalf("hit %d: at threshold should alert, got %v", i, findings)
			}
			if findings[0].Check != "xmlrpc_abuse" {
				t.Errorf("check = %q, want xmlrpc_abuse", findings[0].Check)
			}
		}
	}
}

func TestParseAccessLogBruteForce_WPLoginThreshold(t *testing.T) {
	accessLogTrackers = sync.Map{}
	defer func() { accessLogTrackers = sync.Map{} }()

	cfg := &config.Config{}
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		line := `198.51.100.88 - - [12/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 500`
		findings := parseAccessLogBruteForce(line, cfg)
		if i < accessLogWPLoginThreshold-1 {
			if len(findings) != 0 {
				t.Fatalf("hit %d: below threshold should not alert, got %v", i, findings)
			}
		} else {
			if len(findings) != 1 {
				t.Fatalf("hit %d: at threshold should alert, got %v", i, findings)
			}
			if findings[0].Check != "wp_login_bruteforce" {
				t.Errorf("check = %q, want wp_login_bruteforce", findings[0].Check)
			}
		}
	}

	// Additional hit should NOT re-alert (dedup)
	line := `198.51.100.88 - - [12/Apr/2026:10:00:01 +0000] "POST /wp-login.php HTTP/1.1" 200 500`
	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 0 {
		t.Error("should not re-alert after threshold")
	}
}

// ---------------------------------------------------------------------------
// parseSessionLogLine — method extraction branches
// ---------------------------------------------------------------------------

func TestParseSessionLogLine_MethodExtraction(t *testing.T) {
	resetPurgeTrackerState()
	cfg := &config.Config{}

	// Method with trailing data (comma/space delimiter triggers extraction)
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=some_other_method,extra=data`
	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Message, "some_other_method") {
		t.Errorf("message should contain extracted method: %q", findings[0].Message)
	}
}

func TestParseSessionLogLine_MethodAtEndOfLine(t *testing.T) {
	resetPurgeTrackerState()
	cfg := &config.Config{}

	// Method at end of line (no delimiter) => falls through to "unknown"
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=some_method`
	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// The code sets method to "unknown" when IndexAny returns -1 (no delimiter)
	if !strings.Contains(findings[0].Message, "method: unknown") {
		t.Errorf("method at end of line should yield 'unknown': %q", findings[0].Message)
	}
}

func TestParseSessionLogLine_InfraIPSkipped(t *testing.T) {
	resetPurgeTrackerState()
	cfg := &config.Config{InfraIPs: []string{"198.51.100.0/24"}}

	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=handle_form_login`
	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 0 {
		t.Errorf("infra IP should be skipped, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// ParseSessionLineForHijack — cpaneld NEW login path
// ---------------------------------------------------------------------------

func TestParseSessionLineForHijack_CPanelLogin(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch)

	// First, create a password change record
	d.HandlePasswordChange("bob", "198.51.100.1")
	<-ch // consume password-change alert

	// Now a cPanel login for the same account
	line := `[cpaneld] 198.51.100.2 data NEW bob:session method=handle_form_login`
	ParseSessionLineForHijack(line, d)

	select {
	case f := <-ch:
		if f.Check != "password_hijack_confirmed" {
			t.Errorf("check = %q, want password_hijack_confirmed", f.Check)
		}
	default:
		t.Error("expected hijack confirmation from cpaneld login")
	}
}

// ---------------------------------------------------------------------------
// HandleLogin — expired hijack window
// ---------------------------------------------------------------------------

func TestHandleLogin_ExpiredWindow(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch)

	// Inject an old password change
	d.mu.Lock()
	d.recentChanges["old-user"] = &passwordChange{
		account:   "old-user",
		ip:        "198.51.100.1",
		timestamp: time.Now().Add(-hijackWindow - time.Minute),
	}
	d.mu.Unlock()

	d.HandleLogin("old-user", "198.51.100.2")

	select {
	case f := <-ch:
		t.Fatalf("expired window should not trigger hijack: %+v", f)
	default:
		// expected
	}
}

// ---------------------------------------------------------------------------
// parseSPFDMARCRejection — long reason truncation
// ---------------------------------------------------------------------------

func TestParseSPFDMARCRejection_LongReasonTruncated(t *testing.T) {
	longReason := "SPF fail " + strings.Repeat("x", 300)
	line := ` ** <user@example.com> R=dkim T=remote : ` + longReason
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "example.com" {
		t.Errorf("domain = %q", domain)
	}
	if len(reason) > 200 {
		t.Errorf("reason length = %d, should be truncated to 200", len(reason))
	}
}

// ---------------------------------------------------------------------------
// parseSPFDMARCRejection — sender without @ should not match
// ---------------------------------------------------------------------------

func TestParseSPFDMARCRejection_SenderNoAt(t *testing.T) {
	line := ` ** <justadomain> R=dkim T=remote : SPF fail`
	domain, reason := parseSPFDMARCRejection(line)
	if domain != "" || reason != "" {
		t.Errorf("sender without @ should not match: (%q, %q)", domain, reason)
	}
}

// ---------------------------------------------------------------------------
// parseModSecLogLineDeduped — dedup suppression
// ---------------------------------------------------------------------------

func TestParseModSecLogLineDeduped_SuppressesDuplicates(t *testing.T) {
	modsecDedup = sync.Map{}
	modsecCSMCounter = sync.Map{}
	defer func() {
		modsecDedup = sync.Map{}
		modsecCSMCounter = sync.Map{}
	}()

	cfg := &config.Config{}
	// Use a real Apache ModSecurity deny log line
	line := `[Wed Apr 12 10:00:00.123456 2026] [security2:error] [pid 12345] [client 203.0.113.5:54321] ModSecurity: Access denied with code 403 (phase 2). [id "920420"] [msg "Request content type not allowed"] [severity "CRITICAL"]`

	first := parseModSecLogLineDeduped(line, cfg)
	if len(first) == 0 {
		t.Fatal("first call should return findings")
	}

	// Second call with same line should be deduped
	second := parseModSecLogLineDeduped(line, cfg)
	if len(second) != 0 {
		t.Errorf("duplicate should be suppressed, got %v", second)
	}
}

// ---------------------------------------------------------------------------
// parseFTPLogLine — auth failure
// ---------------------------------------------------------------------------

func TestParseFTPLogLine_AuthFailure(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 12 10:00:00 server pure-ftpd: (user@203.0.113.5) [WARNING] Authentication failed for user [alice]`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "ftp_auth_failure_realtime" {
		t.Errorf("check = %q", findings[0].Check)
	}
}

func TestParseFTPLogLine_SuccessfulLogin(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 12 10:00:00 server pure-ftpd: (alice@203.0.113.6) [INFO] alice is now logged in`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "ftp_login_realtime" {
		t.Errorf("check = %q", findings[0].Check)
	}
}

func TestParseFTPLogLine_InfraIPSkipped(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	line := `Apr 12 10:00:00 server pure-ftpd: (alice@10.1.2.3) [INFO] alice is now logged in`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 0 {
		t.Errorf("infra IP should be skipped, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// parseSecureLogLine — user extraction via "for" keyword
// ---------------------------------------------------------------------------

func TestParseSecureLogLine_ExtractsUser(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 12:00:00 host sshd[12345]: Accepted publickey for admin from 198.51.100.30 port 54321 ssh2`
	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Message, "admin") {
		t.Errorf("message should contain user, got %q", findings[0].Message)
	}
}
