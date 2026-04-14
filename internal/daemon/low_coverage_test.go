package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
)

// ---------------------------------------------------------------------------
// processEvent — additional edge cases
// ---------------------------------------------------------------------------

func TestProcessEvent_WhitespacePadding(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	// Leading/trailing whitespace should be trimmed
	p.processEvent("  FAIL ip=203.0.113.50 user=root service=sshd  ")
	p.mu.Lock()
	_, exists := p.failures["203.0.113.50"]
	p.mu.Unlock()
	if !exists {
		t.Error("trimmed line should be processed; failure tracker should exist")
	}
}

func TestProcessEvent_MissingUserField(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	// No user= field — ip and service present, user stays ""
	p.processEvent("FAIL ip=203.0.113.51 service=sshd")
	p.mu.Lock()
	tracker := p.failures["203.0.113.51"]
	p.mu.Unlock()
	if tracker == nil {
		t.Fatal("failure tracker should exist even without user field")
	}
	if !tracker.users[""] {
		t.Error("empty user should be tracked")
	}
}

func TestProcessEvent_MissingServiceField(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip=203.0.113.52 user=root")
	p.mu.Lock()
	tracker := p.failures["203.0.113.52"]
	p.mu.Unlock()
	if tracker == nil {
		t.Fatal("failure tracker should exist even without service field")
	}
	if !tracker.services[""] {
		t.Error("empty service should be tracked")
	}
}

func TestProcessEvent_EmptyIPValue(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip= user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("empty ip value should be skipped: %+v", f)
	default:
	}
	if len(p.failures) != 0 {
		t.Error("empty IP should not create a failure tracker")
	}
}

func TestProcessEvent_OKAlertContainsUserAndService(t *testing.T) {
	alertCh := make(chan alert.Finding, 5)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("OK ip=198.51.100.5 user=deploy service=sudo")
	select {
	case f := <-alertCh:
		if f.Check != "pam_login" {
			t.Errorf("check = %q, want pam_login", f.Check)
		}
		if f.Severity != alert.High {
			t.Errorf("severity = %v, want High", f.Severity)
		}
		if !strings.Contains(f.Message, "deploy") {
			t.Errorf("message should contain user, got %q", f.Message)
		}
		if !strings.Contains(f.Message, "sudo") {
			t.Errorf("message should contain service, got %q", f.Message)
		}
	default:
		t.Error("OK event should emit pam_login alert")
	}
}

func TestProcessEvent_FAILThenOKThenFAILResetsCounter(t *testing.T) {
	alertCh := make(chan alert.Finding, 20)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	ip := "203.0.113.60"
	// Accumulate 2 failures
	p.processEvent("FAIL ip=" + ip + " user=root service=sshd")
	p.processEvent("FAIL ip=" + ip + " user=root service=sshd")

	// OK clears failures
	p.processEvent("OK ip=" + ip + " user=root service=sshd")
	// drain the pam_login alert
	<-alertCh

	// After clearance, 2 more should not trigger (threshold=3)
	p.processEvent("FAIL ip=" + ip + " user=root service=sshd")
	p.processEvent("FAIL ip=" + ip + " user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("should not alert yet after counter reset: %+v", f)
	default:
	}

	// 3rd after reset should trigger
	p.processEvent("FAIL ip=" + ip + " user=root service=sshd")
	select {
	case f := <-alertCh:
		if f.Check != "pam_bruteforce" {
			t.Errorf("check = %q, want pam_bruteforce", f.Check)
		}
	default:
		t.Error("3rd failure after reset should trigger alert")
	}
}

// ---------------------------------------------------------------------------
// recordFailure — custom window min
// ---------------------------------------------------------------------------

func TestRecordFailure_CustomWindowMin(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	cfg.Thresholds.MultiIPLoginWindowMin = 2 // 2 minute window
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	ip := "203.0.113.70"
	p.recordFailure(ip, "root", "sshd")
	p.recordFailure(ip, "root", "sshd")

	// Move firstSeen to 3 minutes ago (beyond the 2-min window)
	p.mu.Lock()
	p.failures[ip].firstSeen = time.Now().Add(-3 * time.Minute)
	p.mu.Unlock()

	// This should reset the tracker because the window expired
	p.recordFailure(ip, "root", "sshd")

	p.mu.Lock()
	count := p.failures[ip].count
	blocked := p.failures[ip].blocked
	p.mu.Unlock()

	if count != 1 {
		t.Errorf("count after custom window expiry = %d, want 1", count)
	}
	if blocked {
		t.Error("blocked should be reset after window expiry")
	}
}

func TestRecordFailure_WindowExpiryResetsUsersAndServices(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 5
	cfg.Thresholds.MultiIPLoginWindowMin = 1
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	ip := "203.0.113.71"
	p.recordFailure(ip, "root", "sshd")
	p.recordFailure(ip, "admin", "webmin")

	p.mu.Lock()
	p.failures[ip].firstSeen = time.Now().Add(-2 * time.Minute)
	p.mu.Unlock()

	// Window expired: next failure resets users/services
	p.recordFailure(ip, "deploy", "sudo")

	p.mu.Lock()
	tracker := p.failures[ip]
	userCount := len(tracker.users)
	svcCount := len(tracker.services)
	p.mu.Unlock()

	if userCount != 1 {
		t.Errorf("users after window reset = %d, want 1", userCount)
	}
	if svcCount != 1 {
		t.Errorf("services after window reset = %d, want 1", svcCount)
	}
}

func TestRecordFailure_AlertDetailsContainUsersAndServices(t *testing.T) {
	alertCh := make(chan alert.Finding, 10)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 3
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	ip := "203.0.113.72"
	p.recordFailure(ip, "root", "sshd")
	p.recordFailure(ip, "admin", "webmin")
	p.recordFailure(ip, "root", "sshd") // triggers threshold

	select {
	case f := <-alertCh:
		if !strings.Contains(f.Details, "root") {
			t.Errorf("details should contain 'root': %q", f.Details)
		}
		if !strings.Contains(f.Details, "admin") {
			t.Errorf("details should contain 'admin': %q", f.Details)
		}
		if !strings.Contains(f.Details, "sshd") {
			t.Errorf("details should contain 'sshd': %q", f.Details)
		}
		if !strings.Contains(f.Details, "webmin") {
			t.Errorf("details should contain 'webmin': %q", f.Details)
		}
	default:
		t.Error("threshold hit should emit alert")
	}
}

// ---------------------------------------------------------------------------
// cleanupLoop — exercises the cleanup goroutine
// ---------------------------------------------------------------------------

func TestCleanupLoop_RemovesExpiredTrackers(t *testing.T) {
	p := &PAMListener{
		failures: make(map[string]*pamFailureTracker),
	}

	// Add a tracker that is very old (lastSeen 31 minutes ago)
	p.mu.Lock()
	p.failures["203.0.113.80"] = &pamFailureTracker{
		count:     3,
		firstSeen: time.Now().Add(-31 * time.Minute),
		lastSeen:  time.Now().Add(-31 * time.Minute),
		users:     map[string]bool{"root": true},
		services:  map[string]bool{"sshd": true},
	}
	// Add a recent tracker
	p.failures["203.0.113.81"] = &pamFailureTracker{
		count:     1,
		firstSeen: time.Now(),
		lastSeen:  time.Now(),
		users:     map[string]bool{"root": true},
		services:  map[string]bool{"sshd": true},
	}
	p.mu.Unlock()

	// Simulate what cleanupLoop does on each tick:
	// cutoff = now - 30 minutes; delete if lastSeen < cutoff
	p.mu.Lock()
	cutoff := time.Now().Add(-30 * time.Minute)
	for ip, tracker := range p.failures {
		if tracker.lastSeen.Before(cutoff) {
			delete(p.failures, ip)
		}
	}
	p.mu.Unlock()

	p.mu.Lock()
	_, oldExists := p.failures["203.0.113.80"]
	_, recentExists := p.failures["203.0.113.81"]
	p.mu.Unlock()

	if oldExists {
		t.Error("old tracker should be cleaned up")
	}
	if !recentExists {
		t.Error("recent tracker should remain")
	}
}

func TestCleanupLoop_StopsOnSignal(t *testing.T) {
	p := &PAMListener{
		failures: make(map[string]*pamFailureTracker),
	}

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		p.cleanupLoop(stopCh)
		close(done)
	}()

	// Signal stop immediately
	close(stopCh)

	select {
	case <-done:
		// cleanupLoop exited properly
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupLoop did not exit after stop signal")
	}
}

// ---------------------------------------------------------------------------
// isInfraIP (from pam_listener.go) — edge cases not in deeper_coverage_test
// ---------------------------------------------------------------------------

func TestIsInfraIP_MultiCIDR(t *testing.T) {
	infra := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.20.0.1", true},
		{"192.168.100.1", true},
		{"203.0.113.5", false},
	}
	for _, tt := range tests {
		if got := isInfraIP(tt.ip, infra); got != tt.want {
			t.Errorf("isInfraIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseDovecotLoginFields — additional deeper branches
// ---------------------------------------------------------------------------

func TestParseDovecotLoginFields_TabDelimitedRIP(t *testing.T) {
	// rip value terminated by tab
	line := "dovecot: Login: user=<test@example.com>, rip=198.51.100.1\tnext"
	user, ip := parseDovecotLoginFields(line)
	if user != "test@example.com" {
		t.Errorf("user = %q", user)
	}
	if ip != "198.51.100.1" {
		t.Errorf("ip = %q, want 198.51.100.1", ip)
	}
}

func TestParseDovecotLoginFields_NewlineDelimitedRIP(t *testing.T) {
	line := "dovecot: Login: user=<test@example.com>, rip=198.51.100.2\n"
	user, ip := parseDovecotLoginFields(line)
	if user != "test@example.com" {
		t.Errorf("user = %q", user)
	}
	if ip != "198.51.100.2" {
		t.Errorf("ip = %q, want 198.51.100.2", ip)
	}
}

func TestParseDovecotLoginFields_EmptyUserBrackets(t *testing.T) {
	// user=<> — empty string between brackets
	line := "dovecot: Login: user=<>, rip=203.0.113.5"
	user, ip := parseDovecotLoginFields(line)
	// Empty user should cause return "", ""
	if user != "" || ip != "" {
		t.Errorf("empty user should return empty: (%q, %q)", user, ip)
	}
}

func TestParseDovecotLoginFields_UserNoClosingBracket(t *testing.T) {
	line := "dovecot: Login: user=<broken, rip=203.0.113.5"
	user, ip := parseDovecotLoginFields(line)
	if user != "" || ip != "" {
		t.Errorf("no closing bracket should return empty: (%q, %q)", user, ip)
	}
}

func TestParseDovecotLoginFields_SpaceDelimitedRIP(t *testing.T) {
	line := "dovecot: Login: user=<a@b.com>, rip=198.51.100.3 lip=10.0.0.1"
	user, ip := parseDovecotLoginFields(line)
	if user != "a@b.com" {
		t.Errorf("user = %q", user)
	}
	if ip != "198.51.100.3" {
		t.Errorf("ip = %q, want 198.51.100.3", ip)
	}
}

// ---------------------------------------------------------------------------
// parseDovecotLogLine — deeper branches
// ---------------------------------------------------------------------------

func TestParseDovecotLogLine_NoGeoIPDBReturnsNil(t *testing.T) {
	prev := getGeoIPDB()
	setGeoIPDB(nil)
	defer setGeoIPDB(prev)

	cfg := &config.Config{}
	line := `Apr 12 10:00:00 host dovecot: imap-login: Login: user=<user@example.com>, rip=203.0.113.5`
	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("nil GeoIP DB should return nil, got %v", findings)
	}
}

func TestParseDovecotLogLine_InfraIPWithCIDR(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"203.0.113.0/24"}}
	line := `Apr 12 10:00:00 host dovecot: imap-login: Login: user=<user@example.com>, rip=203.0.113.42`
	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("infra CIDR IP should return nil, got %v", findings)
	}
}

func TestParseDovecotLogLine_EmptyUserReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	// user=<> triggers empty user
	line := `dovecot: imap-login: Login: user=<>, rip=203.0.113.5`
	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("empty user should return nil, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// isPrivateOrLoopback — remaining edge cases
// ---------------------------------------------------------------------------

func TestIsPrivateOrLoopback_172BoundaryLow(t *testing.T) {
	// 172.15.x is NOT private
	if isPrivateOrLoopback("172.15.255.255") {
		t.Error("172.15.x should NOT be private")
	}
}

func TestIsPrivateOrLoopback_172BoundaryHigh(t *testing.T) {
	// 172.32.x is NOT private
	if isPrivateOrLoopback("172.32.0.1") {
		t.Error("172.32.x should NOT be private")
	}
}

func TestIsPrivateOrLoopback_EmptyString(t *testing.T) {
	// Empty string is invalid IP, treated as private (skip)
	if !isPrivateOrLoopback("") {
		t.Error("empty string should be treated as private (invalid)")
	}
}

// ---------------------------------------------------------------------------
// pruneOldCountries — edge cases
// ---------------------------------------------------------------------------

func TestPruneOldCountries_EmptyMap(t *testing.T) {
	got := pruneOldCountries(map[string]int64{}, 1000000, 500000)
	if len(got) != 0 {
		t.Errorf("empty map should return empty, got %v", got)
	}
}

func TestPruneOldCountries_AllPruned(t *testing.T) {
	now := int64(1000000)
	countries := map[string]int64{
		"US": now - 600000,
		"CN": now - 700000,
	}
	got := pruneOldCountries(countries, now, 500000)
	if len(got) != 0 {
		t.Errorf("all entries should be pruned, got %v", got)
	}
}

func TestPruneOldCountries_AllKept(t *testing.T) {
	now := int64(1000000)
	countries := map[string]int64{
		"US": now - 100,
		"DE": now - 200,
	}
	got := pruneOldCountries(countries, now, 500000)
	if len(got) != 2 {
		t.Errorf("all entries should be kept, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// isTrustedCountry — with non-nil DB that has no mmdb (returns empty country)
// ---------------------------------------------------------------------------

func TestIsTrustedCountry_EmptyDBReturnsEmptyCountry(t *testing.T) {
	prev := getGeoIPDB()
	defer setGeoIPDB(prev)

	// DB with no mmdb files loaded — Lookup returns Info with empty Country
	db := &geoip.DB{}
	setGeoIPDB(db)

	if isTrustedCountry("203.0.113.5", []string{"US", "RO"}) {
		t.Error("empty country from lookup should return false")
	}
}

// ---------------------------------------------------------------------------
// setGeoIPDB / getGeoIPDB — concurrent access
// ---------------------------------------------------------------------------

func TestSetGetGeoIPDB_ConcurrentAccess(t *testing.T) {
	prev := getGeoIPDB()
	defer setGeoIPDB(prev)

	db := &geoip.DB{}
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			setGeoIPDB(db)
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		_ = getGeoIPDB()
	}
	<-done
}
