package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// ---------------------------------------------------------------------------
// handlers_dovecot.go — trusted-country suppression branch
// ---------------------------------------------------------------------------

func TestParseDovecotLogLine_MissingDovecotTag(t *testing.T) {
	// Line has "Login: user=<...>" but no "dovecot:" prefix -> returns nil
	cfg := &config.Config{}
	line := `Apr 12 10:00:00 host other: Login: user=<user@example.com>, rip=203.0.113.5`
	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("non-dovecot line should return nil, got %+v", findings)
	}
}

func TestParseDovecotLogLine_BothFieldsMissing(t *testing.T) {
	// Has "dovecot:" + "Login: user=<" but malformed -> parseDovecotLoginFields
	// returns empty strings, so parent bails out.
	cfg := &config.Config{}
	line := `Apr 12 10:00:00 host dovecot: imap-login: Login: user=<alice@ex.com>, nothing=here`
	findings := parseDovecotLogLine(line, cfg)
	if findings != nil {
		t.Errorf("missing rip should return nil, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// pam_listener.go — processEvent branch coverage
// ---------------------------------------------------------------------------

func TestPAMProcessEventMalformedLine(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	// Line with only one part, no key=value payload
	p.processEvent("FAIL")
	select {
	case f := <-alertCh:
		t.Fatalf("malformed should not alert: %+v", f)
	default:
	}
	if len(p.failures) != 0 {
		t.Errorf("malformed should not create tracker, got %+v", p.failures)
	}
}

func TestPAMProcessEventDashIP(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip=- user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("dash IP should be ignored: %+v", f)
	default:
	}
	if len(p.failures) != 0 {
		t.Errorf("dash IP should not create tracker, got %+v", p.failures)
	}
}

func TestPAMProcessEventEmptyIP(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip= user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("empty IP should be ignored: %+v", f)
	default:
	}
}

func TestPAMProcessEventInfraIPIgnored(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("FAIL ip=10.5.5.5 user=root service=sshd")
	p.processEvent("OK ip=10.5.5.5 user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("infra IP should not produce alert: %+v", f)
	default:
	}
}

func TestPAMProcessEventUnknownEventType(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	// Events like "MAYBE" fall through the switch without matching.
	p.processEvent("MAYBE ip=203.0.113.5 user=root service=sshd")
	select {
	case f := <-alertCh:
		t.Fatalf("unknown event should not alert: %+v", f)
	default:
	}
}

// ---------------------------------------------------------------------------
// pam_listener.go — recordFailure window expiration resets tracker
// ---------------------------------------------------------------------------

func TestPAMRecordFailureWindowExpiration(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginWindowMin = 1 // 1 minute window
	cfg.Thresholds.MultiIPLoginThreshold = 5
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	// Seed a tracker with an old firstSeen so the window has expired.
	ip := "203.0.113.77"
	p.mu.Lock()
	p.failures[ip] = &pamFailureTracker{
		count:     4,
		firstSeen: time.Now().Add(-10 * time.Minute),
		lastSeen:  time.Now().Add(-10 * time.Minute),
		users:     map[string]bool{"root": true},
		services:  map[string]bool{"sshd": true},
	}
	p.mu.Unlock()

	// This failure should trigger window expiration reset (not alert).
	p.recordFailure(ip, "alice", "ssh")

	select {
	case f := <-alertCh:
		t.Fatalf("window reset should not alert: %+v", f)
	default:
	}

	// Verify tracker was reset: count back to 1, users/services only has new values
	p.mu.Lock()
	tr := p.failures[ip]
	if tr.count != 1 {
		t.Errorf("count = %d, want 1 (reset)", tr.count)
	}
	if !tr.users["alice"] {
		t.Errorf("users should contain new user after reset, got %v", tr.users)
	}
	if tr.users["root"] {
		t.Errorf("old users should be cleared, got %v", tr.users)
	}
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// pam_listener.go — clearFailures removes entry
// ---------------------------------------------------------------------------

func TestPAMClearFailuresRemovesEntry(t *testing.T) {
	p := &PAMListener{
		failures: make(map[string]*pamFailureTracker),
	}
	p.failures["1.2.3.4"] = &pamFailureTracker{count: 3}

	p.clearFailures("1.2.3.4")

	if _, ok := p.failures["1.2.3.4"]; ok {
		t.Error("clearFailures should remove entry")
	}
}

func TestPAMClearFailuresMissingIsNoop(t *testing.T) {
	p := &PAMListener{
		failures: make(map[string]*pamFailureTracker),
	}
	// Should not panic or alter state
	p.clearFailures("nonexistent")
	if len(p.failures) != 0 {
		t.Errorf("map size = %d", len(p.failures))
	}
}

// ---------------------------------------------------------------------------
// pam_listener.go — OK event fires pam_login alert with user/service details
// ---------------------------------------------------------------------------

func TestPAMProcessEventOKCarriesDetails(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}
	p.processEvent("OK ip=203.0.113.5 user=bob service=sshd")
	select {
	case f := <-alertCh:
		if f.Check != "pam_login" {
			t.Errorf("check = %q, want pam_login", f.Check)
		}
		if f.Severity != alert.High {
			t.Errorf("severity = %v, want High", f.Severity)
		}
		if !strings.Contains(f.Message, "bob") {
			t.Errorf("message missing user: %q", f.Message)
		}
		if !strings.Contains(f.Message, "sshd") {
			t.Errorf("message missing service: %q", f.Message)
		}
	default:
		t.Fatal("expected pam_login finding")
	}
}
