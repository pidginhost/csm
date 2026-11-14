package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- hasRecentCompromisedFinding -------------------------------------

func TestHasRecentCompromisedFindingTrue(t *testing.T) {
	emailRateSuppressed.mu.Lock()
	emailRateSuppressed.domains["example.com"] = time.Now()
	emailRateSuppressed.mu.Unlock()
	defer func() {
		emailRateSuppressed.mu.Lock()
		delete(emailRateSuppressed.domains, "example.com")
		emailRateSuppressed.mu.Unlock()
	}()

	if !hasRecentCompromisedFinding("example.com") {
		t.Error("recent domain should return true")
	}
}

func TestHasRecentCompromisedFindingExpired(t *testing.T) {
	emailRateSuppressed.mu.Lock()
	emailRateSuppressed.domains["old.com"] = time.Now().Add(-2 * time.Hour)
	emailRateSuppressed.mu.Unlock()

	if hasRecentCompromisedFinding("old.com") {
		t.Error("expired domain should return false")
	}
}

func TestHasRecentCompromisedFindingMissing(t *testing.T) {
	if hasRecentCompromisedFinding("unknown.com") {
		t.Error("unknown domain should return false")
	}
}

// --- RecordCompromisedDomain ----------------------------------------

func TestRecordCompromisedDomain(t *testing.T) {
	RecordCompromisedDomain("test.com")
	defer func() {
		emailRateSuppressed.mu.Lock()
		delete(emailRateSuppressed.domains, "test.com")
		emailRateSuppressed.mu.Unlock()
	}()

	if !hasRecentCompromisedFinding("test.com") {
		t.Error("recorded domain should be found")
	}
}

// --- parseEximLogLine with more scenarios ----------------------------

func TestParseEximLogLineDelivery(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-12 10:00:00 ABC123 => alice@example.com R=virtual_user T=virtual_user_delivery`
	findings := parseEximLogLine(line, cfg)
	if len(findings) != 0 {
		t.Errorf("normal delivery should produce 0, got %d", len(findings))
	}
}

func TestParseEximLogLineFrozen(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-12 10:00:00 ABC123 Message is frozen`
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	findings := parseEximLogLine(line, cfg)
	if len(findings) != 1 || findings[0].Check != "exim_frozen_realtime" || findings[0].Severity != alert.Warning {
		t.Fatalf("frozen line findings = %+v, want one Warning exim_frozen_realtime", findings)
	}
}

func TestParseEximLogLineAuthFail(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-12 10:00:00 H=host [203.0.113.5] F=<> rejected RCPT: relay not permitted`
	// A refused relay attempt is the MTA doing its job: nothing to report.
	if findings := parseEximLogLine(line, cfg); len(findings) != 0 {
		t.Fatalf("refused relay line produced findings: %+v", findings)
	}
}
