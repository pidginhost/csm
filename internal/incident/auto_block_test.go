package incident

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAutoBlockFiresOnCriticalIncidentWithRemoteIP(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.50",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("OnIncidentBlock called %d times, want 1 at open", got)
	}
	if cap.calls[0].IP != "192.0.2.50" {
		t.Errorf("block IP = %q, want 192.0.2.50", cap.calls[0].IP)
	}
}

func TestAutoBlockSkipsBelowSeverityGate(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "modsec_block_escalation",
		Severity:  alert.High,
		SourceIP:  "192.0.2.51",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("OnIncidentBlock fired %d times below gate; want 0", got)
	}
}

func TestAutoBlockBlocksOnNextFindingAfterArming(t *testing.T) {
	// An operator who enables AutoBlock after a Critical incident is
	// already open still expects the next finding for that IP to fire a
	// block, because the helper re-evaluates on every merge.
	var cap blockCapture
	cfg := CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.record,
	}
	c := NewCorrelator(cfg)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f1 := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.52",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f1); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("first finding fired %d blocks; want 1", got)
	}

	// Second finding into the same incident -- idempotency check.
	f2 := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.52",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return now.Add(time.Minute) }
	if _, _, err := c.OnFinding(f2); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("second finding fired %d blocks; want still 1 (idempotent)", got)
	}
}

func TestAutoBlockSkipsCredentialSprayKind(t *testing.T) {
	// The dedicated spray hand-off owns credential_spray; the generic
	// path must not fire a duplicate block for it.
	var sprayCap blockCapture
	var incCap blockCapture
	spray := SpraySuppressionConfig{
		Enabled:           true,
		DistinctMailboxes: 2,
		PerCheck:          map[string]bool{"email_auth_failure_realtime": true},
		BlockAtSeverity:   "high",
	}
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold:    1,
		SpraySuppression: spray,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnSprayBlock:    sprayCap.record,
		OnIncidentBlock: incCap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}

	for i := 0; i < 2; i++ {
		f := alert.Finding{
			Check:     "email_auth_failure_realtime",
			Severity:  alert.High,
			Mailbox:   "user" + strconv.Itoa(i) + "@example.com",
			SourceIP:  "192.0.2.53",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		}
		if _, _, err := c.OnFinding(f); err != nil {
			t.Fatalf("OnFinding[%d]: %v", i, err)
		}
	}

	if got := sprayCap.len(); got != 1 {
		t.Errorf("spray callback fired %d times; want 1", got)
	}
	if got := incCap.len(); got != 0 {
		t.Errorf("incident callback fired %d times for spray kind; want 0", got)
	}
}

func TestAutoBlockHonorsKindsFilter(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
			Kinds:           map[Kind]bool{KindWebAccountCompromise: true},
		},
		OnIncidentBlock: cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	// Mailbox takeover with a remote_ip -- excluded by kinds filter.
	mb := alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "victim@example.com",
		SourceIP:  "192.0.2.54",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(mb); err != nil {
		t.Fatalf("OnFinding mailbox: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Errorf("blocked excluded kind: %d firings, want 0", got)
	}

	// Web account compromise -- allowed by kinds filter.
	wp := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		SourceIP:  "192.0.2.55",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return now.Add(time.Minute) }
	if _, _, err := c.OnFinding(wp); err != nil {
		t.Fatalf("OnFinding wp: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Errorf("expected web kind block, got %d firings", got)
	}
}

func TestAutoBlockSkipsWhenRemoteIPMissing(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnIncidentBlock: cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("blocked without remote_ip: %d firings, want 0", got)
	}
}

func TestAutoBlockHonorsCanIncidentBlockGate(t *testing.T) {
	var cap blockCapture
	allow := false
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		CanIncidentBlock: func() bool { return allow },
		OnIncidentBlock:  cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		SourceIP:  "192.0.2.56",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Errorf("blocked while gate denied; %d firings, want 0", got)
	}

	allow = true
	f2 := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		SourceIP:  "192.0.2.56",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return now.Add(time.Minute) }
	if _, _, err := c.OnFinding(f2); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Errorf("expected block once gate flips open, got %d firings", got)
	}
	if !strings.Contains(cap.calls[0].Reason, "incident") {
		t.Errorf("reason = %q, want 'incident' prefix", cap.calls[0].Reason)
	}
}
