package incident

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func (b *blockCapture) recordOK(ip, reason string) bool {
	b.record(ip, reason)
	return true
}

func TestAutoBlockFiresOnCriticalIncidentWithRemoteIP(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
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

func TestAutoBlockSkipsFTPLoginAfterBruteforceOnly(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "ftp_login_after_bruteforce",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.60",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired for FTP success-after-brute advisory: %d", got)
	}
}

func TestAutoBlockSkipsFTPLoginAfterBruteforceOnlyAfterTimelineCap(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
	})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < maxIncidentTimeline*2; i++ {
		now := base.Add(time.Duration(i) * time.Millisecond)
		c.now = func() time.Time { return now }
		f := alert.Finding{
			Check:     "ftp_login_after_bruteforce",
			Severity:  alert.Critical,
			SourceIP:  "192.0.2.60",
			Timestamp: now,
		}
		if _, _, err := c.OnFinding(f); err != nil {
			t.Fatalf("OnFinding %d: %v", i, err)
		}
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired for repeated FTP success-after-brute advisory: %d", got)
	}
}

func TestAutoBlockFiresWhenBlockableFindingJoinsFTPAdvisory(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	advisory := alert.Finding{
		Check:     "ftp_login_after_bruteforce",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.61",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(advisory); err != nil {
		t.Fatalf("OnFinding advisory: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired before blockable evidence joined: %d", got)
	}

	brute := alert.Finding{
		Check:     "ftp_bruteforce",
		Severity:  alert.High,
		SourceIP:  "192.0.2.61",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return brute.Timestamp }
	if _, _, err := c.OnFinding(brute); err != nil {
		t.Fatalf("OnFinding brute: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("incident auto-block calls = %d, want 1 after ftp_bruteforce joins", got)
	}
}

func TestAutoBlockSkipsMailBruteforceSuspectedOnly(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	// High severity at a high gate would block any non-excluded finding; the
	// advisory must stay visibility-only so a misconfigured customer is not
	// locked out.
	f := alert.Finding{
		Check:     "mail_bruteforce_suspected",
		Severity:  alert.High,
		SourceIP:  "192.0.2.70",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired for mail_bruteforce_suspected advisory at high gate: %d", got)
	}
}

func TestAutoBlockSkipsEstablishedSourceMailCompromiseAdvisory(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "mail_account_compromised",
		Severity:  alert.High,
		SourceIP:  "192.0.2.73",
		Mailbox:   "victim@example.com",
		Message:   "Mail account compromise from 192.0.2.73 (established multi-mailbox source)",
		Timestamp: now,
	}
	id, _, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired for established-source compromise advisory: %d", got)
	}
	inc, ok := c.Get(id)
	if !ok || len(inc.Timeline) != 1 || inc.Timeline[0].Severity != alert.High.String() {
		t.Fatalf("timeline did not retain advisory severity: found=%v incident=%+v", ok, inc)
	}
}

func TestAutoBlockCriticalMailCompromiseStillBlocksAfterAdvisory(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	advisory := alert.Finding{
		Check:     "mail_account_compromised",
		Severity:  alert.High,
		SourceIP:  "192.0.2.74",
		Mailbox:   "victim@example.com",
		Message:   "Mail account compromise from 192.0.2.74 (established multi-mailbox source)",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(advisory); err != nil {
		t.Fatalf("OnFinding advisory: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired before Critical evidence joined: %d", got)
	}

	critical := advisory
	critical.Severity = alert.Critical
	critical.Message = "Mail account compromise from 192.0.2.74"
	critical.Timestamp = now.Add(time.Minute)
	c.now = func() time.Time { return critical.Timestamp }
	if _, _, err := c.OnFinding(critical); err != nil {
		t.Fatalf("OnFinding critical: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("incident auto-block calls = %d, want 1 after Critical compromise", got)
	}
}

func TestSprayAutoBlockSkipsEstablishedSourceMailCompromiseAdvisory(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		SpraySuppression: SpraySuppressionConfig{
			Enabled:            true,
			DistinctMailboxes:  1,
			SeverityEscalateAt: 2,
			PerCheck:           map[string]bool{"mail_account_compromised": true},
			BlockAtSeverity:    "high",
		},
		OnSprayBlock: cap.record,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}

	f := alert.Finding{
		Check:     "mail_account_compromised",
		Severity:  alert.High,
		SourceIP:  "192.0.2.75",
		Mailbox:   "victim@example.com",
		Message:   "Mail account compromise from 192.0.2.75 (established multi-mailbox source)",
		Timestamp: now,
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if id == "" || !created {
		t.Fatalf("advisory finding did not remain visible as an incident: id=%q created=%v", id, created)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("spray auto-block fired for established-source compromise advisory: %d", got)
	}

	critical := f
	critical.Severity = alert.Critical
	critical.Mailbox = "victim2@example.com"
	critical.Message = "Mail account compromise from 192.0.2.75"
	critical.Timestamp = now.Add(time.Minute)
	c.now = func() time.Time { return critical.Timestamp }
	if c.spray != nil {
		c.spray.now = c.now
	}
	if _, _, err := c.OnFinding(critical); err != nil {
		t.Fatalf("OnFinding critical: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("spray auto-block calls = %d, want 1 after Critical compromise", got)
	}
}

func TestIncidentAutoBlockExclusionRestoresLegacyMailCompromiseEvents(t *testing.T) {
	tests := []struct {
		name    string
		event   IncidentEvent
		exclude bool
	}{
		{
			name: "advisory marker",
			event: IncidentEvent{
				Kind:    "finding",
				Check:   "mail_account_compromised",
				Message: "Mail account compromise (established multi-mailbox source)",
			},
			exclude: true,
		},
		{
			name: "critical message",
			event: IncidentEvent{
				Kind:    "finding",
				Check:   "mail_account_compromised",
				Message: "Mail account compromise",
			},
			exclude: false,
		},
		{
			name: "marker inside attacker-controlled text",
			event: IncidentEvent{
				Kind:    "finding",
				Check:   "mail_account_compromised",
				Message: "Mail account compromise for (established multi-mailbox source) from 192.0.2.76",
			},
			exclude: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inc := &Incident{Timeline: []IncidentEvent{tt.event}}
			if got := incidentAutoBlockExcludedOnly(inc); got != tt.exclude {
				t.Errorf("incidentAutoBlockExcludedOnly() = %v, want %v", got, tt.exclude)
			}
		})
	}
}

func TestAutoBlockSkipsModSecAdvisoryOnly(t *testing.T) {
	for _, check := range []string{"modsec_low_confidence_burst", "modsec_classifier_gap"} {
		t.Run(check, func(t *testing.T) {
			var cap blockCapture
			c := NewCorrelator(CorrelatorConfig{
				OpenThreshold: 1,
				AutoBlock: IncidentAutoBlockConfig{
					Enabled:         true,
					BlockAtSeverity: "high",
				},
				OnIncidentBlock: cap.recordOK,
			})
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }

			f := alert.Finding{
				Check:     check,
				Severity:  alert.High,
				SourceIP:  "192.0.2.72",
				Timestamp: now,
			}
			if _, _, err := c.OnFinding(f); err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			if got := cap.len(); got != 0 {
				t.Fatalf("incident auto-block fired for advisory %s: %d", check, got)
			}
		})
	}
}

func TestAutoBlockFiresWhenBlockableFindingJoinsMailSuspected(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "high",
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	advisory := alert.Finding{
		Check:     "mail_bruteforce_suspected",
		Severity:  alert.High,
		SourceIP:  "192.0.2.71",
		Timestamp: now,
	}
	if _, _, err := c.OnFinding(advisory); err != nil {
		t.Fatalf("OnFinding advisory: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("incident auto-block fired before blockable evidence joined: %d", got)
	}

	// A real brute-force from the same source joins the incident: the exclusion
	// no longer holds and the block fires.
	brute := alert.Finding{
		Check:     "mail_bruteforce",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.71",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return brute.Timestamp }
	if _, _, err := c.OnFinding(brute); err != nil {
		t.Fatalf("OnFinding brute: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("incident auto-block calls = %d, want 1 after mail_bruteforce joins", got)
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
		OnIncidentBlock: cap.recordOK,
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

func TestAutoBlockFiresOncePerIncident(t *testing.T) {
	// Repeated findings in the same incident must not emit duplicate
	// generic block callbacks after one live request has been recorded.
	var cap blockCapture
	cfg := CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cap.recordOK,
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
		OnIncidentBlock: incCap.recordOK,
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
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	// Mailbox bruteforce with a remote_ip -- excluded by kinds filter.
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

	// Web account compromise -- allowed by kinds filter. On-disk evidence
	// (a webshell under the account home) classifies as web_account_compromise,
	// not the inbound-attack web_attack kind.
	wp := alert.Finding{
		Check:     "webshell_detected",
		Severity:  alert.High,
		TenantID:  "alice",
		FilePath:  "/home/alice/public_html/x.php",
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
		OnIncidentBlock: cap.recordOK,
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
		OnIncidentBlock:  cap.recordOK,
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

func TestAutoBlockRetriesWhenCallbackReportsNoLiveBlock(t *testing.T) {
	var cap blockCapture
	live := false
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: func(ip, reason string) bool {
			cap.record(ip, reason)
			return live
		},
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f1 := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.57",
		Timestamp: now,
	}
	id, _, err := c.OnFinding(f1)
	if err != nil {
		t.Fatalf("OnFinding first: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("dry-run callback attempts = %d, want 1", got)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("created incident not found")
	}
	if hasIncidentAction(inc.Actions, "incident_block_requested") {
		t.Fatal("dry-run callback latched incident_block_requested")
	}

	live = true
	f2 := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.57",
		Timestamp: now.Add(time.Minute),
	}
	c.now = func() time.Time { return now.Add(time.Minute) }
	if _, _, err := c.OnFinding(f2); err != nil {
		t.Fatalf("OnFinding second: %v", err)
	}
	if got := cap.len(); got != 2 {
		t.Fatalf("live retry attempts = %d, want 2 total", got)
	}
	inc, ok = c.Get(id)
	if !ok {
		t.Fatal("incident not found after retry")
	}
	if !hasIncidentAction(inc.Actions, "incident_block_requested") {
		t.Fatal("live retry did not record incident_block_requested")
	}
}

func TestAutoBlockUsesTimelineRemoteIPForMailboxIncident(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
			Kinds:           map[Kind]bool{KindMailboxTakeover: true},
		},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "email_compromised_account",
		Severity:  alert.Critical,
		Mailbox:   "victim@example.com",
		SourceIP:  "192.0.2.58",
		Timestamp: now,
	}
	id, _, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("OnIncidentBlock fired %d times, want 1", got)
	}
	if cap.calls[0].IP != "192.0.2.58" {
		t.Errorf("block IP = %q, want 192.0.2.58", cap.calls[0].IP)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("created incident not found")
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != "" {
		t.Fatalf("mailbox incident correlation key = %+v, want mailbox key without RemoteIP", inc.CorrelationKey)
	}
}

func TestAutoBlockSkipsTruncatedTimelineWithoutRemoteIPKey(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
			Kinds:           map[Kind]bool{KindMailboxTakeover: true},
		},
		OnIncidentBlock: cap.recordOK,
	})
	base := time.Unix(1_700_000_000, 0)
	var id string
	for i := 0; i < maxIncidentTimeline*3; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		c.now = func() time.Time { return now }
		ip := "192.0.2.58"
		if i == maxIncidentTimeline {
			ip = "192.0.2.59"
		}
		sev := alert.Warning
		if i == maxIncidentTimeline*3-1 {
			sev = alert.Critical
		}
		gotID, _, err := c.OnFinding(alert.Finding{
			Check:     "email_compromised_account",
			Severity:  sev,
			Mailbox:   "victim@example.com",
			SourceIP:  ip,
			Timestamp: now,
		})
		if err != nil {
			t.Fatalf("OnFinding %d: %v", i, err)
		}
		if gotID != "" {
			id = gotID
		}
	}

	if got := cap.len(); got != 0 {
		t.Fatalf("OnIncidentBlock fired %d times for truncated non-IP-keyed timeline; want 0", got)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("created incident not found")
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != "" {
		t.Fatalf("mailbox incident correlation key = %+v, want mailbox key without RemoteIP", inc.CorrelationKey)
	}
	if _, markers := timelineTruncationCountForTest(t, inc.Timeline); markers != 1 {
		t.Fatalf("truncation markers = %d, want 1", markers)
	}
	if candidate := incidentBlockCandidate(&inc); candidate != "" {
		t.Fatalf("incidentBlockCandidate = %q, want empty for truncated non-IP-keyed timeline", candidate)
	}
}

// X13 regression: when OnIncidentBlock panics the in-flight slot must
// still be cleared. Before the fix, a panicking callback left the
// incident permanently latched in pendingIncidentBlocks and every
// subsequent finding hit the "block already in-flight" early-return.
// A recurring panic class (nil deref in a verdict integration, a
// closed channel send in a fault-injection harness) would then take
// the auto-block path offline for the entire incident's lifetime.
func TestAutoBlockReleasesPendingSlotOnPanic(t *testing.T) {
	calls := 0
	cb := func(_, _ string) bool {
		calls++
		if calls == 1 {
			panic("simulated firewall panic")
		}
		return true
	}
	c := NewCorrelator(CorrelatorConfig{
		OpenThreshold: 1,
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
		},
		OnIncidentBlock: cb,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	f := alert.Finding{
		Check:     "modsec_csm_block_escalation",
		Severity:  alert.Critical,
		SourceIP:  "192.0.2.60",
		Timestamp: now,
	}

	// First finding: callback panics. The OnFinding defer chain runs
	// afterUnlock at the bottom of the stack, so the panic propagates
	// to OnFinding's caller (us). Recover so the test can continue,
	// then verify the next finding can re-trigger the auto-block path.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic to propagate from OnIncidentBlock")
			}
		}()
		_, _, _ = c.OnFinding(f)
	}()

	if calls != 1 {
		t.Fatalf("OnIncidentBlock call count after first finding = %d, want 1", calls)
	}

	c.mu.Lock()
	leftover := len(c.pendingIncidentBlocks)
	c.mu.Unlock()
	if leftover != 0 {
		t.Fatalf("pendingIncidentBlocks count after panic = %d, want 0", leftover)
	}

	// Second finding from the same source: same incident, same IP. The
	// auto-block path must arm again and the callback must run a second
	// time (no longer stuck behind the latched in-flight slot).
	f2 := f
	f2.Timestamp = now.Add(time.Minute)
	if _, _, err := c.OnFinding(f2); err != nil {
		t.Fatalf("OnFinding retry: %v", err)
	}
	if calls != 2 {
		t.Fatalf("OnIncidentBlock call count after retry = %d, want 2", calls)
	}
	foundAction := false
	for _, inc := range c.Snapshot() {
		// The modsec_csm_block_escalation finding is remote-IP-only, so it
		// classifies as web_attack.
		if inc.Kind != KindWebAttack {
			continue
		}
		if hasIncidentAction(inc.Actions, "incident_block_requested") {
			foundAction = true
		}
	}
	if !foundAction {
		t.Fatal("incident missing incident_block_requested action after retry")
	}
}
