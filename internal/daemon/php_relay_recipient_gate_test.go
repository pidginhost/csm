package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestPerIPWindow_DistinctRecipients(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.50"

	// Case/bracket normalization and dedup: three logical recipients.
	w.recordRecipients(ip, []string{"Admin@Example.com", "<admin@example.com>", "ops@example.org"}, now)
	w.recordRecipients(ip, []string{"sales@example.net"}, now)

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if !known {
		t.Fatal("known = false, want true after recording recipients")
	}
	if count != 3 {
		t.Fatalf("distinct recipients = %d, want 3", count)
	}

	// Recipients older than the window are excluded.
	w.recordRecipients(ip, []string{"old@example.com"}, now.Add(-2*time.Hour))
	count, _ = w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if count != 3 {
		t.Fatalf("distinct recipients with window = %d, want 3", count)
	}

	// An IP we never recorded recipients for is unknown, not zero-known.
	if c, k := w.distinctRecipientsSince("198.51.100.7", now.Add(-time.Minute)); c != 0 || k {
		t.Fatalf("unseen IP = (%d,%v), want (0,false)", c, k)
	}
}

func TestPerIPWindow_StaleRecipientsAreUnknown(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.51"

	w.recordRecipients(ip, []string{"old@example.com"}, now.Add(-2*time.Hour))

	count, known := w.distinctRecipientsSince(ip, now.Add(-5*time.Minute))
	if count != 0 || known {
		t.Fatalf("stale recipients = (%d,%v), want (0,false)", count, known)
	}
}

func TestPerIPWindow_RecipientParseGapMakesWindowUnknown(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.52"

	w.recordRecipients(ip, []string{"admin@example.com"}, now)
	w.recordRecipients(ip, nil, now.Add(time.Second))

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if count != 1 || known {
		t.Fatalf("partial recipient data = (%d,%v), want (1,false)", count, known)
	}
}

func TestPerIPWindow_StaleRecipientParseGapDoesNotHideFreshKnownData(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.53"

	w.recordRecipients(ip, nil, now.Add(-2*time.Hour))
	w.recordRecipients(ip, []string{"admin@example.com"}, now)

	count, known := w.distinctRecipientsSince(ip, now.Add(-5*time.Minute))
	if count != 1 || !known {
		t.Fatalf("fresh known data after stale gap = (%d,%v), want (1,true)", count, known)
	}
}

func TestPerIPWindow_RecipientEvictionKeepsHighDiversityAboveGate(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.54"

	for i := 0; i < maxRecipientsPerIP+50; i++ {
		w.recordRecipients(ip, []string{fmt.Sprintf("victim%03d@example.com", i)}, now)
	}

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if !known {
		t.Fatal("known = false, want true after recording recipients")
	}
	if count < 5 {
		t.Fatalf("distinct recipients after eviction = %d, want at least 5", count)
	}
	if count > maxRecipientsPerIP {
		t.Fatalf("distinct recipients after eviction = %d, want capped at %d", count, maxRecipientsPerIP)
	}
}

// addFanout seeds both the per-script and per-IP windows so Path 4 sees the
// script fanout, optionally recording recipients for the per-IP window.
func seedFanout(psw *perScriptWindow, pip *perIPWindow, ip string, now time.Time) {
	for i, k := range []scriptKey{"kA:/", "kB:/", "kC:/"} {
		at := now.Add(-time.Duration(i) * time.Minute)
		psw.getOrCreate(k).append(scriptEvent{At: at, SourceIP: ip})
		pip.append(ip, k, at, "subj")
	}
}

func fanoutFired(findings []alert.Finding) bool {
	for _, f := range findings {
		if f.Path == "fanout" {
			return true
		}
	}
	return false
}

// FP: one HTTP source IP fans across many scripts but the mail reaches only a
// small fixed recipient set (WordPress comment-moderation notifications). With
// the recipient-diversity gate active, Path 4 must not escalate.
func TestEvaluatePaths_Path4_SuppressedForLowRecipientDiversity(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"

	seedFanout(psw, pip, ip, now)
	// Fixed admin set, three distinct recipients across all the mails.
	pip.recordRecipients(ip, []string{"info@example.com"}, now)
	pip.recordRecipients(ip, []string{"alex@example.org"}, now)
	pip.recordRecipients(ip, []string{"alex@example.net"}, now)

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if fanoutFired(findings) {
		t.Fatalf("Path 4 must be suppressed for low recipient diversity, got %+v", findings)
	}
}

// True positive: same script fanout, but the mail reaches many distinct
// external recipients (real relay spam). Path 4 must still fire.
func TestEvaluatePaths_Path4_FiresOnHighRecipientDiversity(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"

	seedFanout(psw, pip, ip, now)
	for i := 0; i < 8; i++ {
		pip.recordRecipients(ip, []string{fmt.Sprintf("victim%d@example.com", i)}, now)
	}

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if !fanoutFired(findings) {
		t.Fatalf("Path 4 must fire for high recipient diversity, got %+v", findings)
	}
}

// Fail open: when no recipient data was recorded (parse gap), the gate must not
// suppress Path 4 -- detection is never weakened by missing recipient info.
func TestEvaluatePaths_Path4_FiresWhenRecipientsUnknown(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"

	seedFanout(psw, pip, ip, now) // no recordRecipients

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if !fanoutFired(findings) {
		t.Fatalf("Path 4 must fire when recipients are unknown (fail open), got %+v", findings)
	}
}

// Fail open: partial recipient data is still unknown for suppression purposes.
// A real relay with parser gaps must not be hidden by a small known subset.
func TestEvaluatePaths_Path4_FiresWhenRecipientWindowPartiallyUnknown(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"

	seedFanout(psw, pip, ip, now)
	pip.recordRecipients(ip, []string{"info@example.com"}, now)
	pip.recordRecipients(ip, nil, now)

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if !fanoutFired(findings) {
		t.Fatalf("Path 4 must fire when recipient data is partially unknown, got %+v", findings)
	}
}

// Gate disabled (threshold 0): Path 4 fires on script fanout regardless of
// recipient diversity, preserving the original behavior for operators who
// opt out.
func TestEvaluatePaths_Path4_GateDisabledWhenThresholdZero(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 0
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"

	seedFanout(psw, pip, ip, now)
	pip.recordRecipients(ip, []string{"info@example.com"}, now)

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if !fanoutFired(findings) {
		t.Fatalf("Path 4 must fire when the recipient gate is disabled, got %+v", findings)
	}
}
