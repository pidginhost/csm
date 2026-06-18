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
