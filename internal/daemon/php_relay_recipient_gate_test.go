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
	w.appendMessage(ip, "k:/", now, "", []string{"Admin@Example.com", "<admin@example.com>", "ops@example.org"})
	w.appendMessage(ip, "k:/", now, "", []string{"sales@example.net"})

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if !known {
		t.Fatal("known = false, want true after recording recipients")
	}
	if count != 3 {
		t.Fatalf("distinct recipients = %d, want 3", count)
	}

	// Recipients older than the window are excluded.
	w.appendMessage(ip, "k:/", now.Add(-2*time.Hour), "", []string{"old@example.com"})
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

	w.appendMessage(ip, "k:/", now.Add(-2*time.Hour), "", []string{"old@example.com"})

	count, known := w.distinctRecipientsSince(ip, now.Add(-5*time.Minute))
	if count != 0 || known {
		t.Fatalf("stale recipients = (%d,%v), want (0,false)", count, known)
	}
}

func TestPerIPWindow_RecipientParseGapMakesWindowUnknown(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.52"

	w.appendMessage(ip, "k:/", now, "", []string{"admin@example.com"})
	w.appendMessage(ip, "k:/", now.Add(time.Second), "", nil)

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if count != 1 || known {
		t.Fatalf("partial recipient data = (%d,%v), want (1,false)", count, known)
	}
}

func TestPerIPWindow_StaleRecipientParseGapDoesNotHideFreshKnownData(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.53"

	w.appendMessage(ip, "k:/", now.Add(-2*time.Hour), "", nil)
	w.appendMessage(ip, "k:/", now, "", []string{"admin@example.com"})

	count, known := w.distinctRecipientsSince(ip, now.Add(-5*time.Minute))
	if count != 1 || !known {
		t.Fatalf("fresh known data after stale gap = (%d,%v), want (1,true)", count, known)
	}
}

func TestPerIPWindow_RecipientEvictionKeepsHighDiversityAboveGate(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.54"

	for i := 0; i < maxTrackedRecipients+50; i++ {
		w.appendMessage(ip, "k:/", now, "", []string{fmt.Sprintf("victim%03d@example.com", i)})
	}

	count, known := w.distinctRecipientsSince(ip, now.Add(-time.Minute))
	if !known {
		t.Fatal("known = false, want true after recording recipients")
	}
	if count < 5 {
		t.Fatalf("distinct recipients after eviction = %d, want at least 5", count)
	}
	if count > maxTrackedRecipients {
		t.Fatalf("distinct recipients after eviction = %d, want capped at %d", count, maxTrackedRecipients)
	}
}

// seedFanout records complete messages in both windows so each Path 4 script
// hit and its recipient parse outcome become visible together.
func seedFanout(psw *perScriptWindow, pip *perIPWindow, ip string, now time.Time, recipients [][]string) {
	for i, k := range []scriptKey{"kA:/", "kB:/", "kC:/"} {
		at := now.Add(-time.Duration(i) * time.Minute)
		var rcpts []string
		if i < len(recipients) {
			rcpts = recipients[i]
		}
		psw.getOrCreate(k).appendMessage(scriptEvent{At: at, SourceIP: ip}, rcpts)
		pip.appendMessage(ip, k, at, "subj", rcpts)
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

	// Fixed admin set, three distinct recipients across all the mails.
	seedFanout(psw, pip, ip, now, [][]string{
		{"info@example.com"},
		{"alex@example.org"},
		{"alex@example.net"},
	})

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

	seedFanout(psw, pip, ip, now, [][]string{
		{"victim0@example.com", "victim1@example.com", "victim2@example.com"},
		{"victim3@example.com", "victim4@example.com", "victim5@example.com"},
		{"victim6@example.com", "victim7@example.com"},
	})

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

	seedFanout(psw, pip, ip, now, nil)

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

	seedFanout(psw, pip, ip, now, [][]string{
		{"info@example.com"},
		nil,
		{"info@example.com"},
	})

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

	seedFanout(psw, pip, ip, now, [][]string{
		{"info@example.com"},
		{"info@example.com"},
		{"info@example.com"},
	})

	findings := eng.evaluatePaths("kC:/", ip, "u", now)
	if !fanoutFired(findings) {
		t.Fatalf("Path 4 must fire when the recipient gate is disabled, got %+v", findings)
	}
}

// seedVolume appends n mails from one script inside the Path 2 window.
func seedVolume(psw *perScriptWindow, k scriptKey, n int, now time.Time) {
	st := psw.getOrCreate(k)
	for i := 0; i < n; i++ {
		st.append(scriptEvent{At: now.Add(-time.Duration(i) * 15 * time.Second), MsgID: fmt.Sprintf("m%d", i)})
	}
}

func seedVolumeWithRecipients(psw *perScriptWindow, k scriptKey, n int, now time.Time, recipients func(int) []string) {
	st := psw.getOrCreate(k)
	for i := 0; i < n; i++ {
		e := scriptEvent{At: now.Add(-time.Duration(i) * 15 * time.Second), MsgID: fmt.Sprintf("m%d", i)}
		st.appendMessage(e, recipients(i))
	}
}

func volumeFired(findings []alert.Finding) bool {
	for _, f := range findings {
		if f.Path == "volume" {
			return true
		}
	}
	return false
}

// FP seen in production: a WordPress security plugin emitted 91 alert mails in
// an hour to one admin address. Path 2 counted them as relay abuse, opened a
// CRITICAL account-compromise incident and auto-blocked the visitor IP for 24h.
func TestEvaluatePaths_Path2_SuppressedForLowRecipientDiversity(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	eng := newEvaluator(psw, newPerIPWindow(64), nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()

	seedVolumeWithRecipients(psw, "kV:/wp-cron.php", 91, now, func(int) []string {
		return []string{"admin@example.com"}
	})
	count, known := psw.getOrCreate("kV:/wp-cron.php").distinctRecipientsSince(now.Add(-time.Hour))
	if count != 1 || !known {
		t.Fatalf("Wordfence recipients = (%d,%v), want (1,true)", count, known)
	}

	findings := eng.evaluatePaths("kV:/wp-cron.php", "192.0.2.44", "u", now)
	if volumeFired(findings) {
		t.Fatalf("Path 2 must be suppressed for notification mail to one address, got %+v", findings)
	}
}

// True positive: same volume, but spread across many distinct recipients is
// what relay abuse actually looks like.
func TestEvaluatePaths_Path2_FiresOnHighRecipientDiversity(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	eng := newEvaluator(psw, newPerIPWindow(64), nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()

	seedVolumeWithRecipients(psw, "kV:/mailer.php", 30, now, func(i int) []string {
		return []string{fmt.Sprintf("victim%d@example.com", i%8)}
	})

	findings := eng.evaluatePaths("kV:/mailer.php", "", "u", now)
	if !volumeFired(findings) {
		t.Fatalf("Path 2 must fire for high recipient diversity, got %+v", findings)
	}
}

// Fail open: no recipient data recorded must never weaken detection.
func TestEvaluatePaths_Path2_FiresWhenRecipientsUnknown(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	eng := newEvaluator(psw, newPerIPWindow(64), nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()

	seedVolume(psw, "kV:/unknown.php", 30, now)

	findings := eng.evaluatePaths("kV:/unknown.php", "", "u", now)
	if !volumeFired(findings) {
		t.Fatalf("Path 2 must fire when recipients are unknown (fail open), got %+v", findings)
	}
}

// A parse gap inside the window leaves the window unknown, so a real relay
// cannot hide behind one successfully parsed notification.
func TestEvaluatePaths_Path2_FiresWhenRecipientWindowPartiallyUnknown(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 5
	psw := newPerScriptWindow()
	eng := newEvaluator(psw, newPerIPWindow(64), nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()

	seedVolumeWithRecipients(psw, "kV:/partial.php", 30, now, func(i int) []string {
		if i == 12 {
			return nil
		}
		return []string{"admin@example.com"}
	})

	findings := eng.evaluatePaths("kV:/partial.php", "", "u", now)
	if !volumeFired(findings) {
		t.Fatalf("Path 2 must fire when recipient data is partially unknown, got %+v", findings)
	}
}

// Operators who set the threshold to 0 opt out of the gate entirely.
func TestEvaluatePaths_Path2_GateDisabledWhenThresholdZero(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 0
	psw := newPerScriptWindow()
	eng := newEvaluator(psw, newPerIPWindow(64), nil, cfg, nil)
	now := time.Unix(1_700_000_000, 0).UTC()

	seedVolumeWithRecipients(psw, "kV:/optout.php", 30, now, func(int) []string {
		return []string{"admin@example.com"}
	})

	findings := eng.evaluatePaths("kV:/optout.php", "", "u", now)
	if !volumeFired(findings) {
		t.Fatalf("gate disabled must leave Path 2 firing, got %+v", findings)
	}
}
