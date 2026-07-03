package daemon

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// DMN-02: thresholds are tagged hotreload:"safe", so a SIGHUP reload that
// changes them must reach the live SMTP/mail brute-force trackers. Before the
// fix the trackers froze their thresholds at construction and kept using the
// startup values until a full daemon restart.

func hasCheckFinding(findings []alert.Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check {
			return true
		}
	}
	return false
}

func TestSMTPAuthTrackerSetThresholdsAppliesLive(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	tr := newSMTPAuthTracker(100, 100, 100, 10*time.Minute, time.Hour, 10000, clk)

	ip := "203.0.113.7"
	for i := 0; i < 6; i++ {
		if f := tr.Record(ip, ""); hasCheckFinding(f, "smtp_bruteforce") {
			t.Fatalf("smtp_bruteforce fired under the high (100) threshold at i=%d", i)
		}
	}

	// Operator lowers the per-IP threshold and sends SIGHUP.
	tr.SetThresholds(5, 100, 100, 10*time.Minute, time.Hour, 10000)

	f := tr.Record(ip, "")
	if !hasCheckFinding(f, "smtp_bruteforce") {
		t.Fatalf("smtp_bruteforce did not fire after lowering threshold to 5; got %+v", f)
	}
}

func TestMailAuthTrackerSetThresholdsAppliesLive(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	tr := newMailAuthTracker(100, 100, 100, 10*time.Minute, time.Hour, 10000, clk)

	ip := "203.0.113.8"
	for i := 0; i < 6; i++ {
		if f := tr.Record(ip, "victim@example.com"); hasCheckFinding(f, "mail_bruteforce") {
			t.Fatalf("mail_bruteforce fired under the high (100) threshold at i=%d", i)
		}
	}

	tr.SetThresholds(5, 100, 100, 10*time.Minute, time.Hour, 10000)

	f := tr.Record(ip, "victim@example.com")
	if !hasCheckFinding(f, "mail_bruteforce") {
		t.Fatalf("mail_bruteforce did not fire after lowering threshold to 5; got %+v", f)
	}
}

func TestSMTPAuthTrackerSetThresholdsZeroDisablesSignals(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	tr := newSMTPAuthTracker(5, 8, 12, 10*time.Minute, time.Hour, 10000, clk)
	tr.SetThresholds(0, 0, 0, 10*time.Minute, time.Hour, 10000)

	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		for i := 0; i < 3; i++ {
			if got := tr.Record(ip, "victim@example.com"); len(got) != 0 {
				t.Fatalf("disabled SMTP auth thresholds emitted findings: %+v", got)
			}
		}
	}
}

func TestMailAuthTrackerSetThresholdsZeroDisablesSignals(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	tr := newMailAuthTracker(5, 8, 12, 10*time.Minute, time.Hour, 10000, clk)
	tr.SetThresholds(0, 0, 0, 10*time.Minute, time.Hour, 10000)

	for _, ip := range []string{"203.0.113.4", "203.0.113.5", "203.0.113.6"} {
		for i := 0; i < 3; i++ {
			if got := tr.Record(ip, "victim@example.com"); len(got) != 0 {
				t.Fatalf("disabled mail auth thresholds emitted findings: %+v", got)
			}
		}
	}
}

func TestSMTPProbeTrackerSetThresholdsAppliesLive(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	tr := newSMTPProbeTracker(100, 5*time.Minute, time.Hour, 10000, clk, nil)

	ip := "203.0.113.9"
	for i := 0; i < 6; i++ {
		if f := tr.Record(ip); hasCheckFinding(f, "smtp_probe_abuse") {
			t.Fatalf("smtp_probe_abuse fired under the high (100) threshold at i=%d", i)
		}
	}

	tr.SetThresholds(5, 5*time.Minute, time.Hour, 10000)

	f := tr.Record(ip)
	if !hasCheckFinding(f, "smtp_probe_abuse") {
		t.Fatalf("smtp_probe_abuse did not fire after lowering threshold to 5; got %+v", f)
	}
}

// hotReloadThresholdConfig returns a config whose brute-force thresholds are
// low enough that a handful of failures trips the per-IP detectors.
func hotReloadThresholdConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Thresholds.SMTPBruteForceThreshold = 5
	cfg.Thresholds.SMTPBruteForceSubnetThresh = 100
	cfg.Thresholds.SMTPAccountSprayThreshold = 100
	cfg.Thresholds.SMTPBruteForceWindowMin = 10
	cfg.Thresholds.SMTPBruteForceSuppressMin = 60
	cfg.Thresholds.SMTPBruteForceMaxTracked = 10000
	cfg.Thresholds.SMTPProbeThreshold = 5
	cfg.Thresholds.SMTPProbeWindowMin = 5
	cfg.Thresholds.SMTPProbeSuppressMin = 60
	cfg.Thresholds.SMTPProbeMaxTracked = 10000
	cfg.Thresholds.MailBruteForceThreshold = 5
	cfg.Thresholds.MailBruteForceSubnetThresh = 100
	cfg.Thresholds.MailAccountSprayThreshold = 100
	cfg.Thresholds.MailBruteForceWindowMin = 10
	cfg.Thresholds.MailBruteForceSuppressMin = 60
	cfg.Thresholds.MailBruteForceMaxTracked = 10000
	return cfg
}

func TestReconcileBruteThresholdsPushesConfigIntoTrackers(t *testing.T) {
	now := time.Now()
	clk := func() time.Time { return now }
	d := &Daemon{
		smtpAuthTracker:  newSMTPAuthTracker(100, 100, 100, 10*time.Minute, time.Hour, 10000, clk),
		smtpProbeTracker: newSMTPProbeTracker(100, 5*time.Minute, time.Hour, 10000, clk, nil),
		mailAuthTracker:  newMailAuthTracker(100, 100, 100, 10*time.Minute, time.Hour, 10000, clk),
	}

	prev := config.Active()
	config.SetActive(hotReloadThresholdConfig())
	t.Cleanup(func() { config.SetActive(prev) })

	d.reconcileBruteThresholds()

	smtpFired, mailFired, probeFired := false, false, false
	for i := 0; i < 6; i++ {
		if hasCheckFinding(d.smtpAuthTracker.Record("203.0.113.10", ""), "smtp_bruteforce") {
			smtpFired = true
		}
		if hasCheckFinding(d.mailAuthTracker.Record("203.0.113.11", "victim@example.com"), "mail_bruteforce") {
			mailFired = true
		}
		if hasCheckFinding(d.smtpProbeTracker.Record("203.0.113.12"), "smtp_probe_abuse") {
			probeFired = true
		}
	}
	if !smtpFired {
		t.Error("smtp auth tracker did not adopt the reloaded threshold")
	}
	if !mailFired {
		t.Error("mail auth tracker did not adopt the reloaded threshold")
	}
	if !probeFired {
		t.Error("smtp probe tracker did not adopt the reloaded threshold")
	}
}

func TestReloadConfigPushesBruteThresholdsIntoAllTrackers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := hotReloadThresholdConfig()
	orig.Hostname = "host-a"
	orig.Thresholds.SMTPBruteForceThreshold = 50
	orig.Thresholds.MailBruteForceThreshold = 50
	orig.Thresholds.SMTPProbeThreshold = 10000
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load seeded config: %v", err)
	}
	prev := config.Active()
	config.SetActive(loaded)
	t.Cleanup(func() {
		config.SetActive(prev)
		SetAccountExtractor(nil)
	})

	d := New(loaded, nil, nil, "")
	for i := 0; i < 4; i++ {
		if got := d.smtpAuthTracker.Record("203.0.113.30", ""); len(got) != 0 {
			t.Fatalf("smtp auth fired before reload: %+v", got)
		}
		if got := d.mailAuthTracker.Record("203.0.113.31", "victim@example.com"); len(got) != 0 {
			t.Fatalf("mail auth fired before reload: %+v", got)
		}
	}
	for i := 0; i < 9; i++ {
		if got := d.smtpProbeTracker.Record("203.0.113.32"); len(got) != 0 {
			t.Fatalf("smtp probe fired before reload: %+v", got)
		}
	}

	edited := hotReloadThresholdConfig()
	edited.Hostname = "host-a"
	edited.Thresholds.SMTPBruteForceSubnetThresh = 64
	edited.Thresholds.SMTPProbeThreshold = 10
	edited.Thresholds.MailBruteForceSubnetThresh = 64
	edited.Integrity = loaded.Integrity
	seedConfigAtPath(t, cfgPath, edited)

	d.reloadConfig()

	if got := d.smtpAuthTracker.Record("203.0.113.30", ""); !hasCheckFinding(got, "smtp_bruteforce") {
		t.Fatalf("reload did not push smtp auth threshold; got %+v", got)
	}
	if got := d.mailAuthTracker.Record("203.0.113.31", "victim@example.com"); !hasCheckFinding(got, "mail_bruteforce") {
		t.Fatalf("reload did not push mail auth threshold; got %+v", got)
	}
	if got := d.smtpProbeTracker.Record("203.0.113.32"); !hasCheckFinding(got, "smtp_probe_abuse") {
		t.Fatalf("reload did not push smtp probe threshold; got %+v", got)
	}
}

// TestReconcileBruteThresholdsRaceWithRecord runs the reload push concurrently
// with live Record traffic under -race to prove the threshold swap is
// serialized through each tracker's mutex.
func TestReconcileBruteThresholdsRaceWithRecord(t *testing.T) {
	d := &Daemon{
		smtpAuthTracker:  newSMTPAuthTracker(5, 8, 12, 10*time.Minute, time.Hour, 10000, time.Now),
		smtpProbeTracker: newSMTPProbeTracker(100, 5*time.Minute, time.Hour, 10000, time.Now, nil),
		mailAuthTracker:  newMailAuthTracker(5, 8, 12, 10*time.Minute, time.Hour, 10000, time.Now),
	}

	prev := config.Active()
	config.SetActive(hotReloadThresholdConfig())
	t.Cleanup(func() { config.SetActive(prev) })

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.smtpAuthTracker.Record("203.0.113.20", "victim@example.com")
				d.smtpProbeTracker.Record("203.0.113.20")
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.mailAuthTracker.Record("203.0.113.21", "victim@example.com")
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			d.reconcileBruteThresholds()
		}
		close(stop)
	}()
	wg.Wait()
}
