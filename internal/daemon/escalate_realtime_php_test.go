package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A realtime PHP finding that realtime could not confirm only alerted, and the
// file stayed until a scheduled scan reached it. The scheduled analysis of
// that file now runs at once, and its Critical verdict gets the scheduled
// response through the next dispatch batch.
func TestDispatchBatchRespondsToTheScheduledVerdictOfARealtimePHPFile(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	_, restore := openTestBoltStore(t, cfg.StatePath)
	defer restore()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	homes := filepath.Join(root, "home")
	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{homes}))
	t.Cleanup(checks.SetQuarantineDirForTest(filepath.Join(root, "quarantine")))
	path := filepath.Join(homes, "alice", "public_html", "assets", "x.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := "<?php\n$u = 'https://pastebin.com/raw/abc';\nev" + "al(base64_decode($x));\n"
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	d := openRepeatDaemon(t, cfg)
	startPHPEscalationWorker(t, d)

	d.dispatchBatch([]alert.Finding{{
		Severity: alert.Critical,
		Check:    "obfuscated_php_realtime",
		Message:  "Obfuscated PHP detected: " + path,
		FilePath: path,
		TenantID: "alice",
	}})

	result := receivePHPEscalation(t, d)
	d.dispatchBatch([]alert.Finding{result})

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("file the scheduled analysis rates Critical is still in place: %v", err)
	}
	history, _ := d.store.ReadHistory(100, 0)
	count := 0
	escalatedFingerprint := ""
	for _, f := range history {
		if f.Check == result.Check {
			count++
			escalatedFingerprint = f.Fingerprint()
			if f.Timestamp.IsZero() || f.TenantID != "alice" {
				t.Fatalf("missing history context: %+v", f)
			}
		}
	}
	if count != 1 {
		t.Fatalf("scheduled verdict recorded %d times", count)
	}
	incidents := IncidentCorrelator().Snapshot()
	if len(incidents) != 1 || incidents[0].Account != "alice" || !slices.Contains(incidents[0].Findings, escalatedFingerprint) {
		t.Fatalf("incident context=%+v", incidents)
	}
	if hook.count("AUTO-QUARANTINE: "+path) != 1 {
		t.Fatalf("no quarantine notice; last webhook body %q", hook.last())
	}
}

func TestDispatchBatchDoesNotWaitForPHPAnalysis(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	d := openRepeatDaemon(t, cfg)
	release := make(chan struct{})
	entered := make(chan struct{})
	old := escalateRealtimePHP
	escalateRealtimePHP = func(*config.Config, []alert.Finding) []alert.Finding {
		close(entered)
		<-release
		return nil
	}
	d.wg.Add(1)
	go d.phpEscalationWorker()
	done := make(chan struct{})
	go func() {
		d.dispatchBatch([]alert.Finding{{Severity: alert.Critical, Check: "obfuscated_php_realtime", FilePath: "/home/alice/public_html/x.php"}})
		close(done)
	}()
	blocked := false
	select {
	case <-done:
	case <-time.After(time.Second):
		blocked = true
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		blocked = true
	}
	close(release)
	<-done
	close(d.stopCh)
	d.wg.Wait()
	escalateRealtimePHP = old
	if blocked {
		t.Fatal("slow PHP analysis blocked alert dispatch")
	}
}

func startPHPEscalationWorker(t *testing.T, d *Daemon) {
	t.Helper()
	d.wg.Add(1)
	go d.phpEscalationWorker()
	t.Cleanup(func() { close(d.stopCh); d.wg.Wait() })
}

func receivePHPEscalation(t *testing.T, d *Daemon) alert.Finding {
	t.Helper()
	select {
	case f := <-d.alertCh:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("PHP escalation produced no result")
		return alert.Finding{}
	}
}

func TestDispatchBatchPHPEscalationEligibility(t *testing.T) {
	for _, mode := range []string{"inline evaluated", "scheduled evaluated", "scheduled pending", "suppressed", "seen"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := emailRepeatSetup(t)
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = true
			d := openRepeatDaemon(t, cfg)
			f := alert.Finding{Severity: alert.Critical, Check: "obfuscated_php_realtime", FilePath: "/home/alice/public_html/x.php"}
			batch := []alert.Finding{f}
			switch mode {
			case "inline evaluated":
				// Deliberately put provenance on the duplicate discarded by dedup.
				f.AutoFileResponseEvaluated = true
				batch = append(batch, f)
			case "scheduled evaluated", "scheduled pending":
				f.Check = "obfuscated_php"
				f.AutoFileResponseEvaluated = mode == "scheduled evaluated"
				batch = append(batch, f)
			case "suppressed":
				if err := d.store.SaveSuppressions([]state.SuppressionRule{{Check: f.Check}}); err != nil {
					t.Fatal(err)
				}
			case "seen":
				d.store.Update([]alert.Finding{f})
			}
			d.dispatchBatch(batch)
			if len(d.phpEscalations) != 0 {
				t.Fatalf("queued %d duplicate/suppressed analyses", len(d.phpEscalations))
			}
		})
	}
}

func TestDispatchEscalatedPHPUsesNormalStateAndSuppressions(t *testing.T) {
	for _, mode := range []string{"new", "seen", "suppressed"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := emailRepeatSetup(t)
			_, restore := openTestBoltStore(t, cfg.StatePath)
			defer restore()
			d := openRepeatDaemon(t, cfg)
			// No remediation: assert the observation pipeline independently.
			f := alert.Finding{Severity: alert.Critical, Check: "obfuscated_php", Message: "Obfuscated PHP", FilePath: "/home/alice/public_html/x.php"}
			if mode == "seen" {
				d.store.Update([]alert.Finding{f})
			}
			if mode == "suppressed" {
				if err := d.store.SaveSuppressions([]state.SuppressionRule{{Check: f.Check}}); err != nil {
					t.Fatal(err)
				}
			}
			d.dispatchBatch([]alert.Finding{f})
			history, _ := d.store.ReadHistory(100, 0)
			count := 0
			for _, entry := range history {
				if entry.Check == f.Check {
					count++
					if entry.Timestamp.IsZero() {
						t.Error("escalated history has no timestamp")
					}
				}
			}
			want := 0
			if mode == "new" {
				want = 1
			}
			if count != want {
				t.Fatalf("history contains %d escalations, want %d", count, want)
			}
			if len(d.store.FilterNew([]alert.Finding{f})) != 0 {
				t.Fatal("escalated result was not deduplicated")
			}
		})
	}
}

func TestPHPEscalationQueueIsBounded(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	d.queuePHPEscalations(make([]alert.Finding, cap(d.phpEscalations)+1))
	if len(d.phpEscalations) != cap(d.phpEscalations) || d.droppedAlerts != 1 {
		t.Fatalf("queue=%d dropped=%d", len(d.phpEscalations), d.droppedAlerts)
	}
	close(d.stopCh)
	d.queuePHPEscalations([]alert.Finding{{}})
	if d.droppedAlerts != 1 {
		t.Fatal("accepted work after shutdown")
	}
}

func TestDispatchEscalatedPHPDoesNotRepeatScheduledResponse(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{root}))
	t.Cleanup(checks.SetQuarantineDirForTest(filepath.Join(t.TempDir(), "quarantine")))
	path := filepath.Join(root, "alice", "public_html", "x.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := "<?php $u = 'https://pastebin.com/raw/abc'; ev" + "al(base64_decode($x));"
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	result := checks.EscalateRealtimePHP(cfg, []alert.Finding{{Check: "obfuscated_php_realtime", Severity: alert.Critical, FilePath: path}})
	if len(result) != 1 {
		t.Fatalf("result=%+v", result)
	}
	evaluated := result[0]
	evaluated.FileResponseIdentity = ""
	evaluated.AutoFileResponseEvaluated = true
	d := openRepeatDaemon(t, cfg)
	d.dispatchBatch(append(result, evaluated))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repeated an already evaluated scheduled response: %v", err)
	}
}

func TestPHPEscalationDoesNotInheritOtherCheckSuppression(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	d := openRepeatDaemon(t, cfg)
	if err := d.store.SaveSuppressions([]state.SuppressionRule{{Check: "signature_match_realtime"}}); err != nil {
		t.Fatal(err)
	}
	source := alert.Finding{Severity: alert.Critical, Check: "obfuscated_php_realtime", FilePath: "/home/alice/public_html/x.php"}
	suppressed := source
	suppressed.Check = "signature_match_realtime"
	d.dispatchBatch([]alert.Finding{source, suppressed})
	if len(d.phpEscalations) != 1 {
		t.Fatal("a suppressed, unevaluated signature prevented PHP analysis")
	}
}
