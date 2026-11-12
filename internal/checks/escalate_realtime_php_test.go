package checks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Two converging indicators: the scheduled analysis rates this Critical.
const escalationCriticalPHP = "<?php\n$u = 'https://pastebin.com/raw/abc';\nev" + "al(base64_decode($x));\n"

func escalationConfig() *config.Config {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	return cfg
}

func realtimePHPFinding(check, path string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: check, Message: "Obfuscated PHP detected: " + path, FilePath: path}
}

func writeEscalationFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(realTempDir(t), "index.php")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Realtime reads a small window and only alerts on what it cannot confirm.
// The scheduled analysis of the same file decides whether the scheduled
// response acts, now instead of when a scan next reaches the file.
func TestEscalateRealtimePHPReturnsTheScheduledVerdict(t *testing.T) {
	path := writeEscalationFile(t, escalationCriticalPHP)
	for _, check := range []string{"obfuscated_php_realtime", "webshell_content_realtime", "php_dropper_realtime"} {
		got := EscalateRealtimePHP(escalationConfig(), []alert.Finding{realtimePHPFinding(check, path)})
		if len(got) != 1 || got[0].Check != "obfuscated_php" || got[0].Severity != alert.Critical || got[0].FilePath != path {
			t.Fatalf("%s: escalated = %+v, want one Critical obfuscated_php for %s", check, got, path)
		}
		if got[0].ContentSHA256 == "" {
			t.Fatalf("%s: escalated finding carries no content digest", check)
		}
	}
}

func TestEscalateRealtimePHPLeavesTheRestAlone(t *testing.T) {
	critical := writeEscalationFile(t, escalationCriticalPHP)
	high := writeEscalationFile(t, "<?php\n$u = 'https://pastebin.com/raw/abc';\n")
	clean := writeEscalationFile(t, "<?php echo 'site';\n")
	off := escalationConfig()
	off.AutoResponse.QuarantineFiles = false
	disabled := escalationConfig()
	disabled.AutoResponse.Enabled = false
	observe := escalationConfig()
	observe.Mode = config.ModeObserve
	high0 := realtimePHPFinding("obfuscated_php_realtime", critical)
	high0.Severity = alert.High
	for name, tc := range map[string]struct {
		cfg *config.Config
		f   alert.Finding
	}{
		"scheduled High":       {escalationConfig(), realtimePHPFinding("obfuscated_php_realtime", high)},
		"scheduled clean":      {escalationConfig(), realtimePHPFinding("obfuscated_php_realtime", clean)},
		"other check":          {escalationConfig(), realtimePHPFinding("signature_match_realtime", critical)},
		"realtime High":        {escalationConfig(), high0},
		"no file":              {escalationConfig(), realtimePHPFinding("obfuscated_php_realtime", "")},
		"auto-response off":    {disabled, realtimePHPFinding("obfuscated_php_realtime", critical)},
		"observe mode":         {observe, realtimePHPFinding("obfuscated_php_realtime", critical)},
		"quarantine off":       {off, realtimePHPFinding("obfuscated_php_realtime", critical)},
		"file gone":            {escalationConfig(), realtimePHPFinding("obfuscated_php_realtime", critical+".gone")},
		"not a PHP source":     {escalationConfig(), realtimePHPFinding("obfuscated_php_realtime", critical+".txt")},
		"no auto response cfg": {nil, realtimePHPFinding("obfuscated_php_realtime", critical)},
	} {
		if got := EscalateRealtimePHP(tc.cfg, []alert.Finding{tc.f}); len(got) != 0 {
			t.Errorf("%s: escalated %+v, want nothing", name, got)
		}
	}
}

func TestEscalateRealtimePHPAnalysesEachFileOnce(t *testing.T) {
	path := writeEscalationFile(t, escalationCriticalPHP)
	got := EscalateRealtimePHP(escalationConfig(), []alert.Finding{
		realtimePHPFinding("obfuscated_php_realtime", path),
		realtimePHPFinding("webshell_content_realtime", path),
	})
	if len(got) != 1 {
		t.Fatalf("escalated %d findings for one file, want 1", len(got))
	}
}

// The dispatcher handles every alert. A FIFO or a link swapped in at the
// reported path must neither stall it nor lead it out of the site.
func TestEscalateRealtimePHPNeverBlocksOrFollows(t *testing.T) {
	dir := realTempDir(t)
	fifo := filepath.Join(dir, "fifo.php")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	target := writeEscalationFile(t, escalationCriticalPHP)
	link := filepath.Join(dir, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	done := make(chan []alert.Finding, 1)
	go func() {
		done <- EscalateRealtimePHP(escalationConfig(), []alert.Finding{
			realtimePHPFinding("obfuscated_php_realtime", fifo),
			realtimePHPFinding("obfuscated_php_realtime", link),
		})
	}()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("escalated through a FIFO or a link: %+v", got)
		}
	case <-time.After(5 * time.Second):
		writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		<-done
		t.Fatal("escalation blocked on a FIFO")
	}
}

func TestEscalateRealtimePHPDoesNotRepeatEvaluatedResponses(t *testing.T) {
	path := writeEscalationFile(t, escalationCriticalPHP)
	for _, check := range []string{"obfuscated_php_realtime", "obfuscated_php", "signature_match_realtime"} {
		t.Run(check, func(t *testing.T) {
			evaluated := realtimePHPFinding(check, path)
			evaluated.AutoFileResponseEvaluated = true
			got := EscalateRealtimePHP(escalationConfig(), []alert.Finding{
				realtimePHPFinding("webshell_content_realtime", path), evaluated,
			})
			if len(got) != 0 {
				t.Fatalf("repeated evaluated response: %+v", got)
			}
		})
	}
}

func TestEscalateRealtimePHPRejectsSymlinkedParent(t *testing.T) {
	path := writeEscalationFile(t, escalationCriticalPHP)
	link := filepath.Join(realTempDir(t), "site")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal(err)
	}
	got := EscalateRealtimePHP(escalationConfig(), []alert.Finding{
		realtimePHPFinding("obfuscated_php_realtime", filepath.Join(link, filepath.Base(path))),
	})
	if len(got) != 0 {
		t.Fatalf("followed a symlinked parent: %+v", got)
	}
}

func TestEscalatedPHPResponseRejectsReplacement(t *testing.T) {
	root := realTempDir(t)
	t.Cleanup(SetAccountHomeRootsForTest([]string{root}))
	t.Cleanup(SetQuarantineDirForTest(filepath.Join(t.TempDir(), "quarantine")))
	path := filepath.Join(root, "alice", "public_html", "x.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(escalationCriticalPHP), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := escalationConfig()
	cfg.StatePath = t.TempDir()
	findings := EscalateRealtimePHP(cfg, []alert.Finding{realtimePHPFinding("obfuscated_php_realtime", path)})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	clean := "<?php echo 'site';\n"
	clean += strings.Repeat(" ", len(escalationCriticalPHP)-len(clean))
	if err = os.WriteFile(path, []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("fixture did not preserve inode, size and mtime")
	}
	AutoQuarantineFiles(cfg, findings)
	got, err := os.ReadFile(path)
	if err != nil || string(got) != clean {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
}

func TestEscalateRealtimePHPPreservesAttribution(t *testing.T) {
	path := writeEscalationFile(t, escalationCriticalPHP)
	source := realtimePHPFinding("obfuscated_php_realtime", path)
	source.TenantID, source.Domain, source.PID = "alice", "example.com", 42
	source.ProcessInfo = "pid=42 cmd=php uid=1000"
	got := EscalateRealtimePHP(escalationConfig(), []alert.Finding{source})
	if len(got) != 1 || got[0].TenantID != source.TenantID || got[0].Domain != source.Domain || got[0].PID != source.PID || got[0].ProcessInfo != source.ProcessInfo {
		t.Fatalf("lost attribution: %+v", got)
	}
}

func TestEscalateRealtimePHPKeepsWordPressAndBudgetPolicy(t *testing.T) {
	root := realTempDir(t)
	t.Cleanup(SetAccountHomeRootsForTest([]string{root}))
	t.Cleanup(SetQuarantineDirForTest(filepath.Join(realTempDir(t), "quarantine")))
	cfg := escalationConfig()
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.MaxFileActionsPerHour = 1
	wp := filepath.Join(root, "alice", "public_html", "wp-includes", "post.php")
	if err := os.MkdirAll(filepath.Dir(wp), 0o755); err != nil {
		t.Fatal(err)
	}
	cleanable := strings.Replace(escalationCriticalPHP, "$x", "'"+strings.Repeat("QUJDREVGRw==", 20)+"'", 1)
	if err := os.WriteFile(wp, []byte(cleanable), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := EscalateRealtimePHP(cfg, []alert.Finding{realtimePHPFinding("obfuscated_php_realtime", wp)})
	if len(findings) != 1 {
		t.Fatalf("escalation = %+v", findings)
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN:") {
		t.Fatalf("expected cleaning: %+v", actions)
	}
	if _, err := os.Stat(wp); err != nil {
		t.Fatalf("WordPress file was removed: %v", err)
	}
	cleaned, err := os.ReadFile(wp)
	if err != nil || strings.Contains(string(cleaned), "eval") {
		t.Fatalf("injection remained after cleaning: %q, %v", cleaned, err)
	}
	next := writeEscalationFile(t, escalationCriticalPHP)
	findings = EscalateRealtimePHP(cfg, []alert.Finding{realtimePHPFinding("obfuscated_php_realtime", next)})
	actions = AutoQuarantineFiles(cfg, findings)
	if len(actions) != 1 || actions[0].Check != "auto_response_paused" {
		t.Fatalf("budget bypassed: %+v", actions)
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatalf("budget removed file: %v", err)
	}
}

func TestEscalatedPHPRefusedCleanDoesNotQuarantine(t *testing.T) {
	path := themeFile(t, escalationCriticalPHP)
	cfg := escalationConfig()
	cfg.StatePath = t.TempDir()
	t.Cleanup(SetQuarantineDirForTest(filepath.Join(realTempDir(t), "quarantine")))
	findings := EscalateRealtimePHP(cfg, []alert.Finding{realtimePHPFinding("obfuscated_php_realtime", path)})
	if len(findings) != 1 {
		t.Fatalf("escalation=%+v", findings)
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN refused") {
		t.Fatalf("clean refusal=%+v", actions)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != escalationCriticalPHP {
		t.Fatalf("refused clean changed file: %q, %v", got, err)
	}
}
