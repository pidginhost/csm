package checks

import (
	"os"
	"path/filepath"
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
	path := filepath.Join(t.TempDir(), "index.php")
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
	dir := t.TempDir()
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
