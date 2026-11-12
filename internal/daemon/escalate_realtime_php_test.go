package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// A realtime PHP finding that realtime could not confirm only alerted, and the
// file stayed until a scheduled scan reached it. The scheduled analysis of
// that file now runs at once, and its Critical verdict gets the scheduled
// response in the same batch.
func TestDispatchBatchRespondsToTheScheduledVerdictOfARealtimePHPFile(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	root := t.TempDir()
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

	d.dispatchBatch([]alert.Finding{{
		Severity: alert.Critical,
		Check:    "obfuscated_php_realtime",
		Message:  "Obfuscated PHP detected: " + path,
		FilePath: path,
	}})

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("file the scheduled analysis rates Critical is still in place: %v", err)
	}
	if hook.count("AUTO-QUARANTINE: "+path) != 1 {
		t.Fatalf("no quarantine notice; last webhook body %q", hook.last())
	}
}
