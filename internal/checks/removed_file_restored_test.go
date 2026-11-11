package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func restoreResponseConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	return cfg
}

// themeFile returns a path where the path rule alone would clean rather than
// quarantine, so the tests show the response follows the earlier removal.
func themeFile(t *testing.T, content string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "public_html", "wp-content", "themes", "theme", "modules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.php")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ShouldCleanInsteadOfQuarantine(path) {
		t.Fatalf("setup: %s is not a path the cleaner owns", path)
	}
	return path
}

func restoredFinding(path string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Message: "File CSM removed was written back: " + path, FilePath: path}
}

// Bytes CSM quarantined as a whole file are quarantined again when they come
// back, even where the path rule would only try to clean them.
func TestRestoredFileIsQuarantinedAgainAfterAQuarantine(t *testing.T) {
	withActionSink(t)
	withAutoRespQuarantineDir(t, filepath.Join(t.TempDir(), "quarantine"))
	path := themeFile(t, "<?php /* whole-file shell */ echo 1;")
	rememberRemovedFile(path, actionlog.Stat(path).Digest, 10, "quarantine")

	actions := AutoQuarantineFiles(restoreResponseConfig(t), []alert.Finding{restoredFinding(path)})

	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-QUARANTINE: ") {
		t.Fatalf("actions = %+v, want one quarantine", actions)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("restored file still in place: %v", err)
	}
}

// Bytes CSM cleaned are cleaned again, even where the path rule would remove
// the whole file: the file around the injection is the customer's.
func TestRestoredFileIsCleanedAgainAfterAClean(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	const infected = "<?php\n\x00\x0b@include(base64_decode(\"ZXZpbA==\"));\necho 'ok';\n"
	path := filepath.Join(t.TempDir(), "public_html", "index.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(infected), 0o644); err != nil {
		t.Fatal(err)
	}
	if ShouldCleanInsteadOfQuarantine(path) {
		t.Fatalf("setup: %s is a path the cleaner owns", path)
	}
	rememberRemovedFile(path, actionlog.Stat(path).Digest, int64(len(infected)), "clean")

	actions := AutoQuarantineFiles(restoreResponseConfig(t), []alert.Finding{restoredFinding(path)})

	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
		t.Fatalf("actions = %+v, want one clean", actions)
	}
	got, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(got), "base64_decode") {
		t.Fatalf("restored injection not removed: %q err=%v", got, err)
	}
}
