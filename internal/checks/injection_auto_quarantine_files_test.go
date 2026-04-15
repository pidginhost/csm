package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// AutoQuarantineFiles behaviour:
//   - Enabled=false or QuarantineFiles=false → returns nil
//   - Unrelated check types → skipped
//   - Non-critical severity → skipped
//   - No file path extractable → skipped
//   - Path doesn't exist → skipped
//   - Symlink → skipped
//   - Webshell in WP core → CleanInfectedFile path (covered in clean tests)
//   - Standalone webshell → moved to quarantine with .meta sidecar

// withAutoRespQuarantineDir redirects quarantineDir for AutoQuarantineFiles.
// Distinct name to avoid clashing with other temp-dir helpers.
func withAutoRespQuarantineDir(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

func TestAutoQuarantineFilesDisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	// AutoResponse.Enabled defaults to false.
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: "/tmp/x.php"},
	})
	if got != nil {
		t.Errorf("disabled → nil, got %d actions", len(got))
	}
}

func TestAutoQuarantineFilesQuarantineFilesOffReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = false
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: "/tmp/x.php"},
	})
	if got != nil {
		t.Errorf("QuarantineFiles=false → nil, got %d actions", len(got))
	}
}

func TestAutoQuarantineFilesIgnoresUnrelatedChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "suspicious_process", Severity: alert.Critical, FilePath: "/tmp/x.php"},
		{Check: "ip_reputation", Severity: alert.Critical, FilePath: "/tmp/y.php"},
	})
	if len(got) != 0 {
		t.Errorf("unrelated checks should be skipped, got %+v", got)
	}
}

func TestAutoQuarantineFilesSkipsNonCritical(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Warning, FilePath: "/tmp/x.php"},
		{Check: "webshell", Severity: alert.High, FilePath: "/tmp/y.php"},
	})
	if len(got) != 0 {
		t.Errorf("non-critical should be skipped, got %+v", got)
	}
}

func TestAutoQuarantineFilesSkipsFindingWithoutPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, Message: "no path anywhere"},
	})
	if len(got) != 0 {
		t.Errorf("missing path should be skipped, got %+v", got)
	}
}

func TestAutoQuarantineFilesSkipsMissingFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: "/nonexistent-xyz/shell.php"},
	})
	if len(got) != 0 {
		t.Errorf("missing file should be skipped, got %+v", got)
	}
}

func TestAutoQuarantineFilesRejectsSymlinks(t *testing.T) {
	tmp := t.TempDir()
	withAutoRespQuarantineDir(t, filepath.Join(tmp, "q"))

	target := filepath.Join(tmp, "target.php")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{Check: "webshell", Severity: alert.Critical, FilePath: link},
	})
	if len(got) != 0 {
		t.Errorf("symlink should be rejected, got %+v", got)
	}
	// And the symlink must still be on disk.
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("symlink should be untouched: %v", err)
	}
}

func TestAutoQuarantineFilesMovesStandaloneWebshell(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	withAutoRespQuarantineDir(t, qdir)

	// Path NOT in wp-content/ so ShouldCleanInsteadOfQuarantine returns false
	// and the function takes the quarantine path.
	src := filepath.Join(tmp, "dropper.php")
	if err := os.WriteFile(src, []byte("<?php evil"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{
			Check:    "php_dropper",
			Severity: alert.Critical,
			FilePath: src,
			Message:  "PHP dropper found",
		},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 quarantine action, got %d: %+v", len(got), got)
	}
	if got[0].Check != "auto_response" {
		t.Errorf("action check = %q, want auto_response", got[0].Check)
	}
	if !strings.Contains(got[0].Message, "AUTO-QUARANTINE") {
		t.Errorf("action message should say AUTO-QUARANTINE: %s", got[0].Message)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source should be gone, stat err=%v", err)
	}
	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatal(err)
	}
	hasFile, hasMeta := false, false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			hasMeta = true
		} else {
			hasFile = true
		}
	}
	if !hasFile || !hasMeta {
		t.Errorf("expected quarantined file + .meta sidecar, got %v", entries)
	}
}

func TestAutoQuarantineFilesMovesQuarantineDirectory(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	withAutoRespQuarantineDir(t, qdir)

	src := filepath.Join(tmp, "LEVIATHAN")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "shell.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	got := AutoQuarantineFiles(cfg, []alert.Finding{
		{
			Check:    "phishing_directory",
			Severity: alert.Critical,
			FilePath: src,
		},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 quarantine action, got %d: %+v", len(got), got)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source dir should be gone, stat err=%v", err)
	}
}
