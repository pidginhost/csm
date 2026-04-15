package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// scanForWebshells:
//   - cancelled context → returns immediately
//   - maxDepth <= 0 → returns immediately
//   - ReadDir error → silent return
//   - suppressed path → skipped
//   - known webshell directory → Critical finding
//   - known webshell filename → Critical finding
//   - .haxor / .cgix extensions → Critical finding
//   - recursion into non-webshell subdirs

func TestScanForWebshellsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "c99.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(ctx, tmp, 4, map[string]bool{"c99.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("cancelled ctx should yield 0 findings, got %d", len(findings))
	}
}

func TestScanForWebshellsDepthZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "c99.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 0, map[string]bool{"c99.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("depth=0 should yield 0 findings, got %d", len(findings))
	}
}

func TestScanForWebshellsMissingDir(t *testing.T) {
	var findings []alert.Finding
	scanForWebshells(context.Background(), "/no-such-dir-xyz", 4, map[string]bool{"x.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should yield 0 findings, got %d", len(findings))
	}
}

func TestScanForWebshellsSuppressedPathSkipped(t *testing.T) {
	tmp := t.TempDir()
	shell := filepath.Join(tmp, "c99.php")
	if err := os.WriteFile(shell, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{filepath.Join(tmp, "*")}

	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{"c99.php": true}, map[string]bool{}, cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("suppressed path should yield 0 findings, got %+v", findings)
	}
}

func TestScanForWebshellsFlagsKnownFilename(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "c99.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{"c99.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Check != "webshell" || findings[0].Severity != alert.Critical {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestScanForWebshellsFilenameCaseInsensitive(t *testing.T) {
	tmp := t.TempDir()
	// Uppercase on disk, lowercase in name set — function normalises to lower.
	if err := os.WriteFile(filepath.Join(tmp, "C99.PHP"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{"c99.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 1 {
		t.Errorf("expected case-insensitive match, got %d findings", len(findings))
	}
}

func TestScanForWebshellsFlagsHaxorExtension(t *testing.T) {
	tmp := t.TempDir()
	for _, name := range []string{"evil.haxor", "other.cgix"} {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (.haxor + .cgix), got %d: %+v", len(findings), findings)
	}
}

func TestScanForWebshellsFlagsKnownDirectory(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "LEVIATHAN")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{}, map[string]bool{"LEVIATHAN": true}, &config.Config{}, &findings)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding for webshell dir, got %d", len(findings))
	}
	hasWebshellDir := false
	for _, f := range findings {
		if f.Check == "webshell" && filepath.Base(f.FilePath) == "LEVIATHAN" {
			hasWebshellDir = true
		}
	}
	if !hasWebshellDir {
		t.Errorf("expected webshell finding for LEVIATHAN dir, got %+v", findings)
	}
}

func TestScanForWebshellsRecursesIntoSubdirs(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "uploads", "2024")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "c99.php"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForWebshells(context.Background(), tmp, 4,
		map[string]bool{"c99.php": true}, map[string]bool{}, &config.Config{}, &findings)
	if len(findings) != 1 {
		t.Errorf("expected nested webshell to be flagged, got %d: %+v", len(findings), findings)
	}
}
