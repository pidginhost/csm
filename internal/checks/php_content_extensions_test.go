package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The periodic content scanner gated on ".php" only, while the realtime
// fanotify path content-analysed .phtml/.pht/.php5 too. A webshell planted
// before CSM started (or on a host where fanotify is unavailable) under any
// other PHP-executable extension slipped through with at most a low-severity
// "suspicious extension" warning. These tests assert the periodic scanner
// content-analyses every extension a stock PHP handler executes.

func TestIsExecutablePHPName(t *testing.T) {
	// Contract: callers lowercase the name first (matches the realtime path).
	exec := []string{
		"x.php", "x.php3", "x.php4", "x.php5", "x.php7", "x.php8",
		"x.phtml", "x.pht",
	}
	for _, n := range exec {
		if !isExecutablePHPName(n) {
			t.Errorf("%q should be treated as executable PHP", n)
		}
	}
	notExec := []string{"x.txt", "x.inc", "x.phps", "x.html", "x.js", "index.phpx", "noext"}
	for _, n := range notExec {
		if isExecutablePHPName(n) {
			t.Errorf("%q must not be treated as executable PHP by extension alone", n)
		}
	}
}

func TestScanObfuscatedPHP_PhtmlWebshellDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.phtml")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf(".phtml webshell must be content-analysed, got %d findings", len(findings))
	}
}

func TestScanObfuscatedPHP_Php7WebshellDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php7")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf(".php7 webshell must be content-analysed, got %d findings", len(findings))
	}
}

// A bare .inc file with no handler mapping is NOT PHP-executable on a stock
// server, so the scanner must not waste a read on it (and must not false-positive
// on data .inc files). This documents the intended default-deny-but-handler-aware
// behaviour, distinguishing it from the AddHandler case below.
func TestScanObfuscatedPHP_IncWithoutHandlerNotScanned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.inc")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, &config.Config{}, &findings)
	if findingForPath(findings, path) {
		t.Fatalf("bare .inc with no handler mapping should not be content-analysed")
	}
}

// The LEVIATHAN .htaccess-handler trick: an attacker maps a non-PHP extension
// to the PHP handler so an innocuous-looking file executes. The scanner must
// honour the local .htaccess and content-analyse the mapped extension.
func TestScanObfuscatedPHP_IncWithHtaccessHandlerDetected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("AddHandler application/x-httpd-php .inc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evil.inc")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf(".inc mapped to PHP via .htaccess must be content-analysed, got %d findings", len(findings))
	}
}

// SetHandler with no extension routes EVERY file in the directory through PHP.
// A webshell with any extension (here .txt) must be content-analysed.
func TestScanObfuscatedPHP_SetHandlerScansAllExtensions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("SetHandler application/x-httpd-php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evil.txt")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf("SetHandler php must make every extension scannable, got %d findings", len(findings))
	}
}

// A parent .htaccess handler mapping applies to child directories too (Apache
// merges parent config), so a mapped-extension webshell in a subdir must also
// be content-analysed.
func TestScanObfuscatedPHP_HtaccessHandlerInheritedBySubdir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("AddHandler application/x-httpd-php .inc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "evil.inc")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), dir, 3, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf("inherited .htaccess handler mapping must apply to subdir, got %d findings", len(findings))
	}
}
