package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// These tests assert BEHAVIOUR, not implementation: a webshell must be detected
// regardless of the filename or directory it hides in. The previous
// IsSafePHPInWPDir name/path allowlist skipped content analysis for files named
// like translations, index.php, mu-plugin vendor names, or anything under
// vendor/ or node_modules/ -- letting an attacker hide a backdoor by choosing a
// "safe" name. The project rule is: never skip scanning by path/name; fix
// detection instead.

const evalWebshell = "<?php eval(base64_decode($_POST['c'])); ?>"

// A backdoor disguised under a WordPress translation filename in
// wp-content/languages/ must still be flagged. .l10n.php was on the old
// allowlist, so this returned (-1, "", "") before the fix.
func TestSensitiveDirPHP_MaliciousTranslationNameDetected(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "en_US.l10n.php")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	sev, check, _ := classifySensitiveDirPHP(path, "en_US.l10n.php")
	if check == "" || sev < alert.High {
		t.Fatalf("malicious .l10n.php must be detected, got sev=%v check=%q", sev, check)
	}
}

// A clean translation file in the same dir must NOT produce a Critical/High
// alert (it may surface as the clean visibility Warning). This guards against
// over-correcting the allowlist removal into a false-positive flood.
func TestSensitiveDirPHP_CleanTranslationNotCritical(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "fr_FR.l10n.php")
	// Real WP 6.5+ PHP translation files are pure data return arrays.
	content := "<?php\nreturn ['x' => 'Bonjour', 'y' => 'Au revoir'];\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sev, check, _ := classifySensitiveDirPHP(path, "fr_FR.l10n.php")
	if sev >= alert.High {
		t.Fatalf("clean translation must not be High/Critical, got sev=%v check=%q", sev, check)
	}
}

// A webshell in a mu-plugins file whose name contains an allowlisted vendor
// substring ("jetpack") must be flagged. The old allowlist matched the name
// substring and skipped the file entirely.
func TestScanObfuscatedPHP_MaliciousMuPluginNameDetected(t *testing.T) {
	dir := t.TempDir()
	muDir := filepath.Join(dir, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(muDir, "evil-jetpack-loader.php")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), muDir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf("malicious mu-plugin with allowlisted name must be flagged, got %d findings", len(findings))
	}
}

// A webshell hidden under a plugin's vendor/ directory must be flagged.
// vendor/ and node_modules/ were unconditionally skipped before the fix --
// the supply-chain hiding spot.
func TestScanObfuscatedPHP_MaliciousVendorFileDetected(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "wp-content", "plugins", "myplugin", "vendor", "lib")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorDir, "autoload.php")
	if err := os.WriteFile(path, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), vendorDir, 2, &config.Config{}, &findings)
	if !findingForPath(findings, path) {
		t.Fatalf("malicious vendor/ file must be flagged, got %d findings", len(findings))
	}
}

func findingForPath(findings []alert.Finding, path string) bool {
	for _, f := range findings {
		if f.FilePath == path {
			return true
		}
	}
	return false
}
