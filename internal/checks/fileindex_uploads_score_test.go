package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// --- classifyUploadPHP: content-first, no path/name allowlist ---------

func writeUploadPHP(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, name)
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestClassifyUploadPHPWebshellInCacheDirFlagged(t *testing.T) {
	// A webshell whose path contains "/cache/" was previously skipped wholesale
	// by isKnownSafeUpload. It must now be flagged on content, regardless of
	// the "safe" directory name.
	target := writeUploadPHP(t, "shell.php", "<?php system($_POST['cmd']); ?>")
	sev, check, _ := classifyUploadPHP(target)
	if sev < alert.High {
		t.Fatalf("webshell -> severity %v, want >= High", sev)
	}
	if check == "new_php_in_uploads_clean" || check == "" {
		t.Errorf("webshell -> check %q, want an actionable content check", check)
	}
}

func TestClassifyUploadPHPObfuscatedFlagged(t *testing.T) {
	target := writeUploadPHP(t, "x.php", "<?php eval(base64_decode(\"ZWNobyAxOw==\")); ?>")
	sev, check, _ := classifyUploadPHP(target)
	if sev < alert.High {
		t.Errorf("eval+base64 -> severity %v, want >= High", sev)
	}
	if check == "" || check == "new_php_in_uploads_clean" {
		t.Errorf("eval+base64 -> check %q, want an actionable content check", check)
	}
}

func TestClassifyUploadPHPCleanRealCodeIsWarningVisibility(t *testing.T) {
	// A clean real-code PHP file (e.g. a plugin cache class) is no longer
	// path-skipped; it surfaces as a non-actionable visibility Warning.
	target := writeUploadPHP(t, "class-cache.php", "<?php\nclass Cache_Widget { public function render() { return 'ok'; } }\n")
	sev, check, _ := classifyUploadPHP(target)
	if sev != alert.Warning {
		t.Errorf("clean real-code -> severity %v, want Warning", sev)
	}
	if check != "new_php_in_uploads_clean" {
		t.Errorf("clean real-code -> check %q, want new_php_in_uploads_clean", check)
	}
}

func TestClassifyUploadPHPInertStubSuppressed(t *testing.T) {
	// WordPress "silence is golden" index.php and similar inert stubs are
	// content-verified benign and must be suppressed (negative severity).
	target := writeUploadPHP(t, "index.php", "<?php // Silence is golden\n")
	sev, _, _ := classifyUploadPHP(target)
	if sev >= 0 {
		t.Errorf("inert stub -> severity %v, want negative (suppressed)", sev)
	}
}

func TestClassifyUploadPHPUnreadableFailsClosed(t *testing.T) {
	sev, check, _ := classifyUploadPHP("/nonexistent/wp-content/uploads/gone.php")
	if sev != alert.High {
		t.Errorf("unreadable -> severity %v, want High (fail-closed)", sev)
	}
	if check != "new_php_in_uploads" {
		t.Errorf("unreadable -> check %q, want new_php_in_uploads", check)
	}
}

func TestClassifyUploadPHPEmptyFileFailsClosed(t *testing.T) {
	target := writeUploadPHP(t, "empty.php", "")
	sev, _, _ := classifyUploadPHP(target)
	if sev != alert.High {
		t.Errorf("empty file -> severity %v, want High (fail-closed)", sev)
	}
}
