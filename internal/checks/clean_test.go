package checks

import (
	"path/filepath"
	"strings"
	"testing"
)

// --- shannonEntropy ---------------------------------------------------

func TestShannonEntropyEmpty(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("empty string entropy = %f, want 0", got)
	}
}

func TestShannonEntropySingleChar(t *testing.T) {
	if got := shannonEntropy("aaaaaaa"); got != 0 {
		t.Errorf("single-char string entropy = %f, want 0", got)
	}
}

func TestShannonEntropyHighEntropy(t *testing.T) {
	s := "aB3$xZ9@mQ7!pL5&"
	e := shannonEntropy(s)
	if e < 3.5 {
		t.Errorf("high-diversity string entropy = %f, want > 3.5", e)
	}
}

func TestShannonEntropyNormalPHP(t *testing.T) {
	code := `<?php echo "hello world"; function foo() { return 42; } ?>`
	e := shannonEntropy(code)
	if e < 3.0 || e > 5.5 {
		t.Errorf("normal PHP entropy = %f, expected 3.0-5.5", e)
	}
}

// --- containsLongEncodedString ----------------------------------------

func TestContainsLongEncodedStringPositive(t *testing.T) {
	s := "some prefix " + strings.Repeat("ABCD1234", 20) + " suffix"
	if !containsLongEncodedString(s, 50) {
		t.Error("should find long encoded string")
	}
}

func TestContainsLongEncodedStringTooShort(t *testing.T) {
	if containsLongEncodedString("abc123", 50) {
		t.Error("short string should not match")
	}
}

// --- getLineContext ---------------------------------------------------

func TestGetLineContextMiddle(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e", "f", "g"}
	got := getLineContext(lines, 3, 1) // d +/- 1
	if got != "c\nd\ne" {
		t.Errorf("got %q", got)
	}
}

func TestGetLineContextStartEdge(t *testing.T) {
	lines := []string{"a", "b", "c"}
	got := getLineContext(lines, 0, 2)
	if got != "a\nb\nc" {
		t.Errorf("got %q", got)
	}
}

func TestGetLineContextEndEdge(t *testing.T) {
	lines := []string{"a", "b", "c"}
	got := getLineContext(lines, 2, 5)
	if got != "a\nb\nc" {
		t.Errorf("got %q", got)
	}
}

// --- FormatCleanResult ------------------------------------------------

func TestFormatCleanResultError(t *testing.T) {
	r := CleanResult{Path: "/test.php", Error: "bad file"}
	got := FormatCleanResult(r)
	if !strings.Contains(got, "FAILED") || !strings.Contains(got, "bad file") {
		t.Errorf("got %q", got)
	}
}

func TestFormatCleanResultNoChange(t *testing.T) {
	r := CleanResult{Path: "/test.php"}
	got := FormatCleanResult(r)
	if !strings.Contains(got, "No changes") {
		t.Errorf("got %q", got)
	}
}

func TestFormatCleanResultSuccess(t *testing.T) {
	r := CleanResult{Path: "/test.php", Cleaned: true, BackupPath: "/bak/test.php", Removals: []string{"removed injection"}}
	got := FormatCleanResult(r)
	if !strings.Contains(got, "CLEANED") || !strings.Contains(got, "removed injection") {
		t.Errorf("got %q", got)
	}
}

// --- removeIncludeInjections ------------------------------------------
// These tests exercise the malware cleaning engine which detects and
// removes PHP code injection patterns. The test fixtures contain
// synthetic malware samples that are not functional.

func TestRemoveIncludeInjectionsTmpPath(t *testing.T) {
	input := "<?php\n@include(\"/tmp/evil.php\");\necho 'hello';\n"
	out, removed := removeIncludeInjections(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if strings.Contains(out, "/tmp/evil") {
		t.Error("malicious include still present")
	}
	if !strings.Contains(out, "echo 'hello'") {
		t.Error("legitimate code was removed")
	}
}

func TestRemoveIncludeInjectionsBase64(t *testing.T) {
	input := "<?php\n@include(base64_decode(\"L3RtcC9ldmlsLnBocA==\"));\necho 1;\n"
	out, removed := removeIncludeInjections(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code was removed")
	}
}

func TestRemoveIncludeInjectionsLegitimate(t *testing.T) {
	input := "<?php\ninclude('config.php');\nrequire_once('utils.php');\n"
	out, removed := removeIncludeInjections(input)
	if len(removed) != 0 {
		t.Errorf("legitimate includes should not be removed: %v", removed)
	}
	if out != input {
		t.Error("content should be unchanged")
	}
}

func TestRemoveIncludeInjectionsObfuscatedVar(t *testing.T) {
	input := "<?php\n$x = base64_decode('aaa');\n@include($x)\n"
	_, removed := removeIncludeInjections(input)
	if len(removed) == 0 {
		t.Error("obfuscated variable include should be removed")
	}
}

// --- removePrependInjection -------------------------------------------

func TestRemovePrependInjectionMalicious(t *testing.T) {
	// High-entropy obfuscated prefix followed by ?><?php and legitimate code.
	payload := "<?php $x=base64_decode('" + strings.Repeat("QUJDREVGRw==", 20) + "');"
	input := payload + "?><?php echo 'real code'; ?>"
	out, removed := removePrependInjection(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if !strings.Contains(out, "real code") {
		t.Error("legitimate code was removed")
	}
}

func TestRemovePrependInjectionNonPHP(t *testing.T) {
	input := "<html>not php</html>"
	out, removed := removePrependInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("non-PHP should be unchanged")
	}
}

func TestRemovePrependInjectionLowEntropy(t *testing.T) {
	input := "<?php echo 'a';?><?php echo 1; ?>"
	out, removed := removePrependInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("low-entropy prefix should not be removed")
	}
}

// --- removeAppendInjection --------------------------------------------

func TestRemoveAppendInjectionAfterClose(t *testing.T) {
	// Malicious code appended after the only closing ?>
	input := "<?php echo 1; ?>\n$x=base64_decode('payload');"
	out, removed := removeAppendInjection(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if strings.Contains(out, "base64_decode") {
		t.Error("appended malware still present")
	}
}

func TestRemoveAppendInjectionCleanFile(t *testing.T) {
	input := "<?php echo 'hello'; ?>\n"
	out, removed := removeAppendInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("clean file should be unchanged")
	}
}

func TestRemoveAppendInjectionPSR12(t *testing.T) {
	// PSR-12 file (no closing ?>) with code appended after blank lines.
	// Detection requires both literal "eval(" and "base64_decode" in the tail.
	legitimate := "<?php\nnamespace App;\nclass Foo {\n    public function bar() {}\n}\n"
	appended := "\n\n$v = base64_decode('x'); eval($v);\n"
	input := legitimate + appended
	out, removed := removeAppendInjection(input)
	if len(removed) == 0 {
		t.Fatal("expected PSR-12 append removal")
	}
	if strings.Contains(out, "base64_decode") {
		t.Error("appended code still present")
	}
}

// --- removeInlineEvalInjections ---------------------------------------

func TestRemoveInlineEvalInjectionsShortKept(t *testing.T) {
	input := "<?php\nsome_func(base64_decode('dGVzdA=='));\necho 1;\n"
	_, removed := removeInlineEvalInjections(input)
	if len(removed) != 0 {
		t.Errorf("short line should be kept: %v", removed)
	}
}

// --- removeMultiLayerBase64 -------------------------------------------

func TestRemoveMultiLayerBase64Nested(t *testing.T) {
	payload := "$x = base64_decode(base64_decode('" + strings.Repeat("A", 100) + "'));"
	input := "<?php\n" + payload + "\necho 1;\n"
	out, removed := removeMultiLayerBase64(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code was removed")
	}
}

func TestRemoveMultiLayerBase64ShortLine(t *testing.T) {
	input := "<?php\n$x = base64_decode(base64_decode('a'));\necho 1;\n"
	_, removed := removeMultiLayerBase64(input)
	if len(removed) != 0 {
		t.Errorf("short lines should be kept: %v", removed)
	}
}

// --- removeChrPackInjections ------------------------------------------

func TestRemoveChrPackInjectionsChrChain(t *testing.T) {
	// 5+ chr() calls concatenated — obfuscated function name construction.
	payload := "chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);"
	input := "<?php\n" + payload + "\necho 1;\n"
	out, removed := removeChrPackInjections(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code was removed")
	}
}

func TestRemoveChrPackInjectionsPackHexSafe(t *testing.T) {
	input := "<?php\n$data = pack(\"H*\", \"48656c6c6f\");\necho $data;\n"
	_, removed := removeChrPackInjections(input)
	if len(removed) != 0 {
		t.Errorf("safe pack() should not be removed: %v", removed)
	}
}

// --- removeHexVarInjections -------------------------------------------

func TestRemoveHexVarInjectionsWithDangerousOp(t *testing.T) {
	payload := `$GLOBALS["\x61\x64\x6d\x69\x6e"] = base64_decode("payload_here");`
	input := "<?php\n" + payload + "\necho 1;\n"
	out, removed := removeHexVarInjections(input)
	if len(removed) == 0 {
		t.Fatal("expected removal")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code was removed")
	}
}

func TestRemoveHexVarInjectionsShortLine(t *testing.T) {
	input := "<?php\n$x = \"\\x41\";\necho 1;\n"
	_, removed := removeHexVarInjections(input)
	if len(removed) != 0 {
		t.Errorf("short lines should be kept: %v", removed)
	}
}

// --- ShouldCleanInsteadOfQuarantine -----------------------------------

func TestShouldCleanWPCore(t *testing.T) {
	if !ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-includes/version.php") {
		t.Error("wp-includes should be cleaned")
	}
	if !ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-admin/admin.php") {
		t.Error("wp-admin should be cleaned")
	}
}

func TestShouldCleanPlugin(t *testing.T) {
	if !ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-content/plugins/akismet/akismet.php") {
		t.Error("plugin file should be cleaned")
	}
}

func TestShouldCleanWebshellInTheme(t *testing.T) {
	// Known webshell filename inside a theme should be quarantined, not cleaned.
	if ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-content/themes/flavor/shell.php") {
		t.Error("webshell in theme should be quarantined, not cleaned")
	}
}

func TestShouldQuarantineStandalone(t *testing.T) {
	if ShouldCleanInsteadOfQuarantine("/home/user/public_html/backdoor.php") {
		t.Error("standalone file should be quarantined")
	}
}

// --- CleanInfectedFile ------------------------------------------------
// CleanInfectedFile writes backups to quarantineDir which is a const
// pointing to /opt/csm/quarantine. We test the missing-file error path
// (which returns before hitting the quarantine dir) and leave the
// end-to-end cleaning to integration tests on a real host.

func TestCleanInfectedFileMissing(t *testing.T) {
	result := CleanInfectedFile(filepath.Join(t.TempDir(), "missing.php"))
	if result.Cleaned {
		t.Error("missing file should not be cleaned")
	}
	if result.Error == "" {
		t.Error("expected error for missing file")
	}
}
