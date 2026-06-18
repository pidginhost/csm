package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// realL10nShape mirrors the byte structure WordPress 6.5+ GlotPress emits for
// *.l10n.php translation caches: <?php return [ ... ]; with single- and
// double-quoted string literals, UTF-8 message text, a nested messages map,
// and plural entries joined by constant concatenation of a "\0" separator.
// No variables, no calls, no executable constructs.
const realL10nShape = "<?php\n" +
	"return ['x-generator'=>'GlotPress/4.0.3'," +
	"'translation-revision-date'=>'2025-11-15 17:57:45+0000'," +
	"'plural-forms'=>'nplurals=3; plural=(n == 1) ? 0 : 2;'," +
	"'project-id-version'=>'WordPress - 7.0.x'," +
	"'language'=>'ro'," +
	"'messages'=>['Site flagged for deletion.'=>'Site marcat pentru \xc8\x99tergere'," +
	"'%s site'=>'%s site' . \"\\0\" . '%s site-uri' . \"\\0\" . '%s de site-uri'," +
	"'Count'=>'Num\xc4\x83r','Empty'=>'']];\n"

func writeL10nTempPHP(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A pure WP translation cache must be suppressed entirely, not surfaced as a
// new_php_in_sensitive_dir_clean Warning. This is the false positive: WordPress
// auto-generates ~30 of these per locale and each opened an incident.
func TestSensitiveDirPHP_TranslationCacheSuppressed(t *testing.T) {
	path := writeL10nTempPHP(t, "admin-ro_RO.l10n.php", realL10nShape)
	sev, check, _ := classifySensitiveDirPHP(path, "admin-ro_RO.l10n.php")
	if sev >= 0 || check != "" {
		t.Fatalf("clean translation cache must be suppressed, got sev=%v check=%q", sev, check)
	}
}

func TestSensitiveDirPHP_LargeTranslationCacheFailsClosedToWarning(t *testing.T) {
	large := realL10nShape + strings.Repeat(" ", benignPHPStubMaxScan+1)
	path := writeL10nTempPHP(t, "admin-ro_RO.l10n.php", large)
	if isWPTranslationCache(path) {
		t.Fatal("oversized translation cache read must fail closed")
	}
	sev, check, _ := classifySensitiveDirPHP(path, "admin-ro_RO.l10n.php")
	if sev != alert.Warning || check != "new_php_in_sensitive_dir_clean" {
		t.Fatalf("oversized translation cache must warn, got sev=%v check=%q", sev, check)
	}
}

// True positive: the exact same translation-shaped file with executable code
// appended after the array must still fire. Proves the recognizer is not a
// path/name allowlist and does not weaken detection.
func TestSensitiveDirPHP_TranslationShapedWithTrailingCodeFlagged(t *testing.T) {
	poisoned := realL10nShape + " " + "ev" + "al(bas" + "e64_decode($_POST['c']));\n"
	path := writeL10nTempPHP(t, "fr_FR.l10n.php", poisoned)
	sev, check, _ := classifySensitiveDirPHP(path, "fr_FR.l10n.php")
	if check == "" || sev < alert.High {
		t.Fatalf("translation-shaped file with trailing code must be flagged, got sev=%v check=%q", sev, check)
	}
}

func TestIsWPTranslationCache_RealShape(t *testing.T) {
	if !IsWPTranslationCacheBytesComplete([]byte(realL10nShape), true) {
		t.Fatal("real l10n.php shape must be recognized")
	}
}

func TestIsWPTranslationCache_ArrayKeywordSyntax(t *testing.T) {
	src := "<?php\nreturn array('a' => 'one', 'b' => array('c' => 'two'));\n"
	if !IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("array() long-form syntax must be recognized")
	}
}

func TestIsWPTranslationCache_EmptyArray(t *testing.T) {
	if !IsWPTranslationCacheBytesComplete([]byte("<?php\nreturn [];\n"), true) {
		t.Fatal("empty return array must be recognized")
	}
}

func TestIsWPTranslationCache_EscapedDollarLiteral(t *testing.T) {
	src := "<?php return ['price' => \"\\$5.00 each\"];\n"
	if !IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("escaped dollar in double-quoted string is literal, must be recognized")
	}
}

func TestIsWPTranslationCache_ComplexInterpolationRejected(t *testing.T) {
	tests := []string{
		"<?php return ['a' => \"${payload}\"];\n",
		"<?php return ['a' => \"{$payload}\"];\n",
	}
	for _, src := range tests {
		if IsWPTranslationCacheBytesComplete([]byte(src), true) {
			t.Fatalf("complex interpolation must be rejected: %q", src)
		}
	}
}

func TestIsWPTranslationCache_TruncatedNotRecognized(t *testing.T) {
	// complete=false: a truncated buffer cannot prove the unseen tail is inert.
	if IsWPTranslationCacheBytesComplete([]byte(realL10nShape), false) {
		t.Fatal("truncated buffer must not be recognized (fail closed)")
	}
}

func TestIsWPTranslationCache_TrailingCodeRejected(t *testing.T) {
	src := "<?php return ['a' => 'b']; " + "sys" + "tem($_GET['x']);\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("code after the return statement must be rejected")
	}
}

func TestIsWPTranslationCache_ConcatWithCallRejected(t *testing.T) {
	src := "<?php return ['a' => 'x' . sh" + "ell_exec('id')];\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("concatenation with a function call must be rejected")
	}
}

func TestIsWPTranslationCache_ConcatWithVariableRejected(t *testing.T) {
	src := "<?php return ['a' => 'x' . $payload];\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("concatenation with a variable operand must be rejected")
	}
}

func TestIsWPTranslationCache_DoubleQuotedInterpolationRejected(t *testing.T) {
	src := "<?php return ['a' => \"$" + "x payload\"];\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("variable interpolation in a double-quoted string must be rejected")
	}
}

func TestIsWPTranslationCache_VariableValueRejected(t *testing.T) {
	src := "<?php return ['a' => $" + "GLOBALS['x']];\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("a variable value must be rejected")
	}
}

func TestIsWPTranslationCache_BareScalarReturnRejected(t *testing.T) {
	if IsWPTranslationCacheBytesComplete([]byte("<?php return 'x';\n"), true) {
		t.Fatal("a non-array return must be rejected")
	}
}

func TestIsWPTranslationCache_BareArrayKeywordRejected(t *testing.T) {
	tests := []string{
		"<?php return array;\n",
		"<?php return ['a' => array];\n",
	}
	for _, src := range tests {
		if IsWPTranslationCacheBytesComplete([]byte(src), true) {
			t.Fatalf("bare array keyword without parentheses must be rejected: %q", src)
		}
	}
}

func TestIsWPTranslationCache_ShortEchoOpenerRejected(t *testing.T) {
	if IsWPTranslationCacheBytesComplete([]byte("<?= return ['a'=>'b'];\n"), true) {
		t.Fatal("short-echo opener must be rejected")
	}
}

func TestIsWPTranslationCache_ClosingTagReentryRejected(t *testing.T) {
	src := "<?php return ['a'=>'b']; ?>\n<?php sys" + "tem($_GET['x']);\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("a closing tag enabling later re-entry must be rejected")
	}
}

func TestIsWPTranslationCache_FunctionCallValueRejected(t *testing.T) {
	src := "<?php return ['a' => fi" + "le_get_contents('/etc/passwd')];\n"
	if IsWPTranslationCacheBytesComplete([]byte(src), true) {
		t.Fatal("a function-call value must be rejected")
	}
}
