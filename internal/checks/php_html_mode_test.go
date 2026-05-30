package checks

import (
	"strings"
	"testing"
)

// Inline HTML (template text outside <?php ... ?>) is literal output and cannot
// execute PHP. Scanning it as code produces false positives: apostrophes in
// prose desync the string scanner, and href URLs and English words like
// "include"/"require" in markup then look like PHP execution sinks. These tests
// pin the real-world shapes that tripped suspicious_php_content on stock
// WordPress plugin view/template files.

func TestAnalyzePHPContentInlineHTMLTemplateNotFlagged(t *testing.T) {
	// Shape of newsletter/extensions.php and wp-asset-clean-up how-it-works.php:
	// a mostly-HTML view with apostrophes in prose, https:// hrefs, the word
	// "include" inside a translated string, and benign __DIR__ includes.
	content := "<?php if (!isset($data)) { exit; } ?>\n" +
		"<p>Often, our websites are loaded with assets that aren't needed. " +
		"Here's a list and you'll want to read it.</p>\n" +
		"<p><?php _e('Page caching solutions include', 'newsletter'); ?>:</p>\n" +
		"<a target=\"_blank\" href=\"https://wordpress.org/plugins/wp-fastest-cache/\">Read more</a>\n" +
		"<?php include __DIR__ . '/css/extensions.css' ?>\n" +
		"<a href=\"http://www.example.com/visit\">It's worth it, you're welcome</a>\n"
	res := analyzePHPString(t, content)
	if res.severity >= 0 {
		t.Errorf("inline-HTML template wrongly flagged; check=%q details=%q", res.check, res.details)
	}
}

func TestAnalyzePHPContentJSBacktickTemplateNotFlagged(t *testing.T) {
	// Shape of woocommerce-products-filter front_builder/index.php: inline
	// <script> with JS backtick template literals that wrap a real
	// <?php echo $_SERVER[...] ?> snippet. Scanned as PHP, the JS template
	// literal looks like a shell-exec backtick span carrying request input.
	content := "<?php class W { function out() { ?>\n" +
		"<script>\n" +
		"  document.title = `<?php echo $_SERVER['HTTP_HOST'] ?>`;\n" +
		"  el.querySelector(`#row[data-id='${id}']`).click();\n" +
		"</script>\n" +
		"<?php } } ?>\n"
	res := analyzePHPString(t, content)
	if res.severity >= 0 {
		t.Errorf("JS backtick template wrongly flagged; check=%q details=%q", res.check, res.details)
	}
}

func TestAnalyzePHPContentServerDocumentRootIncludeNotFlagged(t *testing.T) {
	// Shape of buddyboss bb-core-native-presence.php: a standalone bootstrap
	// that includes wp-load.php via $_SERVER['DOCUMENT_ROOT']. $_SERVER is
	// server-derived, not request body/query, and the suffix is a fixed path;
	// this is the canonical WordPress bootstrap, not an LFI primitive.
	content := "<?php\n" +
		"if (isset($_SERVER['DOCUMENT_ROOT']) && file_exists($_SERVER['DOCUMENT_ROOT'] . '/wp-load.php')) {\n" +
		"    require_once $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php';\n" +
		"}\n" +
		"require ABSPATH . WPINC . '/pluggable.php';\n"
	res := analyzePHPString(t, content)
	if res.severity >= 0 {
		t.Errorf("$_SERVER['DOCUMENT_ROOT'] bootstrap include wrongly flagged; check=%q details=%q", res.check, res.details)
	}
}

func TestAnalyzePHPContentServerHeaderIncludeStillFlagged(t *testing.T) {
	cases := []string{
		"<?php require $_SERVER['HTTP_X_TEMPLATE']; ?>",
		"<?php require $_SERVER[\"\\x48\\x54\\x54\\x50_X_TEMPLATE\"]; ?>",
		"<?php require \"{$_SERVER['HTTP_X_TEMPLATE']}\"; ?>",
		"<?php require $_SERVER['HT' . 'TP_X_TEMPLATE']; ?>",
	}
	for _, content := range cases {
		res := analyzePHPString(t, content)
		if res.severity < 0 || !strings.Contains(res.details, "include/require of request input") {
			t.Errorf("header-derived $_SERVER include must still flag; content=%q details=%q", content, res.details)
		}
	}
}

// --- Regression guards: the HTML-mode fix must not blind real PHP sinks. ---

func TestAnalyzePHPContentRequestIncludeStillFlaggedAfterHTMLStrip(t *testing.T) {
	res := analyzePHPString(t, "<?php include $_GET['page'] . '.php'; ?>")
	if res.severity < 0 || !strings.Contains(res.details, "include/require of request input") {
		t.Errorf("real LFI via $_GET include must still flag; details=%q", res.details)
	}
}

func TestAnalyzePHPContentBacktickInRealPHPStillFlagged(t *testing.T) {
	// A backtick shell span in actual PHP code (not inline HTML/JS) is RCE.
	res := analyzePHPString(t, "<?php $out = `id $_GET[host]`; echo $out; ?>")
	if res.severity < 0 || !strings.Contains(res.details, "backtick shell execution") {
		t.Errorf("real backtick RCE must still flag; details=%q", res.details)
	}
}

func TestAnalyzePHPContentSinkAfterRunTogetherEmptyTagStillFlagged(t *testing.T) {
	content := "<?php?><?php system($_GET['cmd']); ?>"
	res := analyzePHPString(t, content)
	if res.severity < 0 || !strings.Contains(res.details, "shell function with request input") {
		t.Errorf("sink after run-together empty tag must still flag; details=%q", res.details)
	}
}

func TestAnalyzePHPContentSinkInSecondBlockStillFlagged(t *testing.T) {
	// A clean first PHP block, then inline HTML, then a real sink in a second
	// PHP block: the second block is code and must still be analysed.
	content := "<?php echo 'header'; ?>\n<div>welcome</div>\n<?php system($_GET['cmd']); ?>\n"
	res := analyzePHPString(t, content)
	if res.severity < 0 {
		t.Errorf("sink in second PHP block must still flag; details=%q", res.details)
	}
}

func TestAnalyzePHPContentNestedOpenTagInsideHeredocDoesNotHideLaterSink(t *testing.T) {
	content := "<?php\n" +
		"$tpl = <<<EOT\n" +
		"<?php not a real tag ?>\n" +
		"EOT;\n" +
		"system($_GET['cmd']);\n"
	res := analyzePHPString(t, content)
	if res.severity < 0 || !strings.Contains(res.details, "shell function with request input") {
		t.Errorf("sink after heredoc body must still flag; details=%q", res.details)
	}
}
