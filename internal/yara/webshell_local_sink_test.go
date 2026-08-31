//go:build yara

package yara

import "testing"

// A shell that puts request input in a local before running it, and a shell
// planted in a theme rather than a plugin, are the same threats the rules
// already claim. Both slipped through.

func TestWebshellWpFakePlugin_ThemeHeaderShell(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A fake theme functions.php is the same threat as a fake plugin, and the
	// local-hop sink arms only accepted a plugin header.
	mal := []byte("<?php\n/*\nTheme Name: Twenty Sixteen Child\n*/\n$c = $_GET['c'];\nsystem($c);\n")
	if !hasYaraRule(s.ScanBytes(mal), "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin gap: theme-header shell running request input through a local not detected")
	}
	blob := []byte("<?php\n/*\nTheme Name: Storefront Child\n*/\neval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOyBAdW5saW5rKF9fRklMRV9fKTsgZXhpdDs='));\n")
	if !hasYaraRule(s.ScanBytes(blob), "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin gap: theme-header encoded payload not detected")
	}
	legit := []byte("<?php\n/*\nTheme Name: Storefront Child\n*/\nadd_action('after_setup_theme', function () { load_child_theme_textdomain('storefront-child'); });\n")
	if hasYaraRule(s.ScanBytes(legit), "webshell_wp_fake_plugin") {
		t.Error("webshell_wp_fake_plugin FP: ordinary child theme matched")
	}
}

func TestWebshellGenericPassthru_RequestThroughLocal(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// The rule required the superglobal to be the direct argument, so one
	// assignment defeated it.
	mal := []byte("<?php $x = $_REQUEST['code']; eval($x);")
	if !hasYaraRule(s.ScanBytes(mal), "webshell_generic_passthru") {
		t.Errorf("webshell_generic_passthru gap: request input evaluated through a local not detected: %s", mal)
	}
	decoded := []byte("<?php\n$code = base64_decode($_POST['p']);\neval($code);\n")
	if !hasYaraRule(s.ScanBytes(decoded), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec gap: decoded request input evaluated through a local not detected")
	}
	legit := []byte("<?php $id = $_GET['id']; echo esc_html(get_the_title(intval($id)));")
	if hasYaraRule(s.ScanBytes(legit), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru FP: ordinary request handling matched")
	}
	template := []byte(`<?php
$template = $_GET['template'];
$source = load_template_source($template);
$compiledTemplate = compile_template($source);
eval($compiledTemplate);`)
	if hasYaraRule(s.ScanBytes(template), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru FP: request-selected template and separately compiled eval matched")
	}
	immediateTemplate := []byte(`<?php
$template = trim($_GET['template']);
eval($compiledTemplate);`)
	if hasYaraRule(s.ScanBytes(immediateTemplate), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru FP: sanitized template selection and unrelated eval matched")
	}
	decodedTemplate := []byte(`<?php
$payload = base64_decode($_POST['template']);
eval($compiledTemplate);`)
	if hasYaraRule(s.ScanBytes(decodedTemplate), "webshell_generic_passthru") {
		t.Error("webshell_generic_passthru FP: decoded template input and unrelated eval matched")
	}
}
