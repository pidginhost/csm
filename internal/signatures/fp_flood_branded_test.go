package signatures

import "testing"

// YAML-engine mirror of the branded-webshell FP-flood fix (internal/yara has
// the YARA-X side). The YAML engine filters by file type, so image/wordlist/
// archive FPs never reach it; the residual FP is a security-plugin signature
// database that IS a .php file (Wordfence wflogs/rules.php, hide-my-wp
// firewall Rules.php) cataloging the brand with no dangerous action. A match
// requires a PHP open tag plus a command-execution or file-modification action,
// matching the YARA-X rule.

const wfRulesetPHP = `<?php
if (!defined('WFWAF_VERSION')) { exit('Access denied'); }
$this->add(new wfWAFRule($this, 1001, 'block', 'attackers',
	new wfWAFRuleComparison($this, 'match', '#^anonymousfox#i',
		array(wfWAFRuleComparisonSubject::create($this, 'getPath')))));
`

const hideMyWpRulesPHP = `<?php
class HMW_Rules {
	public function check($uri) {
		return preg_match('/(mobiquo|muiebl|priv8|r3vn330|raiz0|r00t)/i', $uri);
	}
}
`

func TestFPFlood_YML_WebshellAnonymousfox_WordfenceRuleset(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(wfRulesetPHP), ".php"), "webshell_anonymousfox") {
		t.Error("webshell_anonymousfox FP: matched Wordfence WAF ruleset (.php)")
	}
	mal := []byte(`<?php /* AnonymousFox */ if($_GET['fox']){ system($_GET['cmd']); }`)
	if !hasRule(s.ScanContent(mal, ".php"), "webshell_anonymousfox") {
		t.Error("webshell_anonymousfox regression: real shell not detected")
	}
}

func TestFPFlood_YML_WebshellPriv8_HideMyWpRuleset(t *testing.T) {
	s := loadRepoScanner(t)
	if hasRule(s.ScanContent([]byte(hideMyWpRulesPHP), ".php"), "webshell_priv8") {
		t.Error("webshell_priv8 FP: matched hide-my-wp firewall rules (.php)")
	}
	mal := []byte(`<?php /* Priv8 Shell */ echo "Priv8 Shell"; shell_exec($_REQUEST['c']);`)
	if !hasRule(s.ScanContent(mal, ".php"), "webshell_priv8") {
		t.Error("webshell_priv8 regression: real shell not detected")
	}
}

func TestFPFlood_YML_BrandedShells_NeedPhpAndSink(t *testing.T) {
	s := loadRepoScanner(t)
	// A .php file that only names the brand in a comment/string, with no
	// dangerous action.
	for _, tc := range []struct{ rule, body string }{
		{"webshell_c99", `<?php // note: blocks c99shell uploads via mime check
$allowed = array('image/png'); return in_array($mime, $allowed);`},
		{"webshell_b374k", `<?php $signatures = array('b374k', 'wso', 'r57'); // scanner db`},
		{"webshell_laudanum", `<?php $wordlist = array('laudanum','launch','laundry');`},
	} {
		if hasRule(s.ScanContent([]byte(tc.body), ".php"), tc.rule) {
			t.Errorf("%s FP: matched a .php file that only catalogs the brand", tc.rule)
		}
	}
	// Real shells: brand + php + sink stay detected.
	for _, tc := range []struct{ rule, body string }{
		{"webshell_c99", `<?php // c99shell v1 $c99sh_ = 1; passthru($_POST['c']);`},
		{"webshell_b374k", `<?php // b374k $x=create_function('',base64_decode($p)); $x();`},
		{"webshell_laudanum", `<?php // Laudanum shell exec($_GET['cmd']);`},
	} {
		if !hasRule(s.ScanContent([]byte(tc.body), ".php"), tc.rule) {
			t.Errorf("%s regression: real shell not detected", tc.rule)
		}
	}
}

func TestFPFlood_YML_AllBrandedShellsKeepDirectSinkDetection(t *testing.T) {
	s := loadRepoScanner(t)
	for _, tc := range []struct{ rule, brand string }{
		{"webshell_c99", "c99shell"},
		{"webshell_r57", "r57shell"},
		{"webshell_wso", "wso_version"},
		{"webshell_alfa", "AlfaTeam"},
		{"webshell_b374k", "b374k"},
		{"webshell_anonymousfox", "AnonymousFox"},
		{"webshell_indoxploit", "IndoXploit"},
		{"webshell_sadrazam", "Sadrazam"},
		{"webshell_mini_shell", "Mini Shell"},
		{"webshell_filesman_variants", "Fil3sM4n"},
		{"webshell_priv8", "Priv8"},
		{"webshell_meterpreter_php", "meterpreter"},
		{"webshell_laudanum", "laudanum"},
		{"webshell_phpsploit", "phpsploit"},
		{"webshell_icesword", "IceSword"},
	} {
		body := []byte("<?php /* " + tc.brand + " */\nsystem($_POST['cmd']);")
		if !hasRule(s.ScanContent(body, ".php"), tc.rule) {
			t.Errorf("%s regression: bare sink after newline was not detected", tc.rule)
		}
	}
}

func TestFPFlood_YML_SinkBoundaryAndPhpComments(t *testing.T) {
	s := loadRepoScanner(t)
	for _, body := range []string{
		"<?php /* c99shell */ Runner::system($cmd);",
		"<?php /* c99shell */ $runner->exec($cmd);",
		"<?php /* c99shell */ $exec($cmd);",
	} {
		if hasRule(s.ScanContent([]byte(body), ".php"), "webshell_c99") {
			t.Errorf("webshell_c99 FP: method or variable call counted as a built-in sink: %s", body)
		}
	}

	for _, body := range []string{
		"<?php /* c99shell */ system/* split token */($_POST['cmd']);",
		"<?php /* c99shell */ system // split token\n($_POST['cmd']);",
		"<?php /* c99shell */ system # split token\n($_POST['cmd']);",
	} {
		if !hasRule(s.ScanContent([]byte(body), ".php"), "webshell_c99") {
			t.Errorf("webshell_c99 regression: PHP comment before call parenthesis bypassed sink gate: %s", body)
		}
	}

	bufferStart := []byte("eval($payload); <?php /* c99shell */")
	if !hasRule(s.ScanContent(bufferStart, ".php"), "webshell_c99") {
		t.Error("webshell_c99 regression: bare sink at buffer start was not detected")
	}
}

func TestFPFlood_YML_FileManagerActionsRemainDetected(t *testing.T) {
	s := loadRepoScanner(t)
	for _, tc := range []struct{ rule, body string }{
		{"webshell_wso", `<?php $wso_version = '2.5'; move_uploaded_file($_FILES['f']['tmp_name'], $_POST['path']);`},
		{"webshell_filesman_variants", `<?php /* Fil3sM4n */ move_uploaded_file($_FILES['f']['tmp_name'], $_POST['path']);`},
		{"webshell_anonymousfox", `<?php /* AnonymousFox password reset */ file_put_contents($_POST['path'], $_POST['data']);`},
	} {
		if !hasRule(s.ScanContent([]byte(tc.body), ".php"), tc.rule) {
			t.Errorf("%s regression: file-operation-only shell was not detected", tc.rule)
		}
	}
}

func TestFPFlood_YML_P0wnyStructuralPath(t *testing.T) {
	s := loadRepoScanner(t)
	mal := []byte(`<?php
function featureShell($cmd) { return makeCommand($cmd); }
`)
	if !hasRule(s.ScanContent(mal, ".php"), "webshell_p0wny") {
		t.Error("webshell_p0wny regression: structural-marker path was not detected")
	}
	legit := []byte(`<?php // p0wny-shell is blocked by the upload scanner`)
	if hasRule(s.ScanContent(legit, ".php"), "webshell_p0wny") {
		t.Error("webshell_p0wny FP: a single brand mention cleared the structural gate")
	}
}
