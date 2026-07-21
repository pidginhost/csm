package signatures

import "testing"

// YAML-engine mirror of the branded-webshell FP-flood fix (internal/yara has
// the YARA-X side). The YAML engine filters by file type, so image/wordlist/
// archive FPs never reach it; the residual FP is a security-plugin signature
// database that IS a .php file (Wordfence wflogs/rules.php, hide-my-wp
// firewall Rules.php) cataloging the brand with no exec sink. The fix requires
// a PHP open tag plus an execution sink, matching the YARA-X rule.

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
	// A .php file that only names the brand in a comment/string, no exec sink.
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
