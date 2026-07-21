package signatures

import "testing"

// YAML-engine mirror of the dual-use FP-flood fixes. The .php false positives:
// old PHPMailer's /e encoder, a theme's extract($_POST) unpack, and backup
// plugins reading wp-config. (bashrc/uploader/wget rules are file_type-scoped
// or .yar-only.)

func TestFPFlood_YML_PregReplaceEval_Phpmailer(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php $x = preg_replace("/([\(\)\"])/e", "'='.sprintf('%02X', ord('$1'))", $str);`)
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval FP: matched PHPMailer's fixed /e encoder")
	}
	mal := []byte(`<?php preg_replace('/.*/e', $_POST['code'], $s);`)
	if !hasRule(s.ScanContent(mal, ".php"), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval regression: real /e injection not detected")
	}
}

func TestFPFlood_YML_ExtractGlobals_ThemeUnpack(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php extract($_POST); switch($action){ case 'save': save_option($key,$value); }`)
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_extract_globals") {
		t.Error("obfuscation_extract_globals FP: matched a theme form-field unpack")
	}
	mal := []byte(`<?php extract($_REQUEST); $func($arg);`)
	if !hasRule(s.ScanContent(mal, ".php"), "obfuscation_extract_globals") {
		t.Error("obfuscation_extract_globals regression: real variable-injection backdoor not detected")
	}
}

func TestFPFlood_YML_WpConfigStealer_Backup(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte(`<?php $c = file_get_contents($p.'/wp-config.php'); $c = str_replace(DB_PASSWORD,$n,$c); file_put_contents($d.'/wp-config.php',$c);`)
	if hasRule(s.ScanContent(legit, ".php"), "exploit_wp_config_stealer") {
		t.Error("exploit_wp_config_stealer FP: matched a backup/restore plugin")
	}
	for _, mal := range [][]byte{
		[]byte(`<?php echo file_get_contents('wp-config.php');`),
		[]byte(`<?php readfile('/home/x/public_html/wp-config.php');`),
	} {
		if !hasRule(s.ScanContent(mal, ".php"), "exploit_wp_config_stealer") {
			t.Errorf("exploit_wp_config_stealer regression: real stealer not detected: %s", mal)
		}
	}
}
