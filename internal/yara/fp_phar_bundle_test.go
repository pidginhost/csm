//go:build yara

package yara

import (
	"bytes"
	"testing"
)

// A PHP archive bundles hundreds of unrelated vendor files into one blob, so
// any rule that ANDs bare substrings with no locality matches it. wp-cli.phar
// on a production host tripped five critical rules at once; these two ask for
// nothing but co-occurrence anywhere in the file.

// gap returns filler that separates strings so no proximity window spans them.
func gap() []byte { return bytes.Repeat([]byte("// vendor code\n"), 400) }

func TestFPPhar_CGIWebshellBash_VendorArchive(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var b bytes.Buffer
	b.WriteString("<?php /* phar stub */ Phar::mapPhar();\n")
	b.Write(gap())
	b.WriteString("#!/bin/bash\n# bundled helper script\n")
	b.Write(gap())
	b.WriteString("$encoded = base64_encode($payload);\n")
	b.Write(gap())
	b.WriteString("function eval_template($tpl) { return $tpl; }\n")
	b.Write(gap())
	b.WriteString("header('Content-type: application/json');\n")
	if hasYaraRule(s.ScanBytes(b.Bytes()), "cgi_webshell_bash") {
		t.Error("cgi_webshell_bash FP: matched a PHP archive with the tokens scattered across vendor files")
	}
}

func TestFPPhar_CGIWebshellBash_RealShellStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("#!/bin/bash\n" +
		"echo \"Content-type: text/html\"\n" +
		"echo \"\"\n" +
		"CMD=$(echo \"$QUERY_STRING\" | base64 -d)\n" +
		"eval \"$CMD\"\n")
	if !hasYaraRule(s.ScanBytes(mal), "cgi_webshell_bash") {
		t.Error("cgi_webshell_bash regression: real bash CGI webshell not detected")
	}
}

func TestFPPhar_NetworkBruteForce_VendorArchive(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var b bytes.Buffer
	b.WriteString("<?php\nclass Vault { private $passwords = array(); }\n")
	b.Write(gap())
	b.WriteString("$ch = curl_init($url);\n$body = curl_exec($ch);\n")
	if hasYaraRule(s.ScanBytes(b.Bytes()), "network_brute_force_tool") {
		t.Error("network_brute_force_tool FP: a credential store and an unrelated HTTP call are not a brute-force tool")
	}
}

func TestFPPhar_NetworkBruteForce_UnrelatedRequestBeforeLoop(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte("<?php\n" +
		"$passwords = $vault->all();\n" +
		"$ch = curl_init($audit_url);\n" +
		"$result = curl_exec($ch);\n" +
		"foreach ($passwords as $password) {\n" +
		"  $hashes[] = password_hash($password, PASSWORD_DEFAULT);\n" +
		"}\n")
	if hasYaraRule(s.ScanBytes(legit), "network_brute_force_tool") {
		t.Error("network_brute_force_tool FP: an earlier HTTP request is not part of a later local credential loop")
	}
}

func TestFPPhar_NetworkBruteForce_FunctionNameIsNotLoop(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte("<?php\n" +
		"function wait_for($passwords, $ch) {\n" +
		"  return curl_exec($ch);\n" +
		"}\n")
	if hasYaraRule(s.ScanBytes(legit), "network_brute_force_tool") {
		t.Error("network_brute_force_tool FP: a function name ending in for is not a credential loop")
	}
}

func TestFPPhar_NetworkBruteForce_ListDeclaredInsideOtherLoop(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte("<?php\n" +
		"foreach ($accounts as $account) {\n" +
		"  $passwords = $vault->forAccount($account);\n" +
		"  $result = curl_exec($account->auditRequest());\n" +
		"}\n")
	if hasYaraRule(s.ScanBytes(legit), "network_brute_force_tool") {
		t.Error("network_brute_force_tool FP: declaring a password list inside another loop does not iterate that list")
	}
}

func TestFPPhar_NetworkBruteForce_RealToolStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("<?php\n" +
		"$passwords = file('list.txt');\n" +
		"foreach ($passwords as $p) {\n" +
		"  $fp = fsockopen($host, 21);\n" +
		"  fwrite($fp, \"USER admin\\r\\nPASS $p\\r\\n\");\n" +
		"}\n")
	if !hasYaraRule(s.ScanBytes(mal), "network_brute_force_tool") {
		t.Error("network_brute_force_tool regression: real credential brute-force loop not detected")
	}
}

func TestFPPhar_NetworkBruteForce_CurlWordlistStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("<?php\n" +
		"$wordlist = file('list.txt');\n" +
		"foreach ($wordlist as $candidate) {\n" +
		"  curl_setopt($ch, CURLOPT_POSTFIELDS, 'password=' . $candidate);\n" +
		"  $result = curl_exec($ch);\n" +
		"}\n")
	if !hasYaraRule(s.ScanBytes(mal), "network_brute_force_tool") {
		t.Error("network_brute_force_tool regression: curl credential brute-force loop not detected")
	}
}

// Requiring the credential list in the loop header alone misses a tool that
// consumes the list from inside the body, which iterates it just as surely.
// The distinction that matters is consuming the list versus declaring one.
func TestFPPhar_NetworkBruteForce_ConsumedInLoopBodyStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for name, src := range map[string]string{
		"array_pop": "<?php\n$passwords = file('list.txt');\nwhile (true) {\n" +
			"  $p = array_pop($passwords);\n  if (!$p) break;\n  $fp = fsockopen($host, 21);\n}\n",
		"array_shift": "<?php\n$wordlist = file('list.txt');\nwhile ($wordlist) {\n" +
			"  $w = array_shift($wordlist);\n  curl_exec($ch);\n}\n",
	} {
		if !hasYaraRule(s.ScanBytes([]byte(src)), "network_brute_force_tool") {
			t.Errorf("network_brute_force_tool regression (%s): credential loop consuming the list in its body not detected", name)
		}
	}
}
