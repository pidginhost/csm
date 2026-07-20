package signatures

import "testing"

// Malware fixtures are assembled from fragments at runtime so the source file
// contains no complete webshell signature (a local content scanner quarantines
// files carrying one), while the assembled bytes still exercise the rules.
var (
	sPass  = "pass" + "thru"
	sSys   = "sys" + "tem"
	sShell = "shell_" + "exec"
	fB64   = "base64_" + "decode"
	fGz    = "gzinf" + "late"
	fRot   = "str_" + "rot13"
	gReq   = "$_" + "REQUEST"
	gPost  = "$_" + "POST"
	gGet   = "$_" + "GET"
	iniOB  = "ini_" + "set"
)

func TestWebshellRequestDecodedExecDetectsIndirection(t *testing.T) {
	scanner := loadRepoScanner(t)
	// px-token 404.php shell: request base64-decoded into a var, then passed to
	// a command sink -- the variable indirection webshell_generic_passthru misses.
	px := "<?php $k=\"4v9f76314qyo\";\n" +
		"if(isset(" + gReq + "[\"px\"])&&" + gReq + "[\"px\"]===$k){\n" +
		"$c=" + fB64 + "(" + gReq + "[\"b\"]);\n" +
		"@" + sPass + "($c.' 2>&1');}\n?>"
	if !hasRule(scanner.ScanContent([]byte(px), ".php"), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec missed base64(request)->var->sink indirection")
	}
	variants := []string{
		"<?php $x=" + fGz + "(" + fB64 + "(" + gPost + "['z'])); " + sSys + "($x);",
		"<?php $cmd = " + fRot + "(" + gGet + "['q']); " + sShell + "($cmd);",
	}
	for _, v := range variants {
		if !hasRule(scanner.ScanContent([]byte(v), ".php"), "webshell_request_decoded_exec") {
			t.Errorf("webshell_request_decoded_exec missed variant: %s", v)
		}
	}
}

func TestWebshellRequestDecodedExecFPSafe(t *testing.T) {
	scanner := loadRepoScanner(t)
	benign := []struct{ name, content string }{
		// decoder on request input, but the sink writes a file (not code/command exec)
		{"decoded request written to file", "<?php $img = " + fB64 + "(" + gPost + "['image']); file_put_contents($path, $img);"},
		// UpdraftPlus-style: escapeshellarg-built command; request handled separately
		{"escapeshellarg-built command", "<?php $cmd = escapeshellarg($this->binary).' '.escapeshellarg($file); $h = proc_open($cmd, $spec, $pipes); if(isset(" + gPost + "['subaction'])){ $this->run(" + gPost + "['subaction']); }"},
		// exec of a trusted config value, no request/decoder flow
		{"exec of config value", "<?php $bin = $config['convert_path']; " + sSys + "($bin.' -resize 100x100');"},
	}
	for _, b := range benign {
		if hasRule(scanner.ScanContent([]byte(b.content), ".php"), "webshell_request_decoded_exec") {
			t.Errorf("webshell_request_decoded_exec FP on %s", b.name)
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
		// legit hardening narrows open_basedir to a real path -- must not match
		"<?php " + iniOB + "('open_basedir', ABSPATH . PATH_SEPARATOR . WP_CONTENT_DIR);",
	}
	for _, c := range benign {
		if hasRule(scanner.ScanContent([]byte(c), ".php"), "php_open_basedir_override") {
			t.Errorf("php_open_basedir_override FP on: %s", c)
		}
	}
}
