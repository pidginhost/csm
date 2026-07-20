package signatures

import "testing"

// The 2026-07-20 filmetaricom shell gated exec behind a hardcoded token, but
// routed the request value through an intermediate variable before comparing
// it ($input_token = $_GET['t']; if ($token === $input_token)) and passed a
// second request-derived variable to the sink. webshell_auth_token_gate keys on
// the superglobal appearing directly inside the equality, so the indirection
// walked past it. Fixtures are assembled from fragments so this source file
// carries no complete webshell signature.
func TestWebshellTokenGateIndirectDetectsRealShell(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Shape of the quarantined system-monitor dropper.
	realShell := "<?php\n$token = '9129ed4863864b21448183d53e8dbd05';\n" +
		"$input_token = isset(" + gGet + "['t']) ? (string)" + gGet + "['t'] : '';\n\n" +
		"if ($token === $input_token && isset(" + gGet + "['c'])) {\n" +
		"    $cmd = (string)" + gGet + "['c'];\n" +
		"    $output = '';\n" +
		"    // Try multiple execution methods\n" +
		"    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', @ini_get('disable_functions')))) {\n" +
		"        $output = @shell_exec($cmd . ' 2>&1');\n" +
		"    }\n}"
	if !hasRule(scanner.ScanContent([]byte(realShell), ".php"), "webshell_token_gate_indirect") {
		t.Error("webshell_token_gate_indirect missed the real filmetaricom token shell")
	}

	variants := []struct{ name, content string }{
		{
			"direct assignment then loose compare",
			"<?php $k = 'a1b2c3d4e5f6'; $t = " + gPost + "['t']; if ($t == $k) { $c = " + gPost + "['c']; " + sSys + "($c); }",
		},
		{
			"request var compared first, strict",
			"<?php $secret = \"zx98yw76vu54\"; $given = " + gReq + "['auth']; if ($given === $secret) { $c = " + gReq + "['cmd']; @" + sPass + "((string)$c . ' 2>&1'); }",
		},
		{
			"GET-sourced token with popen sink",
			"<?php $tok = 'qqww11ee22rr'; $in = " + gGet + "['k']; if ($tok === $in) { $cmd = " + gGet + "['c']; $fp = @popen($cmd, 'r'); }",
		},
		// Declaration order is trivially swapped by an author; the gate is the
		// same shape, so reversing it must not evade the rule.
		{
			"request captured before the token literal",
			"<?php $in = " + gGet + "['k']; $tok = 'mm44nn55bb66'; if ($in === $tok) { $cmd = " + gGet + "['c']; " + sSys + "($cmd); }",
		},
		{
			"double-quoted token, key, and comment separators",
			"<?php $secret/*a*/=/*b*/\"zx98yw76vu54\"; $given = " + gReq + "[\"auth\"]; if ($given === $secret) { $c = " + gReq + "['cmd']; @" + sPass + "($c); }",
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
		if !hasRule(scanner.ScanContent([]byte(v.content), ".php"), "webshell_token_gate_indirect") {
			t.Errorf("webshell_token_gate_indirect missed %s", v.name)
		}
	}
}

func TestWebshellTokenGateIndirectFPSafe(t *testing.T) {
	scanner := loadRepoScanner(t)
	benign := []struct{ name, content string }{
		// Compared value comes from a function, not a hardcoded literal.
		{
			"wp nonce via variable",
			"<?php $expected = wp_create_nonce('act'); $sent = " + gPost + "['_wpnonce']; if ($sent === $expected) { do_thing(); }",
		},
		// Token gate present but the guarded branch has no code/command sink.
		{
			"license gate without sink",
			"<?php $license = 'prolicense2026'; $given = " + gPost + "['license']; if ($given == $license) { enable_pro(); }",
		},
		// Sink is a method on an object, not a PHP built-in.
		{
			"object exec method",
			"<?php $key = 'a1b2c3d4e5'; $in = " + gPost + "['key']; if ($in === $key) { $runner->exec($task); }",
		},
		// Identifier merely contains a sink name.
		{
			"sink substring function",
			"<?php $key = 'a1b2c3d4e5'; $in = " + gPost + "['key']; if ($in === $key) { my_" + sSys + "($task); }",
		},
		// Capability probe with exec but no hardcoded secret gate.
		{
			"capability probe without token",
			"<?php $cmd = " + gPost + "['c']; if (function_exists('exec')) { $out = shell_exec(escapeshellarg($binary)); }",
		},
		// Short literal is not a random secret.
		{
			"short token",
			"<?php $m = 'ok'; $t = " + gGet + "['t']; if ($t === $m) { " + sSys + "($c); }",
		},
		// Two unrelated variables compared, no request source at all.
		{
			"config comparison",
			"<?php $expected = 'buildhash1234'; $actual = $manifest['hash']; if ($actual === $expected) { " + sSys + "($deployCmd); }",
		},
		// The original four uncorrelated fragments must not chain across an
		// ordinary request handler and a command outside the guarded branch.
		{
			"unrelated sink after closed gate",
			"<?php $channel = 'production'; $action = " + gReq + "['action']; if ($current === $expected) { dispatch($action); } " + sSys + "($maintenanceCmd);",
		},
		// A large plugin method can contain a request capture, an unrelated
		// configuration comparison, and a capability command in the same branch.
		// None of that establishes request-to-command data flow.
		{
			"unrelated capability command inside gate",
			"<?php $channel = 'production'; $action = " + gReq + "['action']; if ($installed === $required) { " + sSys + "($healthCheck); dispatch($action); }",
		},
		// Comparison helper names must have a callable boundary, just like sinks.
		{
			"hash_equals wrapper",
			"<?php $secret = 'aa11bb22cc33'; $in = " + gGet + "['k']; if (my_hash_equals($secret, $in)) { $cmd = " + gGet + "['c']; " + sSys + "($cmd); }",
		},
	}
	for _, b := range benign {
		if hasRule(scanner.ScanContent([]byte(b.content), ".php"), "webshell_token_gate_indirect") {
			t.Errorf("webshell_token_gate_indirect FP on %s", b.name)
		}
	}
}
