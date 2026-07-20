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
		"    $output = @shell_" + "exec($cmd . ' 2>&1');\n}"
	if !hasYaraRule(s.ScanBytes([]byte(realShell)), "webshell_token_gate_indirect") {
		t.Error("webshell_token_gate_indirect: real token shell not detected by deep scan")
	}

	reversed := "<?php $in = " + gGet + "['k']; $tok = 'mm44nn55bb66'; if ($in === $tok) { " + sSys + "($cmd); }"
	if !hasYaraRule(s.ScanBytes([]byte(reversed)), "webshell_token_gate_indirect") {
		t.Error("webshell_token_gate_indirect: reversed declaration order not detected")
	}

	benign := []struct{ name, content string }{
		{"nonce via variable", "<?php $expected = wp_create_nonce('act'); $sent = " + gPost + "['_wpnonce']; if ($sent === $expected) { do_thing(); }"},
		{"license gate without sink", "<?php $license = 'prolicense2026'; $given = " + gPost + "['license']; if ($given == $license) { enable_pro(); }"},
		{"object method sink", "<?php $key = 'a1b2c3d4e5'; $in = " + gPost + "['key']; if ($in === $key) { $runner->" + "exec($task); }"},
		{"no request source", "<?php $expected = 'buildhash1234'; $actual = $manifest['hash']; if ($actual === $expected) { " + sSys + "($deployCmd); }"},
	}
	for _, b := range benign {
		if hasYaraRule(s.ScanBytes([]byte(b.content)), "webshell_token_gate_indirect") {
			t.Errorf("webshell_token_gate_indirect FP on %s", b.name)
		}
	}
}
