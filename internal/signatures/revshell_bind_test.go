package signatures

import "testing"

// The YARA copy of this rule already requires a PHP open tag, because coding
// standards and security plugins carry lists of forbidden function names and
// those lists cannot execute. The YAML copy kept matching the bare names, so
// the two engines disagreed on the same content.

func TestRevshellPHPBind_ForbiddenFunctionListIsNotAShell(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
return [
    'forbidden' => [
        'shell_exec(' => 'Avoid shell_exec() - command injection risk.',
        'socket_bind(' => 'Avoid socket_bind() - binds to ports.',
        'socket_listen(' => 'Avoid socket_listen() - opens services.',
    ],
];
`)

	if hasRule(scanner.ScanContent(legit, ".php"), "revshell_php_bind") {
		t.Error("revshell_php_bind FP: a forbidden-function list names the calls, it does not make them")
	}
}

func TestRevshellPHPBind_RealBindShell(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($sock, '0.0.0.0', 4444);
socket_listen($sock, 1);
$client = socket_accept($sock);
while (true) {
    $cmd = socket_read($client, 2048);
    $out = shell_exec($cmd);
    socket_write($client, $out);
}
`)

	if !hasRule(scanner.ScanContent(malicious, ".php"), "revshell_php_bind") {
		t.Error("revshell_php_bind miss: a socket bind shell reading commands was not detected")
	}
}
