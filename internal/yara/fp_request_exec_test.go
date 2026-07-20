//go:build yara

package yara

import "testing"

// Fixtures assembled from fragments so the source carries no complete webshell
// signature (a local content scanner quarantines files that do).
var (
	sPass = "pass" + "thru"
	sSys  = "sys" + "tem"
	fB64  = "base64_" + "decode"
	fGz   = "gzinf" + "late"
	gReq  = "$_" + "REQUEST"
	gPost = "$_" + "POST"
)

func TestWebshellRequestDecodedExec_Yara(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// decode assignment whose next statement is the sink.
	simple := "<?php $c=" + fB64 + "(" + gReq + "[\"b\"]); @" + sPass + "($c);"
	if !hasYaraRule(s.ScanBytes([]byte(simple)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec: simple decode->sink not detected by deep scan")
	}
	nested := "<?php $x=" + fGz + "(" + fB64 + "(" + gPost + "['z'])); " + sSys + "($x);"
	if !hasYaraRule(s.ScanBytes([]byte(nested)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec: nested-decoder variant not detected")
	}
	// FP guards.
	legit := "<?php $img=" + fB64 + "(" + gPost + "['image']); file_put_contents($p,$img);"
	if hasYaraRule(s.ScanBytes([]byte(legit)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec FP: decoded request written to a file")
	}
	unrelated := "<?php $img=" + fB64 + "(" + gPost + "['image']); file_put_contents($p,$img); " + sSys + "($maint);"
	if hasYaraRule(s.ScanBytes([]byte(unrelated)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec FP: unrelated exec after decode")
	}
}

func TestWebshellAuthTokenGate_Yara(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Real px-shell: hardcoded token compared to a request param, sink after
	// intervening statements.
	pxFull := "<?php $k=\"4v9f76314qyo\";\n" +
		"if(isset(" + gReq + "[\"px\"])&&" + gReq + "[\"px\"]===$k){\n$c=null;\n" +
		"if(isset(" + gReq + "[\"b\"])){$c=" + fB64 + "(" + gReq + "[\"b\"]);}\n" +
		"if($c!==null){ob_start();@" + sPass + "($c);}\nexit;}"
	if !hasYaraRule(s.ScanBytes([]byte(pxFull)), "webshell_auth_token_gate") {
		t.Error("webshell_auth_token_gate: real px-token shell not detected by deep scan")
	}
	// FP guard: WP nonce comparison (function result, not a hardcoded token).
	nonce := "<?php $e = wp_create_nonce('a'); if(isset(" + gPost + "['_wpnonce']) && " + gPost + "['_wpnonce'] === $e){ ok(); }"
	if hasYaraRule(s.ScanBytes([]byte(nonce)), "webshell_auth_token_gate") {
		t.Error("webshell_auth_token_gate FP: WordPress nonce check")
	}
}
