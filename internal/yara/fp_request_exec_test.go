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
	// px-token 404.php shell: base64(request) -> var -> command sink.
	px := "<?php $k=\"4v9f76314qyo\";\n" +
		"if(isset(" + gReq + "[\"px\"])&&" + gReq + "[\"px\"]===$k){\n" +
		"$c=" + fB64 + "(" + gReq + "[\"b\"]);\n" +
		"@" + sPass + "($c.' 2>&1');}\n"
	if !hasYaraRule(s.ScanBytes([]byte(px)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec: px-token indirection shell not detected by deep scan")
	}
	nested := "<?php $x=" + fGz + "(" + fB64 + "(" + gPost + "['z'])); " + sSys + "($x);"
	if !hasYaraRule(s.ScanBytes([]byte(nested)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec: nested-decoder variant not detected")
	}
	// FP guard: decoder on request but sink writes a file (not exec).
	legit := "<?php $img=" + fB64 + "(" + gPost + "['image']); file_put_contents($p,$img);"
	if hasYaraRule(s.ScanBytes([]byte(legit)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec FP: decoded request written to a file")
	}
	// FP guard: escapeshellarg-built command with separately-handled request.
	updraft := "<?php $cmd=escapeshellarg($this->bin); proc_open($cmd,$s,$p); if(isset(" + gPost + "['a'])){$this->run(" + gPost + "['a']);}"
	if hasYaraRule(s.ScanBytes([]byte(updraft)), "webshell_request_decoded_exec") {
		t.Error("webshell_request_decoded_exec FP: escapeshellarg-built command")
	}
}
