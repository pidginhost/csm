package signatures

import "testing"

// Genuine PDF/font libraries build binary strings with chr() constantly. The
// rule fired on TCPDF because it only asked for "a variable assigned from chr()
// within 500 chars of any variable call", which ordinary code in any large PHP
// file satisfies. What makes chr() malicious is the assembled string reaching a
// dynamic-execution sink.

// Shape A: the chain sits inside the sink call.
const chrChainInSink = `<?php
$data = $_POST['d'];
eval(chr(101).chr(118).chr(97).chr(108).chr(40).chr(36).chr(120).chr(41));
$x = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
`

// Shape B: the chain builds a function NAME which is then called through a
// variable. This is the common evasion and must not be lost when tightening.
const chrChainBuiltThenCalled = `<?php
$fn = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$arg = chr(105).chr(100);
$fn($arg);
$pad = chr(1).chr(2).chr(3).chr(4).chr(5).chr(6).chr(7).chr(8).chr(9).chr(10);
`

// Real TCPDF: many chr() calls, a two-call chain, and in older versions a
// legitimate create_function() used for text justification. None of it feeds a
// dynamically assembled string to a sink.
const tcpdfBenign = `<?php
class TCPDF {
	protected function getSpaceString() {
		$spacestr = chr(32);
		if ($this->isUnicodeFont()) {
			$spacestr = chr(0).chr(32);
		}
		return $spacestr;
	}
	protected function justify($strpiece) {
		return preg_replace_callback('/([0-9\.\+\-]*)[\s]('.$strpiece[1][0].')/x',
			create_function('$matches', 'global $spacew; return $matches[1];'),
			$this->txt);
	}
	protected function binaryTable() {
		return chr(0).chr(1).chr(2).chr(3).chr(4).chr(5).chr(6).chr(7).chr(8).chr(9)
			.chr(10).chr(11).chr(12).chr(13).chr(14).chr(15).chr(16).chr(17);
	}
	protected function encode($s) {
		$out = chr(254).chr(255);
		foreach ($this->words as $w) { $out .= chr(32); }
		return $out;
	}
}
`

func TestChrConstructionDetectsChainIntoSink(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainInSink))["obfuscation_chr_construction"]; !ok {
		t.Error("chr chain inside eval() not detected")
	}
}

func TestChrConstructionDetectsBuiltNameThenCalled(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainBuiltThenCalled))["obfuscation_chr_construction"]; !ok {
		t.Error("chr-built function name called via variable not detected")
	}
}

func TestChrConstructionIgnoresGenuinePDFLibrary(t *testing.T) {
	if m, ok := scanRepoRules(t, []byte(tcpdfBenign))["obfuscation_chr_construction"]; ok {
		t.Errorf("false positive on genuine TCPDF-style code: %+v", m)
	}
}

// A short chr() pair assigned to a variable is ordinary string building and
// must not be enough on its own, whatever follows it.
func TestChrConstructionIgnoresShortChainNearCall(t *testing.T) {
	sample := `<?php
$sep = chr(13).chr(10);
$this->write($sep);
$table = chr(1).chr(2).chr(3).chr(4).chr(5).chr(6).chr(7).chr(8).chr(9).chr(10);
`
	if m, ok := scanRepoRules(t, []byte(sample))["obfuscation_chr_construction"]; ok {
		t.Errorf("false positive on short chr pair near a call: %+v", m)
	}
}
