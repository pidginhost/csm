package signatures

import (
	"strings"
	"testing"
)

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

// Shape B2: the assembled code is passed to a direct execution sink after the
// assignment. This differs from assembling a function name and invoking it.
const chrChainBuiltThenEval = `<?php
$code = chr(112).chr(104).chr(112).chr(105).chr(110).chr(102).chr(111).chr(40).chr(41).chr(59);
eval($code);
`

// Shape C: malware can assemble the payload one byte per statement before a
// direct sink consumes the completed variable.
const chrChainAcrossStatements = `<?php
$code = chr(112);
$code .= chr(104);
$code .= chr(112);
$code .= chr(105);
$code .= chr(110);
$code .= chr(102);
$code .= chr(111);
$code .= chr(40);
$code .= chr(41);
$code .= chr(59);
eval($code);
`

// Shape D: PHP variable-variable syntax can invoke an assembled function name
// without the plain $fn(...) form.
const chrChainVariableVariable = `<?php
$name = chr(115).chr(104).chr(101).chr(108).chr(108).chr(95).chr(101).chr(120).chr(101).chr(99);
${$name}($_POST['cmd']);
`

// Shape E: empty str_repeat() terms are inert padding that break a matcher
// which accepts only adjacent chr() calls.
const chrChainStrRepeatPadding = `<?php
$fn = chr(115).str_repeat('', 8).chr(104).chr(101).str_repeat('', 16).chr(108).chr(108).chr(95).chr(101).chr(120).chr(101).chr(99);
$fn($_REQUEST['cmd']);
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

func TestChrConstructionDetectsBuiltCodeThenEval(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainBuiltThenEval))["obfuscation_chr_construction"]; !ok {
		t.Error("chr-built code passed to eval() not detected")
	}
}

func TestChrConstructionDetectsChainAcrossStatements(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainAcrossStatements))["obfuscation_chr_construction"]; !ok {
		t.Error("chr chain assembled across statements and passed to eval() not detected")
	}
}

func TestChrConstructionDetectsVariableVariableSink(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainVariableVariable))["obfuscation_chr_construction"]; !ok {
		t.Error("chr-built function invoked through variable-variable syntax not detected")
	}
}

func TestChrConstructionDetectsStrRepeatPadding(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(chrChainStrRepeatPadding))["obfuscation_chr_construction"]; !ok {
		t.Error("str_repeat padding inside a chr chain bypassed the sink gate")
	}
}

func TestChrConstructionDetectsMixedCaseCalls(t *testing.T) {
	sample := []byte(`<?php
$fn = CHR(115).CHR(104).CHR(101).CHR(108).CHR(108).CHR(95).CHR(101).CHR(120).CHR(101).CHR(99);
$fn($_REQUEST['cmd']);
`)
	if _, ok := scanRepoRules(t, sample)["obfuscation_chr_construction"]; !ok {
		t.Error("mixed-case chr calls bypassed the fallback signature")
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

func TestChrConstructionIgnoresScatteredChrCallsNearCallback(t *testing.T) {
	sample := `<?php
$prefix = chr(0).chr(1).chr(2);
$callback($prefix);
$table = [chr(3), chr(4), chr(5), chr(6), chr(7), chr(8), chr(9), chr(10)];
`
	if m, ok := scanRepoRules(t, []byte(sample))["obfuscation_chr_construction"]; ok {
		t.Errorf("false positive on scattered chr calls near a callback: %+v", m)
	}
}

func TestChrConstructionDoesNotCombineSeparateSubthresholdFragments(t *testing.T) {
	sample := []byte(`<?php
$buffer=chr(1);$buffer.=chr(2);$buffer.=chr(3);$buffer.=chr(4);
$buffer.=chr(5);$buffer.=chr(6);$buffer.=chr(7);
` + strings.Repeat("$padding .= 'ordinary data';\n", 50) + `
$code=chr(112);$code.=chr(104);$code.=chr(112);eval($code);
`)
	if m, ok := scanRepoRules(t, sample)["obfuscation_chr_construction"]; ok {
		t.Errorf("separate subthreshold chr fragments were combined into a finding: %+v", m)
	}
}
