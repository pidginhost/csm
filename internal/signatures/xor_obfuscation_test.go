package signatures

import (
	"strings"
	"testing"
)

// The realtime engine must fire on the same shape the scan engine does. A
// stored snippet is written to disk by nothing, but realtime sees theme and
// plugin files carrying the identical construction, and the two rule files are
// only useful if they agree.
func TestXorStringObfuscation_RealtimeEngine(t *testing.T) {
	scanner := loadRepoScanner(t)

	// Live sample shape: WPCode snippet 4052, infiltratiizero.ro, 2026-07-27.
	mal := []byte(`if (defined("_WP_WEBSITE")) { return; }
if (!defined("\xf3\x69\x6d\xf9\x7b\x1a\x56\xbb" ^ "\xa4\x39\x32\xba\x3a\x59\x1e\xfe")) { return; }`)
	if !hasRule(scanner.ScanContent(mal, ".php"), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: realtime engine missed XOR-built identifier")
	}

	// The rule is deliberately unscoped by extension, so a snippet exported to
	// any file type is still caught.
	if !hasRule(scanner.ScanContent(mal, ".txt"), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: realtime engine skipped non-.php content")
	}
	longPair := []byte(`"` + strings.Repeat(`\x41`, 40) + `" ^ "` + strings.Repeat(`\x42`, 40) + `"`)
	if !hasRule(scanner.ScanContent(longPair, ".txt"), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: realtime engine missed a long XOR literal pair")
	}

	for name, body := range map[string]string{
		"xor of variables":     `<?php for ($i=0;$i<16;$i++) { $o .= $b[$i] ^ $k[$i]; }`,
		"lone hex literal":     `<?php $magic = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";`,
		"integer xor":          `<?php $flags = $a ^ $b; $mask = 0xff ^ 0x0f;`,
		"concatenated literal": `<?php $sig = "\x1f\x8b\x08\x00" . "\x00\x00\x00\x00";`,
	} {
		if hasRule(scanner.ScanContent([]byte(body), ".php"), "php_xor_string_obfuscation") {
			t.Errorf("php_xor_string_obfuscation FP in realtime engine: %s", name)
		}
	}
}
