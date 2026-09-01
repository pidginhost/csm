//go:build yara

package yara

import (
	"strings"
	"testing"
)

// XOR-constructed identifiers hide every literal a keyword rule looks for. The
// live sample is WPCode snippet 4052 on infiltratiizero.ro (2026-07-27): 17KB
// of PHP whose constant and hook names are all built by XOR-ing two binary
// string literals, so the words WP_CACHE, DONOTCACHEPAGE and
// rest_send_nocache_headers never appear in the source at all.
func TestXorObfuscation_StoredBackdoor(t *testing.T) {
	s := loadRepoYaraScanner(t)

	mal := []byte(`<?php
if (defined("_WP_WEBSITE")) { return; }
define("_WP_PWSA", "5dda2dc60a726556d76ab1e47570331f");
if (!defined("\xf3\x69\x6d\xf9\x7b\x1a\x56\xbb" ^ "\xa4\x39\x32\xba\x3a\x59\x1e\xfe")) {
    define("\xf3\x69\x6d\xf9\x7b\x1a\x56\xbb" ^ "\xa4\x39\x32\xba\x3a\x59\x1e\xfe", false);
}
add_filter("\xdc\xcf\x0e\x21\xac\xe7\x9b\x5c\x09\x62" ^ "\xae\xaa\x7d\x55\xf3\x94\xfe\x32\x6d\x3d", "x", PHP_INT_MAX);`)
	if !hasYaraRule(s.ScanBytes(mal), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: XOR-built identifiers not detected")
	}
}

// A single XOR pair is already conclusive: no legitimate PHP builds an
// identifier this way, and the technique exists only to defeat grep.
func TestXorObfuscation_SinglePair(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $f = "\x8f\x44\x51\xe6\x61\x0b" ^ "\xcb\x0b\x1f\xa9\x35\x48"; $f();`)
	if !hasYaraRule(s.ScanBytes(mal), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: single XOR literal pair not detected")
	}
	longPair := []byte(`"` + strings.Repeat(`\x41`, 40) + `" ^ "` + strings.Repeat(`\x42`, 40) + `"`)
	if !hasYaraRule(s.ScanBytes(longPair), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: long XOR literal pair not detected")
	}
}

// Benign controls. These are the shapes real code uses, and every one must stay
// quiet or the rule is unusable on a shared host.
func TestXorObfuscation_BenignControls(t *testing.T) {
	s := loadRepoYaraScanner(t)
	controls := []struct {
		name string
		body string
	}{
		{
			// Crypto libraries XOR variables, not literal blobs. phpseclib and
			// mpdf ship on many of these accounts.
			name: "xor of variables",
			body: `<?php for ($i = 0; $i < 16; $i++) { $out .= $block[$i] ^ $key[$i]; }`,
		},
		{
			// Binary constants are ordinary; it is the paired XOR that is not.
			name: "lone hex string literal",
			body: `<?php $magic = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"; if (substr($d,0,8) === $magic) {}`,
		},
		{
			// Integer XOR in bit-flag handling.
			name: "integer xor",
			body: `<?php $flags = $a ^ $b; $mask = 0xff ^ 0x0f;`,
		},
		{
			// Two adjacent binary literals with no XOR between them.
			name: "adjacent literals concatenated",
			body: `<?php $sig = "\x1f\x8b\x08\x00" . "\x00\x00\x00\x00";`,
		},
	}
	for _, c := range controls {
		if hasYaraRule(s.ScanBytes([]byte(c.body)), "php_xor_string_obfuscation") {
			t.Errorf("php_xor_string_obfuscation FP: matched benign control %q", c.name)
		}
	}
}

// Snippet managers store bare PHP with no open tag, which is exactly how the
// live backdoor was stored. A rule that requires <?php would never fire on the
// database rows this technique actually lives in.
func TestXorObfuscation_BareSnippetNoOpenTag(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`if (defined("_WP_WEBSITE")) { return; }
foreach (["\x8f\x44\x51\xe6\x61\x0b\x12\x6e" ^ "\xcb\x0b\x1f\xa9\x35\x48\x53\x2d"] as $c) { define($c, true); }`)
	if !hasYaraRule(s.ScanBytes(mal), "php_xor_string_obfuscation") {
		t.Error("php_xor_string_obfuscation: bare stored snippet (no open tag) not detected")
	}
}
