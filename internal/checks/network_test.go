package checks

import "testing"

// --- isInfraIP --------------------------------------------------------

func TestIsInfraIPExactMatch(t *testing.T) {
	if !isInfraIP("10.0.0.1", []string{"10.0.0.1"}) {
		t.Error("exact match should return true")
	}
}

func TestIsInfraIPTrimsConfiguredEntries(t *testing.T) {
	if !isInfraIP("10.0.0.5", []string{" 10.0.0.0/24 "}) {
		t.Error("CIDR match with spaces should return true")
	}
}

func TestIsInfraIPExactMatchCanonicalIPv6(t *testing.T) {
	expanded := "2001:0db8:0000:0000:0000:0000:0000:0001"
	if !isInfraIP("2001:db8::1", []string{expanded}) {
		t.Error("canonical IPv6 exact match should return true")
	}
}

func TestIsInfraIPCIDRMatch(t *testing.T) {
	if !isInfraIP("10.0.0.5", []string{"10.0.0.0/24"}) {
		t.Error("CIDR match should return true")
	}
}

func TestIsInfraIPNoMatch(t *testing.T) {
	if isInfraIP("203.0.113.5", []string{"10.0.0.0/8"}) {
		t.Error("non-infra should return false")
	}
}

func TestIsInfraIPInvalid(t *testing.T) {
	if isInfraIP("not-an-ip", []string{"10.0.0.0/8"}) {
		t.Error("invalid IP should return false")
	}
}

func TestIsInfraIPEmpty(t *testing.T) {
	if isInfraIP("10.0.0.1", nil) {
		t.Error("empty infra list should return false")
	}
}

// --- hexToByte --------------------------------------------------------

func TestHexToByteValid(t *testing.T) {
	if got := hexToByte("FF"); got != 0xFF {
		t.Errorf("got %x, want FF", got)
	}
	if got := hexToByte("0A"); got != 0x0A {
		t.Errorf("got %x, want 0A", got)
	}
}

func TestHexToByteWrongLength(t *testing.T) {
	if got := hexToByte("F"); got != 0 {
		t.Errorf("wrong length should return 0, got %x", got)
	}
}

// --- matchGlob --------------------------------------------------------

func TestMatchGlobExact(t *testing.T) {
	if !matchGlob("/home/alice/evil.php", "*.php") {
		t.Error("*.php should match evil.php")
	}
}

func TestMatchGlobSubstring(t *testing.T) {
	if !matchGlob("/home/alice/wp-content/uploads/bad.php", "/uploads/") {
		t.Error("/uploads/ substring should match via Contains fallback")
	}
}

func TestMatchGlobNoMatch(t *testing.T) {
	if matchGlob("/home/alice/readme.txt", "*.php") {
		t.Error("*.php should not match .txt")
	}
}

// A wildcard pattern must not over-suppress by being stripped to a bare
// substring. "*.php" must not silence a non-PHP file just because an ancestor
// directory name ends in ".php" -- the old strip-stars-then-Contains did, which
// let an attacker hide a webshell in a "safe" subtree.
func TestMatchGlobWildcardNotStrippedToSubstring(t *testing.T) {
	if matchGlob("/home/u/public_html/x.php/evil.txt", "*.php") {
		t.Error("*.php must not suppress evil.txt under a dir named x.php")
	}
	if matchGlob("/home/u/somewhere/cacheconfig/shell.aspx", "*config*") {
		t.Error("*config* must not suppress a file under a dir merely containing 'config'")
	}
}

// A slash-bearing wildcard pattern keeps its "directory anywhere in the path"
// meaning without degrading to a bare substring.
func TestMatchGlobDirGlobMatchesAnywhere(t *testing.T) {
	if !matchGlob("/home/u/public_html/node_modules/dep/x.js", "*/node_modules/*") {
		t.Error("*/node_modules/* should match node_modules anywhere in the path")
	}
}
