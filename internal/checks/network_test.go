package checks

import "testing"

// --- isInfraIP --------------------------------------------------------

func TestIsInfraIPExactMatch(t *testing.T) {
	if !isInfraIP("10.0.0.1", []string{"10.0.0.1"}) {
		t.Error("exact match should return true")
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
