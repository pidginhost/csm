package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCandidates_BasicPatterns(t *testing.T) {
	candidates := generateCandidates("john", "example.com")

	// Should contain year variants (current year is 2026 based on currentYear)
	assertContains(t, candidates, "john2024")
	assertContains(t, candidates, "john2025")
	assertContains(t, candidates, "john2026")
	assertContains(t, candidates, "john2027")
	assertContains(t, candidates, "john2028")

	// Should contain domain first label
	assertContains(t, candidates, "example")
	assertContains(t, candidates, "example2026")

	// Should contain uppercase variants
	assertContains(t, candidates, "John2026")
	assertContains(t, candidates, "Example2026")

	// Should NOT contain short candidates (< 6 chars)
	for _, c := range candidates {
		if len(c) < 6 {
			t.Errorf("candidate %q is shorter than 6 chars", c)
		}
	}
}

func TestGenerateCandidates_AdminExampleCorp(t *testing.T) {
	candidates := generateCandidates("admin", "examplecorp.test")

	assertContains(t, candidates, "admin2026")
	assertContains(t, candidates, "Admin2026")
	assertContains(t, candidates, "examplecorp")
	assertContains(t, candidates, "Examplecorp")
	assertContains(t, candidates, "Examplecorp2026")
	assertContains(t, candidates, "examplecorp2026")

	// Two-digit suffixes
	assertContains(t, candidates, "admin00")
	assertContains(t, candidates, "admin99")
	assertContains(t, candidates, "Admin00")

	for _, c := range candidates {
		if len(c) < 6 {
			t.Errorf("candidate %q is shorter than 6 chars", c)
		}
	}
}

func TestGenerateCandidates_ShortUsername(t *testing.T) {
	candidates := generateCandidates("ab", "x.com")

	// "ab" alone is too short (< 6), but "ab2026" is 6 chars -- should be included
	assertContains(t, candidates, "ab2026")

	// All candidates must be >= 6 chars
	for _, c := range candidates {
		if len(c) < 6 {
			t.Errorf("candidate %q is shorter than 6 chars", c)
		}
	}
}

func TestGenerateCandidates_NoDuplicates(t *testing.T) {
	// When username == domain label, ensure no duplicates
	candidates := generateCandidates("testuser", "testuser.com")

	seen := make(map[string]bool)
	for _, c := range candidates {
		if seen[c] {
			t.Errorf("duplicate candidate: %q", c)
		}
		seen[c] = true
	}
}

func TestGenerateCandidates_SubdomainDomain(t *testing.T) {
	candidates := generateCandidates("info", "my-company.co.uk")

	// Domain first label is "my-company"
	assertContains(t, candidates, "my-company")
	assertContains(t, candidates, "My-company")
	assertContains(t, candidates, "my-company2026")
}

func TestParseShadowLine(t *testing.T) {
	tests := []struct {
		line    string
		mailbox string
		hash    string
	}{
		{"user:{SHA512-CRYPT}$6$abc$xyz", "user", "{SHA512-CRYPT}$6$abc$xyz"},
		{"admin:{BLF-CRYPT}$2y$05$hash", "admin", "{BLF-CRYPT}$2y$05$hash"},
		{"nocolon", "", ""},
		{":", "", ""},
	}

	for _, tt := range tests {
		mailbox, hash := parseShadowLine(tt.line)
		if mailbox != tt.mailbox || hash != tt.hash {
			t.Errorf("parseShadowLine(%q) = (%q, %q), want (%q, %q)",
				tt.line, mailbox, hash, tt.mailbox, tt.hash)
		}
	}
}

func TestIsLockedHash(t *testing.T) {
	tests := []struct {
		hash   string
		locked bool
	}{
		{"{SHA512-CRYPT}$6$abc$xyz", false},
		{"!{SHA512-CRYPT}$6$abc$xyz", true},
		{"*{SHA512-CRYPT}$6$abc$xyz", true},
		{"", true},
		{"{SHA512-CRYPT}$6$rounds=5000$salt$hash", false},
	}

	for _, tt := range tests {
		got := isLockedHash(tt.hash)
		if got != tt.locked {
			t.Errorf("isLockedHash(%q) = %v, want %v", tt.hash, got, tt.locked)
		}
	}
}

func TestHIBPResponseParsing(t *testing.T) {
	// Simulated HIBP response body (k-anonymity format)
	body := "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n" +
		"00D4F6E8FA6EECAD2A3AA415EEC418D38EC:5\r\n" +
		"011053FD0102E94D6AE2F8B83D76FAF94F6:3\r\n"

	// Test matching suffix
	count := parseHIBPCount(body, "0018A45C4D1DEF81644B54AB7F969B88D65")
	if count != 10 {
		t.Errorf("parseHIBPCount = %d, want 10", count)
	}

	// Test non-matching suffix
	count = parseHIBPCount(body, "FFFFF")
	if count != 0 {
		t.Errorf("parseHIBPCount for missing suffix = %d, want 0", count)
	}

	// Test case insensitivity
	count = parseHIBPCount(body, "0018a45c4d1def81644b54ab7f969b88d65")
	if count != 10 {
		t.Errorf("parseHIBPCount case insensitive = %d, want 10", count)
	}
}

func TestHashFingerprint(t *testing.T) {
	fp1 := hashFingerprint("{SHA512-CRYPT}$6$abc$xyz")
	fp2 := hashFingerprint("{SHA512-CRYPT}$6$abc$xyz")
	fp3 := hashFingerprint("{SHA512-CRYPT}$6$abc$different")

	if fp1 != fp2 {
		t.Error("same input should produce same fingerprint")
	}
	if fp1 == fp3 {
		t.Error("different input should produce different fingerprint")
	}
	if len(fp1) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (SHA256 hex)", len(fp1))
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"admin", "Admin"},
		{"examplecorp", "Examplecorp"},
		{"", ""},
		{"A", "A"},
		{"my-company", "My-company"},
	}
	for _, tt := range tests {
		got := capitalizeFirst(tt.in)
		if got != tt.want {
			t.Errorf("capitalizeFirst(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- readShadowFile ---------------------------------------------------

func TestReadShadowFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	content := "# comment\n" +
		"alice:{SHA512-CRYPT}$6$salt$hash\n" +
		"bob:!{SHA512-CRYPT}$6$salt$lockedhash\n" +
		"carol:{BLF-CRYPT}$2y$05$active\n" +
		"malformed\n" +
		"\n"
	_ = os.WriteFile(path, []byte(content), 0600)

	sf := shadowFile{path: path, account: "cpuser", domain: "example.com"}
	entries := readShadowFile(sf)

	// alice = active, bob = locked (skipped), carol = active, malformed = skipped
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (alice + carol)", len(entries))
	}
	if entries[0].mailbox != "alice" || entries[0].account != "cpuser" {
		t.Errorf("first entry: %+v", entries[0])
	}
	if entries[1].mailbox != "carol" || entries[1].domain != "example.com" {
		t.Errorf("second entry: %+v", entries[1])
	}
}

func TestReadShadowFileMissing(t *testing.T) {
	sf := shadowFile{path: filepath.Join(t.TempDir(), "nope"), account: "x", domain: "y"}
	if got := readShadowFile(sf); got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func assertContains(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("slice does not contain %q", want)
}
