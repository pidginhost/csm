package checks

import (
	"testing"
)

func TestParseValiasLine(t *testing.T) {
	tests := []struct {
		line      string
		localPart string
		dest      string
	}{
		{"info: admin@example.com", "info", "admin@example.com"},
		{"*: catchall@external.com", "*", "catchall@external.com"},
		{"user: |/usr/local/bin/script.sh", "user", "|/usr/local/bin/script.sh"},
		{"blackhole: /dev/null", "blackhole", "/dev/null"},
		{"multi: user1@example.com,user2@example.com", "multi", "user1@example.com,user2@example.com"},
		{"  info :  admin@example.com  ", "info", "admin@example.com"},
		{"# comment line", "", ""},
		{"", "", ""},
		{"nocolon", "", ""},
	}

	for _, tt := range tests {
		localPart, dest := parseValiasLine(tt.line)
		if localPart != tt.localPart || dest != tt.dest {
			t.Errorf("parseValiasLine(%q) = (%q, %q), want (%q, %q)",
				tt.line, localPart, dest, tt.localPart, tt.dest)
		}
	}
}

func TestIsPipeForwarder(t *testing.T) {
	tests := []struct {
		dest string
		pipe bool
	}{
		{"|/usr/local/bin/script.sh", true},
		{"| /path/to/cmd", true},
		{"user@example.com", false},
		{"/dev/null", false},
	}

	for _, tt := range tests {
		got := isPipeForwarder(tt.dest)
		if got != tt.pipe {
			t.Errorf("isPipeForwarder(%q) = %v, want %v", tt.dest, got, tt.pipe)
		}
	}
}

func TestIsDevNull(t *testing.T) {
	tests := []struct {
		dest    string
		devnull bool
	}{
		{"/dev/null", true},
		{" /dev/null ", false}, // already trimmed by parseValiasLine
		{"user@example.com", false},
		{"|/dev/null", false}, // pipe, not devnull
	}

	for _, tt := range tests {
		got := isDevNullForwarder(tt.dest)
		if got != tt.devnull {
			t.Errorf("isDevNullForwarder(%q) = %v, want %v", tt.dest, got, tt.devnull)
		}
	}
}

func TestIsExternalDest(t *testing.T) {
	localDomains := map[string]bool{
		"example.com":  true,
		"example.org":  true,
		"mydomain.net": true,
	}

	tests := []struct {
		dest     string
		external bool
	}{
		{"admin@example.com", false},
		{"user@example.org", false},
		{"user@gmail.com", true},
		{"user@external.io", true},
		{"|/path/to/script", false}, // pipe, not email
		{"/dev/null", false},        // devnull, not email
		{"localuser", false},        // local delivery, no @
	}

	for _, tt := range tests {
		got := isExternalDest(tt.dest, localDomains)
		if got != tt.external {
			t.Errorf("isExternalDest(%q) = %v, want %v", tt.dest, got, tt.external)
		}
	}
}

func TestParseVfilterExternalDests(t *testing.T) {
	content := `# Maildrop filter
if (/^From: .*spammer/)
{
  to "admin@gmail.com"
}
if (/^Subject: .*urgent/)
{
  to "backup@example.com"
}
to "alerts@external.io"
`

	localDomains := map[string]bool{
		"example.com": true,
	}

	dests := parseVfilterExternalDests(content, localDomains)

	found := make(map[string]bool)
	for _, d := range dests {
		found[d] = true
	}

	if !found["admin@gmail.com"] {
		t.Error("should detect admin@gmail.com as external")
	}
	if found["backup@example.com"] {
		t.Error("backup@example.com is local, should not be detected")
	}
	if !found["alerts@external.io"] {
		t.Error("should detect alerts@external.io as external")
	}
}

func TestLoadLocalDomains(t *testing.T) {
	// Test the parsing logic with sample content
	content := "example.com\nexample.org\n# comment\n\nmydomain.net\n"
	domains := parseLocalDomainsContent(content)

	if !domains["example.com"] {
		t.Error("should contain example.com")
	}
	if !domains["example.org"] {
		t.Error("should contain example.org")
	}
	if !domains["mydomain.net"] {
		t.Error("should contain mydomain.net")
	}
	if domains["# comment"] {
		t.Error("should not contain comment line")
	}
}

func TestIsKnownForwarder(t *testing.T) {
	knownForwarders := []string{
		"info@example.com: admin@gmail.com",
		"*@test.org: backup@external.io",
	}

	tests := []struct {
		localPart string
		domain    string
		dest      string
		known     bool
	}{
		{"info", "example.com", "admin@gmail.com", true},
		{"*", "test.org", "backup@external.io", true},
		{"info", "example.com", "other@gmail.com", false},
		{"user", "example.com", "admin@gmail.com", false},
	}

	for _, tt := range tests {
		got := isKnownForwarder(tt.localPart, tt.domain, tt.dest, knownForwarders)
		if got != tt.known {
			t.Errorf("isKnownForwarder(%q, %q, %q) = %v, want %v",
				tt.localPart, tt.domain, tt.dest, got, tt.known)
		}
	}
}
