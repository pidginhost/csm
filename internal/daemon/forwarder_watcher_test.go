package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseValiasFileForFindings(t *testing.T) {
	// Create a temporary valiases file
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	content := `info: admin@gmail.com
support: user@example.com
deploy: |/usr/bin/deploy.sh
blackhole: /dev/null
*: catchall@external.io
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{
		"example.com": true,
	}
	knownForwarders := []string{}

	findings := parseValiasFileForFindings(path, "example.com", localDomains, knownForwarders)

	// Should detect:
	// 1. info -> admin@gmail.com (external)
	// 2. deploy -> |/usr/bin/deploy.sh (pipe) - CRITICAL
	// 3. blackhole -> /dev/null
	// 4. * -> catchall@external.io (wildcard external)
	// Should NOT detect:
	// support -> user@example.com (local)

	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.Check, f.Message)
		}
	}

	// Verify pipe forwarder is CRITICAL
	hasCriticalPipe := false
	for _, f := range findings {
		if f.Check == "email_pipe_forwarder" {
			hasCriticalPipe = true
		}
	}
	if !hasCriticalPipe {
		t.Error("expected a CRITICAL pipe forwarder finding")
	}
}

func TestParseValiasFileForFindings_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{"example.com": true}
	findings := parseValiasFileForFindings(path, "example.com", localDomains, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestParseValiasFileForFindings_Suppressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	content := `info: admin@gmail.com
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	localDomains := map[string]bool{"example.com": true}
	knownForwarders := []string{"info@example.com: admin@gmail.com"}

	findings := parseValiasFileForFindings(path, "example.com", localDomains, knownForwarders)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (suppressed), got %d", len(findings))
	}
}
