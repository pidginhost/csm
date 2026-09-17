package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// expectAttributed asserts every finding in findings resolves to owner and
// returns the set of check names seen, so callers can require coverage.
func expectAttributed(t *testing.T, findings []alert.Finding, owner string) map[string]int {
	t.Helper()
	seen := map[string]int{}
	for _, f := range findings {
		seen[f.Check]++
		if got := extractAccountFromFinding(f); got != owner {
			t.Errorf("%s: attributed to %q, want %q (TenantID=%q FilePath=%q)", f.Check, got, owner, f.TenantID, f.FilePath)
		}
	}
	return seen
}

func requireChecks(t *testing.T, seen map[string]int, want ...string) {
	t.Helper()
	var missing []string
	for _, w := range want {
		if seen[w] == 0 {
			missing = append(missing, w)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("fixture did not produce %v (saw %v); extend the fixture, never drop the name", missing, seen)
	}
}

// Every .htaccess detector emits through AuditHtaccessContent, which sets
// FilePath from the audited path. Synthetic inert detectors under the real
// names exercise that shared boundary for each name; the detectors' own
// matching logic is covered by their existing tests.
func TestHtaccessFindingsAttributeByPath(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	prev := htaccessDetectors
	var synthetic []htaccessDetector
	for _, d := range prev {
		name := d.Name
		synthetic = append(synthetic, htaccessDetector{Name: name, Severity: d.Severity, Detect: func(content []byte, path string) []htaccessMatch {
			return []htaccessMatch{{Excerpt: "# " + name, Retain: true}}
		}})
	}
	htaccessDetectors = synthetic
	t.Cleanup(func() { htaccessDetectors = prev })

	findings, _ := AuditHtaccessContent("/home/alice/public_html/.htaccess", []byte("# benign\n"))
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "htaccess_php_in_uploads", "htaccess_auto_prepend", "htaccess_user_agent_cloak",
		"htaccess_spam_redirect", "htaccess_filesmatch_shield", "htaccess_header_injection",
		"htaccess_errordocument_hijack", "htaccess_cgi_handler_abuse", "htaccess_security_disabled")

	// The legacy web.go audit emits htaccess_injection with the path too; an
	// oversized real file under a temporary account root drives its first
	// branch without any directive fixture.
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	big := filepath.Join(root, "bob", "public_html", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(big), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, make([]byte, htaccessMaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var legacy []alert.Finding
	checkHtaccessFile(big, nil, nil, &legacy)
	requireChecks(t, expectAttributed(t, legacy, "bob"), "htaccess_injection")
}

// The file index classifies new paths and stamps FilePath on every finding.
func TestFileIndexFindingsAttributeByPath(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	// An unreadable body in a sensitive directory fails closed as
	// new_php_in_sensitive_dir; the other names are decided by path or name.
	withMockOS(t, &mockOS{
		stat: mtimesByPath(map[string]time.Time{}),
		readFile: func(path string) ([]byte, error) {
			if strings.Contains(path, "/wp-content/languages/") {
				return nil, os.ErrPermission
			}
			return []byte("<?php echo 'benign';"), nil
		},
	})
	paths := []string{
		"/home/alice/public_html/wp-content/languages/loader.php",
		"/home/alice/.config/htop/run.sh",
		"/home/alice/public_html/c99.php",
		"/home/alice/public_html/x7y2.php",
	}
	findings := checkFileIndexAnalyzeNewFiles(context.Background(), &config.Config{}, paths)
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "new_php_in_sensitive_dir", "new_suspicious_php", "new_webshell_file", "new_executable_in_config")
}

// SUID binaries are reported with their full path under the account home.
func TestFilesystemFindingsAttributeByPath(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	// The scanner deliberately skips public_html; a planted binary in a
	// private directory is the case it exists for.
	bin := filepath.Join(root, "alice", "bin", "escalate")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The setuid bit is the fixture under test; creation masks it, so set it
	// explicitly afterwards.
	if err := os.Chmod(bin, 0o755|os.ModeSetuid); err != nil { // #nosec G302 -- setuid fixture in a private temp dir
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), filepath.Join(root, "alice"), 4, &findings)
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "suid_binary")
	if !reflect.DeepEqual(findingPaths(findings, "suid_binary"), []string{bin}) {
		t.Fatalf("suid paths %v", findingPaths(findings, "suid_binary"))
	}
}
