package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CHK-P02: cleaning a user-agent cloak used to remove only the RewriteCond
// line and leave the paired RewriteRule behind. A RewriteRule with no
// preceding RewriteCond applies to EVERY request, so the "clean" turned a
// crawler-only cloak into an unconditional redirect of every visitor to the
// attacker URL. The removal range must cover the full cond chain plus its
// paired RewriteRule so the cleaned file redirects nobody.
//
// The redirect target is on a non-spam TLD (evil.example) so that only the
// user_agent_cloak detector - not the spam_redirect detector - is responsible
// for removing the RewriteRule. That isolates the fix under test.

func TestUACloakCleanRemovesPairedRewriteRule(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteEngine On\n" +
		"RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot) [NC]\n" +
		"RewriteRule ^(.*)$ http://evil.example/malware/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)

	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 1 {
		t.Fatalf("ua_cloak matches = %d, want 1", countByCheck(findings, "htaccess_user_agent_cloak"))
	}

	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	if strings.Contains(cleaned, "RewriteRule") {
		t.Errorf("paired RewriteRule survived clean - cleaned file still redirects every visitor:\n%s", cleaned)
	}
	if strings.Contains(cleaned, "evil.example") {
		t.Errorf("attacker redirect target survived clean:\n%s", cleaned)
	}
	if strings.Contains(cleaned, "RewriteCond") {
		t.Errorf("RewriteCond survived clean:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "RewriteEngine On") {
		t.Errorf("unrelated RewriteEngine directive was destroyed:\n%s", cleaned)
	}
}

// A chain of two crawler conds feeding one rule must be removed whole. If only
// the cond lines were removed, the rule would redirect everyone; if only one
// cond were removed, a dangling cond would remain. The whole cond chain plus
// the rule must go.
func TestUACloakCleanRemovesFullCondChain(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteEngine On\n" +
		"RewriteCond %{HTTP_USER_AGENT} Googlebot [OR]\n" +
		"RewriteCond %{HTTP_USER_AGENT} Bingbot [NC]\n" +
		"RewriteRule ^(.*)$ http://evil.example/x/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)

	_, ranges := AuditHtaccessFile(path)
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	if strings.Contains(cleaned, "RewriteRule") || strings.Contains(cleaned, "RewriteCond") {
		t.Errorf("cond chain / rule survived clean:\n%s", cleaned)
	}
	if strings.Contains(cleaned, "evil.example") {
		t.Errorf("attacker target survived clean:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "RewriteEngine On") {
		t.Errorf("unrelated directive destroyed:\n%s", cleaned)
	}
}

// End-to-end through CleanHtaccessFile: the file on disk must not redirect
// anyone after cleaning.
func TestCleanHtaccessFileNeutralizesUACloak(t *testing.T) {
	prevRoots := fixHtaccessAllowedRoots
	prevBackup := htaccessBackupDirRoot
	defer func() {
		fixHtaccessAllowedRoots = prevRoots
		htaccessBackupDirRoot = prevBackup
	}()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	dir = resolved
	fixHtaccessAllowedRoots = []string{dir}
	htaccessBackupDirRoot = filepath.Join(t.TempDir(), "pre_clean")

	body := "RewriteEngine On\n" +
		"RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]\n" +
		"RewriteRule ^(.*)$ http://evil.example/malware/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)

	res := CleanHtaccessFile(path)
	if !res.Success {
		t.Fatalf("Clean failed: %v", res.Error)
	}
	cleaned, err := os.ReadFile(path) // #nosec G304 -- t.TempDir path
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	if strings.Contains(string(cleaned), "RewriteRule") {
		t.Errorf("cleaned .htaccess still carries a RewriteRule that redirects everyone:\n%s", cleaned)
	}
}
