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
		"# keep this operator comment\n" +
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
	if !strings.Contains(cleaned, "# keep this operator comment") {
		t.Errorf("unrelated comment before the cloak block was destroyed:\n%s", cleaned)
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

	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 2 {
		t.Fatalf("two crawler conds should each emit a ua_cloak finding, got %d",
			countByCheck(findings, "htaccess_user_agent_cloak"))
	}
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

func TestUACloakCleanPairsAcrossCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteEngine On\n" +
		"# keep this operator comment\n" +
		"RewriteCond %{HTTP_REFERER} bad.example [NC]\n" +
		"# attacker condition note\n" +
		"RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]\n" +
		"\n" +
		"# attacker rule note\n" +
		"RewriteRule ^(.*)$ http://evil.example/commented/$1 [L,R=302]\n" +
		"Header set X-Keep yes\n"
	path := writeHtaccess(t, dir, "site", body)

	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 1 {
		t.Fatalf("commented UA cloak block should emit one finding, got %d",
			countByCheck(findings, "htaccess_user_agent_cloak"))
	}
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	for _, gone := range []string{"RewriteCond", "RewriteRule", "bad.example", "evil.example/commented"} {
		if strings.Contains(cleaned, gone) {
			t.Errorf("cloak content %q survived clean:\n%s", gone, cleaned)
		}
	}
	for _, want := range []string{"RewriteEngine On", "# keep this operator comment", "Header set X-Keep yes"} {
		if !strings.Contains(cleaned, want) {
			t.Errorf("unrelated content %q was removed:\n%s", want, cleaned)
		}
	}
}

func TestUACloakDoesNotPairAcrossUnrelatedDirective(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteEngine On\n" +
		"RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]\n" +
		"Header set X-Keep yes\n" +
		"RewriteRule ^(.*)$ http://evil.example/unrelated/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)

	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Fatalf("UA cond separated from RewriteRule by Header directive should not pair, got %d",
			countByCheck(findings, "htaccess_user_agent_cloak"))
	}
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	for _, want := range []string{"RewriteCond", "Header set X-Keep yes", "RewriteRule", "evil.example/unrelated"} {
		if !strings.Contains(cleaned, want) {
			t.Errorf("unrelated content %q was removed:\n%s", want, cleaned)
		}
	}
}

func TestUACloakCleanRemovesMultipleBlocksIndependently(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteEngine On\n" +
		"RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]\n" +
		"RewriteRule ^a$ http://evil.example/one [L,R=302]\n" +
		"Header set X-Keep yes\n" +
		"RewriteCond %{HTTP_USER_AGENT} Bingbot [NC]\n" +
		"RewriteRule ^b$ http://evil.example/two [L,R=302]\n" +
		"# footer\n"
	path := writeHtaccess(t, dir, "site", body)

	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 2 {
		t.Fatalf("two independent cloak blocks should emit two findings, got %d",
			countByCheck(findings, "htaccess_user_agent_cloak"))
	}
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	for _, gone := range []string{"evil.example/one", "evil.example/two", "RewriteCond", "RewriteRule"} {
		if strings.Contains(cleaned, gone) {
			t.Errorf("cloak content %q survived clean:\n%s", gone, cleaned)
		}
	}
	for _, want := range []string{"RewriteEngine On", "Header set X-Keep yes", "# footer"} {
		if !strings.Contains(cleaned, want) {
			t.Errorf("unrelated content %q was removed:\n%s", want, cleaned)
		}
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
