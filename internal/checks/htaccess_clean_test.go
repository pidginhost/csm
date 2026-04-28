package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func writeHtaccess(t *testing.T, dir, sub, content string) string {
	t.Helper()
	full := filepath.Join(dir, sub, ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return full
}

func countByCheck(findings []alert.Finding, name string) int {
	n := 0
	for _, f := range findings {
		if f.Check == name {
			n++
		}
	}
	return n
}

// --- Detector unit tests --------------------------------------------------

func TestDetectorPHPInUploadsFiresInUploadsDir(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "uploads", "AddHandler application/x-httpd-php .jpg\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 1 {
		t.Errorf("php_in_uploads matches = %d, want 1", countByCheck(findings, "htaccess_php_in_uploads"))
	}
}

func TestDetectorPHPInUploadsSkipsDocumentRoot(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "public_html", "AddHandler application/x-httpd-php .jpg\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 0 {
		t.Errorf("php_in_uploads fired in public_html (should only fire under uploads/cache/etc.)")
	}
}

func TestDetectorAutoPrependFlagsTmpTarget(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "php_value auto_prepend_file /tmp/.cache.php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_auto_prepend") != 1 {
		t.Errorf("auto_prepend matches = %d, want 1", countByCheck(findings, "htaccess_auto_prepend"))
	}
}

func TestDetectorAutoPrependFlagsImageExtensionTarget(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "php_value auto_prepend_file /var/www/html/header.png\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_auto_prepend") != 1 {
		t.Errorf("auto_prepend (image ext) matches = %d, want 1", countByCheck(findings, "htaccess_auto_prepend"))
	}
}

func TestDetectorAutoPrependIgnoresLegitimatePath(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "php_value auto_prepend_file /etc/csm-prelude.php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_auto_prepend") != 0 {
		t.Error("auto_prepend matched a legitimate-looking path")
	}
}

func TestDetectorUserAgentCloakFlagsGooglebot(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot) [NC]\n" +
		"RewriteRule ^(.*)$ http://spam.example.xyz/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 1 {
		t.Errorf("ua_cloak matches = %d, want 1", countByCheck(findings, "htaccess_user_agent_cloak"))
	}
}

func TestDetectorUserAgentCloakIgnoresArbitraryUA(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteCond %{HTTP_USER_AGENT} ^MyOwnApp [NC]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Error("ua_cloak matched a non-crawler UA")
	}
}

func TestDetectorSpamRedirectFlagsSpamTLD(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteRule ^(.*)$ https://attacker.tk/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_spam_redirect") != 1 {
		t.Errorf("spam_redirect matches = %d, want 1", countByCheck(findings, "htaccess_spam_redirect"))
	}
}

func TestDetectorSpamRedirectIgnoresLegitTLD(t *testing.T) {
	dir := t.TempDir()
	body := "RewriteRule ^(.*)$ https://example.com/$1 [L,R=302]\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_spam_redirect") != 0 {
		t.Error("spam_redirect matched a legitimate .com target")
	}
}

func TestDetectorFilesMatchShieldFiresOnAllowAll(t *testing.T) {
	dir := t.TempDir()
	body := "<FilesMatch \"\\.php$\">\n  Require all granted\n  Allow from all\n</FilesMatch>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 1 {
		t.Errorf("filesmatch_shield matches = %d, want 1", countByCheck(findings, "htaccess_filesmatch_shield"))
	}
}

func TestDetectorFilesMatchShieldIgnoresDenyBlock(t *testing.T) {
	dir := t.TempDir()
	body := "<FilesMatch \"\\.php$\">\n  Require all denied\n</FilesMatch>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 0 {
		t.Error("filesmatch_shield matched a deny block (which is a security measure, not malicious)")
	}
}

func TestDetectorHeaderInjectionFlagsTrackingHeader(t *testing.T) {
	dir := t.TempDir()
	body := "Header set X-Track-ID \"abc123\"\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_header_injection") != 1 {
		t.Errorf("header_injection matches = %d, want 1", countByCheck(findings, "htaccess_header_injection"))
	}
}

func TestDetectorHeaderInjectionIgnoresSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	body := "Header set Content-Security-Policy \"default-src 'self'\"\n" +
		"Header set Strict-Transport-Security \"max-age=31536000\"\n" +
		"Header set X-Frame-Options \"SAMEORIGIN\"\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_header_injection") != 0 {
		t.Errorf("header_injection matched legitimate security headers")
	}
}

func TestDetectorErrorDocumentHijackFlagsExternalURL(t *testing.T) {
	dir := t.TempDir()
	body := "ErrorDocument 404 https://phish.example.tk/landing.html\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 1 {
		t.Errorf("errordocument_hijack matches = %d, want 1", countByCheck(findings, "htaccess_errordocument_hijack"))
	}
}

func TestDetectorErrorDocumentHijackIgnoresLocalPath(t *testing.T) {
	dir := t.TempDir()
	body := "ErrorDocument 404 /errors/404.html\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 0 {
		t.Error("errordocument_hijack matched a local-path target")
	}
}

// --- Range manipulation ---------------------------------------------------

func TestMergeRangesSortsAndCollapsesAdjacent(t *testing.T) {
	in := []htaccessByteRange{
		{Start: 30, End: 50},
		{Start: 5, End: 20},
		{Start: 18, End: 25},
		{Start: 60, End: 70},
	}
	got := mergeRanges(in)
	want := []htaccessByteRange{
		{Start: 5, End: 25},
		{Start: 30, End: 50},
		{Start: 60, End: 70},
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestApplyRangeRemovalCollapsesNewlines(t *testing.T) {
	content := []byte("keep1\nremove\nkeep2\n")
	got := applyRangeRemoval(content, []htaccessByteRange{{Start: 6, End: 12}})
	want := "keep1\nkeep2\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- Cleaning round trip --------------------------------------------------

func TestCleanHtaccessFileRemovesAndBacksUp(t *testing.T) {
	prevRoots := fixHtaccessAllowedRoots
	prevBackup := htaccessBackupDirRoot
	defer func() {
		fixHtaccessAllowedRoots = prevRoots
		htaccessBackupDirRoot = prevBackup
	}()
	dir := t.TempDir()
	// macOS /var/folders is a symlink to /private/var/folders; the
	// remediation guard resolves to the real path before checking
	// allowed roots, so the test seam needs to mirror that.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	dir = resolved
	fixHtaccessAllowedRoots = []string{dir}
	htaccessBackupDirRoot = filepath.Join(t.TempDir(), "pre_clean")

	body := "# legit comment\n" +
		"Header set Content-Security-Policy \"default-src 'self'\"\n" +
		"ErrorDocument 404 https://phish.example.tk/oops.html\n" +
		"RewriteRule ^(.*)$ https://attacker.xyz/$1 [L,R=302]\n" +
		"# end\n"
	path := writeHtaccess(t, dir, "site", body)

	res := CleanHtaccessFile(path)
	if !res.Success {
		t.Fatalf("Clean: %v", res.Error)
	}

	cleaned, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	if strings.Contains(string(cleaned), "phish.example.tk") {
		t.Error("phishing ErrorDocument still present after clean")
	}
	if strings.Contains(string(cleaned), "attacker.xyz") {
		t.Error("spam RewriteRule still present after clean")
	}
	if !strings.Contains(string(cleaned), "Content-Security-Policy") {
		t.Error("legitimate header was removed")
	}
	if !strings.Contains(string(cleaned), "# legit comment") {
		t.Error("comment was removed")
	}

	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("backup dir: %v", err)
	}
	hasMeta := false
	hasBackup := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			hasMeta = true
		} else {
			hasBackup = true
		}
	}
	if !hasBackup || !hasMeta {
		t.Errorf("backup dir missing files (backup=%v meta=%v)", hasBackup, hasMeta)
	}
}

func TestCleanHtaccessFileNoOpWhenNothingToClean(t *testing.T) {
	prevRoots := fixHtaccessAllowedRoots
	defer func() { fixHtaccessAllowedRoots = prevRoots }()
	dir := t.TempDir()
	// macOS /var/folders is a symlink to /private/var/folders; the
	// remediation guard resolves to the real path before checking
	// allowed roots, so the test seam needs to mirror that.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	dir = resolved
	fixHtaccessAllowedRoots = []string{dir}

	body := "# clean file\nHeader set X-Frame-Options \"SAMEORIGIN\"\nErrorDocument 404 /errors/404.html\n"
	path := writeHtaccess(t, dir, "site", body)

	res := CleanHtaccessFile(path)
	if res.Success {
		t.Errorf("CleanHtaccessFile reported success on a clean file: %+v", res)
	}
}

func TestAutoCleanHtaccessRunsOnlyWhenFlagSet(t *testing.T) {
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

	body := "ErrorDocument 404 https://attacker.tk/oops.html\n"
	path := writeHtaccess(t, dir, "site", body)

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanHtaccess = false

	findings := []alert.Finding{{
		Severity: alert.High,
		Check:    "htaccess_errordocument_hijack",
		FilePath: path,
	}}
	if got := AutoCleanHtaccess(cfg, findings); len(got) != 0 {
		t.Errorf("AutoCleanHtaccess ran with CleanHtaccess=false: %+v", got)
	}

	cfg.AutoResponse.CleanHtaccess = true
	got := AutoCleanHtaccess(cfg, findings)
	if len(got) != 1 {
		t.Fatalf("AutoCleanHtaccess actions = %d, want 1", len(got))
	}
	if got[0].Check != "auto_response" {
		t.Errorf("action Check = %q, want auto_response", got[0].Check)
	}

	// File should have been mutated.
	cleaned, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	if strings.Contains(string(cleaned), "attacker.tk") {
		t.Error("malicious ErrorDocument still present after AutoCleanHtaccess")
	}
}

func TestAutoCleanHtaccessRespectsAutoResponseDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = false
	cfg.AutoResponse.CleanHtaccess = true
	got := AutoCleanHtaccess(cfg, []alert.Finding{{
		Check:    "htaccess_spam_redirect",
		FilePath: "/some/path/.htaccess",
	}})
	if len(got) != 0 {
		t.Errorf("AutoCleanHtaccess ran with AutoResponse.Enabled=false: %+v", got)
	}
}
