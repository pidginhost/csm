package checks

import (
	"encoding/json"
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

// Regression: the htaccess cleaner used to write a key=value
// .meta sidecar that no consumer in the pipeline parsed,
// rendering pre_clean entries invisible in the existing
// /api/v1/quarantine listing. Switching to the JSON
// QuarantineMeta shape lets the existing webui handlers pick
// them up. This test asserts the format on disk.
func TestCleanHtaccessFileMetaIsValidQuarantineJSON(t *testing.T) {
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

	res := CleanHtaccessFile(path)
	if !res.Success {
		t.Fatalf("Clean: %v", res.Error)
	}

	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("backup dir: %v", err)
	}
	var metaPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			metaPath = filepath.Join(htaccessBackupDirRoot, e.Name())
			break
		}
	}
	if metaPath == "" {
		t.Fatal(".meta file not produced")
	}
	raw, err := os.ReadFile(metaPath) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta QuarantineMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("meta is not valid JSON QuarantineMeta: %v\nbody=%s", err, raw)
	}
	if meta.OriginalPath == "" {
		t.Errorf("OriginalPath empty in %+v", meta)
	}
	if meta.QuarantineAt.IsZero() {
		t.Errorf("QuarantineAt zero in %+v", meta)
	}
	if !strings.Contains(meta.Reason, "htaccess") {
		t.Errorf("Reason should mention htaccess, got %q", meta.Reason)
	}
}

// 2026-04-28 production FPs: htaccess_filesmatch_shield fired on stock
// plugin .htaccess files that grant execution to a specific PHP file
// (or a small allowlist of named files). Stock plugins ship these to
// allow their own dispatcher under hosts where directory-level Require
// all denied is the default.
//
// The malicious shape is a bare \.php$ wildcard dropped into a
// directory where PHP should not run. The legitimate shape names a
// specific filename or short allowlist.

func TestDetectorFilesMatchShield_WebPExpressSpecificFilename(t *testing.T) {
	dir := t.TempDir()
	body := `<FilesMatch "wpc\.php$">
  <IfModule !mod_authz_core.c>
    Order deny,allow
    Allow from all
  </IfModule>
  <IfModule mod_authz_core.c>
    Require all granted
  </IfModule>
</FilesMatch>
`
	path := writeHtaccess(t, dir, "wp-content/plugins/webp-express/web-service", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 0 {
		t.Errorf("filesmatch_shield FP: matched WebP Express specific-filename allowlist")
	}
}

func TestDetectorFilesMatchShield_WebPExpressNamedAllowlist(t *testing.T) {
	dir := t.TempDir()
	body := `<FilesMatch "(webp-on-demand\.php|webp-realizer\.php|ping\.php|ping\.txt)$">
  <IfModule mod_authz_core.c>
    Require all granted
  </IfModule>
</FilesMatch>
`
	path := writeHtaccess(t, dir, "wp-content/plugins/webp-express/wod", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 0 {
		t.Errorf("filesmatch_shield FP: matched WebP Express named-file allowlist")
	}
}

func TestDetectorFilesMatchShield_PrestaShopFacetedSearchPrefix(t *testing.T) {
	dir := t.TempDir()
	body := `<FilesMatch "ps_facetedsearch-.+\.php$">
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Allow from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
</FilesMatch>
`
	path := writeHtaccess(t, dir, "modules/ps_facetedsearch", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 0 {
		t.Errorf("filesmatch_shield FP: matched PrestaShop ps_facetedsearch prefix-pattern allowlist")
	}
}

func TestDetectorFilesMatchShield_KCFinderWildcardWithSiblingPHP(t *testing.T) {
	// KCFinder ships a bare \.php$ wildcard in its own plugin directory
	// that contains many legitimate PHP dispatchers (browse.php,
	// upload.php, index.php, js_localize.php, etc.). The bare wildcard
	// matches the malicious shape exactly, so the discriminator is
	// "the directory contains multiple sibling PHP files that this
	// FilesMatch grants access to" - i.e., the shield protects an
	// existing legitimate PHP layout, not a freshly-dropped dropper.
	dir := t.TempDir()
	pluginDir := "admin/plugins/CKEditorPlugin/kcfinder"
	full := filepath.Join(dir, pluginDir)
	if err := os.MkdirAll(full, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"browse.php", "upload.php", "index.php", "js_localize.php"} {
		if err := os.WriteFile(filepath.Join(full, name), []byte("<?php // legit\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	body := `<FilesMatch "\.php$">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Allow from all
        Satisfy All
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
</FilesMatch>
`
	path := writeHtaccess(t, dir, pluginDir, body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 0 {
		t.Errorf("filesmatch_shield FP: matched KCFinder bare-wildcard shield in a directory with %d sibling PHP files", 4)
	}
}

func TestDetectorFilesMatchShield_WildcardInEmptyUploadsDir(t *testing.T) {
	// The malicious shape: bare \.php$ wildcard dropped into a directory
	// without any legitimate PHP dispatchers. An attacker who can write
	// the .htaccess but only one (or zero) PHP files alongside it. The
	// shield must keep firing on this shape.
	dir := t.TempDir()
	body := `<FilesMatch "\.php$">
    Order allow,deny
    Allow from all
</FilesMatch>
`
	path := writeHtaccess(t, dir, "wp-content/uploads/2026/04", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 1 {
		t.Errorf("filesmatch_shield regression: bare-wildcard shield in empty uploads dir was not detected (count=%d)", countByCheck(findings, "htaccess_filesmatch_shield"))
	}
}

func TestDetectorFilesMatchShield_WildcardInDirWithSingleAttackerDropper(t *testing.T) {
	// Edge case: attacker drops .htaccess + one webshell.php. The
	// wildcard shield + a single sibling PHP must keep firing. The
	// discriminator threshold is "multiple sibling PHP files"; a single
	// file alongside a fresh shield is the canonical drop pattern.
	dir := t.TempDir()
	full := filepath.Join(dir, "wp-content/uploads/2026")
	if err := os.MkdirAll(full, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "x.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	body := `<FilesMatch "\.php$">
    Require all granted
</FilesMatch>
`
	path := writeHtaccess(t, dir, "wp-content/uploads/2026", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_filesmatch_shield") != 1 {
		t.Errorf("filesmatch_shield regression: wildcard shield + single dropper was not detected (count=%d)", countByCheck(findings, "htaccess_filesmatch_shield"))
	}
}

// 2026-04-28 production FPs: htaccess_user_agent_cloak fired on three
// distinct legitimate shapes. The detector emitted High alerts on
// every one of them for ~30 production sites, burying real signal
// under cache-plugin and bot-blocklist noise.
//
// Discriminators added:
//   1. Negated UA cond ("RewriteCond %{HTTP_USER_AGENT} !..."): the
//      rule applies WHEN the UA is NOT one of these names - i.e.,
//      excluding crawlers from a cache-serving rule. The cloaking
//      shape is the inverse (apply when UA IS this).
//   2. Long alternation (4+ entries): operator-installed bot
//      blocklists ship a long OR-list of audit/scraper UAs, paired
//      with a [F]-forbid or sinkhole rewrite. Cloakers use one or
//      two crawler names.
//   3. Paired RewriteRule: when the next RewriteRule after the cond
//      block has [F] / [F,L] / [G] flags or a "-" substitution, the
//      cond is part of a defensive block, not a cloak.

func TestDetectorUserAgentCloak_NegatedCacheExclusion(t *testing.T) {
	// WP Fastest Cache pattern: negative match excludes social
	// crawlers from the cached-content rewrite so they always get
	// fresh OG meta tags.
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} !(facebookexternalhit|WP_FASTEST_CACHE_CSS_VALIDATOR|Twitterbot|LinkedInBot|WhatsApp|Mediatoolkitbot)
RewriteRule ^(.*) "/wp-content/cache/all/$1/index.html" [L]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched negative-UA cache exclusion (count=%d)", countByCheck(findings, "htaccess_user_agent_cloak"))
	}
}

func TestDetectorUserAgentCloak_NegatedShortList(t *testing.T) {
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} !(Mediatoolkitbot|facebookexternalhit|SpeedyCacheCCSS)
RewriteRule ^(.*) "/wp-content/cache/all/$1/index.html" [L]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched 3-item negative-UA list")
	}
}

func TestDetectorUserAgentCloak_NegatedAnchoredRegex(t *testing.T) {
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} !^(facebookexternalhit|WhatsApp).* [NC]
RewriteRule ^(.*) "/cache/$1.html" [L]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched negative-UA anchored regex")
	}
}

func TestDetectorUserAgentCloak_LongBotBlocklist(t *testing.T) {
	// Operator-installed defensive blocklist: 20+ scraper / audit
	// tool UAs OR'd together, paired with a sinkhole rewrite.
	dir := t.TempDir()
	body := `RewriteEngine on
RewriteCond %{HTTP_USER_AGENT} (?:virusbot|spambot|evilbot|acunetix|BLEXBot|domaincrawler\.com|LinkpadBot|MJ12bot/v|majestic12\.co\.uk|AhrefsBot|TwengaBot|SemrushBot|nikto|winhttp|Xenu\s+Link\s+Sleuth|Baiduspider|HTTrack|clshttp|harvest|extract|grab|miner|python-requests) [NC]
RewriteRule ^(.*)$ http://no.access/
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched 20+ entry defensive blocklist (count=%d)", countByCheck(findings, "htaccess_user_agent_cloak"))
	}
}

func TestDetectorUserAgentCloak_PairedForbidRule(t *testing.T) {
	// Single crawler UA paired with [F] forbid: a defensive block
	// targeting a specific abusive crawler. The malicious shape
	// rewrites somewhere; the defensive shape forbids.
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} AhrefsBot [NC]
RewriteRule ^(.*)$ - [F,L]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched UA cond paired with [F,L] forbid rule")
	}
}

func TestDetectorUserAgentCloak_PairedNoOpDash(t *testing.T) {
	// Single crawler UA paired with "-" substitution: a no-op (used
	// to set environment variables or pass through to the next
	// directive without rewriting).
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} Googlebot [NC]
RewriteRule .* - [E=cache_skip:1]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 0 {
		t.Errorf("ua_cloak FP: matched UA cond paired with no-op '-' substitution")
	}
}

func TestDetectorUserAgentCloak_RealCloakRedirect(t *testing.T) {
	// The malicious shape: positive crawler match paired with a
	// rewrite to a different file (serving SEO-clean content to
	// search bots while humans get spam). Must keep firing.
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot) [NC]
RewriteRule ^(.*)$ http://spam.example.xyz/$1 [L,R=302]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 1 {
		t.Errorf("ua_cloak regression: spam-redirect cloak missed (count=%d)", countByCheck(findings, "htaccess_user_agent_cloak"))
	}
}

func TestDetectorUserAgentCloak_RealCloakSeoFile(t *testing.T) {
	// Cloak that serves a clean dispatcher file to crawlers.
	dir := t.TempDir()
	body := `RewriteCond %{HTTP_USER_AGENT} googlebot [NC]
RewriteRule ^(.*)$ /seo-clean.php?orig=$1 [L]
`
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_user_agent_cloak") != 1 {
		t.Errorf("ua_cloak regression: clean-dispatcher cloak missed (count=%d)", countByCheck(findings, "htaccess_user_agent_cloak"))
	}
}

// 2026-04-28 production FP: htaccess_errordocument_hijack fired on a
// same-brand redirect ("ErrorDocument 404 https://floresgrup.ro" from
// /home/flores/public_html/.htaccess). Custom 404 redirects to the
// site's own homepage are extremely common and not malicious; the
// detector previously flagged any external-URL ErrorDocument target
// regardless of host.
//
// The malicious shape: redirect to a different domain (typically on
// a spam TLD or an unrelated common TLD), often paired with a
// hardcoded phishing page path.
//
// Discriminator: extract the URL host's "registrable label" (the part
// before the public TLD), compare against the .htaccess path
// components. If the label appears in the path (account name or
// domain dir), treat as same-brand and skip. Spam TLD targets always
// fire regardless of name match.

func TestDetectorErrorDocumentHijack_SameBrandSubstring(t *testing.T) {
	dir := t.TempDir()
	body := "ErrorDocument 404 https://floresgrup.ro\n"
	full := filepath.Join(dir, "home", "flores", "public_html", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _ := AuditHtaccessFile(full)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 0 {
		t.Errorf("errordocument_hijack FP: matched same-brand redirect (account 'flores' substring of 'floresgrup.ro')")
	}
}

func TestDetectorErrorDocumentHijack_SameBrandWithSubdomain(t *testing.T) {
	dir := t.TempDir()
	body := "ErrorDocument 404 https://www.example-shop.com/404\n"
	full := filepath.Join(dir, "home", "shop", "example-shop.com", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _ := AuditHtaccessFile(full)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 0 {
		t.Errorf("errordocument_hijack FP: matched same-brand redirect (domain dir 'example-shop.com' contains URL host)")
	}
}

func TestDetectorErrorDocumentHijack_DifferentBrandNonSpamTLD(t *testing.T) {
	// A redirect to an unrelated .com domain - could be legit (host
	// outsourcing 404s to a marketing site) or malicious (phishing
	// hijack). We err on the side of detection: fire the alert,
	// operator can suppress per-path if it is intentional.
	dir := t.TempDir()
	body := "ErrorDocument 404 https://attacker.com/landing\n"
	full := filepath.Join(dir, "home", "victim", "public_html", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _ := AuditHtaccessFile(full)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 1 {
		t.Errorf("errordocument_hijack regression: cross-brand redirect missed (count=%d)", countByCheck(findings, "htaccess_errordocument_hijack"))
	}
}

func TestDetectorErrorDocumentHijack_SpamTLDAlwaysFires(t *testing.T) {
	// Spam TLDs always fire even if the brand somehow matches: the
	// TLD itself is the signal of compromise.
	dir := t.TempDir()
	body := "ErrorDocument 404 https://floresgrup.tk/landing\n"
	full := filepath.Join(dir, "home", "flores", "public_html", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _ := AuditHtaccessFile(full)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 1 {
		t.Errorf("errordocument_hijack regression: spam-TLD target missed even with same-brand label")
	}
}

func TestDetectorErrorDocumentHijack_IPAddressTarget(t *testing.T) {
	// Numeric IP target is suspicious by definition - legit ErrorDocument
	// redirects use a hostname.
	dir := t.TempDir()
	body := "ErrorDocument 404 http://192.0.2.42/dropper\n"
	full := filepath.Join(dir, "home", "victim", "public_html", ".htaccess")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _ := AuditHtaccessFile(full)
	if countByCheck(findings, "htaccess_errordocument_hijack") != 1 {
		t.Errorf("errordocument_hijack regression: IP-address target missed")
	}
}
