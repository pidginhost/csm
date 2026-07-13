package checks

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression batch for the 2026-07-13 cluster6 phishing false-positive storm.
// The phishing_credential_log, phishing_php, phishing_kit_archive and
// phishing_iframe detectors mislabelled binary media, legit plugin/theme
// source, distribution archives and a shipped iframe demo as attacks. These
// tests pin the corrected behaviour while keeping the genuine-threat cases.

// ---- credential_log: binary media is never a text credential dump ----

func TestCheckCredentialLogBinaryImageNotFlagged(t *testing.T) {
	dir := t.TempDir()
	// Filename carries the "harvest" keyword; the bytes are a PNG-like binary
	// blob with NUL and high bytes plus incidental '@'/':' that the old text
	// scan mis-read as email:password lines.
	path := filepath.Join(dir, "olive-harvest-220x154.jpg")
	blob := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00}
	for i := 0; i < 400; i++ {
		blob = append(blob, 0x00, 0xff, '@', ':', 'x', 0x0a, 0x88, 0x01)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkCredentialLog(path); got != "" {
		t.Errorf("binary image must not flag as credential log, got %q", got)
	}
}

func TestCheckCredentialLogBinaryVideoNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "WEBM-Result-1.webm")
	blob := []byte{0x1a, 0x45, 0xdf, 0xa3, 0x00}
	for i := 0; i < 500; i++ {
		blob = append(blob, 0x00, 'a', '@', 'b', ':', 'c', 0x9c)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkCredentialLog(path); got != "" {
		t.Errorf("binary video must not flag as credential log, got %q", got)
	}
}

// ---- credential_log: source files with a minority of embedded emails ----

func TestCheckCredentialLogSourceScatteredEmailsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.js") // matches the "result" keyword
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("  var node = build(items, index, opts); // step line\n")
	}
	for i := 0; i < 12; i++ {
		b.WriteString("// contributor: dev" + string(rune('a'+i)) + "@example.com\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkCredentialLog(path); got != "" {
		t.Errorf("source file with minority embedded emails must not flag, got %q", got)
	}
}

// ---- credential_log: genuine dumps still flag (recall guard) ----

func TestCheckCredentialLogRealPairsStillFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.txt")
	content := "alice@example.com:Passw0rd\nbob@example.com|s3cret\ncarol@example.com,hunter2\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkCredentialLog(path); !strings.Contains(got, "credential-like lines") {
		t.Errorf("real email:password dump must still flag, got %q", got)
	}
}

// ---- phishing_php: body-brand backend files are not phishing pages ----

func TestAnalyzePHPBackupClassBodyBrandNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wpadm-class-wp.php")
	content := `<?php
class wpadm_dropbox_backup {
  function run() {
    $em = $_POST['email'];
    mail("owner@example.com", "backup", "dropbox backup for $em done");
    file_put_contents("dropbox-result.log", "ok\n", FILE_APPEND);
    return "https://dropbox.com/upload";
  }
}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("dropbox backup class must not flag, got %+v", res)
	}
}

func TestAnalyzePHPPaymentGatewayBodyBrandNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dgx-donate-paypalstd.php")
	content := `<?php // Seamless Donations PayPal Standard gateway
$email = $_POST['email'];
?>
<form action="https://www.paypal.com/cgi-bin/webscr" method="post">
<input type="hidden" name="business" value="x">
<input name="email" value="">
<input type="hidden" name="amount" value="10">
</form>`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("paypal donation gateway must not flag, got %+v", res)
	}
}

func TestAnalyzePHPPluginPasswordFieldBodyBrandNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bt_cost_calculator.php")
	content := `<?php // Plugin Name: Cost Calculator
$email = $_POST['email'];
?>
<html><body>
<form method="post" action="/calc">
<input type="email" name="email">
<input type="password" name="api_secret">
</form>
<p>Pay via paypal.com after calculation.</p>
</body></html>`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("cost calculator plugin must not flag, got %+v", res)
	}
}

func TestAnalyzePHPAjaxHandlerBodyBrandNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "td_ajax.php")
	content := `<?php
class td_ajax {
  function subscribe() {
    $em = $_POST['email'];
    // share to dropbox
    mail("list@example.com", "sub", $em);
  }
}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if res := analyzePHPForPhishing(path); res != nil {
		t.Errorf("ajax handler must not flag, got %+v", res)
	}
}

// ---- phishing_iframe: a documented demo embed is not a redirect wrapper ----

func TestCheckIframePhishingDocumentedEmbedNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iframe-example.html")
	content := `<p>A quick example of using iframes to embed another site (e.g. your Nagios, or some other app?). <a href="http://www.w3schools.com/tags/tag_iframe.asp">IFRAME docs</a></p>
<iframe width='100%' height='100%' frameborder="0" src="http://www.cacti.net/"></iframe>`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkIframePhishing(path); got != "" {
		t.Errorf("documented demo embed must not flag, got %q", got)
	}
}

// ---- phishing_kit_archive: content-shape, not filename, decides ----

func writeKitTestZip(t *testing.T, path string, names []string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		// Store (no compression) with padding so the archive clears the
		// scanner's >1000-byte size gate in integration tests.
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, 500)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestZipLooksLikeKitLegitPluginFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Instagram-Feed-4.3.1.zip")
	writeKitTestZip(t, path, []string{
		"insta-gallery-pro/insta-gallery-pro.php",
		"insta-gallery-pro/readme.txt",
		"insta-gallery-pro/build/backend/css/style.css",
		"insta-gallery-pro/includes/class-instagram.php",
	})
	if zipLooksLikeKit(path) {
		t.Error("legit instagram plugin zip must not look like a kit")
	}
}

func TestZipLooksLikeKitRealKitTrue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "office365.zip")
	writeKitTestZip(t, path, []string{
		"office365/login.html",
		"office365/next.php",
		"office365/results.txt",
	})
	if !zipLooksLikeKit(path) {
		t.Error("real office365 kit zip must be detected")
	}
}
