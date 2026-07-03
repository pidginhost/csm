package checks

import (
	"strings"
	"testing"
)

// CHK-P01: a single-argument `SetHandler application/x-httpd-php` (no
// extension list) in an uploads/.htaccess maps EVERY file in the directory
// to the PHP interpreter, so an uploaded image runs as PHP. It is strictly
// worse than the two-argument `AddHandler ... .jpg` form, yet the detector
// regex used to demand a second argument and missed it entirely.

func TestDetectorPHPInUploadsFlagsSingleArgSetHandler(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "wp-content/uploads", "SetHandler application/x-httpd-php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 1 {
		t.Errorf("single-arg SetHandler in uploads: php_in_uploads matches = %d, want 1",
			countByCheck(findings, "htaccess_php_in_uploads"))
	}
}

func TestDetectorPHPInUploadsFlagsSingleArgForceType(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "uploads", "ForceType application/x-httpd-php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 1 {
		t.Errorf("single-arg ForceType in uploads: php_in_uploads matches = %d, want 1",
			countByCheck(findings, "htaccess_php_in_uploads"))
	}
}

func TestDetectorPHPInUploadsFlagsSingleArgProxyFPMSetHandler(t *testing.T) {
	// php-fpm proxy handler set directory-wide (no extension scoping) still
	// executes every uploaded file as PHP.
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "images",
		"SetHandler \"proxy:unix:/run/php-fpm/site.sock|fcgi://localhost\"\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 1 {
		t.Errorf("single-arg php-fpm SetHandler in images: php_in_uploads matches = %d, want 1",
			countByCheck(findings, "htaccess_php_in_uploads"))
	}
}

func TestDetectorPHPInUploadsIgnoresSingleArgSetHandlerOutsideNonScriptDirs(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "public_html", "SetHandler application/x-httpd-php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 0 {
		t.Errorf("legitimate PHP directory SetHandler should not flag (got %d)",
			countByCheck(findings, "htaccess_php_in_uploads"))
	}
}

// The single-arg SetHandler is worst-case: cleaning must remove the directive
// so no file in the directory keeps executing as PHP.
func TestDetectorPHPInUploadsSingleArgRemovable(t *testing.T) {
	dir := t.TempDir()
	body := "# uploads guard\nSetHandler application/x-httpd-php\n"
	path := writeHtaccess(t, dir, "wp-content/uploads", body)
	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 1 {
		t.Fatalf("php_in_uploads matches = %d, want 1", countByCheck(findings, "htaccess_php_in_uploads"))
	}
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	if strings.Contains(cleaned, "SetHandler") {
		t.Fatalf("SetHandler survived cleaning:\n%s", cleaned)
	}
}

// Regression guard: AddHandler with no extension list is an Apache no-op (it
// maps nothing), so it must NOT be treated as a directory-wide remap.
func TestDetectorPHPInUploadsIgnoresAddHandlerWithoutExtension(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "uploads", "AddHandler application/x-httpd-php\n")
	findings, _ := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_php_in_uploads") != 0 {
		t.Errorf("AddHandler with no extension is a no-op and must not flag (got %d)",
			countByCheck(findings, "htaccess_php_in_uploads"))
	}
}
