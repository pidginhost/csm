package checks

import "testing"

// Attacker enables Perl/CGI execution of an uploaded shell by mapping a
// non-standard extension to a CGI handler. Real case 2026-07-23 (ALFA
// webshell): AddHandler cgi-script .alfa + AddType application/x-httpd-cgi .alfa.
func TestDetectorCGIHandlerAbuseFlagsAddHandlerCustomExt(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddHandler cgi-script .alfa\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (AddHandler custom ext) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsAddTypeHttpdCGI(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddType application/x-httpd-cgi .alfa\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (AddType x-httpd-cgi) = %d, want 1", got)
	}
}

// A real cgi-bin maps the conventional CGI extensions (.cgi/.pl); flagging
// those would be a false positive on legitimate Perl scripts.
func TestDetectorCGIHandlerAbuseSkipsConventionalCGIExts(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "cgi-bin", "AddHandler cgi-script .cgi .pl\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse fired on conventional .cgi/.pl mapping = %d, want 0", got)
	}
}

// The cleaner must be able to strip the malicious handler line.
func TestDetectorCGIHandlerAbuseCleans(t *testing.T) {
	dir := t.TempDir()
	body := "keep\nAddHandler cgi-script .alfa\nend\n"
	path := writeHtaccess(t, dir, "site", body)
	_, ranges := AuditHtaccessFile(path)
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	if cleaned != "keep\nend\n" {
		t.Fatalf("cleaned = %q, want \"keep\\nend\\n\"", cleaned)
	}
}

// Attacker disables the WAF from a per-account .htaccess to hide the
// intrusion. Real case 2026-07-23: an obfuscated `Sec------Engine Off`
// inside <IfModule mod_security.c>.
func TestDetectorSecurityDisabledFlagsStandardDirective(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "<IfModule mod_security.c>\nSecFilterEngine Off\n</IfModule>\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 1 {
		t.Errorf("security_disabled (SecFilterEngine Off) = %d, want 1", got)
	}
}

func TestDetectorSecurityDisabledFlagsObfuscatedVariant(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "Sec------Engine Off\nSec------ScanPOST Off\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got < 1 {
		t.Errorf("security_disabled did not match obfuscated Sec------Engine Off (got %d)", got)
	}
}

// Turning the engine ON is a hardening action, not tampering.
func TestDetectorSecurityDisabledSkipsEngineOn(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "SecRuleEngine On\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 0 {
		t.Errorf("security_disabled fired on SecRuleEngine On = %d, want 0", got)
	}
}
