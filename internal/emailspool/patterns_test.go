package emailspool

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMailerClasses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mailer_classes.yaml"), `
version: 1
suspicious: [PHPMailer, mass mailer]
safe: [WordPress, cPanel]
`)
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if !pol.MailerSuspicious("PHPMailer 7.0.0") {
		t.Errorf("PHPMailer should be suspicious")
	}
	if pol.MailerSafe("PHPMailer 7.0.0") {
		t.Errorf("PHPMailer should NOT be safe")
	}
	if !pol.MailerSafe("WordPress 6.4") {
		t.Errorf("WordPress should be safe")
	}
}

func TestMailerClassification_OrderedAndCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mailer_classes.yaml"), `
version: 1
suspicious: [PHPMailer]
safe: [WordPress]
`)
	pol, _ := LoadPolicies(dir)
	if !pol.MailerSuspicious("phpmailer 5.0") {
		t.Error("case-insensitive substring match required")
	}
}

func TestLoadHTTPProxyRanges(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), `
version: 1
cidrs:
  - 192.0.2.0/24
  - 2001:db8::/32
`)
	pol, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if !pol.IsProxyIP("192.0.2.10") {
		t.Errorf("192.0.2.10 should be in proxy range")
	}
	if pol.IsProxyIP("203.0.113.5") {
		t.Errorf("203.0.113.5 should NOT be in proxy range")
	}
	if !pol.IsProxyIP("2001:db8::1") {
		t.Errorf("v6 in proxy range expected")
	}
}

func TestLoadHTTPProxyRanges_InvalidCIDR(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http_proxy_ranges.yaml"), `
version: 1
cidrs:
  - not-a-cidr
  - 192.0.2.0/24
`)
	pol, err := LoadPolicies(dir)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !pol.IsProxyIP("192.0.2.10") {
		t.Error("valid CIDR should still be loaded despite invalid sibling")
	}
}
