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
