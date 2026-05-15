package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListRecentMtimesSkipsPrivateMailAndCageFSDirs(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	files := map[string]string{
		"public_html/index.php":      "public",
		"public_html/mailchimp.php":  "public name containing mail",
		"public_html/mail/index.php": "public mail path",
		"mail/cur/msg":               "private mail",
		".cagefs/tmp/cache":          "private cagefs",
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		if err := os.Chtimes(path, now, now); err != nil {
			t.Fatalf("chtimes %s: %v", rel, err)
		}
	}

	out, err := listRecentMtimes(root, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("listRecentMtimes: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "public_html/index.php") {
		t.Fatalf("public file missing from output:\n%s", text)
	}
	if !strings.Contains(text, "public_html/mailchimp.php") {
		t.Fatalf("public file with mail in basename should remain:\n%s", text)
	}
	if !strings.Contains(text, "public_html/mail/index.php") {
		t.Fatalf("public mail path under document root should remain:\n%s", text)
	}
	for _, private := range []string{"mail/cur/msg", ".cagefs/tmp/cache"} {
		if strings.Contains(text, private) {
			t.Fatalf("private path %q leaked into output:\n%s", private, text)
		}
	}
}
