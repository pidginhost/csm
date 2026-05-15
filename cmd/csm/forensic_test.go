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

func TestDiscoverForensicTargetsFindsNestedWordPressRoots(t *testing.T) {
	root := t.TempDir()
	configs := map[string]string{
		"public_html/wp-config.php":                  "define('DB_NAME', 'alice_main');\n$table_prefix = 'wp_';\n",
		"public_html/agroshop.ro/wp-config.php":      "define('DB_NAME', 'alice_nested');\n$table_prefix = 'shop_';\n",
		"public_html/agroshop.ro/copy/wp-config.php": "define('DB_NAME', 'alice_nested');\n$table_prefix = 'other_';\n",
		"mail/private/wp-config.php":                 "define('DB_NAME', 'leaked_mail');\n$table_prefix = 'mail_';\n",
		".cagefs/private/wp-config.php":              "define('DB_NAME', 'leaked_cagefs');\n$table_prefix = 'cage_';\n",
	}
	for rel, body := range configs {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	targets := discoverForensicTargetsInRoot(root)
	got := map[string]string{}
	for _, target := range targets {
		got[target.Schema] = target.TablePrefix
	}
	if got["alice_main"] != "wp_" {
		t.Fatalf("main install missing from targets: %v", targets)
	}
	if got["alice_nested"] != "shop_" {
		t.Fatalf("nested install missing from targets: %v", targets)
	}
	for _, skipped := range []string{"leaked_mail", "leaked_cagefs"} {
		if _, ok := got[skipped]; ok {
			t.Fatalf("private schema %q should be skipped; targets=%v", skipped, targets)
		}
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 unique public schemas: %v", len(targets), targets)
	}
}

func TestForensicSchemaValidatorAllowsAtSignOnlyForSchema(t *testing.T) {
	if !forensicSchemaValid("wowlabro_0r1ent@l") {
		t.Fatal("schema names with @ should be valid")
	}
	if forensicTablePrefixValid("bad@prefix_") {
		t.Fatal("table prefixes with @ must stay invalid because they are interpolated into SQL identifiers")
	}
	for _, bad := range []string{"../escape", "bad/name", "bad`name", "bad name"} {
		if forensicSchemaValid(bad) {
			t.Fatalf("unsafe schema %q should be invalid", bad)
		}
	}
}
