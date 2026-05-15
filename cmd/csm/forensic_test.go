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
		"public_html/.htaccess":               "public dotfile",
		"public_html/index.php":               "public",
		"public_html/mailchimp.php":           "public name containing mail",
		"public_html/mail/index.php":          "public mail path",
		"store.example/wp-content/cache.php":  "addon document root",
		".cagefs/tmp/cache":                   "private cagefs",
		".cpanel/email_accounts.json":         "private cpanel metadata",
		".lastlogin":                          "private top-level dotfile",
		"etc/example.test/shadow":             "private account metadata",
		"homedir/alice/public_html/index.php": "private migration backup",
		"logs/example.test-May-2026.gz":       "private access logs",
		"lscache/0/0/1/cache-entry":           "private cache",
		"mail/cur/msg":                        "private mail",
		"ssl/certs/example.test.crt":          "private ssl metadata",
		"tmp/session":                         "private temp",
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
	if !strings.Contains(text, "public_html/.htaccess") {
		t.Fatalf("public .htaccess should remain:\n%s", text)
	}
	if !strings.Contains(text, "store.example/wp-content/cache.php") {
		t.Fatalf("addon document root file should remain:\n%s", text)
	}
	for _, private := range []string{
		"mail/cur/msg",
		".cagefs/tmp/cache",
		".cpanel/email_accounts.json",
		".lastlogin",
		"etc/example.test/shadow",
		"homedir/alice/public_html/index.php",
		"logs/example.test-May-2026.gz",
		"lscache/0/0/1/cache-entry",
		"ssl/certs/example.test.crt",
		"tmp/session",
	} {
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

	targets, audit := discoverForensicTargetsInRootWithAudit(root)
	got := map[string]string{}
	paths := map[string]string{}
	for _, target := range targets {
		got[target.Schema] = target.TablePrefix
		paths[target.Schema] = target.ConfigPath
	}
	if got["alice_main"] != "wp_" {
		t.Fatalf("main install missing from targets: %v", targets)
	}
	if got["alice_nested"] != "shop_" {
		t.Fatalf("nested install missing from targets: %v", targets)
	}
	if paths["alice_nested"] != filepath.Join(root, "public_html/agroshop.ro/wp-config.php") {
		t.Fatalf("nested install config path = %q", paths["alice_nested"])
	}
	for _, skipped := range []string{"leaked_mail", "leaked_cagefs"} {
		if _, ok := got[skipped]; ok {
			t.Fatalf("private schema %q should be skipped; targets=%v", skipped, targets)
		}
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 unique public schemas: %v", len(targets), targets)
	}
	if !audit.PrivatePathsExcluded {
		t.Fatal("audit should record private path exclusion policy")
	}
	if audit.AccountRoot != root {
		t.Fatalf("audit root = %q, want %q", audit.AccountRoot, root)
	}
	reasons := map[string]string{}
	for _, skipped := range audit.SkippedPaths {
		reasons[filepath.Base(skipped.Path)] = skipped.Reason
	}
	if reasons["mail"] != "private-account-path" {
		t.Fatalf("mail root skip missing from audit: %+v", audit.SkippedPaths)
	}
	if reasons[".cagefs"] != "private-account-path" {
		t.Fatalf(".cagefs root skip missing from audit: %+v", audit.SkippedPaths)
	}
	if reasons["wp-config.php"] != "duplicate-schema" {
		t.Fatalf("duplicate wp-config skip missing from audit: %+v", audit.SkippedPaths)
	}
}

func TestDiscoverForensicTargetsAuditsInvalidConfigs(t *testing.T) {
	root := t.TempDir()
	configs := map[string]string{
		"missing-db/wp-config.php":     "define('AUTH_KEY', 'x');\n$table_prefix = 'wp_';\n",
		"bad-schema/wp-config.php":     "define('DB_NAME', '../escape');\n$table_prefix = 'wp_';\n",
		"bad-prefix/wp-config.php":     "define('DB_NAME', 'alice_prefix');\n$table_prefix = 'bad@prefix_';\n",
		"default-prefix/wp-config.php": "define('DB_NAME', 'alice_default');\n",
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

	targets, audit := discoverForensicTargetsInRootWithAudit(root)
	if len(targets) != 1 {
		t.Fatalf("got targets %v, want one valid default-prefix target", targets)
	}
	if targets[0].Schema != "alice_default" || targets[0].TablePrefix != "wp_" {
		t.Fatalf("default prefix target = %+v", targets[0])
	}
	reasons := map[string]string{}
	for _, skipped := range audit.SkippedPaths {
		reasons[filepath.Base(filepath.Dir(skipped.Path))] = skipped.Reason
	}
	for dir, want := range map[string]string{
		"missing-db": "missing-db-name",
		"bad-schema": "invalid-schema",
		"bad-prefix": "invalid-table-prefix",
	} {
		if reasons[dir] != want {
			t.Fatalf("skip reason for %s = %q, want %q; audit=%+v", dir, reasons[dir], want, audit.SkippedPaths)
		}
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
