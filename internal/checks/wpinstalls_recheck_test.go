package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// nestedInstallFS serves one nested WordPress install: the glob shapes the
// discovery walks, plus a real file behind the wp-config path.
func nestedInstallFS(t *testing.T, wpConfig, body string) *mockOS {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatalf("write wp-config fixture: %v", err)
	}
	return &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/*/wp-config.php" ||
				pattern == "/home/alice/public_html/*/wp-config.php" {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			if name != wpConfig {
				return nil, os.ErrNotExist
			}
			return fakeFileInfo{name: "wp-config.php"}, nil
		},
		open: func(name string) (*os.File, error) {
			if name != wpConfig {
				return nil, os.ErrNotExist
			}
			return os.Open(tmp)
		},
	}
}

const nestedWPConfigBody = "<?php\n" +
	"define('DB_NAME', 'alice_blog');\n" +
	"$table_prefix = 'wp_';\n"

// CHKWEB-04: a finding raised on an install nested under public_html could
// never be re-checked. The verifier could not re-locate the install, so the
// finding stayed unresolved for the life of the site.
func TestFindWPVerifyPrefixes_LocatesNestedInstall(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = nestedInstallFS(t, wpConfig, nestedWPConfigBody)
	t.Cleanup(func() { osFS = old })

	prefixes, ok := findWPVerifyPrefixes("alice", "alice_blog", "")
	if !ok || len(prefixes) == 0 {
		t.Fatalf("nested install not locatable: prefixes=%v ok=%v", prefixes, ok)
	}
}

// The same install must be reachable by the fixer and by the schema lister the
// drop CLI validates operator input against.
func TestFixPaths_LocateNestedInstall(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = nestedInstallFS(t, wpConfig, nestedWPConfigBody)
	t.Cleanup(func() { osFS = old })

	if creds, _ := findCredsForAccount("alice"); creds.dbName != "alice_blog" {
		t.Errorf("findCredsForAccount dbName = %q, want alice_blog", creds.dbName)
	}
	if got := findAccountSchemas("alice"); len(got) != 1 || got[0] != "alice_blog" {
		t.Errorf("findAccountSchemas = %v, want [alice_blog]", got)
	}
}

// The automatic responder resolves credentials by database name; a nested
// install's database was invisible to it.
func TestFindCredsForDB_LocatesNestedInstall(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = nestedInstallFS(t, wpConfig, nestedWPConfigBody)
	t.Cleanup(func() { osFS = old })

	if creds := findCredsForDB("alice_blog"); creds.dbName != "alice_blog" {
		t.Errorf("findCredsForDB dbName = %q, want alice_blog", creds.dbName)
	}
}
