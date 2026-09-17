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
			return mockPathInfo(name, []string{wpConfig})
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

// The rogue-admin re-check carried its own copy of the old discovery, so a
// nested install's administrator finding could never be resolved either.
func TestFindWPAdminVerifyPrefixes_LocatesNestedInstall(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = nestedInstallFS(t, wpConfig, nestedWPConfigBody)
	t.Cleanup(func() { osFS = old })

	prefixes, ok := findWPAdminVerifyPrefixes("alice", "alice_blog", "")
	if !ok || len(prefixes) == 0 {
		t.Fatalf("nested install not locatable: prefixes=%v ok=%v", prefixes, ok)
	}
}

// The spam cleaner acts on the installs it discovers; spam in a nested install
// was left in place.
func TestSpamCleanWPConfigs_IncludesNestedInstall(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = nestedInstallFS(t, wpConfig, nestedWPConfigBody)
	t.Cleanup(func() { osFS = old })

	got := spamCleanWPConfigs("alice")
	if len(got) != 1 || got[0] != wpConfig {
		t.Errorf("spam-clean configs = %v, want the nested install", got)
	}
}

func TestFindCredsForAccountPrefersPrimaryInstall(t *testing.T) {
	const (
		primary = "/home/alice/public_html/wp-config.php"
		addon   = "/home/alice/aaa.example/wp-config.php"
	)
	files := map[string]string{}
	for path, dbName := range map[string]string{primary: "alice_main", addon: "alice_addon"} {
		fixture := filepath.Join(t.TempDir(), filepath.Base(filepath.Dir(path))+"-wp-config.php")
		body := "<?php\ndefine('DB_NAME', '" + dbName + "');\n$table_prefix = 'wp_';\n"
		if err := os.WriteFile(fixture, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files[path] = fixture
	}

	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte("aaa.example: alice==alice==addon==aaa.example==/home/alice/aaa.example\n" +
					"main.example: alice==alice==main==main.example==/home/alice/public_html\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/alice/public_html/wp-config.php":
				return []string{primary}, nil
			case "/home/alice/*/wp-config.php":
				return []string{addon, primary}, nil
			default:
				return nil, nil
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", mode: os.ModeDir | 0o755, isDir: true}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			if _, ok := files[name]; ok {
				return fakeFileInfo{name: "wp-config.php"}, nil
			}
			for path := range files {
				if name == filepath.Dir(path) {
					return accountScanFakeInfo{name: filepath.Base(name), mode: os.ModeDir | 0o755, isDir: true}, nil
				}
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			fixture, ok := files[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return os.Open(fixture)
		},
	}
	t.Cleanup(func() { osFS = old })

	creds, _ := findCredsForAccount("alice")
	if creds.dbName != "alice_main" {
		t.Fatalf("selected database = %q, want primary install alice_main", creds.dbName)
	}
}

func TestFindCredsForAccountPrefersCanonicalPrimaryInstall(t *testing.T) {
	const (
		primaryAlias  = "/home/alice/public_html/wp-config.php"
		primaryConfig = "/home/alice/sites/main/wp-config.php"
		addon         = "/home/alice/aaa.example/wp-config.php"
	)
	files := map[string]string{}
	for path, dbName := range map[string]string{primaryConfig: "alice_main", addon: "alice_addon"} {
		fixture := filepath.Join(t.TempDir(), dbName+"-wp-config.php")
		body := "<?php\ndefine('DB_NAME', '" + dbName + "');\n$table_prefix = 'wp_';\n"
		if err := os.WriteFile(fixture, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		files[path] = fixture
	}

	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte("aaa.example: alice==alice==addon==aaa.example==/home/alice/aaa.example\n" +
					"main.example: alice==alice==main==main.example==/home/alice/public_html\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/alice/public_html/wp-config.php":
				return []string{primaryAlias}, nil
			case "/home/alice/*/wp-config.php":
				return []string{addon, primaryAlias}, nil
			default:
				return nil, nil
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", mode: os.ModeDir | 0o755, isDir: true}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/public_html":
				return accountScanFakeInfo{name: "public_html", mode: os.ModeSymlink | 0o777}, nil
			case "/home/alice/sites", "/home/alice/sites/main", "/home/alice/aaa.example":
				return accountScanFakeInfo{name: filepath.Base(name), mode: os.ModeDir | 0o755, isDir: true}, nil
			case primaryAlias, primaryConfig, addon:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/public_html" {
				return "sites/main", nil
			}
			return "", os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			fixture, ok := files[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return os.Open(fixture)
		},
	}
	t.Cleanup(func() { osFS = old })

	creds, _ := findCredsForAccount("alice")
	if creds.dbName != "alice_main" {
		t.Fatalf("selected database = %q, want canonical primary install alice_main", creds.dbName)
	}
}
