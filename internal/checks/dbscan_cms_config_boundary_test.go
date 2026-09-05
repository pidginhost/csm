package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

func TestCMSConfigRejectsSymlinksAndOversize(t *testing.T) {
	withMockOS(t, realOS{})
	for _, tc := range []struct {
		name, body string
		parse      func(string) (string, error)
	}{
		{"joomla", canonicalJConfigBody("jos_"), func(path string) (string, error) {
			creds, err := parseJConfig(context.Background(), path)
			return creds.dbName, err
		}},
		{"drupal", canonicalDrupalSettings(), func(path string) (string, error) {
			creds, err := parseDrupalSettings(context.Background(), path)
			return creds.dbName, err
		}},
		{"magento1", canonicalM1XML(), func(path string) (string, error) {
			creds, err := parseMagentoM1(context.Background(), path)
			return creds.dbName, err
		}},
		{"magento2", canonicalM2EnvPHP(), func(path string) (string, error) {
			creds, err := parseMagentoM2(context.Background(), path)
			return creds.dbName, err
		}},
		{"opencart", "<?php\ndefine('DB_DRIVER', 'mysqli');\ndefine('DB_DATABASE', 'shop');\ndefine('DB_USERNAME', 'shop_user');\n", func(path string) (string, error) {
			creds, err := parseOpenCartConfig(context.Background(), path)
			return creds.dbName, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			outside := filepath.Join(t.TempDir(), "foreign-config")
			if err := os.WriteFile(outside, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if name, err := tc.parse(outside); name == "" || err != nil {
				t.Fatal("valid regular configuration was not parsed")
			}
			atLimit := filepath.Join(root, "at-limit")
			if err := os.WriteFile(atLimit, []byte(tc.body+strings.Repeat(" ", maxCMSConfigBytes-len(tc.body))), 0o600); err != nil {
				t.Fatal(err)
			}
			if name, err := tc.parse(atLimit); name == "" || err != nil {
				t.Fatalf("configuration at the byte limit was rejected: %v", err)
			}
			link := filepath.Join(root, "linked-config")
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			if name, err := tc.parse(link); name != "" || err == nil {
				t.Error("symlink exposed another file's credentials")
			}
			oversize := filepath.Join(root, "oversize-config")
			body := tc.body + strings.Repeat(" ", (2<<20)-len(tc.body))
			if err := os.WriteFile(oversize, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if name, err := tc.parse(oversize); name != "" || err == nil {
				t.Error("oversized configuration was accepted")
			}
		})
	}
}

func TestReadCMSConfigRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	withMockOS(t, realOS{})
	fifo := filepath.Join(t.TempDir(), "config.pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/null", t.TempDir()} {
		done := make(chan error, 1)
		go func() {
			_, err := readCMSConfig(context.Background(), path)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, errNonRegularFile) {
				t.Errorf("read %s = %v, want non-regular file error", path, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("configuration read blocked on %s", path)
		}
	}
}

func TestDrupalMarkerRequiresRegularFile(t *testing.T) {
	withMockOS(t, realOS{})
	root := t.TempDir()
	marker := filepath.Join(root, "core", "lib", "Drupal.php")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "foreign-marker")
	if err := os.WriteFile(outside, []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, marker); err != nil {
		t.Fatal(err)
	}
	if matched, err := looksLikeDrupal8Plus(root); matched || !errors.Is(err, errNonRegularFile) {
		t.Fatalf("symlink marker = %t, %v", matched, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if matched, err := looksLikeDrupal8Plus(root); matched || err != nil {
		t.Fatalf("absent marker = %t, %v, want a normal non-Drupal result", matched, err)
	}
}

func TestReadCMSConfigCancellation(t *testing.T) {
	for _, cancelAt := range []string{"before-open", "after-open"} {
		t.Run(cancelAt, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			opened := false
			withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
				opened = true
				cancel()
				return os.Open(name)
			}})
			if cancelAt == "before-open" {
				cancel()
			}
			data, err := readCMSConfig(ctx, path)
			if !errors.Is(err, context.Canceled) || data != nil {
				t.Fatalf("canceled read returned %q, %v", data, err)
			}
			if opened != (cancelAt == "after-open") {
				t.Fatalf("open called = %t for %s", opened, cancelAt)
			}
		})
	}
}

func TestReadCMSConfigKeepsOpenedFileAfterReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	outside := filepath.Join(t.TempDir(), "foreign-config")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
		file, err := (realOS{}).openRegularFile(name, unix.O_NOFOLLOW)
		if err != nil {
			return nil, err
		}
		if err := os.Remove(name); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := os.Symlink(outside, name); err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}})
	data, err := readCMSConfig(context.Background(), path)
	if err != nil || string(data) != "original" {
		t.Fatalf("read after replacement = %q, %v, want original bytes", data, err)
	}
}

func TestCMSConfigFailuresMarkActualOwnerIncomplete(t *testing.T) {
	for _, tc := range []struct {
		owner, path string
		check       CheckFunc
	}{
		{"db_content_joomla", "configuration.php", CheckJoomlaContent},
		{"db_content_drupal", "sites/default/settings.php", CheckDrupalContent},
		{"db_content_magento", "app/etc/env.php", CheckMagentoContent},
		{"db_content_opencart", "config.php", CheckOpenCartContent},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, tc.path)
			openCalls := 0
			withMockOS(t, &mockOS{
				glob: func(pattern string) ([]string, error) {
					if strings.HasSuffix(pattern, tc.path) {
						return []string{path}, nil
					}
					return nil, nil
				},
				stat:  func(string) (os.FileInfo, error) { return os.Stat(root) },
				lstat: func(string) (os.FileInfo, error) { return drupalStatStub{}, nil },
				open:  func(string) (*os.File, error) { openCalls++; return nil, os.ErrPermission },
			})
			previous := runMySQLQuery
			runMySQLQuery = func(wpDBCreds, string) []string {
				t.Fatal("query issued after configuration read failure")
				return nil
			}
			t.Cleanup(func() { runMySQLQuery = previous })
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			if findings := tc.check(ctx, &config.Config{}, nil); len(findings) != 0 {
				t.Fatalf("unreadable config returned findings: %+v", findings)
			}
			if openCalls != 1 {
				t.Fatalf("configuration opens = %d, want one failed read", openCalls)
			}
			if !coverage.contains(tc.owner) || coverage.contains("db_content") {
				t.Fatal("configuration failure was not attributed to its CMS owner")
			}
		})
	}
}

func TestMagentoRecheckDoesNotFallBackAfterUnsafeConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"missing-current-config", os.ErrNotExist, true},
		{"unsafe-current-config", errNonRegularFile, false},
		{"unreadable-current-config", os.ErrPermission, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy := filepath.Join(t.TempDir(), "local.xml")
			if err := os.WriteFile(legacy, []byte(canonicalM1XML()), 0o600); err != nil {
				t.Fatal(err)
			}
			legacyOpened := false
			withMockOS(t, &mockOS{open: func(path string) (*os.File, error) {
				if filepath.Base(path) == "env.php" {
					return nil, tc.err
				}
				legacyOpened = true
				return os.Open(legacy)
			}})
			schema, _, ok := discoverMagentoSchema("alice")
			if ok != tc.want || legacyOpened != tc.want {
				t.Fatalf("re-check schema=%q ok=%t legacy read=%t, want %t", schema, ok, legacyOpened, tc.want)
			}
			if ok && schema != "magento_db" {
				t.Fatalf("legacy schema = %q, want magento_db", schema)
			}
		})
	}
}

func TestCMSRecheckLeavesUnsafeConfigUnchecked(t *testing.T) {
	for _, tc := range []struct {
		name, details string
		verify        func(string, string) VerifyResult
	}{
		{"joomla", "Account: alice\nArticle ID: 7", verifyJoomlaContentInjection},
		{"drupal", "Account: alice\nNode entity_id: 7", verifyDrupalContentInjection},
		{"magento", "Account: alice\nTable: cms_page\nRow id: 7", verifyMagentoContentInjection},
		{"opencart", "Account: alice\nTable: product_description\nRow id: 7", verifyOpenCartContentInjection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openCalls := 0
			withMockOS(t, &mockOS{
				lstat: func(string) (os.FileInfo, error) { return drupalStatStub{}, nil },
				open: func(string) (*os.File, error) {
					openCalls++
					return nil, errNonRegularFile
				},
			})
			withRootQuery(t, func(string, string, ...any) ([]string, error) {
				t.Fatal("unsafe configuration reached a privileged database query")
				return nil, nil
			})
			result := tc.verify("", tc.details)
			if result.Checked || result.Resolved || openCalls != 1 {
				t.Fatalf("unsafe re-check = %+v after %d opens, want unchecked after one rejected read", result, openCalls)
			}
		})
	}
}

func TestCMSConfigMarkerRejectsSymlinksAndOversize(t *testing.T) {
	withMockOS(t, realOS{})
	for _, tc := range []struct {
		name, body string
		marker     func(context.Context, string) (bool, error)
	}{
		{"joomla", canonicalJConfigBody("jos_"), looksLikeJoomlaConfig},
		{"opencart", "<?php define('DB_DRIVER', 'mysqli');", configContainsDBDriver},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "config-link")
			if err := os.Symlink(path, link); err != nil {
				t.Fatal(err)
			}
			if matched, err := tc.marker(context.Background(), link); matched || err == nil {
				t.Error("marker probe followed a symlink")
			}
			if err := os.WriteFile(path, []byte(tc.body+strings.Repeat(" ", 2<<20)), 0o600); err != nil {
				t.Fatal(err)
			}
			if matched, err := tc.marker(context.Background(), path); matched || err == nil {
				t.Error("marker probe accepted oversized input")
			}
		})
	}
}
