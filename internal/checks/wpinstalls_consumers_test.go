package checks

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// These three checks globbed public_html only, so an addon-domain or nested
// install was never scanned for injected database objects, shared admin email
// or reused administrator password hashes.
func TestReadOnlyDetectors_SeeNestedAndAddonInstalls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		configs func(ctx context.Context) []string
	}{
		{"db_objects", dbObjectWPConfigs},
		{"admin_overlap", adminOverlapWPConfigs},
		{"credential_reuse", credentialReuseWPConfigs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := osFS
			osFS = &mockOSGlobRoots{files: []string{
				"/home/alice/public_html/wp-config.php",
				"/home/alice/public_html/blog/wp-config.php",
				"/home/alice/shop.example.com/wp-config.php",
			}}
			t.Cleanup(func() { osFS = old })

			if got := tc.configs(context.Background()); len(got) != 3 {
				t.Errorf("configs = %v, want all three installs", got)
			}
		})
	}
}

func TestDatabaseConsumersMarkUnreadableDiscoveredConfigIncomplete(t *testing.T) {
	const wpConfig = "/home/alice/public_html/wp-config.php"
	for _, tc := range []struct {
		name string
		fn   func(context.Context)
	}{
		{"db_objects", func(ctx context.Context) { CheckDatabaseObjects(ctx, nil, nil) }},
		{"admin_overlap", func(ctx context.Context) { CheckAdminEmailOverlap(ctx, nil, nil) }},
		{"credential_reuse", func(ctx context.Context) { CheckCredentialReuse(ctx, nil, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := osFS
			osFS = &mockOS{
				glob: func(pattern string) ([]string, error) {
					if pattern == "/home/*/public_html/wp-config.php" {
						return []string{wpConfig}, nil
					}
					return nil, nil
				},
				lstat: func(name string) (os.FileInfo, error) {
					switch name {
					case "/home/alice/public_html":
						return accountScanFakeInfo{name: "public_html", mode: os.ModeDir | 0o755, isDir: true}, nil
					case wpConfig:
						return fakeFileInfo{name: "wp-config.php"}, nil
					default:
						return nil, os.ErrNotExist
					}
				},
				open: func(string) (*os.File, error) { return nil, os.ErrPermission },
			}
			t.Cleanup(func() { osFS = old })

			if tc.name == "admin_overlap" {
				setupPluginStore(t)
			}
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			tc.fn(ctx)
			if !incomplete.contains(tc.name) {
				t.Fatalf("unreadable config did not mark %s incomplete", tc.name)
			}
		})
	}
}

func TestDatabaseConsumersMarkRootQueryFailureIncomplete(t *testing.T) {
	const wpConfig = "/home/alice/public_html/wp-config.php"
	fixture := t.TempDir() + "/wp-config.php"
	if err := os.WriteFile(fixture, []byte("<?php\n"+
		"define('DB_NAME', 'alice_wp');\n"+
		"define('DB_USER', 'alice_wp');\n"+
		"$table_prefix = 'wp_';\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		fn   func(context.Context)
	}{
		{"db_objects", func(ctx context.Context) { CheckDatabaseObjects(ctx, nil, nil) }},
		{"admin_overlap", func(ctx context.Context) { CheckAdminEmailOverlap(ctx, nil, nil) }},
		{"credential_reuse", func(ctx context.Context) { CheckCredentialReuse(ctx, nil, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMockOS(t, &mockOS{
				glob: func(pattern string) ([]string, error) {
					if pattern == "/home/*/public_html/wp-config.php" {
						return []string{wpConfig}, nil
					}
					return nil, nil
				},
				lstat: func(name string) (os.FileInfo, error) {
					return mockPathInfo(name, []string{wpConfig})
				},
				open: func(name string) (*os.File, error) {
					if name == wpConfig {
						return os.Open(fixture)
					}
					return nil, os.ErrNotExist
				},
			})
			mysqlclient.SetRootQueryForTest(func(context.Context, string, string, ...any) ([]string, error) {
				return nil, errors.New("database unavailable")
			})
			t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
			if tc.name == "admin_overlap" {
				setupPluginStore(t)
			}

			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			tc.fn(ctx)
			if !incomplete.contains(tc.name) {
				t.Fatalf("root query failure did not mark %s incomplete", tc.name)
			}
		})
	}
}
