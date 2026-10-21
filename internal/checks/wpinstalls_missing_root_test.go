package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

func TestWPInstalls_MappedRootAbsence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(*testing.T, string, *mockOS)
		incomplete bool
	}{
		{name: "missing_directory"},
		{
			name: "missing_ancestor",
			setup: func(t *testing.T, root string, _ *mockOS) {
				if err := os.Remove(filepath.Dir(root)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "dangling_alias_within_account",
			setup: func(t *testing.T, root string, _ *mockOS) {
				wpDiscoverySymlink(t, "deleted", root)
			},
		},
		{
			name: "missing_config",
			setup: func(t *testing.T, root string, _ *mockOS) {
				if err := os.Mkdir(root, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "readlink_races_removal",
			setup: func(t *testing.T, root string, m *mockOS) {
				wpDiscoverySymlink(t, "deleted", root)
				m.readlink = func(name string) (string, error) {
					return "", &os.PathError{Op: "readlink", Path: name, Err: syscall.ENOENT}
				}
			},
			incomplete: true,
		},
		{
			name: "readlink_races_live_replacement",
			setup: func(t *testing.T, root string, m *mockOS) {
				wpDiscoveryConfig(t, root)
				m.lstat = func(name string) (os.FileInfo, error) {
					if name == root {
						return accountScanFakeInfo{name: "mapped", mode: os.ModeSymlink}, nil
					}
					return os.Lstat(name)
				}
				m.readlink = func(name string) (string, error) {
					return "", &os.PathError{Op: "readlink", Path: name, Err: syscall.ENOENT}
				}
			},
			incomplete: true,
		},
		{
			name: "permission_denied",
			setup: func(_ *testing.T, root string, m *mockOS) {
				m.lstat = func(name string) (os.FileInfo, error) {
					if name == root {
						return nil, &os.PathError{Op: "lstat", Path: name, Err: os.ErrPermission}
					}
					return os.Lstat(name)
				}
			},
			incomplete: true,
		},
		{
			name: "readlink_permission_denied",
			setup: func(t *testing.T, root string, m *mockOS) {
				wpDiscoverySymlink(t, "deleted", root)
				m.readlink = func(name string) (string, error) {
					return "", &os.PathError{Op: "readlink", Path: name, Err: os.ErrPermission}
				}
			},
			incomplete: true,
		},
		{
			name: "not_a_directory_error",
			setup: func(_ *testing.T, root string, m *mockOS) {
				m.lstat = func(name string) (os.FileInfo, error) {
					if name == root {
						return nil, &os.PathError{Op: "lstat", Path: name, Err: syscall.ENOTDIR}
					}
					return os.Lstat(name)
				}
			},
			incomplete: true,
		},
		{
			name: "regular_file",
			setup: func(t *testing.T, root string, _ *mockOS) {
				if err := os.WriteFile(root, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			incomplete: true,
		},
		{
			name: "escaping_alias_to_missing_target",
			setup: func(t *testing.T, root string, _ *mockOS) {
				wpDiscoverySymlink(t, "../../bob/deleted", root)
			},
			incomplete: true,
		},
		{
			name: "symlink_loop",
			setup: func(t *testing.T, root string, _ *mockOS) {
				wpDiscoverySymlink(t, "mapped", root)
			},
			incomplete: true,
		},
		{
			name: "normalized_target_missing_but_install_exists",
			setup: func(t *testing.T, root string, _ *mockOS) {
				parent := filepath.Dir(root)
				wpDiscoveryConfig(t, filepath.Join(parent, "real", "live"))
				if err := os.Mkdir(filepath.Join(parent, "real", "child"), 0o755); err != nil {
					t.Fatal(err)
				}
				wpDiscoverySymlink(t, "real/child", filepath.Join(parent, "alias"))
				wpDiscoverySymlink(t, "alias/../live", root)
				if _, err := os.Lstat(filepath.Join(root, "wp-config.php")); err != nil {
					t.Fatalf("mapped alias must reach the existing install: %v", err)
				}
			},
			incomplete: true,
		},
		{
			name: "missing_component_but_config_uninspectable",
			setup: func(_ *testing.T, root string, m *mockOS) {
				m.lstat = func(name string) (os.FileInfo, error) {
					if name == filepath.Join(root, "wp-config.php") {
						return nil, &os.PathError{Op: "lstat", Path: name, Err: os.ErrPermission}
					}
					return os.Lstat(name)
				}
			},
			incomplete: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "home")
			withAccountHomeRoots(t, base)
			live := filepath.Join(base, "alice", "public_html")
			root := filepath.Join(base, "alice", "sites", "mapped")
			wpDiscoveryConfig(t, live)
			if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
				t.Fatal(err)
			}
			m := &mockOS{
				stat: os.Stat, lstat: os.Lstat, readlink: os.Readlink, glob: filepath.Glob,
				readFile: func(name string) ([]byte, error) {
					if name == userdataDomainsPath {
						return []byte("live.example: alice==alice==main==live.example==" + live + "\n" +
							"mapped.example: alice==alice==sub==live.example==" + root + "\n"), nil
					}
					return nil, os.ErrNotExist
				},
			}
			if tc.setup != nil {
				tc.setup(t, root, m)
			}
			withMockOS(t, m)

			ctx, gaps := withIncompleteCheckCollector(context.Background())
			ctx = withWPInstallCache(ctx)
			for _, check := range []string{"db_objects", "wp_core"} {
				got := wpInstalls(ctx, check)
				want := []wpInstall{{ConfigPath: filepath.Join(live, "wp-config.php"), DocRoot: live, Account: "alice", Served: servedByPanel}}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s installs = %+v, want %+v", check, got, want)
				}
				if gaps.contains(check) != tc.incomplete {
					t.Errorf("%s incomplete = %v, want %v", check, gaps.contains(check), tc.incomplete)
				}
			}

			db := setupPluginStore(t)
			if err := db.SetSitePlugins(root, store.SitePlugins{Domain: "mapped.example"}); err != nil {
				t.Fatal(err)
			}
			withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				switch {
				case strings.Contains(command, "plugin list"):
					return []byte("[]"), nil
				case strings.Contains(command, "option get siteurl"):
					return []byte("https://live.example\n"), nil
				default:
					t.Errorf("unexpected command: %s", command)
					return nil, os.ErrInvalid
				}
			}})
			refreshPluginCache(ctx, db)
			cached := db.AllSitePlugins()
			if _, found := cached[root]; found != tc.incomplete {
				t.Errorf("mapped site retained = %v, want %v", found, tc.incomplete)
			}
			if _, found := cached[live]; !found {
				t.Error("live site inventory was not saved")
			}
			if db.GetPluginRefreshTime().IsZero() != tc.incomplete {
				t.Errorf("refresh timestamp unset = %v, want %v", db.GetPluginRefreshTime().IsZero(), tc.incomplete)
			}
			for _, check := range []string{"outdated_plugins", "vulnerable_plugins"} {
				if gaps.contains(check) != tc.incomplete {
					t.Errorf("%s incomplete = %v, want %v", check, gaps.contains(check), tc.incomplete)
				}
			}

			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			prior := []alert.Finding{{Check: "wp_core_integrity", Message: "existing core finding", FilePath: filepath.Join(root, "index.php")}}
			st.SetLatestFindings(prior)
			parent, coverage := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(parent, &config.Config{}, st, []namedCheck{{
				name: "wp_core",
				fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					wpInstalls(ctx, "wp_core")
					return nil
				},
			}}, "test", true)
			StoreLatestScanFindingsWithGaps(st, purge, findings, coverage.Paths())
			if got := st.LatestFindings(); tc.incomplete {
				if !reflect.DeepEqual(got, prior) {
					t.Errorf("incomplete discovery changed prior findings: %+v", got)
				}
			} else if len(got) != 0 {
				t.Errorf("complete discovery retained stale findings: %+v", got)
			}
		})
	}
}

func wpDiscoveryConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func wpDiscoverySymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
