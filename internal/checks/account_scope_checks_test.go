package checks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestCheckDatabaseContentAccountScopeIgnoresOtherAccounts(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/alice/public_html/wp-config.php":
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			case "/home/*/public_html/wp-config.php":
				return []string{"/home/bob/public_html/wp-config.php"}, nil
			default:
				return nil, nil
			}
		},
		open: func(name string) (*os.File, error) {
			switch name {
			case "/home/alice/public_html/wp-config.php":
				return tempWPConfig(t, "wp_alice", "alice_wp")
			case "/home/bob/public_html/wp-config.php":
				return tempWPConfig(t, "wp_bob", "bob_wp")
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(_ string, args []string, _ ...string) ([]byte, error) {
			user := mysqlArg(args, "-u")
			query := mysqlArg(args, "-e")
			if user == "bob_wp" && strings.Contains(query, "siteurl") && strings.Contains(query, "admin_email") {
				return []byte("siteurl\t<script src='https://evil.example/p.js'></script>\n"), nil
			}
			return nil, nil
		},
	})

	findings := CheckDatabaseContent(ctx, &config.Config{}, nil)
	if len(findings) != 0 {
		t.Fatalf("scoped alice DB scan returned other-account findings: %+v", findings)
	}
}

func TestCheckWPCoreAccountScopeIgnoresOtherAccounts(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/alice/public_html/wp-config.php":
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			case "/home/*/public_html/wp-config.php":
				return []string{"/home/bob/public_html/wp-config.php"}, nil
			default:
				return nil, nil
			}
		},
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			pathArg := ""
			for _, arg := range args {
				if strings.HasPrefix(arg, "--path=") {
					pathArg = strings.TrimPrefix(arg, "--path=")
					break
				}
			}
			if strings.Contains(pathArg, "/home/bob/") {
				return []byte("evil.php should not exist\n"), errors.New("verify failed")
			}
			return nil, nil
		},
	})

	findings := CheckWPCore(ctx, &config.Config{}, nil)
	if len(findings) != 0 {
		t.Fatalf("scoped alice WP core scan returned other-account findings: %+v", findings)
	}
}

func TestCheckFilesystemAccountScopeDoesNotLetOtherAccountsConsumeCap(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	now := time.Now()
	aliceBackdoor := "/home/alice/.config/htop/defunct"
	bobBackdoor := "/home/bob/.config/htop/defunct"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/alice/.config/htop/*":
				return []string{aliceBackdoor}, nil
			case "/home/alice/.config/*/*":
				return nil, nil
			case "/home/*/.config/htop/*":
				return []string{bobBackdoor, aliceBackdoor}, nil
			case "/tmp/.*":
				return []string{"/tmp/.global-backdoor"}, nil
			default:
				return nil, nil
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice":
				return accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}, nil
			case aliceBackdoor:
				return accountScanFakeInfo{name: "defunct", mtime: now.Add(-time.Hour)}, nil
			case bobBackdoor:
				return accountScanFakeInfo{name: "defunct", mtime: now}, nil
			case "/tmp/.global-backdoor":
				return accountScanFakeInfo{name: ".global-backdoor", mtime: now}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	findings := CheckFilesystem(ctx, cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 scoped finding: %+v", len(findings), findings)
	}
	if findings[0].FilePath != aliceBackdoor {
		t.Fatalf("FilePath = %q, want %q", findings[0].FilePath, aliceBackdoor)
	}
}

func TestBuildFileIndexAccountScopeSkipsGlobalTmpDirs(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/tmp" {
				return []os.DirEntry{
					realDirEntry{name: "shell.phtml", info: accountScanFakeInfo{name: "shell.phtml"}},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	entries := buildFileIndex(ctx, dirMtimeCache{}, nil, true)
	for _, entry := range entries {
		if strings.HasPrefix(entry, "/tmp/") {
			t.Fatalf("scoped file index included global tmp entry %q in %v", entry, entries)
		}
	}
}

func TestCheckOpenBasedirAccountScopeIgnoresOtherUsers(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/cpanel/users" {
				return []os.DirEntry{
					realDirEntry{name: "alice", info: accountScanFakeInfo{name: "alice", isDir: false}},
					realDirEntry{name: "bob", info: accountScanFakeInfo{name: "bob", isDir: false}},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/cpanel/users/alice" {
				return accountScanFakeInfo{name: "alice"}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		glob: func(string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckOpenBasedir(ctx, &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want one scoped finding: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "alice") || strings.Contains(findings[0].Message, "bob") {
		t.Fatalf("unexpected open_basedir finding: %+v", findings[0])
	}
}

func TestCheckNulledPluginsAccountScopeUsesScopedHome(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "alice")
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{
					realDirEntry{name: "bob", info: accountScanFakeInfo{name: "bob", isDir: true, mode: os.ModeDir | 0755}},
				}, nil
			case "/home/alice/public_html/wp-content/plugins":
				return []os.DirEntry{
					realDirEntry{name: "paid-plugin", info: accountScanFakeInfo{name: "paid-plugin", isDir: true, mode: os.ModeDir | 0755}},
				}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/alice/public_html/wp-content/plugins/paid-plugin/*.php" {
				return []string{"/home/alice/public_html/wp-content/plugins/paid-plugin/plugin.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if name == "/home/alice/public_html/wp-content/plugins/paid-plugin/plugin.php" {
				tmp, err := os.CreateTemp(t.TempDir(), "plugin*.php")
				if err != nil {
					return nil, err
				}
				if _, err := tmp.WriteString("<?php // nulled by example\n"); err != nil {
					_ = tmp.Close()
					return nil, err
				}
				if _, err := tmp.Seek(0, 0); err != nil {
					_ = tmp.Close()
					return nil, err
				}
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckNulledPlugins(ctx, &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want one scoped finding: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "alice/paid-plugin") {
		t.Fatalf("unexpected nulled plugin finding: %+v", findings[0])
	}
}

func tempWPConfig(t *testing.T, dbName, dbUser string) (*os.File, error) {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "wpconfig*.php")
	if err != nil {
		return nil, err
	}
	body := "<?php\n" +
		"define( 'DB_NAME', '" + dbName + "' );\n" +
		"define( 'DB_USER', '" + dbUser + "' );\n" +
		"define( 'DB_PASSWORD', 'secret' );\n" +
		"$table_prefix = 'wp_';\n"
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	return tmp, nil
}

func mysqlArg(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
