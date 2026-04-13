package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckOutdatedPlugins with WP install + outdated plugin ----------

func TestCheckOutdatedPluginsWithWP(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "wp-config.php", isDir: false},
					testDirEntry{name: "wp-content", isDir: true},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return fakeFileInfo{name: "wp-config.php", size: 500}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "wp" {
				return []byte(`[{"name":"elementor","status":"active","version":"3.0.0","update_version":"3.18.0"}]`), nil
			}
			return nil, nil
		},
	})

	_ = CheckOutdatedPlugins(context.Background(), &config.Config{}, nil)
}

// --- InlineQuarantine with real file that gets quarantined -----------

func TestInlineQuarantineWithRealData(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/evil.php"
	data := []byte("<?php system('id'); ?>")
	_ = os.WriteFile(path, data, 0644)

	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	f := alert.Finding{Check: "webshell", FilePath: path}
	msg, ok := InlineQuarantine(f, path, data)
	_ = msg
	_ = ok
}

// --- collectRecentIPs with multiple log sources ----------------------

func TestCollectRecentIPsMultipleSources(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte("203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200\n"), nil
			}
			if strings.Contains(name, "secure") || strings.Contains(name, "auth.log") {
				return []byte("Apr 12 10:00:00 host sshd: Failed password for root from 198.51.100.1 port 22\n"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "log", size: 200}, nil
		},
		open: func(name string) (*os.File, error) {
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	_ = ips
}

// --- CheckAPITokens with token directory data ------------------------

func TestCheckAPITokensWithTokenDir(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "api_tokens") && !strings.Contains(pattern, "/*/") {
				return []string{"/home/alice/.cpanel/api_tokens"}, nil
			}
			return nil, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "api_tokens") {
				return []os.DirEntry{
					testDirEntry{name: "token_admin", isDir: false},
					testDirEntry{name: "token_backup", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckAPITokens(context.Background(), &config.Config{}, store)
}

// --- CheckWPTransientBloat with home data ----------------------------

func TestCheckWPTransientBloatWithData(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','wp');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\ndefine('DB_HOST','localhost');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp := t.TempDir() + "/wp-config.php"
				_ = os.WriteFile(tmp, []byte(wpConfig), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("100000000\n"), nil // 100MB of transients
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckWPTransientBloat(context.Background(), &config.Config{}, store)
}
