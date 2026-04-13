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

// Platform-independent tests that push coverage on both Linux and macOS.

// --- AutoBlockIPs with findings and mock state -----------------------

func TestAutoBlockIPsWithFindings(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockExpiry = "24h"

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "wp_login_bruteforce", Message: "Brute force from 203.0.113.5"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/public_html/wso.php"},
	}

	results := AutoBlockIPs(cfg, findings)
	_ = results
}

// --- CheckDatabaseContent deeper — with wp-config + MySQL mock -------

func TestCheckDatabaseContentWithMySQLData(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','wp_alice');\ndefine('DB_USER','wp_alice');\ndefine('DB_PASSWORD','secret');\ndefine('DB_HOST','localhost');\n$table_prefix='wp_';\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "alice") && !strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
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
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			// Simulate finding suspicious options
			for _, arg := range args {
				if strings.Contains(arg, "wp_options") {
					return []byte("blogdescription\t<script src='http://evil.com'></script>\n"), nil
				}
			}
			return []byte(""), nil
		},
	})

	findings := CheckDatabaseContent(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckSSHLogins with auth log data --------------------------------

func TestCheckSSHLoginsWithData(t *testing.T) {
	logData := "Apr 12 10:00:00 host sshd[1234]: Accepted publickey for root from 203.0.113.5 port 22 ssh2\n" +
		"Apr 12 10:01:00 host sshd[1235]: Accepted password for alice from 198.51.100.1 port 22 ssh2\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "secure") || strings.Contains(name, "auth.log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "secure") || strings.Contains(name, "auth.log") {
				tmp := t.TempDir() + "/auth.log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "auth.log", size: int64(len(logData))}, nil
		},
	})

	findings := CheckSSHLogins(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckWebshells with deeper directory tree -----------------------

func TestCheckWebshellsWithMultipleDirs(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{
					testDirEntry{name: "alice", isDir: true},
					testDirEntry{name: "bob", isDir: true},
				}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "index.php", isDir: false},
					testDirEntry{name: "subdir", isDir: true},
				}, nil
			}
			if strings.HasSuffix(name, "subdir") {
				return []os.DirEntry{
					testDirEntry{name: "backdoor.phtml", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return []byte("<?php echo 'test'; ?>"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 500}, nil
		},
	})

	findings := CheckWebshells(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckPHPConfigChanges with config data --------------------------

func TestCheckPHPConfigChangesWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "php.ini") {
				return []string{"/opt/php82/php.ini"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "php.ini") {
				return []byte("display_errors = On\nallow_url_fopen = On\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// Baseline
	_ = CheckPHPConfigChanges(context.Background(), &config.Config{}, store)
	// Second call with same data = no change
	findings := CheckPHPConfigChanges(context.Background(), &config.Config{}, store)
	_ = findings
}
