package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckSSHKeys with authorized_keys data --------------------------

func TestCheckSSHKeysWithKeys(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, ".ssh/authorized_keys") {
				return []string{"/home/alice/.ssh/authorized_keys"}, nil
			}
			if strings.Contains(pattern, "root") {
				return []string{"/root/.ssh/authorized_keys"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "authorized_keys") {
				return []byte("ssh-rsa AAAAB3NzaC1 alice@laptop\nssh-ed25519 AAAAC3 unknown@attacker\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	_ = CheckSSHKeys(context.Background(), &config.Config{}, store)
}

// --- CheckNulledPlugins with wp-content data -------------------------

func TestCheckNulledPluginsWithPluginDir(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-content", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "wp-content") {
				return []os.DirEntry{testDirEntry{name: "plugins", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "plugins") {
				return []os.DirEntry{testDirEntry{name: "nulled-plugin", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "nulled-plugin") {
				return []os.DirEntry{
					testDirEntry{name: "nulled-plugin.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".php") {
				return []byte("<?php /* nulled by h4x0r */ system($_GET['cmd']); ?>"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	_ = CheckNulledPlugins(context.Background(), &config.Config{}, nil)
}

// --- CheckMailQueue with exim count output ---------------------------

func TestCheckMailQueueWithOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "exim" && len(args) > 0 && args[0] == "-bpc" {
				return []byte("250\n"), nil
			}
			return nil, nil
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) == 0 {
		t.Error("250 messages should produce a warning")
	}
}

// --- CheckWebshells with home data -----------------------------------

func TestCheckWebshellsWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "shell.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return []byte("<?php echo 'test'; ?>"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "shell.php", size: 500}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "shell.php", size: 500}, nil
		},
	})

	_ = CheckWebshells(context.Background(), &config.Config{}, nil)
}

// --- CheckFirewall with config + state data --------------------------

func TestCheckFirewallEnabled(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte("table inet csm_filter {}"), nil
			}
			return nil, nil
		},
	})

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{
		Enabled:  true,
		InfraIPs: []string{"10.0.0.1"},
	}

	_ = CheckFirewall(context.Background(), cfg, nil)
}

// --- CheckAPIAuthFailures with log data ------------------------------

func TestCheckAPIAuthFailuresWithLog(t *testing.T) {
	logData := `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "POST /json-api/verify_password HTTP/1.1" 401 123` + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
		},
	})

	_ = CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
}

// --- CheckHtaccess with home + htaccess data -------------------------

func TestCheckHtaccessWithFiles(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: ".htaccess", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".htaccess") {
				return []byte("RewriteEngine On\nRewriteRule ^.*$ http://evil.com [R]\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckHtaccess(context.Background(), &config.Config{}, nil)
}
