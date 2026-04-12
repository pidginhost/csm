package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckAPITokens with token files ---------------------------------

func TestCheckAPITokensWithTokens(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "api_tokens") {
				return []string{"/home/alice/.cpanel/api_tokens"}, nil
			}
			if strings.Contains(pattern, "alice") {
				return []string{"/home/alice/.cpanel/api_tokens/token1"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "api_tokens") {
				return []os.DirEntry{testDirEntry{name: "token1", isDir: false}}, nil
			}
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

// --- CheckWebmailLogins with log data --------------------------------

func TestCheckWebmailLoginsWithLog(t *testing.T) {
	logData := `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "POST /login/ HTTP/1.1" 200 1234 2095` + "\n"
	for i := 0; i < 10; i++ {
		logData += `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "POST /login/ HTTP/1.1" 200 1234 2095` + "\n"
	}

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

	cfg := &config.Config{}
	_ = CheckWebmailLogins(context.Background(), cfg, nil)
}

// --- CheckFilesystem with SUID + glob data ---------------------------

func TestCheckFilesystemWithGlobs(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, ".config") {
				return []string{"/home/alice/.config/htop/htoprc"}, nil
			}
			if strings.Contains(pattern, "tmp") || strings.Contains(pattern, "shm") {
				return nil, nil
			}
			return nil, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "index.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
	})

	_ = CheckFilesystem(context.Background(), &config.Config{}, nil)
}

// --- auditOS with specific distro data --------------------------------

func TestAuditOSAlmaLinux(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"AlmaLinux 9.3\"\nID=almalinux\nVERSION_ID=\"9.3\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "systemctl" {
				return []byte("active\n"), nil
			}
			if name == "sysctl" {
				return []byte("kernel.randomize_va_space = 2\n"), nil
			}
			return nil, nil
		},
	})

	results := auditOS()
	if len(results) == 0 {
		t.Error("auditOS should produce results")
	}
}

// --- getListeningAddr with mock /proc/net/tcp -------------------------

func TestGetListeningAddrMocked(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				// Port 3306 (0CEA) in LISTEN state (0A), bound to 0.0.0.0 (00000000)
				return []byte("  sl  local_address rem_address   st\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0\n"), nil
			}
			if name == "/proc/net/tcp6" {
				return []byte(""), nil
			}
			return nil, os.ErrNotExist
		},
	})

	addr := getListeningAddr(3306)
	if addr == "" {
		t.Error("port 3306 should be found as listening")
	}
}

// --- isPortListening with mock data ----------------------------------

func TestIsPortListeningTrue(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte("  sl  local_address rem_address   st\n   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	if !isPortListening(80) {
		t.Error("port 80 should be listening")
	}
}

func TestIsPortListeningFalse(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	if isPortListening(80) {
		t.Error("empty tcp should not have port 80")
	}
}

// --- auditCPanel with mock WHM API -----------------------------------

func TestAuditCPanelWithWHMAPI(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "cpanel.config") {
				return []byte("skipboxcheck=0\nallow_deprecated_accesshash=0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(`{"data":{"tweaksettings":{"allowunregistereddomains":"0"}}}`), nil
			}
			return nil, nil
		},
	})

	results := auditCPanel("cpanel")
	if len(results) == 0 {
		t.Error("auditCPanel should produce results")
	}
}

// --- getCageFSMode with mock command ---------------------------------

func TestGetCageFSModeEnabled(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cagefs/cagefs.mp" {
				return []byte("cagefs-mode\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	mode := getCageFSMode()
	if mode != "enabled" {
		t.Errorf("got %q, want enabled", mode)
	}
}

func TestGetCageFSModeNotInstalled(t *testing.T) {
	withMockOS(t, &mockOS{})

	mode := getCageFSMode()
	if mode == "enabled" {
		t.Error("missing file should not return enabled")
	}
}
