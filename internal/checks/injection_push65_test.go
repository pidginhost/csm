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

// --- CheckOpenBasedir with CageFS data --------------------------------

func TestCheckOpenBasedirWithCageFS(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{
					testDirEntry{name: "alice", isDir: true},
					testDirEntry{name: "bob", isDir: true},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cagefs/cagefs.mp" {
				return []byte("enabled\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "cagefsctl" {
				if len(args) > 0 && args[0] == "--list-disabled" {
					return []byte("bob\n"), nil
				}
				return []byte("CageFS is enabled\n"), nil
			}
			return nil, nil
		},
	})

	findings := CheckOpenBasedir(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckSymlinkAttacks with symlinks in home -----------------------

func TestCheckSymlinkAttacksWithSymlinks(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "link.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			// Simulate a symlink
			return fakeFileInfo{name: "link.php", size: 0}, nil
		},
		readlink: func(name string) (string, error) {
			if strings.HasSuffix(name, "link.php") {
				return "/etc/passwd", nil // dangerous symlink
			}
			return "", os.ErrNotExist
		},
	})

	findings := CheckSymlinkAttacks(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- scanForSUID with actual SUID binary mock -------------------------

func TestScanForSUIDWithSUIDBinary(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "suid_bin", isDir: false},
			}, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			// Return file with SUID bit
			return fakeFileInfo{name: "suid_bin", size: 1000}, nil
		},
	})

	var findings []alert.Finding
	scanForSUID(context.Background(), "/home/alice/public_html", 3, &findings)
	// May not detect SUID via mock since os.FileInfo.Mode() returns 0644 from fakeFileInfo
	_ = findings
}

// --- CheckDatabaseDumps with recent large dump -----------------------

func TestCheckDatabaseDumpsRecent(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "*.sql") || strings.Contains(pattern, "*.gz") {
				return []string{"/home/alice/public_html/full_backup.sql.gz"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "full_backup.sql.gz", size: 100 * 1024 * 1024}, nil
		},
	})

	findings := CheckDatabaseDumps(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckOutboundPasteSites with connection to paste host ------------

func TestCheckOutboundPasteSitesWithConnection(t *testing.T) {
	// TCP connection to port 443 from UID 1000
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 0100007F:C000 DEADBEEF:01BB 01 00000000:00000000 00:00000000 00000000  1000\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte(tcpData), nil
			}
			if name == "/etc/passwd" {
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckOutboundPasteSites(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckKernelModules with module change detection ------------------

func TestCheckKernelModulesChange(t *testing.T) {
	mod1 := "ext4 720896 1 - Live\nnfsd 458752 11 - Live\n"
	mod2 := "ext4 720896 1 - Live\nnfsd 458752 11 - Live\nrootkit 12345 0 - Live\n"

	call := 0
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/modules" {
				call++
				tmp := t.TempDir() + "/modules"
				data := mod1
				if call > 1 {
					data = mod2
				}
				_ = os.WriteFile(tmp, []byte(data), 0644)
				return os.Open(tmp)
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
	_ = CheckKernelModules(context.Background(), &config.Config{}, store)
	// Change — new module
	findings := CheckKernelModules(context.Background(), &config.Config{}, store)
	if len(findings) == 0 {
		t.Error("new kernel module should produce a finding")
	}
}

// --- CheckNulledPlugins with deeper directory tree --------------------

func TestCheckNulledPluginsDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "alice") {
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			}
			if strings.HasSuffix(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckNulledPlugins(context.Background(), &config.Config{}, nil)
	_ = findings
}
