package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- auditOS with kernel security params -----------------------------

func TestAuditOSWithSysctl(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("ID=almalinux\nVERSION_ID=\"9.3\"\nPRETTY_NAME=\"AlmaLinux 9.3\"\n"), nil
			}
			if strings.Contains(name, "randomize_va_space") {
				return []byte("2\n"), nil
			}
			if strings.Contains(name, "sysrq") {
				return []byte("0\n"), nil
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
				return []byte("kernel.randomize_va_space = 2\nkernel.sysrq = 0\n"), nil
			}
			return nil, nil
		},
	})

	results := auditOS()
	if len(results) == 0 {
		t.Error("auditOS should produce results")
	}
}

// --- auditCPanel with more config data --------------------------------

func TestAuditCPanelDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "cpanel.config") {
				return []byte("skipboxcheck=1\nallow_deprecated_accesshash=1\njailshell_scp=0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(`{"data":{"tweaksettings":{"allowunregistereddomains":"1"}}}`), nil
			}
			return nil, nil
		},
	})

	results := auditCPanel("cpanel")
	if len(results) == 0 {
		t.Error("insecure cpanel config should produce results")
	}
}

// --- auditCloudLinux with data ----------------------------------------

func TestAuditCloudLinuxDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/sys/fs/enforce_symlinksifowner" {
				return []byte("1\n"), nil
			}
			if strings.Contains(name, "cagefs.mp") {
				return []byte("enabled\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "cagefsctl" {
				return []byte("CageFS is enabled\n"), nil
			}
			if name == "selectorctl" {
				return []byte("5.6, 7.0, 7.4, 8.0, 8.1, 8.2\n"), nil
			}
			return nil, nil
		},
	})

	results := auditCloudLinux()
	if len(results) == 0 {
		t.Error("should produce CloudLinux audit results")
	}
}

// --- auditMail with exim running --------------------------------------

func TestAuditMailWithEximConfig(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "exim" {
				return []byte("Exim version 4.96\n"), nil
			}
			if name == "systemctl" {
				return []byte("active\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "exim.conf") || strings.Contains(name, "exim4.conf") {
				return []byte("tls_certificate = /etc/exim.cert\nsmtp_accept_max = 50\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	results := auditMail()
	_ = results
}

// --- scanForMaliciousSymlinks with symlink to /etc -------------------

func TestScanForMaliciousSymlinksWithBadLink(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "backdoor.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "backdoor.php", size: 0}, nil
		},
		readlink: func(name string) (string, error) {
			if strings.HasSuffix(name, "backdoor.php") {
				return "/etc/shadow", nil
			}
			return "", os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanForMaliciousSymlinks("/home/alice/public_html", "alice", "/home/alice", 3, &findings)
	_ = findings
}

// --- CheckPHPProcessLoad with high memory PHP processes ---------------

func TestCheckPHPProcessLoadHighMemory(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "cmdline") {
				return []string{"/proc/1000/cmdline", "/proc/1001/cmdline", "/proc/1002/cmdline"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "cmdline") {
				return []byte("php-fpm: pool www\x00"), nil
			}
			if strings.HasSuffix(name, "status") {
				return []byte("Name:\tphp-fpm\nVmRSS:\t512000 kB\nUid:\t1000\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\nprocessor\t: 1\n"), 0644)
				return os.Open(tmp)
			}
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 2048000 kB\nMemAvailable: 512000 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	cfg := &config.Config{}
	findings := CheckPHPProcessLoad(context.Background(), cfg, nil)
	_ = findings
}

// --- resolveExistingFixPath with valid path ---------------------------

func TestResolveExistingFixPathInTmp(t *testing.T) {
	dir := t.TempDir()
	phpFile := dir + "/test.php"
	_ = os.WriteFile(phpFile, []byte("<?php"), 0644)

	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	// The function validates against allowed roots — exercises the path logic.
	_, _, _ = resolveExistingFixPath(phpFile, []string{"/home", "/tmp", "/var"})
}

func TestResolveExistingFixPathOutsideRoots(t *testing.T) {
	_, _, err := resolveExistingFixPath("/etc/passwd", []string{"/home"})
	if err == nil {
		t.Error("outside roots should return error")
	}
}
