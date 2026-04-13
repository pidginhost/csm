package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// --- scanErrorLogs with bloated log ----------------------------------

func TestScanErrorLogsBloated(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "error_log", isDir: false},
				testDirEntry{name: "subdir", isDir: true},
			}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "error_log") {
				return fakeFileInfo{name: "error_log", size: 100 * 1024 * 1024}, nil
			}
			return fakeFileInfo{name: "subdir", size: 0}, nil
		},
	})

	var findings []alert.Finding
	scanErrorLogs("/home/alice/public_html", 5*1024*1024, 3, &findings)
	_ = findings
}

// --- scanWPConfigs with WP_DEBUG true --------------------------------

func TestScanWPConfigsDebugTrue(t *testing.T) {
	wpConfig := "<?php\ndefine('WP_DEBUG', true);\ndefine('WP_MEMORY_LIMIT', '40M');\ndefine('DB_NAME','wp');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\ndefine('DB_HOST','localhost');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	var findings []alert.Finding
	scanWPConfigs("/home/alice/public_html", "alice", cfg, 3, &findings)
	if len(findings) == 0 {
		t.Error("WP_DEBUG=true should produce a finding")
	}
}

// --- scanDirForObfuscatedPHP with obfuscated content -----------------

func TestScanDirForObfuscatedPHPWithHexContent(t *testing.T) {
	obfuscated := "<?php\n" +
		strings.Repeat(`"\\x63"."\\x75"."\\x72"."\\x6c".`, 10) + `"";` + "\n" +
		strings.Repeat("goto lbl; lbl:\n", 15)

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "obf.php", isDir: false}}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "obf.php", size: int64(len(obfuscated))}, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/obf.php"
			_ = os.WriteFile(tmp, []byte(obfuscated), 0644)
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), "/home/alice/public_html", 3, &config.Config{}, &findings)
	_ = findings
}

// --- analyzePHPContent with obfuscated patterns ----------------------

func TestAnalyzePHPContentWithObfuscation(t *testing.T) {
	content := "<?php\n" +
		strings.Repeat("goto x; x:\n", 15) +
		strings.Repeat(`"\\x63"."\\x75".`, 30) +
		"\n"

	dir := t.TempDir()
	path := dir + "/obf.php"
	_ = os.WriteFile(path, []byte(content), 0644)

	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	result := analyzePHPContent(path)
	_ = result
}

// --- checkDangerousPorts with listening port on dangerous port --------

func TestCheckDangerousPortsWithListening(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				// Port 6379 (18EB hex) in LISTEN state (0A)
				return []byte("  sl  local_address rem_address   st\n   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, TCPIn: []int{22, 80, 443}}
	results := checkDangerousPorts(cfg)
	_ = results
}

// --- CheckSwapAndOOM with OOM in dmesg --------------------------------

func TestCheckSwapAndOOMWithOOMKill(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\nSwapTotal: 1024000 kB\nSwapFree: 512000 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "dmesg" {
				return []byte("[12345.678] Out of memory: Killed process 1234 (php-fpm) total-vm:1234kB\n"), nil
			}
			return nil, nil
		},
	})

	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- auditVfilterFile with filter rules ------------------------------

func TestAuditVfilterFileWithRules(t *testing.T) {
	filterContent := "$header_to: contains \"info@example.com\"\n  save /dev/null\n$header_from: contains \"spammer@evil.com\"\n  pipe \"/usr/bin/malware\"\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(filterContent), nil
		},
	})

	localDomains := map[string]bool{"example.com": true}
	findings := auditVfilterFile("/etc/vfilters/example.com", "example.com", localDomains, &config.Config{})
	_ = findings
}
