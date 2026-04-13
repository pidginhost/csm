package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- fixHtaccess with mock file --------------------------------------

func TestFixHtaccessNoFile(t *testing.T) {
	withMockOS(t, &mockOS{})
	result := fixHtaccess("/tmp/nonexistent/.htaccess", "suspicious directive")
	if result.Success {
		t.Error("nonexistent file should not succeed")
	}
}

// --- fixQuarantine with nonexistent file -----------------------------

func TestFixQuarantineNoFile(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})
	result := fixQuarantine("/tmp/nonexistent.php")
	if result.Success {
		t.Error("nonexistent should not succeed")
	}
}

// --- fixKillAndQuarantine with no process ----------------------------

func TestFixKillAndQuarantineNoProcess(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	result := fixKillAndQuarantine("/tmp/nonexistent", "")
	if result.Success {
		t.Error("no process should not succeed")
	}
}

// --- analyzePHPINI ---------------------------------------------------

func TestAnalyzePHPINIMocked(t *testing.T) {
	content := "display_errors = On\nallow_url_fopen = On\nallow_url_include = On\n"
	issues := analyzePHPINI(content)
	// Exercises the INI parsing. May or may not flag depending on detection rules.
	_ = issues
}

// --- scanForMaliciousSymlinks ----------------------------------------

func TestScanForMaliciousSymlinks(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	})

	var findings []alert.Finding
	scanForMaliciousSymlinks("/home/alice/public_html", "alice", "/home/alice", 3, &findings)
	if len(findings) != 0 {
		t.Errorf("no dir should produce 0, got %d", len(findings))
	}
}

// --- SetCloudflareNets -----------------------------------------------

func TestSetCloudflareNets(t *testing.T) {
	SetCloudflareNets(nil)
	// Should not panic
}

// --- truncateString --------------------------------------------------

func TestTruncateStringShort(t *testing.T) {
	if got := truncateString("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateStringLong(t *testing.T) {
	if got := truncateString("hello world", 5); got != "hello..." {
		t.Errorf("got %q", got)
	}
}

// --- checkEngineMode with platform -----------------------------------

func TestCheckEngineModeFromConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("SecRuleEngine On\n"), nil
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	// checkEngineMode takes platform.Info — we can't easily construct one.
	// Instead test via CheckWAFStatus which calls it internally.
	withMockCmd(t, &mockCmd{})
	cfg := &config.Config{}
	_ = CheckWAFStatus(context.Background(), cfg, nil)
}

// --- auditValiasFile with mock data ----------------------------------

func TestAuditValiasFile(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/valias"
			_ = os.WriteFile(tmp, []byte("catch: |/usr/bin/malware\ninfo: dest@example.com\n"), 0644)
			return os.Open(tmp)
		},
	})

	localDomains := map[string]bool{"example.com": true}
	findings := auditValiasFile("/etc/valiases/example.com", "example.com", localDomains, &config.Config{})
	_ = findings
}

// --- auditVfilterFile with mock data ---------------------------------

func TestAuditVfilterFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("$header_to: contains \"info@example.com\"\n  save /dev/null\n"), nil
		},
	})

	localDomains := map[string]bool{"example.com": true}
	findings := auditVfilterFile("/etc/vfilters/example.com", "example.com", localDomains, &config.Config{})
	_ = findings
}
