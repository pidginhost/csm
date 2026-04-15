package checks

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckWAFStatus with ModSec config data --------------------------

func TestCheckWAFStatusWithModSecConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			// Return a fake modsecurity config
			return []byte("SecRuleEngine On\n"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "modsec.conf", size: 50}, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckSSHLogins --------------------------------------------------

func TestCheckSSHLoginsNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckSSHLogins(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckWHMAccess --------------------------------------------------

func TestCheckWHMAccessNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckWHMAccess(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckWPCore -----------------------------------------------------

func TestCheckWPCoreNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckWPCore(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckOutboundConnections ----------------------------------------

func TestCheckOutboundConnectionsNoProc(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOutboundConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no proc should produce 0, got %d", len(findings))
	}
}

// --- CheckIPReputation -----------------------------------------------

func TestCheckIPReputationNoData(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckIPReputation(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)
	if len(findings) != 0 {
		t.Errorf("no data should produce 0, got %d", len(findings))
	}
}

// --- CheckFirewall ---------------------------------------------------

func TestCheckFirewallWithConfig(t *testing.T) {
	withMockOS(t, &mockOS{})
	// Mock nft to fail (table not found) so the function early-returns
	// with the critical "table not found" finding without touching state.
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("nft: table inet csm: No such file or directory")
		},
	})
	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	findings := CheckFirewall(context.Background(), cfg, st)
	if len(findings) == 0 {
		t.Error("expected critical finding when nft table is missing")
	}
}

// --- Hardening checks ------------------------------------------------

func TestCheckOpenBasedirWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{
					fakeDirEntry{fi: fakeFileInfo{name: "alice"}},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckOpenBasedir(context.Background(), &config.Config{}, nil)
	_ = findings
}

func TestCheckSymlinkAttacksWithHome(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{
					fakeDirEntry{fi: fakeFileInfo{name: "alice"}},
				}, nil
			}
			if name == "/home/alice/public_html" {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})

	findings := CheckSymlinkAttacks(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- WHM checks ------------------------------------------------------

func TestCheckWHMAccessWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("203.0.113.5 - root [12/Apr/2026:10:00:00 +0000] \"GET /scripts/command?PFILE=passwd HTTP/1.1\" 200 1234\n"), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: 500}, nil
		},
	})

	findings := CheckWHMAccess(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckEmailPasswords with shadow data ----------------------------

func TestCheckEmailPasswordsWithShadow(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil // no shadow files
		},
	})

	findings := CheckEmailPasswords(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- RunHardeningAudit auditCPanel -----------------------------------

func TestAuditCPanelWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	results := auditCPanel("cpanel")
	_ = results
}

func TestAuditCloudLinuxWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	results := auditCloudLinux()
	_ = results
}

// --- ApplyFix --------------------------------------------------------

func TestApplyFixUnknownCheck(t *testing.T) {
	result := ApplyFix("unknown_check", "msg", "details")
	if result.Success {
		t.Error("unknown check should not succeed")
	}
}

func TestApplyFixNoPath(t *testing.T) {
	result := ApplyFix("world_writable_php", "no path in message", "")
	if result.Success {
		t.Error("no path should not succeed")
	}
}

// --- InlineQuarantine with nonexistent file --------------------------

func TestInlineQuarantineNonexistent(t *testing.T) {
	f := alert.Finding{Check: "webshell", FilePath: "/tmp/nonexistent_xyz.php"}
	_, ok := InlineQuarantine(f, "/tmp/nonexistent_xyz.php", nil)
	if ok {
		t.Error("nil data should not succeed")
	}
}

// --- CheckSSHDConfig with mock data ----------------------------------

func TestCheckSSHDConfigWithChange(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/etc/ssh/sshd_config" {
				tmp := t.TempDir() + "/sshd_config"
				_ = os.WriteFile(tmp, []byte("Port 22\nPermitRootLogin no\n"), 0644)
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
	// Second call = no change
	findings := CheckSSHDConfig(context.Background(), &config.Config{}, store)
	_ = findings
}
