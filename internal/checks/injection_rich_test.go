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

// --- CheckShadowChanges with data ------------------------------------

func TestCheckShadowChangesDetectsChange(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "shadow", size: 100}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/shadow" {
				return []byte("root:$6$salt$hash:19000:0:99999:7:::\nalice:$6$salt$newhash:19000:0:99999:7:::\n"), nil
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
	_ = CheckShadowChanges(context.Background(), &config.Config{}, store)

	// Change the shadow data
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "shadow", size: 120}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/shadow" {
				return []byte("root:$6$salt$hash:19000:0:99999:7:::\nalice:$6$salt$CHANGED:19000:0:99999:7:::\nhacker:$6$salt$evil:19000:0:99999:7:::\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckShadowChanges(context.Background(), &config.Config{}, store)
	if len(findings) == 0 {
		t.Error("changed shadow should produce findings")
	}
}

// --- CheckCpanelLogins with session data -----------------------------

func TestCheckCpanelLoginsWithSessions(t *testing.T) {
	logData := "[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.5 NEW alice:token123 address=203.0.113.5\n" +
		"[2026-04-12 10:01:00 +0000] info [cpaneld] 198.51.100.1 NEW alice:token456 address=198.51.100.1\n"

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/session_log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "session_log") {
				return fakeFileInfo{name: "session_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckCpanelLogins(context.Background(), &config.Config{}, store)
	_ = findings // exercises the session log parsing path
}

// --- CheckDNSConnections with /proc data -----------------------------

func TestCheckDNSConnectionsWithData(t *testing.T) {
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 0100007F:0035 CB007105:0035 01 00000000:00000000 00:00000000 00000000  1000\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" || name == "/proc/net/tcp6" {
				return []byte(tcpData), nil
			}
			if name == "/etc/resolv.conf" {
				return []byte("nameserver 127.0.0.1\n"), nil
			}
			if name == "/etc/passwd" {
				return []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/etc/resolv.conf" {
				tmp := t.TempDir() + "/resolv.conf"
				_ = os.WriteFile(tmp, []byte("nameserver 127.0.0.1\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckNulledPlugins with mock data --------------------------------

func TestCheckNulledPluginsWithReadDir(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{fakeDirEntry{fi: fakeFileInfo{name: "alice", size: 0}}}, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-content/plugins") {
				return []string{"/home/alice/public_html/wp-content/plugins"}, nil
			}
			return nil, nil
		},
	})

	findings := CheckNulledPlugins(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckFTPLogins with log data ------------------------------------

func TestCheckFTPLoginsWithData(t *testing.T) {
	logData := "Apr 12 10:00:00 host pure-ftpd: (?@203.0.113.5) [INFO] alice is now logged in\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "messages") || strings.Contains(name, "syslog") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "messages") || strings.Contains(name, "syslog") {
				tmp := t.TempDir() + "/messages"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckFTPLogins(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckOutboundEmailContent with spool ----------------------------

func TestCheckOutboundEmailContentWithSpool(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "spool") || strings.Contains(name, "input") {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- AutoKillProcesses with findings ---------------------------------

func TestAutoKillProcessesWithFindings(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "suspicious_process", Message: "Process xmrig from /tmp/xmrig"},
	}

	results := AutoKillProcesses(&config.Config{}, findings)
	_ = results
}

// --- AutoQuarantineFiles with findings -------------------------------

func TestAutoQuarantineFilesWithFindings(t *testing.T) {
	withMockOS(t, &mockOS{})

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Webshell in /tmp/nonexistent_webshell.php", FilePath: "/tmp/nonexistent_webshell.php"},
	}

	cfg := &config.Config{}
	results := AutoQuarantineFiles(cfg, findings)
	_ = results
}

// --- RunAccountScan with mock ----------------------------------------

func TestRunAccountScanNonexistent(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})

	cfg := &config.Config{StatePath: t.TempDir()}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := RunAccountScan(cfg, store, "nonexistent_user")
	_ = findings
}
