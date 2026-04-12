package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- makeAccountSSHKeyCheck ------------------------------------------

func TestMakeAccountSSHKeyCheck(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/home/alice/.ssh/authorized_keys"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte("ssh-rsa AAAAB3 alice@laptop\n"), nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	check := makeAccountSSHKeyCheck("alice")
	findings := check(context.Background(), &config.Config{}, store)
	_ = findings
}

// --- makeAccountCrontabCheck -----------------------------------------

func TestMakeAccountCrontabCheck(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("0 * * * * /usr/bin/backup.sh\n"), nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	check := makeAccountCrontabCheck("alice")
	_ = check(context.Background(), &config.Config{}, store)
}

// --- makeAccountBackdoorCheck ----------------------------------------

func TestMakeAccountBackdoorCheck(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	})

	check := makeAccountBackdoorCheck("alice")
	_ = check(context.Background(), &config.Config{}, nil)
}

// --- runMySQLQuery with mock -----------------------------------------

func TestRunMySQLQueryMocked(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("value1\tvalue2\nvalue3\tvalue4\n"), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "user", dbPass: "pass"}
	rows := runMySQLQuery(creds, "SELECT * FROM wp_options")
	if len(rows) != 2 {
		t.Errorf("got %d rows, want 2", len(rows))
	}
}

func TestRunMySQLQueryError(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "user", dbPass: "pass"}
	rows := runMySQLQuery(creds, "SELECT 1")
	if len(rows) != 0 {
		t.Errorf("error should return 0 rows, got %d", len(rows))
	}
}

// --- checkWPOptions with mock MySQL ----------------------------------

func TestCheckWPOptionsClean(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "user", dbPass: "pass"}
	findings := checkWPOptions("alice", creds, "wp_")
	if len(findings) != 0 {
		t.Errorf("clean options should produce 0, got %d", len(findings))
	}
}

// --- checkWPPosts with mock MySQL ------------------------------------

func TestCheckWPPostsClean(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "user", dbPass: "pass"}
	findings := checkWPPosts("alice", creds, "wp_")
	if len(findings) != 0 {
		t.Errorf("clean posts should produce 0, got %d", len(findings))
	}
}

// --- checkWPUsers with mock MySQL ------------------------------------

func TestCheckWPUsersClean(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "user", dbPass: "pass"}
	findings := checkWPUsers("alice", creds, "wp_")
	if len(findings) != 0 {
		t.Errorf("clean users should produce 0, got %d", len(findings))
	}
}

// --- loadLocalDomains with mock file ---------------------------------

func TestLoadLocalDomainsWithFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte("example.com\ntest.com\n"), nil
		},
	})

	domains := loadLocalDomains()
	if len(domains) == 0 {
		t.Error("should load domains from file")
	}
}

// --- discoverShadowFiles with glob -----------------------------------

func TestDiscoverShadowFilesWithGlob(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/home/alice/etc/example.com/shadow"}, nil
		},
	})

	files := discoverShadowFiles()
	if len(files) != 1 {
		t.Errorf("got %d, want 1", len(files))
	}
	if files[0].account != "alice" {
		t.Errorf("account = %q", files[0].account)
	}
	if files[0].domain != "example.com" {
		t.Errorf("domain = %q", files[0].domain)
	}
}

// --- AutoKillProcesses with real findings ----------------------------

func TestAutoKillProcessesNonCritical(t *testing.T) {
	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF disabled"},
	}
	results := AutoKillProcesses(&config.Config{}, findings)
	if len(results) != 0 {
		t.Errorf("non-critical should produce 0, got %d", len(results))
	}
}
