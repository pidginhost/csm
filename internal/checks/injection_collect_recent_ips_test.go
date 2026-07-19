package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// writeMockLog stores `content` at path `name` inside a temp dir and
// returns a mockOS that serves that path by name. All other paths resolve
// to ErrNotExist.
func writeMockLog(t *testing.T, path, content string) *mockOS {
	t.Helper()
	return writeMockLogs(t, map[string]string{path: content})
}

func writeMockLogs(t *testing.T, logs map[string]string) *mockOS {
	t.Helper()
	tmp := t.TempDir()
	files := make(map[string]string, len(logs))
	for path, content := range logs {
		name := strings.NewReplacer("/", "_").Replace(strings.TrimPrefix(path, "/"))
		f := filepath.Join(tmp, name)
		if err := os.WriteFile(f, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		files[path] = f
	}
	return &mockOS{
		open: func(name string) (*os.File, error) {
			if f, ok := files[name]; ok {
				return os.Open(f)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if f, ok := files[name]; ok {
				return os.Stat(f)
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestCollectRecentIPsSSHLogins(t *testing.T) {
	content := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2\n" +
		"Apr 14 10:00:01 host sshd[2]: Failed password for root from 198.51.100.7 port 22 ssh2\n"
	withMockOS(t, writeMockLogs(t, map[string]string{
		"/var/log/auth.log": content,
		"/var/log/secure":   content,
	}))
	ips := collectRecentIPs(&config.Config{})
	if src, ok := ips["203.0.113.5"]; !ok || src != "SSH login" {
		t.Errorf("expected Accepted IP with source=SSH login, got %v", ips)
	}
	if _, has := ips["198.51.100.7"]; has {
		t.Errorf("Failed-password line should not contribute (only Accepted), got %v", ips)
	}
}

func TestCollectRecentIPsEximSMTPAuthFailure(t *testing.T) {
	// cPanel hosts always check exim_mainlog, even before the file exists.
	forceCPanelPlatform(t)
	// Real exim lines: the first bracketed group in the line is the
	// client IP, which is what extractBracketedIP picks up.
	content := "2026-04-14 10:00:00 H=client [198.51.100.9]:1234 F=<spam@x> rejected RCPT <victim@host>: relay not permitted\n" +
		"2026-04-14 10:00:01 H=client [203.0.113.50]:2222 authenticator failed for bad: 535 Auth failed\n"
	withMockOS(t, writeMockLog(t, "/var/log/exim_mainlog", content))
	ips := collectRecentIPs(&config.Config{})
	if src := ips["198.51.100.9"]; src != "SMTP auth failure" {
		t.Errorf("expected SMTP auth failure source for rejected-RCPT, got %q (full map %v)", src, ips)
	}
	if src := ips["203.0.113.50"]; src != "SMTP auth failure" {
		t.Errorf("expected SMTP auth failure source, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsDovecotAuthFailure(t *testing.T) {
	content := "Apr 14 10:00:00 host dovecot: imap-login: Aborted login (auth failed, 1 attempts in 3 secs): " +
		"user=<alice@x>, method=PLAIN, rip=198.51.100.99, lip=10.0.0.1\n"
	withMockOS(t, writeMockLog(t, "/custom/mail.log", content))
	cfg := &config.Config{}
	cfg.MailLogs.Source = "file"
	cfg.MailLogs.File = "/custom/mail.log"
	ips := collectRecentIPs(cfg)
	if src := ips["198.51.100.99"]; src != "Dovecot IMAP/POP3 auth failure" {
		t.Errorf("expected Dovecot auth-failure source, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsSkipsLocalhostAndEmptyIPs(t *testing.T) {
	content := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 127.0.0.1 port 22 ssh2\n" +
		"Apr 14 10:00:01 host sshd[2]: Accepted publickey for root from ::1 port 22 ssh2\n"
	withMockOS(t, writeMockLogs(t, map[string]string{
		"/var/log/auth.log": content,
		"/var/log/secure":   content,
	}))
	ips := collectRecentIPs(&config.Config{})
	if _, ok := ips["127.0.0.1"]; ok {
		t.Errorf("localhost should be skipped, got %v", ips)
	}
	if _, ok := ips["::1"]; ok {
		t.Errorf("IPv6 localhost should be skipped, got %v", ips)
	}
}

func TestCollectRecentIPsSkipsInfraIPs(t *testing.T) {
	content := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 192.168.1.5 port 22 ssh2\n" +
		"Apr 14 10:00:01 host sshd[2]: Accepted publickey for root from 203.0.113.99 port 22 ssh2\n"
	withMockOS(t, writeMockLogs(t, map[string]string{
		"/var/log/auth.log": content,
		"/var/log/secure":   content,
	}))
	ips := collectRecentIPs(&config.Config{InfraIPs: []string{"192.168.1.0/24"}})
	if _, ok := ips["192.168.1.5"]; ok {
		t.Errorf("infra-range IP should be skipped, got %v", ips)
	}
	if _, ok := ips["203.0.113.99"]; !ok {
		t.Errorf("non-infra IP should be kept, got %v", ips)
	}
}

func TestCollectRecentIPsWebAccessLogPreferred(t *testing.T) {
	// Web access logs come from platform.Detect().AccessLogPaths; declare the
	// path the test serves so detection points the check at it.
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{AccessLogPaths: []string{"/usr/local/apache/logs/access_log"}})
	// Apache access log with a real Combined Log Format line.
	content := "203.0.113.42 - - [14/Apr/2026:10:00:00 +0000] \"GET /index.php HTTP/1.1\" 200 1234 \"-\" \"-\"\n"
	withMockOS(t, writeMockLog(t, "/usr/local/apache/logs/access_log", content))
	ips := collectRecentIPs(&config.Config{})
	if src := ips["203.0.113.42"]; src != "HTTP request" {
		t.Errorf("expected HTTP request source, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsScansEveryWebAccessLogCandidate(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		AccessLogPaths: []string{
			"/var/log/apache2/access.log",
			"/var/log/apache2/other_vhosts_access.log",
		},
	})

	withMockOS(t, writeMockLogs(t, map[string]string{
		"/var/log/apache2/access.log":              "192.0.2.10 - - [14/Apr/2026:10:00:00 +0000] \"GET /server-status HTTP/1.1\" 200 1234 \"-\" \"-\"\n",
		"/var/log/apache2/other_vhosts_access.log": "203.0.113.42 - - [14/Apr/2026:10:00:01 +0000] \"GET /index.php HTTP/1.1\" 200 1234 \"-\" \"-\"\n",
	}))

	ips := collectRecentIPs(&config.Config{})
	if src := ips["192.0.2.10"]; src != "HTTP request" {
		t.Errorf("expected first access-log IP with source HTTP request, got %q (full map %v)", src, ips)
	}
	if src := ips["203.0.113.42"]; src != "HTTP request" {
		t.Errorf("expected second access-log IP with source HTTP request, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsClassifiesWHMAccessAsCPanelSource(t *testing.T) {
	panel := platform.PanelCPanel
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:          &panel,
		AccessLogPaths: []string{"/usr/local/cpanel/logs/access_log"},
	})

	content := "203.0.113.88 - - [14/Apr/2026:10:00:00 +0000] \"GET /json-api/listaccts HTTP/1.1\" 200 1234 \"-\" \"-\"\n"
	withMockOS(t, writeMockLog(t, "/usr/local/cpanel/logs/access_log", content))

	ips := collectRecentIPs(&config.Config{})
	if src := ips["203.0.113.88"]; src != "cPanel/WHM access" {
		t.Errorf("expected cPanel/WHM access source, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsEximSMTPAuthFailureOnNonCPanelWhenLogExists(t *testing.T) {
	panel := platform.PanelNone
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: &panel})

	content := "2026-04-14 10:00:00 H=client [198.51.100.20]:1234 F=<spam@x> rejected RCPT <victim@host>: relay not permitted\n"
	withMockOS(t, writeMockLog(t, "/var/log/exim_mainlog", content))

	ips := collectRecentIPs(&config.Config{})
	if src := ips["198.51.100.20"]; src != "SMTP auth failure" {
		t.Errorf("expected non-cPanel exim auth failure source, got %q (full map %v)", src, ips)
	}
}

func TestCollectRecentIPsDedupesAcrossSources(t *testing.T) {
	// Same IP appears in SSH and cPanel logs. Authentication activity is the
	// stronger surface, so it must win regardless of collection order.
	forceCPanelPlatform(t)
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			tmp, _ := os.CreateTemp(t.TempDir(), "log")
			switch name {
			case "/var/log/auth.log", "/var/log/secure":
				_, _ = tmp.WriteString("Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.77 port 22 ssh2\n")
			case "/usr/local/cpanel/logs/access_log":
				_, _ = tmp.WriteString("203.0.113.77 - - [14/Apr/2026:10:00:01 +0000] \"GET /whm HTTP/1.1\" 200 0 \"-\" \"-\"\n")
			default:
				return nil, os.ErrNotExist
			}
			_, _ = tmp.Seek(0, 0)
			return tmp, nil
		},
	})
	ips := collectRecentIPs(&config.Config{})
	if src := ips["203.0.113.77"]; src != "SSH login" {
		t.Errorf("stronger SSH login should win, got %q (full map %v)", src, ips)
	}
}

// --- firstField (no existing test) ------------------------------------

func TestFirstField(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.5 - - [14/Apr/2026:10:00:00 +0000] \"GET /\"", "203.0.113.5"},
		{"2001:db8::1 rest of line", "2001:db8::1"},
		{"not-an-ip first field here", ""},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := firstField(c.in); got != c.want {
			t.Errorf("firstField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
