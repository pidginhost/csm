package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// serveSyslog points osFS.Open at a temp file holding content, for both the
// legacy tail path and the store-backed follower path of CheckFTPLogins.
func serveSyslog(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/messages"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write mock messages: %v", err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
	return path
}

// cPanel drives its own FTP through loopback service-auth tokens. Those logins
// are internal machinery, not customer or attacker activity, and must never
// alert -- mirroring the loopback exemption the cPanel-login detector already has.
func TestCheckFTPLoginsSkipsLoopbackServiceAuth(t *testing.T) {
	content := "Jun 21 21:26:25 cluster6 pure-ftpd[1]: (?@127.0.0.1) [INFO] __cpanel__service__auth__ftpd__8ut13JQgSaTMaObe is now logged in\n"
	serveSyslog(t, content)

	// Legacy (no store) path.
	if f := CheckFTPLogins(context.Background(), &config.Config{}, nil); len(f) != 0 {
		t.Fatalf("legacy: loopback service-auth must produce no findings, got %+v", f)
	}

	// Store-backed path.
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if f := CheckFTPLogins(context.Background(), &config.Config{}, st); len(f) != 0 {
		t.Fatalf("store: loopback service-auth must produce no findings, got %+v", f)
	}
}

func TestCheckFTPLoginsSkipsIPv6Loopback(t *testing.T) {
	content := "Jun 21 21:26:25 cluster6 pure-ftpd[1]: (?@::1) [INFO] __cpanel__service__auth__ftpd__X is now logged in\n"
	serveSyslog(t, content)

	if f := CheckFTPLogins(context.Background(), &config.Config{}, nil); len(f) != 0 {
		t.Fatalf("IPv6 loopback service-auth must produce no findings, got %+v", f)
	}
}

func TestCheckFTPLoginsSkipsLoopbackVariants(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"ipv4_127_8", "Jun 21 21:26:25 cluster6 pure-ftpd[1]: (?@127.0.0.2) [INFO] __cpanel__service__auth__ftpd__X is now logged in\n"},
		{"ipv4_mapped", "Jun 21 21:26:25 cluster6 pure-ftpd[1]: (?@::ffff:127.0.0.1) [INFO] __cpanel__service__auth__ftpd__X is now logged in\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serveSyslog(t, c.content)
			if f := CheckFTPLogins(context.Background(), &config.Config{}, nil); len(f) != 0 {
				t.Fatalf("legacy: loopback variant must produce no findings, got %+v", f)
			}

			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer func() { _ = st.Close() }()
			if f := CheckFTPLogins(context.Background(), &config.Config{}, st); len(f) != 0 {
				t.Fatalf("store: loopback variant must produce no findings, got %+v", f)
			}
		})
	}
}

// A successful FTP login from an ordinary customer IP is an audit-trail event,
// not paging-level. It should be Warning, matching the cPanel-login detector.
func TestCheckFTPLoginsGenericSuccessIsWarning(t *testing.T) {
	content := "Apr 12 10:01:00 server pure-ftpd[1]: (backup@203.0.113.5) [INFO] backup is now logged in\n"
	serveSyslog(t, content)

	findings := CheckFTPLogins(context.Background(), &config.Config{}, nil)
	var got *alert.Finding
	for i := range findings {
		if findings[i].Check == "ftp_login" && findings[i].SourceIP == "203.0.113.5" {
			got = &findings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected ftp_login finding for non-infra success, got %+v", findings)
	}
	if got.Severity != alert.Warning {
		t.Fatalf("generic FTP login should be Warning (audit-level), got severity %v", got.Severity)
	}
}

// A successful login from an IP that has already crossed the brute-force
// threshold means a credential was likely cracked. That is the real signal:
// escalate to a distinct Critical finding naming the account, and do NOT also
// emit the generic Warning for the same login.
func TestCheckFTPLoginsSuccessAfterBruteForceEscalates(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	path := t.TempDir() + "/messages"
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}

	var b strings.Builder
	for i := 0; i < ftpFailThreshold; i++ {
		b.WriteString("Apr 12 10:00:00 server pure-ftpd[1]: (?@203.0.113.5) [WARNING] Authentication failed for user [mallory]\n")
	}
	write(b.String())
	// Cycle 1: accumulate failures to/over threshold.
	CheckFTPLogins(context.Background(), &config.Config{}, st)

	// Cycle 2: the same IP now succeeds.
	b.WriteString("Apr 12 10:05:00 server pure-ftpd[1]: (mallory@203.0.113.5) [INFO] mallory is now logged in\n")
	write(b.String())
	findings := CheckFTPLogins(context.Background(), &config.Config{}, st)

	var esc *alert.Finding
	for i := range findings {
		if findings[i].Check == "ftp_login_after_bruteforce" && findings[i].SourceIP == "203.0.113.5" {
			esc = &findings[i]
		}
	}
	if esc == nil {
		t.Fatalf("expected ftp_login_after_bruteforce escalation, got %+v", findings)
	}
	if esc.Severity != alert.Critical {
		t.Fatalf("brute-force-then-success escalation must be Critical, got %v", esc.Severity)
	}
	if !strings.Contains(esc.Message, "mallory") {
		t.Fatalf("escalation should name the cracked account, got %q", esc.Message)
	}
	if hasFTPLogin(findings, "203.0.113.5") {
		t.Fatalf("escalated success must not also emit a generic ftp_login finding")
	}
}

func TestCheckFTPLoginsSameCycleKeepsBruteAndSuccessSignals(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var b strings.Builder
	for i := 0; i < ftpFailThreshold; i++ {
		b.WriteString("Apr 12 10:00:00 server pure-ftpd[1]: (?@203.0.113.5) [WARNING] Authentication failed for user [mallory]\n")
	}
	b.WriteString("Apr 12 10:05:00 server pure-ftpd[1]: (mallory@203.0.113.5) [INFO] mallory is now logged in\n")
	serveSyslog(t, b.String())

	findings := alert.Deduplicate(CheckFTPLogins(context.Background(), &config.Config{}, st))
	var brute, success bool
	for _, f := range findings {
		if f.Check == "ftp_bruteforce" && f.SourceIP == "203.0.113.5" {
			brute = true
		}
		if f.Check == "ftp_login_after_bruteforce" && f.SourceIP == "203.0.113.5" {
			success = true
		}
	}
	if !brute || !success {
		t.Fatalf("same-cycle brute then success should keep both facts after dedup, got %+v", findings)
	}
}

func TestCheckFTPLoginsSuccessIgnoresStaleFailures(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	path := t.TempDir() + "/messages"
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
	if err := os.WriteFile(path, []byte("Apr 12 10:05:00 server pure-ftpd[1]: (mallory@203.0.113.5) [INFO] mallory is now logged in\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tracker := newFTPFailTracker()
	staleAt := time.Now().Add(-2 * time.Hour)
	for i := 0; i < ftpFailThreshold; i++ {
		tracker.record("203.0.113.5", staleAt)
	}
	tracker.save(st)

	findings := CheckFTPLogins(context.Background(), &config.Config{}, st)
	for _, f := range findings {
		if f.Check == "ftp_login_after_bruteforce" || f.Check == "ftp_bruteforce" {
			t.Fatalf("stale failures must not escalate or brute-force alert, got %+v", findings)
		}
	}
	if !hasFTPLogin(findings, "203.0.113.5") {
		t.Fatalf("fresh success should still emit generic ftp_login, got %+v", findings)
	}
}

// Legacy (no-store) path correlates failures and the success within one batch.
func TestCheckFTPLoginsLegacySuccessAfterBruteForceEscalates(t *testing.T) {
	var b strings.Builder
	for i := 0; i < ftpFailThreshold; i++ {
		b.WriteString("Apr 12 10:00:00 server pure-ftpd[1]: (?@203.0.113.5) [WARNING] Authentication failed for user [mallory]\n")
	}
	b.WriteString("Apr 12 10:05:00 server pure-ftpd[1]: (mallory@203.0.113.5) [INFO] mallory is now logged in\n")
	serveSyslog(t, b.String())

	findings := CheckFTPLogins(context.Background(), &config.Config{}, nil)
	found := false
	for _, f := range findings {
		if f.Check == "ftp_login_after_bruteforce" && f.SourceIP == "203.0.113.5" && f.Severity == alert.Critical {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy path should escalate success-after-bruteforce to Critical, got %+v", findings)
	}
}

func TestParseFTPLoginAccount(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"Jun 21 20:00:25 cluster6 pure-ftpd[1]: (?@81.196.138.64) [INFO] backup is now logged in", "backup"},
		{"x pure-ftpd[1]: (mallory@203.0.113.5) [INFO] mallory is now logged in", "mallory"},
		{"x pure-ftpd[1]: (?@127.0.0.1) [INFO] user@domain.tld is now logged in", "user@domain.tld"},
		{"no login marker here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseFTPLoginAccount(c.line); got != c.want {
			t.Errorf("parseFTPLoginAccount(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}
