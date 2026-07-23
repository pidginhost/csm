package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// serves admin rows for the recent-admin query and a session_tokens
// meta_value for the per-admin session query.
func withMockAdminAndSessions(t *testing.T, adminRows []string, sessionValue string) {
	t.Helper()
	prev := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		switch {
		case strings.Contains(query, "DATE_SUB"):
			return adminRows
		case strings.Contains(query, "meta_key = 'session_tokens'"):
			if sessionValue == "" {
				return nil
			}
			return []string{sessionValue}
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

// sessionTokensValue builds a valid PHP-serialized session_tokens value with
// one WordPress-shaped session record per IP.
func sessionTokensValue(ips ...string) string {
	return sessionTokensValueWithUA(ips, "Mozilla/5.0")
}

func sessionTokensValueWithUA(ips []string, userAgent string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "a:%d:{", len(ips))
	for i, ip := range ips {
		token := fmt.Sprintf("token-%d", i)
		fmt.Fprintf(&b,
			`s:%d:"%s";a:4:{s:10:"expiration";i:1775817506;s:2:"ip";s:%d:"%s";s:2:"ua";s:%d:"%s";s:5:"login";i:1775644706;}`,
			len(token), token, len(ip), ip, len(userAgent), userAgent)
	}
	b.WriteByte('}')
	return b.String()
}

func rogueAdminFinding(t *testing.T, findings []alert.Finding) *alert.Finding {
	t.Helper()
	for i := range findings {
		if findings[i].Check == "db_rogue_admin" {
			return &findings[i]
		}
	}
	return nil
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// Enough stored sessions from one stable IP downgrades the account to Warning
// but never suppresses it.
func TestCheckWPUsersDowngradesEstablishedSingleIPAdmin(t *testing.T) {
	rows := []string{"2\twebadmin\tagency@example.com\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	withMockAdminAndSessions(t, rows, sessionTokensValue(repeat("203.0.113.7", 8)...))
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil {
		t.Fatal("established single-IP admin must still produce a finding (downgraded, not suppressed)")
	}
	if f.Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
}

// An admin without session evidence stays Critical.
func TestCheckWPUsersKeepsCriticalWithNoLogins(t *testing.T) {
	rows := []string{"2\tsiteadmin\tx@wp2shell.invalid\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	withMockAdminAndSessions(t, rows, "")
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("no-login rogue admin must stay Critical, got %+v", f)
	}
}

// A couple of sessions is below the downgrade threshold and stays Critical.
func TestCheckWPUsersKeepsCriticalForFewLogins(t *testing.T) {
	rows := []string{"2\thelper\tx@example.com\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	withMockAdminAndSessions(t, rows, sessionTokensValue("203.0.113.7", "203.0.113.7"))
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("few-login admin must stay Critical, got %+v", f)
	}
}

// Many sessions spread across multiple IPs do not meet the stable-source
// threshold and stay Critical.
func TestCheckWPUsersKeepsCriticalForMultipleIPs(t *testing.T) {
	rows := []string{"2\thelper\tx@example.com\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	ips := append(repeat("203.0.113.7", 4), repeat("198.51.100.9", 4)...)
	withMockAdminAndSessions(t, rows, sessionTokensValue(ips...))
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("multi-IP admin must stay Critical, got %+v", f)
	}
}

func TestCheckWPUsersIgnoresSessionFragmentsInsideUserAgent(t *testing.T) {
	rows := []string{"2\thelper\tx@example.com\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	fakeSessions := strings.Repeat(`s:2:"ip";s:11:"203.0.113.7";`, wpEstablishedLoginSessions)
	session := sessionTokensValueWithUA([]string{"203.0.113.7"}, fakeSessions)
	withMockAdminAndSessions(t, rows, session)
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("user-agent fragments must not downgrade the finding, got %+v", f)
	}
}

func TestParseSessionTokenIPs(t *testing.T) {
	embedded := strings.Repeat(`s:2:"ip";s:12:"198.51.100.9";`, wpEstablishedLoginSessions)
	tests := []struct {
		name string
		blob string
		want string
	}{
		{
			name: "valid WordPress sessions",
			blob: sessionTokensValue("203.0.113.7", "198.51.100.9", "203.0.113.7"),
			want: "203.0.113.7,198.51.100.9,203.0.113.7",
		},
		{
			name: "token fragment inside user agent",
			blob: sessionTokensValueWithUA([]string{"203.0.113.7"}, embedded),
			want: "203.0.113.7",
		},
		{
			name: "invalid serialized length",
			blob: `a:1:{s:2:"ip";s:1:"203.0.113.7";}`,
		},
		{
			name: "invalid IP",
			blob: sessionTokensValue("not-an-ip"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(parseSessionTokenIPs(tt.blob), ",")
			if got != tt.want {
				t.Fatalf("parseSessionTokenIPs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWPAdminLoginIPsUsesUnprefixedSessionMetaKey(t *testing.T) {
	prev := runMySQLQuery
	var query string
	runMySQLQuery = func(_ wpDBCreds, q string) []string {
		query = q
		return []string{sessionTokensValue("203.0.113.7")}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	got := wpAdminLoginIPs(wpDBCreds{}, "custom_", "42")
	if len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("wpAdminLoginIPs = %v, want one session IP", got)
	}
	want := "SELECT meta_value FROM custom_usermeta WHERE user_id = 42 AND meta_key = 'session_tokens' LIMIT 1"
	if query != want {
		t.Fatalf("session query = %q, want %q", query, want)
	}
}

func TestWPAdminLoginIPsUnescapesBatchEncodedSessionData(t *testing.T) {
	prev := runMySQLQuery
	session := sessionTokensValueWithUA([]string{"203.0.113.7"}, `Mozilla\5.0`)
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		return []string{strings.ReplaceAll(session, `\`, `\\`)}
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	got := wpAdminLoginIPs(wpDBCreds{}, "wp_", "42")
	if len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("wpAdminLoginIPs = %v, want one IP from batch-encoded metadata", got)
	}
}

func TestWPAdminLoginIPsRejectsNonNumericUserID(t *testing.T) {
	prev := runMySQLQuery
	queried := false
	runMySQLQuery = func(_ wpDBCreds, _ string) []string {
		queried = true
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })

	for _, userID := range []string{"", "-1", "1 OR 1=1", "1; DROP TABLE wp_users", "１２"} {
		if got := wpAdminLoginIPs(wpDBCreds{}, "wp_", userID); len(got) != 0 {
			t.Errorf("wpAdminLoginIPs(%q) = %v, want no IPs", userID, got)
		}
	}
	if queried {
		t.Fatal("non-numeric user ID reached the SQL query")
	}
}
