package checks

import (
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
		case strings.Contains(query, "session_tokens"):
			if sessionValue == "" {
				return nil
			}
			return []string{sessionValue}
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = prev })
}

// sessionTokensValue fakes a WP session_tokens serialized blob with one
// "ip" fragment per login. The parser only reads the ip fragments.
func sessionTokensValue(ips ...string) string {
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(`s:2:"ip";s:1:"`)
		b.WriteString(ip)
		b.WriteString(`";`)
	}
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

// A new admin with many interactive logins from one stable IP is a
// legitimate developer/agency (rentvanscy webadmin, 2026-07-23). Downgrade
// to Warning -- but never suppress.
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

// A programmatically-created rogue admin with no interactive logins stays
// Critical.
func TestCheckWPUsersKeepsCriticalWithNoLogins(t *testing.T) {
	rows := []string{"2\tsiteadmin\tx@wp2shell.invalid\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	withMockAdminAndSessions(t, rows, "")
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("no-login rogue admin must stay Critical, got %+v", f)
	}
}

// A couple of logins is below the established-history bar and stays Critical.
func TestCheckWPUsersKeepsCriticalForFewLogins(t *testing.T) {
	rows := []string{"2\thelper\tx@example.com\t2026-07-16 17:03:58\t2019-03-02 08:11:05"}
	withMockAdminAndSessions(t, rows, sessionTokensValue("203.0.113.7", "203.0.113.7"))
	creds := wpDBCreds{dbHost: "localhost", dbName: "wp", dbUser: "u", dbPass: "p"}
	f := rogueAdminFinding(t, checkWPUsers("alice", creds, "wp_"))
	if f == nil || f.Severity != alert.Critical {
		t.Fatalf("few-login admin must stay Critical, got %+v", f)
	}
}

// Many logins spread across multiple IPs is not the stable-single-IP
// developer pattern and stays Critical.
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

func TestParseSessionTokenIPs(t *testing.T) {
	blob := sessionTokensValue("203.0.113.7", "198.51.100.9", "203.0.113.7")
	got := parseSessionTokenIPs(blob)
	if len(got) != 3 || got[0] != "203.0.113.7" || got[1] != "198.51.100.9" {
		t.Fatalf("parseSessionTokenIPs = %v, want 3 ips in order", got)
	}
}
