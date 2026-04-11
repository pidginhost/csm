package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- parseBlockExpiry --------------------------------------------------

func TestParseBlockExpiryEmpty(t *testing.T) {
	if got := parseBlockExpiry(""); got != 24*time.Hour {
		t.Errorf("empty = %v, want 24h default", got)
	}
}

func TestParseBlockExpiryValid(t *testing.T) {
	if got := parseBlockExpiry("4h"); got != 4*time.Hour {
		t.Errorf("got %v, want 4h", got)
	}
}

func TestParseBlockExpiryInvalidFallsBack(t *testing.T) {
	if got := parseBlockExpiry("not a duration"); got != 24*time.Hour {
		t.Errorf("invalid = %v, want 24h fallback", got)
	}
}

// --- truncateStr -------------------------------------------------------

func TestTruncateStrNoOp(t *testing.T) {
	if got := truncateStr("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateStrCuts(t *testing.T) {
	if got := truncateStr("hello world", 5); got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestTruncateStrExactLength(t *testing.T) {
	if got := truncateStr("abcde", 5); got != "abcde" {
		t.Errorf("got %q", got)
	}
}

// --- filterUnsuppressedFindings ---------------------------------------

func TestFilterUnsuppressedEmptyRulesPassesThrough(t *testing.T) {
	store := &state.Store{}
	findings := []alert.Finding{{Check: "c", Message: "m"}}
	got := filterUnsuppressedFindings(store, findings, nil)
	if len(got) != 1 {
		t.Errorf("got %d, want 1", len(got))
	}
}

func TestFilterUnsuppressedFiltersMatches(t *testing.T) {
	// Use a real store (OpenTestStore-like pattern — state.Store with
	// zero value is enough for IsSuppressed since it doesn't touch disk
	// when rules are passed in explicitly).
	s, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	rules := []state.SuppressionRule{
		{Check: "waf", Reason: "false positive"},
	}
	findings := []alert.Finding{
		{Check: "waf", Message: "suppressed"},
		{Check: "malware", Message: "keep me"},
	}
	got := filterUnsuppressedFindings(s, findings, rules)
	if len(got) != 1 || got[0].Check != "malware" {
		t.Errorf("got %+v, want only [malware]", got)
	}
}

func TestFilterUnsuppressedNilFindings(t *testing.T) {
	s, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	rules := []state.SuppressionRule{{Check: "waf"}}
	got := filterUnsuppressedFindings(s, nil, rules)
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// --- parseFTPLogLine additional coverage ------------------------------
//
// POSSIBLE PRODUCTION BUG (flagged for follow-up, not fixed here):
//
// parseFTPLogLine uses extractIPFromLogDaemon, which scans for a
// whitespace-separated field that STARTS with a digit. The pure-ftpd
// standard log format prefixes the client with "(?@IP)" — e.g.
//
//   pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [alice]
//
// That field starts with '(', so extractIPFromLogDaemon returns "".
// On a real host whose pure-ftpd writes this format, no FTP
// brute-force or login alerts would ever fire. Unconfirmed on the
// cPanel default pure-ftpd config — on some installs the IP may
// appear as a bare token elsewhere in the same line, in which case
// the parser still works. Needs verification against a live cPanel
// pure-ftpd log before fixing.
//
// Tests below deliberately use lines with a bare IP so we exercise
// the current parser behavior. A future fix should teach
// extractIPFromLogDaemon (or a pure-ftpd-specific helper) to unwrap
// the "(?@IP)" prefix.

func TestParseFTPLogLineNonPureFTPDIgnored(t *testing.T) {
	cfg := &config.Config{}
	findings := parseFTPLogLine("Apr 11 10:00:00 host sshd: session opened", cfg)
	if findings != nil {
		t.Errorf("non-pure-ftpd line should be ignored, got %v", findings)
	}
}

func TestParseFTPLogLineAuthFailure(t *testing.T) {
	cfg := &config.Config{}
	// Use bare IP format so extractIPFromLogDaemon can find it. See the
	// POSSIBLE PRODUCTION BUG note above the test group.
	line := `Apr 11 10:00:00 host pure-ftpd: Authentication failed from 203.0.113.5 user alice`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Check != "ftp_auth_failure_realtime" {
		t.Errorf("Check = %q", findings[0].Check)
	}
}

func TestParseFTPLogLineInfraIPSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"10.0.0.5"}
	line := `Apr 11 10:00:00 host pure-ftpd: Authentication failed from 10.0.0.5 user alice`
	findings := parseFTPLogLine(line, cfg)
	if findings != nil {
		t.Errorf("infra IP should be skipped, got %v", findings)
	}
}

func TestParseFTPLogLineSuccessfulLogin(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: user alice from 203.0.113.5 is now logged in`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	if findings[0].Check != "ftp_login_realtime" {
		t.Errorf("Check = %q", findings[0].Check)
	}
}

func TestParseFTPLogLineIrrelevantPureFTPDLine(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: connection accepted`
	if got := parseFTPLogLine(line, cfg); got != nil {
		t.Errorf("non-auth line should return nil, got %v", got)
	}
}

// --- extractRequestURI -------------------------------------------------

func TestExtractRequestURINoQuotes(t *testing.T) {
	if got := extractRequestURI("no quotes here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractRequestURIUnbalancedQuote(t *testing.T) {
	if got := extractRequestURI(`prefix "request only`); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractRequestURIStandard(t *testing.T) {
	line := `127.0.0.1 - - [11/Apr/2026:10:00:00] "GET /dashboard HTTP/1.1" 200 1234`
	if got := extractRequestURI(line); got != "GET /dashboard HTTP/1.1" {
		t.Errorf("got %q", got)
	}
}

// --- extractIPFromLogDaemon -------------------------------------------

func TestExtractIPFromLogDaemonStandard(t *testing.T) {
	line := "Apr 11 10:00:00 host sshd[1234]: Failed password from 203.0.113.5 port 22"
	if got := extractIPFromLogDaemon(line); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPFromLogDaemonStripsPunctuation(t *testing.T) {
	line := "access from 198.51.100.1, blocked"
	if got := extractIPFromLogDaemon(line); got != "198.51.100.1" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPFromLogDaemonNoIP(t *testing.T) {
	if got := extractIPFromLogDaemon("plain log line, no ip"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
