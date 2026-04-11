package daemon

import (
	"os"
	"path/filepath"
	"strings"
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

// --- extractPureFTPDClientIP ------------------------------------------

func TestExtractPureFTPDClientIPStandard(t *testing.T) {
	line := `Apr 11 10:00:00 host pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [alice]`
	if got := extractPureFTPDClientIP(line); got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

func TestExtractPureFTPDClientIPAuthenticatedUser(t *testing.T) {
	line := `Apr 11 10:00:00 host pure-ftpd: (alice@198.51.100.1) [INFO] alice is now logged in`
	if got := extractPureFTPDClientIP(line); got != "198.51.100.1" {
		t.Errorf("got %q, want 198.51.100.1", got)
	}
}

func TestExtractPureFTPDClientIPIPv6(t *testing.T) {
	line := `Apr 11 10:00:00 host pure-ftpd: (?@2001:db8::1) [WARNING] Authentication failed for user [alice]`
	if got := extractPureFTPDClientIP(line); got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestExtractPureFTPDClientIPReverseDNSHostname(t *testing.T) {
	// cPanel default with DontResolve=no: reverse-resolved hostname
	// appears in the prefix instead of the IP. We can't block a
	// hostname at the firewall, so the extractor returns empty.
	line := `Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [alice]`
	if got := extractPureFTPDClientIP(line); got != "" {
		t.Errorf("hostname should return empty, got %q", got)
	}
}

func TestExtractPureFTPDClientIPNoParens(t *testing.T) {
	if got := extractPureFTPDClientIP("plain log line"); got != "" {
		t.Errorf("no parens should return empty, got %q", got)
	}
}

func TestExtractPureFTPDClientIPNoAtSign(t *testing.T) {
	if got := extractPureFTPDClientIP("host pure-ftpd: (noatsign) msg"); got != "" {
		t.Errorf("no @ should return empty, got %q", got)
	}
}

func TestExtractPureFTPDClientIPUnclosedParen(t *testing.T) {
	if got := extractPureFTPDClientIP("host pure-ftpd: (?@203.0.113.5 msg"); got != "" {
		t.Errorf("unclosed paren should return empty, got %q", got)
	}
}

// --- parseFTPLogLine with real pure-ftpd format -----------------------

func TestParseFTPLogLineNonPureFTPDIgnored(t *testing.T) {
	cfg := &config.Config{}
	findings := parseFTPLogLine("Apr 11 10:00:00 host sshd: session opened", cfg)
	if findings != nil {
		t.Errorf("non-pure-ftpd line should be ignored, got %v", findings)
	}
}

func TestParseFTPLogLineAuthFailureRealFormat(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [alice]`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Check != "ftp_auth_failure_realtime" {
		t.Errorf("Check = %q", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "203.0.113.5") {
		t.Errorf("Message should contain the IP: %q", findings[0].Message)
	}
}

func TestParseFTPLogLineInfraIPSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"10.0.0.5"}
	line := `Apr 11 10:00:00 host pure-ftpd: (?@10.0.0.5) [WARNING] Authentication failed for user [alice]`
	findings := parseFTPLogLine(line, cfg)
	if findings != nil {
		t.Errorf("infra IP should be skipped, got %v", findings)
	}
}

func TestParseFTPLogLineSuccessfulLoginRealFormat(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: (alice@203.0.113.5) [INFO] alice is now logged in`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	if findings[0].Check != "ftp_login_realtime" {
		t.Errorf("Check = %q", findings[0].Check)
	}
}

func TestParseFTPLogLineHostnameInsteadOfIPIsSkipped(t *testing.T) {
	// cPanel default with DontResolve=no writes a reverse-resolved
	// hostname instead of an IP. parseFTPLogLine should emit no finding
	// rather than hallucinate an IP — the hostname can't be enforced
	// at the firewall anyway.
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [alice]`
	if got := parseFTPLogLine(line, cfg); got != nil {
		t.Errorf("hostname-only log should not emit finding, got %v", got)
	}
}

func TestParseFTPLogLineIrrelevantPureFTPDLine(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: (?@203.0.113.5) connection accepted`
	if got := parseFTPLogLine(line, cfg); got != nil {
		t.Errorf("non-auth line should return nil, got %v", got)
	}
}

func TestParseFTPLogLineFallsBackToBareIPScanner(t *testing.T) {
	// If somehow the (...@IP) prefix is missing but a bare IP is in the
	// line, the extractIPFromLogDaemon fallback should still find it.
	cfg := &config.Config{}
	line := `Apr 11 10:00:00 host pure-ftpd: Authentication failed from 203.0.113.5 user alice`
	findings := parseFTPLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1 (fallback)", len(findings))
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

// --- purgeTracker (purge_correlation.go) ------------------------------

func TestPurgeStateNoSession(t *testing.T) {
	ps := &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
	if ps.isPostPurge401("1.2.3.4") {
		t.Error("unknown IP should not be flagged as post-purge")
	}
}

func TestPurgeStateSessionWithoutPurge(t *testing.T) {
	ps := &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
	ps.recordLogin("1.2.3.4", "alice")
	if ps.isPostPurge401("1.2.3.4") {
		t.Error("session without purge should not be flagged")
	}
}

func TestPurgeStatePostPurge401(t *testing.T) {
	ps := &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
	ps.recordLogin("1.2.3.4", "alice")
	ps.recordPurge("alice")
	if !ps.isPostPurge401("1.2.3.4") {
		t.Error("recent purge on same account should flag 401 as stale")
	}
}

func TestPurgeStatePurgeExpired(t *testing.T) {
	ps := &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
	ps.recordLogin("1.2.3.4", "alice")
	// Manually set a stale purge timestamp outside the window.
	ps.mu.Lock()
	ps.purges["alice"] = time.Now().Add(-5 * time.Minute)
	ps.mu.Unlock()
	if ps.isPostPurge401("1.2.3.4") {
		t.Error("old purge outside suppression window should not flag")
	}
}

func TestPurgeStateCleanupPrunesOldEntries(t *testing.T) {
	ps := &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
	// Seed with a stale purge entry.
	ps.mu.Lock()
	ps.purges["old"] = time.Now().Add(-10 * time.Minute) // outside 2x window
	ps.purges["fresh"] = time.Now()
	ps.mu.Unlock()

	ps.recordLogin("1.2.3.4", "whoever") // triggers cleanupLocked via the Lock
	ps.mu.Lock()
	_, oldStill := ps.purges["old"]
	_, freshStill := ps.purges["fresh"]
	ps.mu.Unlock()

	if oldStill {
		t.Error("stale purge entry should have been pruned")
	}
	if !freshStill {
		t.Error("fresh entry should remain")
	}
}

// --- parseValiasFileForFindings expanded ------------------------------

func TestParseValiasFileMissingFileReturnsNil(t *testing.T) {
	if got := parseValiasFileForFindings("/nonexistent/path", "example.com", nil, nil); got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func TestParseValiasFileSkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com")
	content := `# this is a comment

alice: alice@example.com
bob: # trailing comment ignored by the split
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	localDomains := map[string]bool{"example.com": true}
	findings := parseValiasFileForFindings(path, "example.com", localDomains, nil)
	// alice → local, bob has empty dest — neither yields findings.
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// --- shouldTempfailEmailDelivery (spoolwatch_policy.go) ---------------

func TestShouldTempfailEmailDeliveryFailOpenMode(t *testing.T) {
	// tempfail=false means fail-open: never tempfail.
	if shouldTempfailEmailDelivery(false, nil, nil) {
		t.Error("fail-open mode should not tempfail")
	}
}

func TestShouldTempfailEmailDeliveryQuarantineError(t *testing.T) {
	if !shouldTempfailEmailDelivery(true, nil, errTestSentinel{}) {
		t.Error("quarantine error in tempfail mode should tempfail")
	}
}

func TestShouldTempfailEmailDeliveryNilResult(t *testing.T) {
	if shouldTempfailEmailDelivery(true, nil, nil) {
		t.Error("nil result with no error should not tempfail")
	}
}

type errTestSentinel struct{}

func (errTestSentinel) Error() string { return "test" }
