package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

const ftpRealtimeSuccessLine = `Apr 12 10:00:00 host pure-ftpd[1234]: (alice@198.51.100.7) [INFO] alice is now logged in`

const ftpRealtimeFailureLine = `Apr 12 10:00:00 host pure-ftpd[1234]: (?@198.51.100.7) [WARNING] Authentication failed for user [alice]`

const sshRealtimeSuccessLine = `Apr 12 10:00:00 host sshd[4242]: Accepted password for deploy from 198.51.100.9 port 40000 ssh2`

// The realtime watcher must emit the very finding the scheduled check would
// emit for the same line, so the two paths cannot report one login twice.
func TestParseFTPLogLineEmitsSharedLoginFinding(t *testing.T) {
	cfg := &config.Config{}

	shared, ok := checks.FTPLoginFinding(ftpRealtimeSuccessLine, cfg)
	if !ok {
		t.Fatal("shared builder did not report the login")
	}

	got := parseFTPLogLine(ftpRealtimeSuccessLine, cfg)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one", got)
	}
	if got[0].Check != shared.Check || got[0].Key() != shared.Key() {
		t.Fatalf("realtime finding %q/%q differs from the shared builder %q/%q",
			got[0].Check, got[0].Key(), shared.Check, shared.Key())
	}
}

// A failed login logs the name the client tried, so that name can carry the
// login text. The line is a failure only, never a login from that address.
func TestFailedFTPLoginNamingLoginTextIsNoLogin(t *testing.T) {
	cfg := &config.Config{}
	forged := `Apr 12 10:00:00 host pure-ftpd[1234]: (?@198.51.100.7) [WARNING] Authentication failed for user [x is now logged in]`

	if f, ok := checks.FTPLoginFinding(forged, cfg); ok {
		t.Fatalf("shared builder reported a login: %+v", f)
	}
	got := parseFTPLogLine(forged, cfg)
	if len(got) != 1 || got[0].Check != "ftp_auth_failure_realtime" {
		t.Fatalf("findings = %+v, want only the auth failure", got)
	}
}

func TestFTPLoginTextOutsideSuccessRecordIsNoLogin(t *testing.T) {
	for _, line := range []string{
		`Apr 12 10:00:00 host pure-ftpd[1234]: (?@198.51.100.7) [DEBUG] Command [USER] [x is now logged in]`,
		`Apr 12 10:00:00 host pure-ftpd[1234]: (?@198.51.100.7) [WARNING] Can't change directory to x is now logged in`,
		`Apr 12 10:00:00 host sshd[1234]: pure-ftpd (?@198.51.100.7) [INFO] alice is now logged in`,
		`Apr 12 10:00:00 host pure-ftpd[1234]: (?@host.example.com) [INFO] 203.0.113.8 is now logged in`,
	} {
		if finding, ok := checks.FTPLoginFinding(line, &config.Config{}); ok {
			t.Errorf("non-login produced a successful login: %+v", finding)
		}
		for _, finding := range parseFTPLogLine(line, &config.Config{}) {
			if finding.Check == "ftp_login" {
				t.Errorf("watcher accepted non-login: %+v", finding)
			}
		}
	}
}

// A plain FTP login names the hosting account that owns the FTP account,
// as the brute-force escalation does, without changing its identity.
func TestFTPLoginCarriesOwnerWithSameKey(t *testing.T) {
	line := `Nov  5 09:00:00 host pure-ftpd[1]: (bob@example.com@203.0.113.9) [INFO] bob@example.com is now logged in`
	restore := checks.SetAccountOwnerLookupForTest(func(string) (string, bool) { return "", false })
	bare, ok := checks.FTPLoginFinding(line, &config.Config{})
	restore()
	if !ok || bare.TenantID != "" {
		t.Fatalf("unowned login = %+v, %v", bare, ok)
	}
	defer checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) { return "shopowner", domain == "example.com" })()
	owned, ok := checks.FTPLoginFinding(line, &config.Config{})
	if !ok || owned.Check != "ftp_login" || owned.TenantID != "shopowner" {
		t.Fatalf("owned login = %+v, %v; want TenantID shopowner", owned, ok)
	}
	if owned.Key() != bare.Key() || owned.Fingerprint() != bare.Fingerprint() {
		t.Fatalf("the owner changed the identity: %q vs %q", owned.Key(), bare.Key())
	}
}

// A login stamped in the future is reported now, and a long record is cut
// while every real success line stays whole.
func TestFTPLoginFindingClampsTimeAndBoundsDetails(t *testing.T) {
	future := time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339) + " host pure-ftpd[1]: (?@203.0.113.9) [INFO] alice@example.com is now logged in"
	before := time.Now()
	f, ok := checks.FTPLoginFinding(future, &config.Config{})
	if !ok || f.Timestamp.Before(before) || f.Timestamp.After(time.Now()) {
		t.Fatalf("future login = %v at %v; want clamped to now", ok, f.Timestamp)
	}
	if f.Details != future {
		t.Fatalf("a real success line was cut: %q", f.Details)
	}
	long := "Nov  5 09:00:00 host pure-ftpd[1]: (?@203.0.113.9) [INFO] " + strings.Repeat("a", 600) + " is now logged in"
	if f, ok = checks.FTPLoginFinding(long, &config.Config{}); !ok || len(f.Details) > 512+len("...") {
		t.Fatalf("long record = %v with %d bytes of details", ok, len(f.Details))
	}
}

func TestFTPVirtualAccountKeepsPeerAddress(t *testing.T) {
	for _, ip := range []string{"203.0.113.9", "2001:db8::9"} {
		line := fmt.Sprintf("Nov  5 09:00:00 host pure-ftpd[1]: (ftpuser@example.com@%s) [INFO] ftpuser@example.com is now logged in", ip)
		findings := parseFTPLogLine(line, &config.Config{})
		if len(findings) != 1 || findings[0].Check != "ftp_login" || findings[0].SourceIP != ip {
			t.Errorf("virtual FTP account lost its peer %s: %+v", ip, findings)
		}
	}
}

// A valid hostname and virtual account can make a success line longer than
// the display limit. Customer history must retain the authenticated account.
func TestFTPLoginAccountSurvivesBoundedDetails(t *testing.T) {
	defer checks.SetAccountOwnerLookupForTest(func(string) (string, bool) { return "", false })()
	account := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 40) + ".example.com"
	host := strings.Repeat("h", 63) + "." + strings.Repeat("h", 63) + "." + strings.Repeat("h", 63) + ".example.com"
	now := time.Now().UTC().Truncate(time.Second)
	line := fmt.Sprintf("%s %s pure-ftpd[1234]: (%s@203.0.113.94) [INFO] %s is now logged in", now.Format(time.RFC3339), host, account, account)
	findings := parseFTPLogLine(line, &config.Config{})
	if len(findings) != 1 || len(findings[0].Details) > 515 || findings[0].Details == line {
		t.Fatalf("expected one bounded login finding, got %+v", findings)
	}
	// Queued findings can cross a restart before customer tracking sees them.
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	var restored []alert.Finding
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	k, _ := knownCustomersAt(now)
	(&Daemon{knownCustomers: k}).noteFTPCustomers(restored)
	hit, ok := k.Lookup("203.0.113.94")
	if !ok || hit.Account != account {
		t.Fatalf("customer login = %+v, %v; want the authenticated virtual account", hit, ok)
	}
}

func TestParseSecureLogLineEmitsSharedLoginFinding(t *testing.T) {
	cfg := &config.Config{}

	shared, ok := checks.SSHAcceptedLoginFinding(sshRealtimeSuccessLine, cfg)
	if !ok {
		t.Fatal("shared builder did not report the login")
	}

	got := parseSecureLogLine(sshRealtimeSuccessLine, cfg)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one", got)
	}
	if got[0].Check != shared.Check || got[0].Key() != shared.Key() {
		t.Fatalf("realtime finding %q/%q differs from the shared builder %q/%q",
			got[0].Check, got[0].Key(), shared.Check, shared.Key())
	}
}

// On shared hosting every customer FTP session comes from a non-infra IP, so
// a successful login is an audit record, not something to mail an operator
// about. A failed authentication still is.
func TestSuccessfulFTPLoginIsNotOperatorAlertable(t *testing.T) {
	cfg := &config.Config{}

	success := parseFTPLogLine(ftpRealtimeSuccessLine, cfg)
	if len(success) == 0 {
		t.Fatal("successful login produced no finding")
	}
	if got := operatorAlertableFindings(success); len(got) != 0 {
		t.Fatalf("successful FTP login reached the operator alert path: %+v", got)
	}

	failure := parseFTPLogLine(ftpRealtimeFailureLine, cfg)
	alertable := operatorAlertableFindings(failure)
	if _, ok := findingWithCheckName(alertable, "ftp_auth_failure_realtime"); !ok {
		t.Fatalf("failed FTP authentication must still alert, got %+v", failure)
	}
}

func findingWithCheckName(findings []alert.Finding, check string) (alert.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return alert.Finding{}, false
}
