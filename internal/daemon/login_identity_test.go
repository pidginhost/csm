package daemon

import (
	"testing"

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
