package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// pure-ftpd logs cPanel's own internal transfers, which connect over
// loopback. Reporting 127.0.0.1 as an FTP login "from non-infra IP" is both
// factually wrong and unactionable: the operator cannot add loopback to
// infra_ips to silence it without also suppressing genuine findings.
func TestParseFTPLogLineIgnoresLoopbackLogin(t *testing.T) {
	cfg := &config.Config{}

	lines := []string{
		"pure-ftpd: (?@127.0.0.1) [INFO] user@example.com is now logged in",
		"pure-ftpd: (?@::1) [INFO] user@example.com is now logged in",
		"pure-ftpd: (?@::ffff:127.0.0.1) [INFO] user@example.com is now logged in",
	}
	for _, line := range lines {
		if findings := parseFTPLogLine(line, cfg); len(findings) != 0 {
			t.Errorf("loopback line produced %d finding(s), want 0: %q -> %+v", len(findings), line, findings)
		}
	}
}

// The loopback guard must not swallow real remote activity.
func TestParseFTPLogLineStillReportsRemote(t *testing.T) {
	cfg := &config.Config{}

	login := parseFTPLogLine("pure-ftpd: (?@198.51.100.7) [INFO] user@example.com is now logged in", cfg)
	if len(login) != 1 {
		t.Fatalf("remote login: got %d findings, want 1", len(login))
	}
	if login[0].Check != "ftp_login" {
		t.Errorf("check = %q, want ftp_login", login[0].Check)
	}
	if !strings.Contains(login[0].Message, "198.51.100.7") {
		t.Errorf("message = %q, want it to name the source IP", login[0].Message)
	}

	fail := parseFTPLogLine("pure-ftpd: (?@198.51.100.7) [WARNING] Authentication failed for user [bob]", cfg)
	if len(fail) != 1 {
		t.Fatalf("remote auth failure: got %d findings, want 1", len(fail))
	}
	if fail[0].Check != "ftp_auth_failure_realtime" {
		t.Errorf("check = %q, want ftp_auth_failure_realtime", fail[0].Check)
	}
}

// Loopback is transport attribution, not proof of a trusted caller. Failed
// logins through a local relay still need to reach brute-force detection.
func TestParseFTPLogLineReportsLoopbackAuthFailure(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"} {
		for _, message := range []string{"Authentication failed for user [bob]", "auth failed for user [bob]"} {
			findings := parseFTPLogLine("pure-ftpd: (?@"+ip+") [WARNING] "+message, &config.Config{})
			if len(findings) != 1 {
				t.Errorf("%s: got %d findings, want one authentication failure", ip, len(findings))
				continue
			}
			if findings[0].Check != "ftp_auth_failure_realtime" || findings[0].SourceIP != ip {
				t.Errorf("unexpected finding: %+v", findings[0])
			}
		}
	}
}
