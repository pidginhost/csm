package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// logFileOS serves the same content for every Open, which is what the
// tail-based scheduled checks need.
func logFileOS(t *testing.T, content string) *mockOS {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/log"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }}
}

const ftpSuccessLine = `Apr 12 10:00:00 host pure-ftpd[1234]: (alice@198.51.100.7) [INFO] alice is now logged in`

const sshSuccessLine = `Apr 12 10:00:00 host sshd[4242]: Accepted password for deploy from 198.51.100.9 port 40000 ssh2`

// The realtime watcher and the scheduled check both read the pure-ftpd line
// for one login. They must build the same finding, or the state store cannot
// recognise the second one as a repeat and the operator gets it twice.
func TestRealtimeAndScheduledFTPLoginShareIdentity(t *testing.T) {
	withMockOS(t, logFileOS(t, ftpSuccessLine+"\n"))
	cfg := &config.Config{}

	realtime, ok := FTPLoginFinding(ftpSuccessLine, cfg)
	if !ok {
		t.Fatal("FTPLoginFinding did not report a successful login from a non-infra IP")
	}
	if realtime.Check != "ftp_login" {
		t.Fatalf("realtime check = %q, want ftp_login", realtime.Check)
	}

	scheduled, found := findingWithCheck(CheckFTPLogins(context.Background(), cfg, nil), "ftp_login")
	if !found {
		t.Fatal("scheduled CheckFTPLogins did not report the login")
	}
	if scheduled.Key() != realtime.Key() {
		t.Fatalf("scheduled key = %q, realtime key = %q; one login must be one finding", scheduled.Key(), realtime.Key())
	}
	if scheduled.Fingerprint() != realtime.Fingerprint() {
		t.Fatalf("scheduled fingerprint = %q, realtime fingerprint = %q", scheduled.Fingerprint(), realtime.Fingerprint())
	}
}

// End-to-end proof of the above: once the realtime finding is in the state
// store, the scheduled check's rediscovery of the same line is not new.
func TestScheduledFTPLoginIsNotNewAfterRealtimeReportedIt(t *testing.T) {
	withMockOS(t, logFileOS(t, ftpSuccessLine+"\n"))
	cfg := &config.Config{}
	store := newTestStore(t)

	realtime, ok := FTPLoginFinding(ftpSuccessLine, cfg)
	if !ok {
		t.Fatal("FTPLoginFinding did not report a successful login from a non-infra IP")
	}
	store.Update([]alert.Finding{realtime})

	scheduled := CheckFTPLogins(context.Background(), cfg, nil)
	if len(scheduled) == 0 {
		t.Fatal("scheduled CheckFTPLogins reported nothing")
	}
	if got := store.FilterNew(scheduled); len(got) != 0 {
		t.Fatalf("scheduled rediscovery is new: %+v", got)
	}
}

// With no realtime watcher running the scheduled check is the only reporter,
// so it must still produce the login finding on its own.
func TestScheduledFTPLoginReportsWithoutRealtime(t *testing.T) {
	withMockOS(t, logFileOS(t, ftpSuccessLine+"\n"))

	f, found := findingWithCheck(CheckFTPLogins(context.Background(), &config.Config{}, nil), "ftp_login")
	if !found {
		t.Fatal("scheduled CheckFTPLogins must report the login when realtime is not running")
	}
	if f.SourceIP != "198.51.100.7" {
		t.Fatalf("source IP = %q, want 198.51.100.7", f.SourceIP)
	}
}

func TestFTPLoginFindingSkipsInfraAndLoopback(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"198.51.100.7"}
	if _, ok := FTPLoginFinding(ftpSuccessLine, cfg); ok {
		t.Error("infra IP login must not produce a finding")
	}

	loopback := `Apr 12 10:00:00 host pure-ftpd[1234]: (alice@127.0.0.1) [INFO] alice is now logged in`
	if _, ok := FTPLoginFinding(loopback, &config.Config{}); ok {
		t.Error("loopback login must not produce a finding")
	}
}

func TestFTPLoginFindingIgnoresNonLoginLines(t *testing.T) {
	failure := `Apr 12 10:00:00 host pure-ftpd[1234]: (?@198.51.100.7) [WARNING] Authentication failed for user [alice]`
	if _, ok := FTPLoginFinding(failure, &config.Config{}); ok {
		t.Error("an authentication failure is not a successful login")
	}
}

func TestRealtimeAndScheduledSSHLoginShareIdentity(t *testing.T) {
	withMockOS(t, logFileOS(t, sshSuccessLine+"\n"))
	cfg := &config.Config{}

	realtime, ok := SSHAcceptedLoginFinding(sshSuccessLine, cfg)
	if !ok {
		t.Fatal("SSHAcceptedLoginFinding did not report the accepted login")
	}
	if realtime.Check != "ssh_login_unknown_ip" {
		t.Fatalf("realtime check = %q, want ssh_login_unknown_ip", realtime.Check)
	}
	if realtime.TenantID != "deploy" {
		t.Fatalf("tenant = %q, want deploy", realtime.TenantID)
	}

	scheduled, found := findingWithCheck(CheckSSHLogins(context.Background(), cfg, nil), "ssh_login_unknown_ip")
	if !found {
		t.Fatal("scheduled CheckSSHLogins did not report the login")
	}
	if scheduled.Key() != realtime.Key() {
		t.Fatalf("scheduled key = %q, realtime key = %q", scheduled.Key(), realtime.Key())
	}
	if scheduled.Fingerprint() != realtime.Fingerprint() {
		t.Fatalf("scheduled fingerprint = %q, realtime fingerprint = %q", scheduled.Fingerprint(), realtime.Fingerprint())
	}
}
