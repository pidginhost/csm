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

func TestLoginIdentityUsesCompleteLogRecord(t *testing.T) {
	// A long syslog host field puts the session PID beyond display truncation.
	host := strings.Repeat("hostlabel.", 20) + "example"
	for _, tt := range []struct {
		name  string
		line  string
		build func(string, *config.Config) (alert.Finding, bool)
	}{
		{"FTP", strings.Replace(ftpSuccessLine, "host", host, 1), FTPLoginFinding},
		{"SSH", strings.Replace(sshSuccessLine, "host", host, 1), SSHAcceptedLoginFinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first, ok := tt.build(tt.line, nil)
			if !ok {
				t.Fatal("first login not reported")
			}
			secondLine := strings.NewReplacer("[1234]", "[1235]", "[4242]", "[4243]").Replace(tt.line)
			second, ok := tt.build(secondLine, nil)
			if !ok {
				t.Fatal("second login not reported")
			}
			st := newTestStore(t)
			st.Update([]alert.Finding{first})
			if got := st.FilterNew([]alert.Finding{first, second}); len(got) != 1 || got[0].Key() != second.Key() {
				t.Fatalf("distinct session lost inside reminder window: %+v", got)
			}
		})
	}
}

func TestLoginIdentityStoreBackedFallback(t *testing.T) {
	for _, tt := range []struct {
		name  string
		line  string
		build func(string, *config.Config) (alert.Finding, bool)
		scan  func(context.Context, *config.Config, *state.Store) []alert.Finding
	}{
		{"FTP", ftpSuccessLine, FTPLoginFinding, CheckFTPLogins},
		{"SSH", sshSuccessLine, SSHAcceptedLoginFinding, CheckSSHLogins},
	} {
		for _, realtimeFirst := range []bool{false, true} {
			t.Run(tt.name+map[bool]string{false: "/scheduled", true: "/realtime"}[realtimeFirst], func(t *testing.T) {
				line := strings.Replace(tt.line, "Apr 12 10:00:00", time.Now().Format("Jan _2 15:04:05"), 1)
				path := t.TempDir() + "/log"
				withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
				st := newTestStore(t)
				cfg := &config.Config{}
				if got := tt.scan(context.Background(), cfg, st); len(got) != 0 {
					t.Fatalf("missing log: %+v", got)
				}
				appendLines(t, path, line)
				live, ok := tt.build(line, cfg)
				if !ok {
					t.Fatal("login not parsed")
				}
				if realtimeFirst {
					st.Update([]alert.Finding{live})
				}
				got := tt.scan(context.Background(), cfg, st)
				if len(got) != 1 || got[0].Key() != live.Key() {
					t.Fatalf("fallback lost login: %+v", got)
				}
				wantNew := 1
				if realtimeFirst {
					wantNew = 0
				}
				if fresh := st.FilterNew(got); len(fresh) != wantNew {
					t.Fatalf("fresh=%+v, want %d", fresh, wantNew)
				}
				st.Update(got)
				if fresh := st.FilterNew([]alert.Finding{live}); len(fresh) != 0 {
					t.Fatal("realtime rediscovery duplicated login")
				}
				second := strings.NewReplacer("[1234]", "[1235]", "[4242]", "[4243]").Replace(line)
				appendLines(t, path, second)
				if fresh := st.FilterNew(tt.scan(context.Background(), cfg, st)); len(fresh) != 1 {
					t.Fatalf("second login lost: %+v", fresh)
				}
			})
		}
	}
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
