//go:build integration

package dovecot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestDovecotIntegrationSnapshot(t *testing.T) {
	for _, name := range []string{"dovecot", "doveconf", "doveadm"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not on PATH", name)
		}
	}
	for _, outage := range []bool{false, true} {
		t.Run(fmt.Sprintf("outage=%v", outage), func(t *testing.T) {
			dir := t.TempDir()
			// The auth service reads the synthetic userdb after dropping root.
			for _, p := range []string{filepath.Dir(dir), dir} {
				if err := os.Chmod(p, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			conf := filepath.Join(dir, "dovecot.conf")
			users := filepath.Join(dir, "users")
			data := "alice@example.com::1000:1000::/srv/vmail/alice::\n"
			if outage {
				// The last unknown-user result masks the earlier temporary
				// error in a batch, as Dovecot's captured output demonstrates.
				data += "rel@example.com::1000:1000::relative/home::\nzero@example.com::0:0::/srv/vmail/zero::\n"
			}
			if err := os.WriteFile(users, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := fmt.Sprintf(`base_dir = %s/run
state_dir = %s/state
protocols =
ssl = no
log_path = /dev/stderr
first_valid_uid = 1000
mail_location = maildir:~/Maildir
passdb {
 driver = static
 args = nopassword=y
}
userdb {
 driver = passwd-file
 args = %s
}
namespace inbox {
 inbox = yes
 mailbox Junk {
  special_use = \Junk
 }
}
`, dir, dir, users)
			if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "dovecot", "-F", "-c", conf)
			daemonOutput := head{limit: 4096}
			cmd.Stdout, cmd.Stderr = &daemonOutput, &daemonOutput
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.WaitDelay = time.Second
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = cmd.Wait()
				if t.Failed() {
					t.Logf("Dovecot startup: %s", daemonOutput.buf.String())
				}
			})
			batchNoUser, singleTempFail := false, false
			d := Dovecot{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				lookups := 0
				if name == "doveadm" && len(args) > 4 && args[1] == "-e" {
					lookups = len(args) - 4
				}
				if name != "dovecot" {
					args = append([]string{"-c", conf}, args...)
				}
				out, err := runCommand(ctx, name, args...)
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					batchNoUser = batchNoUser || lookups > 1 && exit.ExitCode() == exNoUser
					singleTempFail = singleTempFail || lookups == 1 && exit.ExitCode() == exTempFail
				}
				return out, err
			}}
			for {
				if _, err := d.Users(ctx); err == nil {
					break
				}
				if ctx.Err() != nil {
					t.Fatal("Dovecot did not start")
				}
				time.Sleep(50 * time.Millisecond)
			}
			snap, err := d.Snapshot(ctx)
			var exit *exec.ExitError
			if outage {
				if !batchNoUser || !singleTempFail || !errors.As(err, &exit) || exit.ExitCode() != exTempFail || !reflect.DeepEqual(snap, Snapshot{}) {
					t.Fatalf("temporary lookup failure not preserved: snapshot %+v, err %v, batchNoUser %v, singleTempFail %v", snap, err, batchNoUser, singleTempFail)
				}
				return
			}
			want := Snapshot{Complete: true, Mailboxes: []DovecotMailbox{{User: "alice@example.com", Domain: "example.com", UID: 1000, GID: 1000, Home: "/srv/vmail/alice", Junk: []string{"/srv/vmail/alice/Maildir/.Junk"}}}}
			if err != nil || !reflect.DeepEqual(snap, want) {
				t.Fatalf("snapshot %+v, err %v, want %+v", snap, err, want)
			}
		})
	}
}
